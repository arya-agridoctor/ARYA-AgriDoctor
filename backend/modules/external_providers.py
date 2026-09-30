"""
ARYA AgriDoctor
External Providers Integration Layer
Version: 1.0.0

Purpose:
- Weather
- Geocoding / Location
- Satellite / Earth Observation
- Generic external agricultural data providers
- Provider registry
- Provider health/status
- API-key management through environment variables
- Request timeout / retry
- SSRF protection
- Response normalization
- No modification of main.py or other ARYA modules

This module is intentionally independent.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "ARYA External Providers"
APP_VERSION = "1.0.0"

HOST = os.getenv("ARYA_EXTERNAL_HOST", "0.0.0.0")
PORT = int(os.getenv("ARYA_EXTERNAL_PORT", "8095"))

DEFAULT_TIMEOUT = float(
    os.getenv("ARYA_PROVIDER_TIMEOUT", "20")
)

MAX_RESPONSE_BYTES = int(
    os.getenv("ARYA_PROVIDER_MAX_RESPONSE_BYTES", str(8 * 1024 * 1024))
)

MAX_RETRIES = int(
    os.getenv("ARYA_PROVIDER_MAX_RETRIES", "2")
)

USER_AGENT = os.getenv(
    "ARYA_PROVIDER_USER_AGENT",
    "ARYA-AgriDoctor-ExternalProviders/1.0"
)

ALLOW_HTTP = os.getenv(
    "ARYA_PROVIDER_ALLOW_HTTP",
    "false"
).lower() == "true"

LOG_LEVEL = os.getenv(
    "ARYA_EXTERNAL_LOG_LEVEL",
    "INFO"
).upper()


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("arya.external.providers")


# ============================================================
# TIME
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# SECURITY
# ============================================================

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
}


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_external_url(url: str) -> str:
    """
    Validate a provider URL before making outbound requests.

    Blocks:
    - localhost
    - private IPv4/IPv6
    - loopback
    - link-local
    - multicast
    - reserved addresses
    - non-http protocols
    """

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP/HTTPS URLs are allowed")

    if parsed.scheme == "http" and not ALLOW_HTTP:
        raise ValueError("HTTP is disabled; use HTTPS")

    if not parsed.hostname:
        raise ValueError("URL hostname is missing")

    hostname = parsed.hostname.lower().rstrip(".")

    if hostname in BLOCKED_HOSTS:
        raise ValueError("Blocked hostname")

    if _is_private_ip(hostname):
        raise ValueError("Private/internal IP addresses are blocked")

    # Resolve DNS and block private addresses.
    try:
        resolved = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )

        for item in resolved:
            address = item[4][0]

            if _is_private_ip(address):
                raise ValueError(
                    "Hostname resolves to a private/internal address"
                )

    except socket.gaierror:
        raise ValueError("Unable to resolve provider hostname")

    return url


# ============================================================
# HELPERS
# ============================================================

def sha256_json(data: Any) -> str:
    raw = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    return hashlib.sha256(raw).hexdigest()


def safe_json(response: httpx.Response) -> Any:
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise ValueError("Provider response is too large")

    content_type = (
        response.headers.get("content-type", "")
        .lower()
    )

    if "json" in content_type:
        return response.json()

    text = response.text

    try:
        return json.loads(text)
    except Exception:
        return {
            "raw_text": text
        }


def build_headers(
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json,text/plain,*/*",
    }

    if extra:
        headers.update(extra)

    return headers


# ============================================================
# HTTP CLIENT
# ============================================================

class ProviderHTTPClient:
    """
    Central HTTP client.

    All external provider requests should pass through this class.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
    ):
        self.timeout = timeout
        self.max_retries = max_retries

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
    ) -> Dict[str, Any]:

        validate_external_url(url)

        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                started = time.monotonic()

                with httpx.Client(
                    timeout=self.timeout,
                    follow_redirects=False,
                    headers=build_headers(headers),
                ) as client:

                    response = client.request(
                        method=method.upper(),
                        url=url,
                        params=params,
                        json=json_body,
                    )

                elapsed = round(
                    time.monotonic() - started,
                    3,
                )

                if response.status_code >= 500:
                    raise RuntimeError(
                        f"Provider server error: {response.status_code}"
                    )

                response.raise_for_status()

                data = safe_json(response)

                return {
                    "ok": True,
                    "status_code": response.status_code,
                    "elapsed_seconds": elapsed,
                    "data": data,
                    "content_hash": sha256_json(data),
                    "retrieved_at": utc_now(),
                }

            except Exception as exc:
                last_error = exc

                if attempt < self.max_retries:
                    time.sleep(
                        min(2 ** attempt, 5)
                    )
                    continue

        return {
            "ok": False,
            "error": str(last_error),
            "retrieved_at": utc_now(),
        }


HTTP = ProviderHTTPClient()


# ============================================================
# PROVIDER MODEL
# ============================================================

class ProviderConfig(BaseModel):
    id: str
    name: str
    category: str
    base_url: str
    enabled: bool = True
    trusted: bool = False
    priority: int = 100
    api_key_env: Optional[str] = None
    description: Optional[str] = None


class ProviderHealth(BaseModel):
    provider_id: str
    ok: bool
    checked_at: str
    response_time: Optional[float] = None
    error: Optional[str] = None


# ============================================================
# PROVIDER REGISTRY
# ============================================================

PROVIDERS: Dict[str, ProviderConfig] = {}


def register_provider(config: ProviderConfig) -> None:
    validate_external_url(config.base_url)

    PROVIDERS[config.id] = config

    logger.info(
        "Provider registered: %s",
        config.id,
    )


def get_provider(provider_id: str) -> ProviderConfig:
    provider = PROVIDERS.get(provider_id)

    if not provider:
        raise KeyError(
            f"Provider not found: {provider_id}"
        )

    if not provider.enabled:
        raise RuntimeError(
            f"Provider disabled: {provider_id}"
        )

    return provider


def provider_api_key(
    provider: ProviderConfig,
) -> Optional[str]:

    if not provider.api_key_env:
        return None

    return os.getenv(
        provider.api_key_env
    )


# ============================================================
# DEFAULT PROVIDERS
# ============================================================

# Open-Meteo:
# Used as a configurable weather/geocoding provider.
#
# Its current documentation provides:
# - global geocoding
# - weather APIs
#
# The URL is kept configurable through the registry.

register_provider(
    ProviderConfig(
        id="open_meteo_geocoding",
        name="Open-Meteo Geocoding",
        category="geocoding",
        base_url="https://geocoding-api.open-meteo.com",
        enabled=True,
        trusted=True,
        priority=10,
        description="Global location/geocoding provider",
    )
)

register_provider(
    ProviderConfig(
        id="open_meteo_weather",
        name="Open-Meteo Weather",
        category="weather",
        base_url="https://api.open-meteo.com",
        enabled=True,
        trusted=True,
        priority=10,
        description="Weather and forecast provider",
    )
)


# Copernicus Data Space STAC.
register_provider(
    ProviderConfig(
        id="copernicus_stac",
        name="Copernicus Data Space STAC",
        category="satellite",
        base_url="https://stac.dataspace.copernicus.eu",
        enabled=True,
        trusted=True,
        priority=10,
        description="Copernicus Earth Observation catalog",
    )
)


# NASA GIBS.
register_provider(
    ProviderConfig(
        id="nasa_gibs",
        name="NASA GIBS",
        category="satellite",
        base_url="https://gibs.earthdata.nasa.gov",
        enabled=True,
        trusted=True,
        priority=20,
        description="NASA global satellite imagery services",
    )
)


# ============================================================
# GEOCODING
# ============================================================

class GeocodeRequest(BaseModel):
    query: str = Field(min_length=1, max_length=300)
    count: int = Field(default=5, ge=1, le=20)
    language: Optional[str] = None
    country_code: Optional[str] = None


def geocode(
    request: GeocodeRequest,
) -> Dict[str, Any]:

    provider = get_provider(
        "open_meteo_geocoding"
    )

    params = {
        "name": request.query,
        "count": request.count,
        "format": "json",
    }

    if request.language:
        params["language"] = request.language

    if request.country_code:
        params["countryCode"] = request.country_code

    result = HTTP.request(
        "GET",
        provider.base_url + "/v1/search",
        params=params,
    )

    if not result["ok"]:
        return result

    data = result.get("data") or {}

    normalized = []

    for item in data.get("results", []):
        normalized.append(
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "latitude": item.get("latitude"),
                "longitude": item.get("longitude"),
                "elevation": item.get("elevation"),
                "country": item.get("country"),
                "country_code": item.get("country_code"),
                "admin1": item.get("admin1"),
                "admin2": item.get("admin2"),
                "timezone": item.get("timezone"),
            }
        )

    return {
        "ok": True,
        "provider": provider.id,
        "query": request.query,
        "results": normalized,
        "retrieved_at": result["retrieved_at"],
        "content_hash": sha256_json(normalized),
    }


# ============================================================
# WEATHER
# ============================================================

class WeatherRequest(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)

    timezone: str = "auto"

    forecast_days: int = Field(
        default=7,
        ge=1,
        le=16,
    )

    hourly: List[str] = Field(
        default_factory=lambda: [
            "temperature_2m",
            "relative_humidity_2m",
            "precipitation",
            "rain",
            "wind_speed_10m",
            "wind_direction_10m",
        ]
    )

    daily: List[str] = Field(
        default_factory=lambda: [
            "temperature_2m_max",
            "temperature_2m_min",
            "precipitation_sum",
            "rain_sum",
            "wind_speed_10m_max",
            "sunrise",
            "sunset",
        ]
    )


def get_weather(
    request: WeatherRequest,
) -> Dict[str, Any]:

    provider = get_provider(
        "open_meteo_weather"
    )

    params = {
        "latitude": request.latitude,
        "longitude": request.longitude,
        "timezone": request.timezone,
        "forecast_days": request.forecast_days,
        "hourly": ",".join(request.hourly),
        "daily": ",".join(request.daily),
    }

    result = HTTP.request(
        "GET",
        provider.base_url + "/v1/forecast",
        params=params,
    )

    if not result["ok"]:
        return result

    data = result["data"]

    return {
        "ok": True,
        "provider": provider.id,
        "location": {
            "latitude": request.latitude,
            "longitude": request.longitude,
        },
        "timezone": data.get("timezone"),
        "timezone_abbreviation": data.get(
            "timezone_abbreviation"
        ),
        "elevation": data.get("elevation"),
        "generationtime_ms": data.get(
            "generationtime_ms"
        ),
        "hourly": data.get("hourly"),
        "hourly_units": data.get("hourly_units"),
        "daily": data.get("daily"),
        "daily_units": data.get("daily_units"),
        "retrieved_at": result["retrieved_at"],
        "content_hash": sha256_json(data),
    }


# ============================================================
# SATELLITE / COPERNICUS STAC
# ============================================================

class SatelliteSearchRequest(BaseModel):
    collection: Optional[str] = None

    bbox: List[float] = Field(
        min_length=4,
        max_length=4,
    )

    datetime_start: Optional[str] = None
    datetime_end: Optional[str] = None

    limit: int = Field(
        default=10,
        ge=1,
        le=100,
    )

    cloud_cover_max: Optional[float] = Field(
        default=None,
        ge=0,
        le=100,
    )


def search_copernicus(
    request: SatelliteSearchRequest,
) -> Dict[str, Any]:

    provider = get_provider(
        "copernicus_stac"
    )

    payload: Dict[str, Any] = {
        "bbox": request.bbox,
        "limit": request.limit,
    }

    if request.collection:
        payload["collections"] = [
            request.collection
        ]

    if request.datetime_start:
        end = request.datetime_end or request.datetime_start

        payload["datetime"] = (
            f"{request.datetime_start}/{end}"
        )

    if request.cloud_cover_max is not None:
        payload.setdefault(
            "query",
            {}
        )[
            "eo:cloud_cover"
        ] = {
            "lte": request.cloud_cover_max
        }

    result = HTTP.request(
        "POST",
        provider.base_url + "/v1/search",
        json_body=payload,
    )

    if not result["ok"]:
        return result

    data = result["data"]

    features = []

    for item in data.get("features", []):
        properties = item.get(
            "properties",
            {},
        )

        features.append(
            {
                "id": item.get("id"),
                "collection": item.get(
                    "collection"
                ),
                "geometry": item.get(
                    "geometry"
                ),
                "bbox": item.get("bbox"),
                "datetime": properties.get(
                    "datetime"
                ),
                "cloud_cover": properties.get(
                    "eo:cloud_cover"
                ),
                "assets": list(
                    (item.get("assets") or {}).keys()
                ),
            }
        )

    return {
        "ok": True,
        "provider": provider.id,
        "number_matched": data.get(
            "numberMatched"
        ),
        "number_returned": data.get(
            "numberReturned"
        ),
        "features": features,
        "retrieved_at": result["retrieved_at"],
        "content_hash": sha256_json(features),
    }


# ============================================================
# NASA GIBS TILE URL
# ============================================================

class NasaGibsTileRequest(BaseModel):
    layer: str
    date: str
    z: int = Field(ge=0, le=30)
    x: int = Field(ge=0)
    y: int = Field(ge=0)


def nasa_gibs_tile(
    request: NasaGibsTileRequest,
) -> Dict[str, Any]:

    provider = get_provider(
        "nasa_gibs"
    )

    # Standard WMTS REST-style URL pattern.
    #
    # The layer itself is deliberately supplied by the caller,
    # because NASA GIBS contains many imagery products.

    url = (
        provider.base_url
        + "/wmts/epsg3857/best/"
        + request.layer
        + "/default/"
        + request.date
        + "/GoogleMapsCompatible_Level9/"
        + str(request.z)
        + "/"
        + str(request.y)
        + "/"
        + str(request.x)
        + ".jpg"
    )

    validate_external_url(url)

    return {
        "ok": True,
        "provider": provider.id,
        "layer": request.layer,
        "date": request.date,
        "tile": {
            "z": request.z,
            "x": request.x,
            "y": request.y,
        },
        "url": url,
        "generated_at": utc_now(),
    }


# ============================================================
# GENERIC PROVIDER REQUEST
# ============================================================

class GenericProviderRequest(BaseModel):
    provider_id: str

    path: str = ""

    method: str = "GET"

    params: Dict[str, Any] = Field(
        default_factory=dict
    )

    body: Optional[Dict[str, Any]] = None


def generic_provider_request(
    request: GenericProviderRequest,
) -> Dict[str, Any]:

    provider = get_provider(
        request.provider_id
    )

    base = provider.base_url.rstrip("/")

    path = request.path.strip()

    if path:
        if not path.startswith("/"):
            path = "/" + path

    url = base + path

    api_key = provider_api_key(provider)

    headers: Dict[str, str] = {}

    if api_key:
        headers["Authorization"] = (
            f"Bearer {api_key}"
        )

    return HTTP.request(
        request.method,
        url,
        params=request.params,
        headers=headers,
        json_body=request.body,
    )


# ============================================================
# PROVIDER HEALTH
# ============================================================

def check_provider(
    provider_id: str,
) -> ProviderHealth:

    try:
        provider = get_provider(
            provider_id
        )

        started = time.monotonic()

        result = HTTP.request(
            "GET",
            provider.base_url,
        )

        elapsed = round(
            time.monotonic() - started,
            3,
        )

        return ProviderHealth(
            provider_id=provider_id,
            ok=bool(result.get("ok")),
            checked_at=utc_now(),
            response_time=elapsed,
            error=result.get("error"),
        )

    except Exception as exc:
        return ProviderHealth(
            provider_id=provider_id,
            ok=False,
            checked_at=utc_now(),
            error=str(exc),
        )


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Independent ARYA external provider integration layer"
    ),
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "provider_count": len(PROVIDERS),
        "time": utc_now(),
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "ok": True,
        "service": APP_NAME,
        "version": APP_VERSION,
        "time": utc_now(),
        "providers": len(PROVIDERS),
    }


# ============================================================
# PROVIDERS
# ============================================================

@app.get("/providers")
def list_providers(
    category: Optional[str] = Query(
        default=None
    ),
):
    result = []

    for provider in sorted(
        PROVIDERS.values(),
        key=lambda x: (
            x.category,
            x.priority,
            x.id,
        ),
    ):

        if category and provider.category != category:
            continue

        result.append(
            {
                "id": provider.id,
                "name": provider.name,
                "category": provider.category,
                "enabled": provider.enabled,
                "trusted": provider.trusted,
                "priority": provider.priority,
                "description": provider.description,
                "api_key_configured": bool(
                    provider_api_key(provider)
                ),
            }
        )

    return {
        "ok": True,
        "providers": result,
        "count": len(result),
    }


# ============================================================
# PROVIDER DETAIL
# ============================================================

@app.get("/providers/{provider_id}")
def provider_detail(
    provider_id: str,
):
    try:
        provider = get_provider(
            provider_id
        )
    except Exception as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    return {
        "ok": True,
        "provider": {
            "id": provider.id,
            "name": provider.name,
            "category": provider.category,
            "base_url": provider.base_url,
            "enabled": provider.enabled,
            "trusted": provider.trusted,
            "priority": provider.priority,
            "description": provider.description,
            "api_key_configured": bool(
                provider_api_key(provider)
            ),
        },
    }


# ============================================================
# PROVIDER HEALTH
# ============================================================

@app.get(
    "/providers/{provider_id}/health"
)
def provider_health(
    provider_id: str,
):
    return check_provider(
        provider_id
    )


# ============================================================
# GEOCODING
# ============================================================

@app.post("/location/geocode")
def location_geocode(
    request: GeocodeRequest,
):
    try:
        return geocode(request)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


# ============================================================
# WEATHER
# ============================================================

@app.post("/weather")
def weather(
    request: WeatherRequest,
):
    try:
        return get_weather(request)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


# ============================================================
# COPERNICUS SATELLITE
# ============================================================

@app.post("/satellite/copernicus/search")
def satellite_search(
    request: SatelliteSearchRequest,
):
    try:
        return search_copernicus(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


# ============================================================
# NASA GIBS
# ============================================================

@app.post("/satellite/nasa/gibs/tile")
def satellite_nasa_tile(
    request: NasaGibsTileRequest,
):
    try:
        return nasa_gibs_tile(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


# ============================================================
# GENERIC PROVIDER
# ============================================================

@app.post("/provider/request")
def provider_request(
    request: GenericProviderRequest,
):
    try:
        return generic_provider_request(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


# ============================================================
# BATCH HEALTH
# ============================================================

@app.get("/providers/health/all")
def all_provider_health():
    results = []

    for provider_id in PROVIDERS:
        results.append(
            check_provider(
                provider_id
            ).model_dump()
        )

    return {
        "ok": True,
        "checked_at": utc_now(),
        "results": results,
    }


# ============================================================
# UPDATE PROVIDER STATE
# ============================================================

@app.post("/providers/{provider_id}/enable")
def enable_provider(
    provider_id: str,
):
    provider = PROVIDERS.get(
        provider_id
    )

    if not provider:
        raise HTTPException(
            status_code=404,
            detail="Provider not found",
        )

    provider.enabled = True

    return {
        "ok": True,
        "provider_id": provider_id,
        "enabled": True,
        "updated_at": utc_now(),
    }


@app.post("/providers/{provider_id}/disable")
def disable_provider(
    provider_id: str,
):
    provider = PROVIDERS.get(
        provider_id
    )

    if not provider:
        raise HTTPException(
            status_code=404,
            detail="Provider not found",
        )

    provider.enabled = False

    return {
        "ok": True,
        "provider_id": provider_id,
        "enabled": False,
        "updated_at": utc_now(),
    }


# ============================================================
# INFORMATION / VERSION
# ============================================================

@app.get("/info")
def info():
    categories: Dict[str, int] = {}

    for provider in PROVIDERS.values():
        categories.setdefault(
            provider.category,
            0,
        )

        categories[
            provider.category
        ] += 1

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "providers": len(PROVIDERS),
        "categories": categories,
        "security": {
            "ssrf_protection": True,
            "private_ip_blocking": True,
            "redirects_disabled": True,
            "response_size_limit": MAX_RESPONSE_BYTES,
            "timeout": DEFAULT_TIMEOUT,
            "retries": MAX_RETRIES,
        },
        "time": utc_now(),
    }


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
    )
