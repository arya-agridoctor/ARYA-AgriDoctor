"""
===============================================================
 ARYA AgriDoctor - External Providers Integration Layer
 Version: 2.0.0
===============================================================

PURPOSE
-------
1. Open-Meteo geocoding
2. Open-Meteo weather
3. Copernicus STAC satellite search
4. NASA GIBS satellite tile URLs
5. Provider registry and health checks
6. Controlled provider requests
7. Provider enable/disable management
8. SSRF defense-in-depth
9. Bounded HTTP response reading
10. Input validation and sanitized errors

SECURITY
--------
- No arbitrary user-supplied destination URLs.
- Redirects are disabled.
- HTTP responses are size-limited while streaming.
- Provider management requires ARYA_EXTERNAL_ADMIN_TOKEN.
- Generic provider requests require ARYA_EXTERNAL_API_TOKEN.
- Tokens must be configured through environment variables.
- Never place credentials directly in this file.

INSTALLATION
------------
File:
    backend/modules/external_providers.py

Dependencies:
    fastapi
    httpx
    pydantic

===============================================================
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import re
import socket
import time

from datetime import date, datetime
from threading import RLock
from typing import Any, Dict, List, Literal, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from fastapi import FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator


# ===============================================================
# APPLICATION / LOGGING
# ===============================================================

APP_NAME = "ARYA External Providers Integration Layer"
APP_VERSION = "2.0.0"

logging.basicConfig(level=os.getenv("ARYA_LOG_LEVEL", "INFO"))
logger = logging.getLogger("arya.external_providers")

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Controlled external data providers for ARYA AgriDoctor. "
        "Provides weather, geocoding, satellite search, and "
        "provider management endpoints."
    ),
)


# ===============================================================
# ENVIRONMENT CONFIGURATION
# ===============================================================

def _env_int(
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name)

    if raw is None:
        return default

    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid integer environment setting: %s; using default",
            name,
        )
        return default

    return max(minimum, min(value, maximum))


def _env_float(
    name: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    raw = os.getenv(name)

    if raw is None:
        return default

    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid float environment setting: %s; using default",
            name,
        )
        return default

    return max(minimum, min(value, maximum))


HTTP_TIMEOUT_SECONDS = _env_float(
    "ARYA_EXTERNAL_HTTP_TIMEOUT",
    15.0,
    1.0,
    60.0,
)

HTTP_MAX_RETRIES = _env_int(
    "ARYA_EXTERNAL_HTTP_RETRIES",
    2,
    0,
    5,
)

MAX_RESPONSE_BYTES = _env_int(
    "ARYA_EXTERNAL_MAX_RESPONSE_BYTES",
    2_000_000,
    16_384,
    20_000_000,
)

MAX_STAC_ITEMS = _env_int(
    "ARYA_EXTERNAL_MAX_STAC_ITEMS",
    20,
    1,
    100,
)

MAX_GENERIC_REQUEST_BYTES = _env_int(
    "ARYA_EXTERNAL_MAX_REQUEST_BYTES",
    64_000,
    1_024,
    500_000,
)

ALLOW_LOCAL_HTTP = (
    os.getenv("ARYA_EXTERNAL_ALLOW_LOCAL_HTTP", "false").lower()
    in {"1", "true", "yes"}
)

ADMIN_TOKEN = os.getenv("ARYA_EXTERNAL_ADMIN_TOKEN", "").strip()
API_TOKEN = os.getenv("ARYA_EXTERNAL_API_TOKEN", "").strip()

USER_AGENT = "ARYA-AgriDoctor-ExternalProviders/2.0.0"


# ===============================================================
# EXCEPTIONS
# ===============================================================

class ProviderError(Exception):
    """Safe internal provider failure."""


class ProviderTimeoutError(ProviderError):
    """Provider request timed out."""


class ProviderResponseError(ProviderError):
    """Provider returned an invalid or unsuccessful response."""


class ProviderSecurityError(ProviderError):
    """A provider request failed a security check."""


class ProviderResponseTooLarge(ProviderError):
    """Provider response exceeded the configured byte limit."""


# ===============================================================
# PROVIDER CONFIGURATION
# ===============================================================

class ProviderConfig(BaseModel):
    provider_id: str
    name: str
    base_url: str
    provider_type: str
    enabled: bool = True
    trusted: bool = False
    description: str = ""
    health_path: str = "/"
    timeout_seconds: float = HTTP_TIMEOUT_SECONDS


def _provider(
    provider_id: str,
    name: str,
    base_url: str,
    provider_type: str,
    description: str,
    health_path: str = "/",
) -> ProviderConfig:
    return ProviderConfig(
        provider_id=provider_id,
        name=name,
        base_url=base_url.rstrip("/"),
        provider_type=provider_type,
        enabled=True,
        trusted=True,
        description=description,
        health_path=health_path,
    )


_INITIAL_PROVIDERS: Dict[str, ProviderConfig] = {
    "open_meteo_geocoding": _provider(
        provider_id="open_meteo_geocoding",
        name="Open-Meteo Geocoding",
        base_url="https://geocoding-api.open-meteo.com",
        provider_type="geocoding",
        description="Geographic place-name search.",
        health_path="/v1/search?name=Tehran&count=1&language=en&format=json",
    ),
    "open_meteo_weather": _provider(
        provider_id="open_meteo_weather",
        name="Open-Meteo Weather",
        base_url="https://api.open-meteo.com",
        provider_type="weather",
        description="Forecast and current weather data.",
        health_path=(
            "/v1/forecast?latitude=35.6892&longitude=51.3890"
            "&current=temperature_2m&forecast_days=1"
        ),
    ),
    "copernicus_stac": _provider(
        provider_id="copernicus_stac",
        name="Copernicus Data Space STAC",
        base_url="https://catalogue.dataspace.copernicus.eu",
        provider_type="satellite",
        description="Copernicus STAC catalogue search.",
        health_path="/",
    ),
    "nasa_gibs": _provider(
        provider_id="nasa_gibs",
        name="NASA Global Imagery Browse Services",
        base_url="https://gibs.earthdata.nasa.gov",
        provider_type="satellite",
        description="NASA GIBS satellite imagery tiles.",
        health_path="/",
    ),
}

_PROVIDERS: Dict[str, ProviderConfig] = {
    key: value.model_copy(deep=True)
    for key, value in _INITIAL_PROVIDERS.items()
}

_PROVIDER_LOCK = RLock()


# ===============================================================
# PROVIDER REGISTRY
# ===============================================================

def get_provider(provider_id: str) -> ProviderConfig:
    with _PROVIDER_LOCK:
        provider = _PROVIDERS.get(provider_id)

        if provider is None:
            raise HTTPException(
                status_code=404,
                detail="Provider not found.",
            )

        return provider.model_copy(deep=True)


def list_providers() -> List[ProviderConfig]:
    with _PROVIDER_LOCK:
        return [
            provider.model_copy(deep=True)
            for provider in _PROVIDERS.values()
        ]


def set_provider_enabled(
    provider_id: str,
    enabled: bool,
) -> ProviderConfig:
    with _PROVIDER_LOCK:
        provider = _PROVIDERS.get(provider_id)

        if provider is None:
            raise HTTPException(
                status_code=404,
                detail="Provider not found.",
            )

        provider.enabled = enabled

        return provider.model_copy(deep=True)


def require_enabled_provider(provider_id: str) -> ProviderConfig:
    provider = get_provider(provider_id)

    if not provider.enabled:
        raise HTTPException(
            status_code=503,
            detail="Provider is disabled.",
        )

    return provider


# ===============================================================
# AUTHORIZATION
# ===============================================================

def _verify_bearer_token(
    authorization: Optional[str],
    configured_token: str,
) -> bool:
    if not configured_token:
        return False

    if not authorization:
        return False

    scheme, separator, supplied_token = authorization.partition(" ")

    if not separator or scheme.lower() != "bearer":
        return False

    supplied_token = supplied_token.strip()

    if not supplied_token:
        return False

    return hmac.compare_digest(
        supplied_token.encode("utf-8"),
        configured_token.encode("utf-8"),
    )


def require_admin_token(
    authorization: Optional[str] = Header(default=None),
) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=503,
            detail=(
                "Provider management is disabled because "
                "ARYA_EXTERNAL_ADMIN_TOKEN is not configured."
            ),
        )

    if not _verify_bearer_token(authorization, ADMIN_TOKEN):
        raise HTTPException(
            status_code=401,
            detail="Valid administrator authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_api_token(
    authorization: Optional[str] = Header(default=None),
) -> None:
    if not API_TOKEN:
        raise HTTPException(
            status_code=503,
            detail=(
                "Generic provider requests are disabled because "
                "ARYA_EXTERNAL_API_TOKEN is not configured."
            ),
        )

    if not _verify_bearer_token(authorization, API_TOKEN):
        raise HTTPException(
            status_code=401,
            detail="Valid API authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ===============================================================
# URL AND NETWORK SECURITY
# ===============================================================

def _is_public_ip(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False

    return (
        parsed.is_global
        and not parsed.is_private
        and not parsed.is_loopback
        and not parsed.is_link_local
        and not parsed.is_multicast
        and not parsed.is_reserved
        and not parsed.is_unspecified
    )


def _is_allowed_local_http_host(host: str) -> bool:
    if not ALLOW_LOCAL_HTTP:
        return False

    normalized = host.lower().rstrip(".")

    return normalized in {
        "localhost",
        "127.0.0.1",
        "::1",
    }


def validate_provider_url(url: str) -> None:
    """
    Defense-in-depth URL validation.

    All normal provider requests use fixed provider base URLs.
    This check rejects unsafe schemes, credentials, local addresses,
    private addresses, and non-public DNS resolutions.

    DNS preflight is not a substitute for network-level egress rules:
    DNS rebinding can still occur between validation and connection.
    Production deployments should also restrict outbound network
    access to approved destinations.
    """
    try:
        parsed = urlsplit(url)
    except Exception as exc:
        raise ProviderSecurityError("Invalid provider URL.") from exc

    if parsed.scheme not in {"https", "http"}:
        raise ProviderSecurityError("Unsupported URL scheme.")

    if not parsed.hostname:
        raise ProviderSecurityError("URL hostname is missing.")

    if parsed.username is not None or parsed.password is not None:
        raise ProviderSecurityError("URL credentials are not allowed.")

    if parsed.fragment:
        raise ProviderSecurityError("URL fragments are not allowed.")

    host = parsed.hostname.lower().rstrip(".")

    if parsed.scheme == "http" and not _is_allowed_local_http_host(host):
        raise ProviderSecurityError("Non-local HTTP URLs are not allowed.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ProviderSecurityError("Invalid URL port.") from exc

    if port is not None and not (1 <= port <= 65535):
        raise ProviderSecurityError("Invalid URL port.")

    try:
        literal_ip = ipaddress.ip_address(host)
        if not _is_public_ip(str(literal_ip)):
            if not _is_allowed_local_http_host(host):
                raise ProviderSecurityError(
                    "Private or non-public IP destinations are blocked."
                )
        return
    except ValueError:
        pass

    if host in {"localhost", "localhost.localdomain"}:
        if not _is_allowed_local_http_host(host):
            raise ProviderSecurityError("Localhost destinations are blocked.")
        return

    try:
        records = socket.getaddrinfo(
            host,
            port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ProviderSecurityError(
            "Provider hostname could not be resolved."
        ) from exc

    addresses = {
        record[4][0]
        for record in records
        if record and len(record) > 4 and record[4]
    }

    if not addresses:
        raise ProviderSecurityError("Provider hostname has no valid address.")

    if not _is_allowed_local_http_host(host):
        for address in addresses:
            if not _is_public_ip(address):
                raise ProviderSecurityError(
                    "Provider hostname resolves to a non-public address."
                )


def _validate_provider_base_url(provider: ProviderConfig) -> None:
    validate_provider_url(provider.base_url)


def _join_provider_url(
    provider: ProviderConfig,
    path: str,
) -> str:
    """
    Join a relative path to a fixed provider base URL.

    Absolute URLs, protocol-relative URLs, backslashes, and traversal
    path segments are rejected.
    """
    if not isinstance(path, str) or not path:
        raise ProviderSecurityError("A provider path is required.")

    if len(path) > 2048:
        raise ProviderSecurityError("Provider path is too long.")

    if "\\" in path:
        raise ProviderSecurityError("Backslashes are not allowed in paths.")

    if path.startswith("//"):
        raise ProviderSecurityError("Protocol-relative URLs are blocked.")

    if "://" in path:
        raise ProviderSecurityError("Absolute URLs are not allowed.")

    path_part = path.split("?", 1)[0].split("#", 1)[0]

    if any(segment == ".." for segment in path_part.split("/")):
        raise ProviderSecurityError("Path traversal is blocked.")

    base = provider.base_url.rstrip("/")
    normalized_path = path if path.startswith("/") else f"/{path}"

    result = base + normalized_path

    validate_provider_url(result)

    return result


# ===============================================================
# BOUNDED HTTP CLIENT
# ===============================================================

class ProviderHTTPClient:
    """
    HTTP client for fixed, registered provider destinations.

    - Does not follow redirects.
    - Streams responses with a hard byte limit.
    - Retries selected transient failures.
    - Never returns raw internal exceptions to API clients.
    """

    def __init__(
        self,
        timeout_seconds: float = HTTP_TIMEOUT_SECONDS,
        retries: int = HTTP_MAX_RETRIES,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self.timeout_seconds = max(1.0, min(timeout_seconds, 60.0))
        self.retries = max(0, min(retries, 5))
        self.max_response_bytes = max(
            16_384,
            min(max_response_bytes, 20_000_000),
        )

    def request(
        self,
        provider: ProviderConfig,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        max_response_bytes: Optional[int] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        if not provider.enabled:
            raise ProviderError("Provider is disabled.")

        method = method.upper().strip()

        if method not in {"GET", "POST"}:
            raise ProviderSecurityError("HTTP method is not allowed.")

        url = _join_provider_url(provider, path)
        limit = self.max_response_bytes

        if max_response_bytes is not None:
            limit = max(
                1,
                min(int(max_response_bytes), self.max_response_bytes),
            )

        safe_headers: Dict[str, str] = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, application/geo+json, */*",
        }

        if headers:
            blocked_headers = {
                "host",
                "connection",
                "transfer-encoding",
                "content-length",
                "proxy-authorization",
                "proxy-connection",
            }

            for key, value in headers.items():
                normalized_key = key.strip().lower()

                if normalized_key in blocked_headers:
                    continue

                if normalized_key in {"authorization", "cookie"}:
                    continue

                if "\r" in key or "\n" in key:
                    continue

                if "\r" in str(value) or "\n" in str(value):
                    continue

                safe_headers[key] = str(value)

        last_error: Optional[Exception] = None

        for attempt in range(self.retries + 1):
            try:
                _validate_provider_base_url(provider)

                timeout = httpx.Timeout(
                    self.timeout_seconds,
                    connect=min(self.timeout_seconds, 10.0),
                )

                chunks: List[bytes] = []
                total_bytes = 0

                with httpx.Client(
                    timeout=timeout,
                    follow_redirects=False,
                    trust_env=False,
                    verify=True,
                ) as client:
                    with client.stream(
                        method,
                        url,
                        params=params,
                        json=json_body,
                        headers=safe_headers,
                    ) as response:
                        if 300 <= response.status_code < 400:
                            raise ProviderResponseError(
                                "Provider redirects are not allowed."
                            )

                        content_length = response.headers.get("content-length")

                        if content_length:
                            try:
                                declared_size = int(content_length)
                            except ValueError:
                                declared_size = -1

                            if declared_size > limit:
                                raise ProviderResponseTooLarge(
                                    "Provider response is too large."
                                )

                        for chunk in response.iter_bytes():
                            total_bytes += len(chunk)

                            if total_bytes > limit:
                                raise ProviderResponseTooLarge(
                                    "Provider response is too large."
                                )

                            chunks.append(chunk)

                        body = b"".join(chunks)

                        return (
                            response.status_code,
                            {
                                "content-type": response.headers.get(
                                    "content-type",
                                    "",
                                ),
                            },
                            body,
                        )

            except ProviderResponseTooLarge:
                raise

            except ProviderSecurityError:
                raise

            except ProviderResponseError:
                raise

            except httpx.TimeoutException as exc:
                last_error = exc

            except httpx.RequestError as exc:
                last_error = exc

            except Exception as exc:
                logger.exception(
                    "Unexpected provider HTTP client error for %s",
                    provider.provider_id,
                )
                last_error = exc

            if attempt < self.retries:
                time.sleep(min(0.25 * (2 ** attempt), 2.0))

        if isinstance(last_error, httpx.TimeoutException):
            raise ProviderTimeoutError(
                "External provider request timed out."
            ) from last_error

        logger.warning(
            "External provider request failed: provider=%s error_type=%s",
            provider.provider_id,
            type(last_error).__name__ if last_error else "unknown",
        )

        raise ProviderResponseError(
            "External provider request failed."
        ) from last_error


http_client = ProviderHTTPClient()


# ===============================================================
# JSON RESPONSE HELPERS
# ===============================================================

def _decode_json_response(
    status_code: int,
    headers: Dict[str, str],
    body: bytes,
) -> Any:
    if status_code < 200 or status_code >= 300:
        raise ProviderResponseError(
            f"External provider returned HTTP {status_code}."
        )

    content_type = headers.get("content-type", "").lower()

    if (
        "json" not in content_type
        and "geo+json" not in content_type
        and body
    ):
        # Some providers do not consistently return a JSON content type.
        # Attempt parsing, but do not expose raw response bodies on failure.
        pass

    try:
        import json
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProviderResponseError(
            "External provider returned invalid JSON."
        ) from exc


def _provider_json(
    provider_id: str,
    method: str,
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    max_response_bytes: Optional[int] = None,
) -> Any:
    provider = require_enabled_provider(provider_id)

    try:
        status, headers, body = http_client.request(
            provider,
            method,
            path,
            params=params,
            json_body=json_body,
            max_response_bytes=max_response_bytes,
        )

        return _decode_json_response(status, headers, body)

    except ProviderTimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail="External provider timed out.",
        ) from exc

    except ProviderResponseTooLarge as exc:
        raise HTTPException(
            status_code=502,
            detail="External provider response exceeded the size limit.",
        ) from exc

    except ProviderSecurityError as exc:
        logger.warning(
            "Blocked provider request: provider=%s",
            provider_id,
        )
        raise HTTPException(
            status_code=400,
            detail="Provider request failed security validation.",
        ) from exc

    except ProviderResponseError as exc:
        logger.warning(
            "Provider response failure: provider=%s",
            provider_id,
        )
        raise HTTPException(
            status_code=502,
            detail="External provider returned an unsuccessful response.",
        ) from exc


# ===============================================================
# REQUEST MODELS
# ===============================================================

class GeocodeRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    count: int = Field(default=5, ge=1, le=10)
    language: str = Field(default="en", min_length=2, max_length=10)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Place name cannot be empty.")

        if any(ord(char) < 32 for char in value):
            raise ValueError("Control characters are not allowed.")

        return value

    @field_validator("language")
    @classmethod
    def validate_language(cls, value: str) -> str:
        value = value.strip()

        if not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?", value):
            raise ValueError("Invalid language code.")

        return value


class WeatherRequest(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    timezone: str = Field(default="auto", min_length=1, max_length=100)
    forecast_days: int = Field(default=7, ge=1, le=16)
    current: bool = True
    hourly: bool = True
    daily: bool = True


class SatelliteSearchRequest(BaseModel):
    bbox: List[float] = Field(min_length=4, max_length=4)
    datetime_start: date
    datetime_end: date
    collections: List[str] = Field(
        default_factory=lambda: ["sentinel-2-l2a"],
        min_length=1,
        max_length=10,
    )
    limit: int = Field(default=10, ge=1, le=MAX_STAC_ITEMS)

    @field_validator("bbox")
    @classmethod
    def validate_bbox(cls, value: List[float]) -> List[float]:
        if len(value) != 4:
            raise ValueError("bbox must contain four coordinates.")

        min_lon, min_lat, max_lon, max_lat = value

        if not all(
            isinstance(item, (int, float))
            for item in value
        ):
            raise ValueError("bbox coordinates must be numeric.")

        if not all(
            -180 <= lon <= 180
            for lon in (min_lon, max_lon)
        ):
            raise ValueError("Longitude is outside the valid range.")

        if not all(
            -90 <= lat <= 90
            for lat in (min_lat, max_lat)
        ):
            raise ValueError("Latitude is outside the valid range.")

        if min_lon >= max_lon or min_lat >= max_lat:
            raise ValueError("Invalid bounding box dimensions.")

        return value

    @field_validator("collections")
    @classmethod
    def validate_collections(cls, value: List[str]) -> List[str]:
        cleaned: List[str] = []

        for item in value:
            item = item.strip()

            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", item):
                raise ValueError("Invalid satellite collection identifier.")

            cleaned.append(item)

        if not cleaned:
            raise ValueError("At least one collection is required.")

        return cleaned


class NasaGibsTileRequest(BaseModel):
    layer: str = Field(min_length=1, max_length=120)
    imagery_date: date
    z: int = Field(ge=0, le=18)
    x: int = Field(ge=0, le=262143)
    y: int = Field(ge=0, le=262143)
    format: Literal["jpg", "png"] = "jpg"

    @field_validator("layer")
    @classmethod
    def validate_layer(cls, value: str) -> str:
        value = value.strip()

        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", value):
            raise ValueError("Invalid NASA GIBS layer name.")

        return value

    @field_validator("x", "y")
    @classmethod
    def validate_tile_coordinates(cls, value: int, info: Any) -> int:
        zoom = info.data.get("z")

        if zoom is not None and value >= (2 ** zoom):
            raise ValueError("Tile coordinate is outside the zoom range.")

        return value


class GenericProviderRequest(BaseModel):
    provider_id: str = Field(min_length=1, max_length=80)
    method: Literal["GET", "POST"] = "GET"
    path: str = Field(min_length=1, max_length=2048)
    params: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None

    @field_validator("provider_id")
    @classmethod
    def validate_provider_id(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", value):
            raise ValueError("Invalid provider identifier.")

        return value

    @field_validator("params", "body")
    @classmethod
    def validate_payload_size(
        cls,
        value: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if value is None:
            return value

        import json

        try:
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("Request payload is invalid.") from exc

        if len(encoded) > MAX_GENERIC_REQUEST_BYTES:
            raise ValueError("Request payload is too large.")

        return value


# ===============================================================
# ROOT / HEALTH
# ===============================================================

@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "providers_count": len(list_providers()),
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    providers = list_providers()

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "healthy",
        "provider_count": len(providers),
        "enabled_count": sum(1 for p in providers if p.enabled),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ===============================================================
# PROVIDER LIST / DETAILS
# ===============================================================

@app.get("/providers")
def providers_list() -> Dict[str, Any]:
    providers = list_providers()

    return {
        "count": len(providers),
        "providers": [
            {
                "provider_id": p.provider_id,
                "name": p.name,
                "provider_type": p.provider_type,
                "enabled": p.enabled,
                "trusted": p.trusted,
                "description": p.description,
                "base_url": p.base_url,
            }
            for p in providers
        ],
    }


@app.get("/providers/{provider_id}")
def provider_details(provider_id: str) -> Dict[str, Any]:
    provider = get_provider(provider_id)

    return {
        "provider_id": provider.provider_id,
        "name": provider.name,
        "provider_type": provider.provider_type,
        "enabled": provider.enabled,
        "trusted": provider.trusted,
        "description": provider.description,
        "base_url": provider.base_url,
        "health_path": provider.health_path,
    }


# ===============================================================
# PROVIDER MANAGEMENT
# ===============================================================

@app.post(
    "/providers/{provider_id}/enable",
    dependencies=[],
)
def enable_provider(
    provider_id: str,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    require_admin_token(authorization)

    provider = set_provider_enabled(provider_id, True)

    logger.info("Provider enabled: %s", provider_id)

    return {
        "success": True,
        "provider_id": provider.provider_id,
        "enabled": provider.enabled,
    }


@app.post("/providers/{provider_id}/disable")
def disable_provider(
    provider_id: str,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    require_admin_token(authorization)

    provider = set_provider_enabled(provider_id, False)

    logger.info("Provider disabled: %s", provider_id)

    return {
        "success": True,
        "provider_id": provider.provider_id,
        "enabled": provider.enabled,
    }


# ===============================================================
# GEOCODING
# ===============================================================

@app.get("/geocode")
def geocode(
    name: str = Query(..., min_length=1, max_length=200),
    count: int = Query(default=5, ge=1, le=10),
    language: str = Query(default="en", min_length=2, max_length=10),
) -> Dict[str, Any]:
    request_data = GeocodeRequest(
        name=name,
        count=count,
        language=language,
    )

    result = _provider_json(
        "open_meteo_geocoding",
        "GET",
        "/v1/search",
        params={
            "name": request_data.name,
            "count": request_data.count,
            "language": request_data.language,
            "format": "json",
        },
    )

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=502,
            detail="Geocoding provider returned an invalid response.",
        )

    return {
        "provider": "open_meteo_geocoding",
        "query": request_data.name,
        "results": result.get("results", []),
        "generationtime_ms": result.get("generationtime_ms"),
    }


@app.post("/geocode")
def geocode_post(payload: GeocodeRequest) -> Dict[str, Any]:
    result = _provider_json(
        "open_meteo_geocoding",
        "GET",
        "/v1/search",
        params={
            "name": payload.name,
            "count": payload.count,
            "language": payload.language,
            "format": "json",
        },
    )

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=502,
            detail="Geocoding provider returned an invalid response.",
        )

    return {
        "provider": "open_meteo_geocoding",
        "query": payload.name,
        "results": result.get("results", []),
        "generationtime_ms": result.get("generationtime_ms"),
    }


# ===============================================================
# WEATHER
# ===============================================================

@app.get("/weather")
def weather_get(
    latitude: float = Query(..., ge=-90, le=90),
    longitude: float = Query(..., ge=-180, le=180),
    timezone: str = Query(default="auto", min_length=1, max_length=100),
    forecast_days: int = Query(default=7, ge=1, le=16),
) -> Dict[str, Any]:
    payload = WeatherRequest(
        latitude=latitude,
        longitude=longitude,
        timezone=timezone,
        forecast_days=forecast_days,
    )

    params: Dict[str, Any] = {
        "latitude": payload.latitude,
        "longitude": payload.longitude,
        "timezone": payload.timezone,
        "forecast_days": payload.forecast_days,
    }

    params["current"] = (
        "temperature_2m,relative_humidity_2m,apparent_temperature,"
        "is_day,precipitation,rain,showers,snowfall,weather_code,"
        "cloud_cover,pressure_msl,wind_speed_10m,wind_direction_10m"
    )

    params["hourly"] = (
        "temperature_2m,relative_humidity_2m,precipitation_probability,"
        "precipitation,weather_code,wind_speed_10m,soil_temperature_0cm,"
        "soil_moisture_0_to_1cm"
    )

    params["daily"] = (
        "weather_code,temperature_2m_max,temperature_2m_min,"
        "apparent_temperature_max,apparent_temperature_min,"
        "sunrise,sunset,daylight_duration,sunshine_duration,"
        "precipitation_sum,rain_sum,showers_sum,snowfall_sum,"
        "precipitation_probability_max,wind_speed_10m_max,"
        "wind_gusts_10m_max,wind_direction_10m_dominant,"
        "et0_fao_evapotranspiration"
    )

    result = _provider_json(
        "open_meteo_weather",
        "GET",
        "/v1/forecast",
        params=params,
    )

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=502,
            detail="Weather provider returned an invalid response.",
        )

    return {
        "provider": "open_meteo_weather",
        "coordinates": {
            "latitude": payload.latitude,
            "longitude": payload.longitude,
        },
        "weather": result,
    }


@app.post("/weather")
def weather_post(payload: WeatherRequest) -> Dict[str, Any]:
    params: Dict[str, Any] = {
        "latitude": payload.latitude,
        "longitude": payload.longitude,
        "timezone": payload.timezone,
        "forecast_days": payload.forecast_days,
    }

    if payload.current:
        params["current"] = (
            "temperature_2m,relative_humidity_2m,apparent_temperature,"
            "is_day,precipitation,rain,showers,snowfall,weather_code,"
            "cloud_cover,pressure_msl,wind_speed_10m,wind_direction_10m"
        )

    if payload.hourly:
        params["hourly"] = (
            "temperature_2m,relative_humidity_2m,precipitation_probability,"
            "precipitation,weather_code,wind_speed_10m,soil_temperature_0cm,"
            "soil_moisture_0_to_1cm"
        )

    if payload.daily:
        params["daily"] = (
            "weather_code,temperature_2m_max,temperature_2m_min,"
            "apparent_temperature_max,apparent_temperature_min,"
            "sunrise,sunset,daylight_duration,sunshine_duration,"
            "precipitation_sum,rain_sum,showers_sum,snowfall_sum,"
            "precipitation_probability_max,wind_speed_10m_max,"
            "wind_gusts_10m_max,wind_direction_10m_dominant,"
            "et0_fao_evapotranspiration"
        )

    result = _provider_json(
        "open_meteo_weather",
        "GET",
        "/v1/forecast",
        params=params,
    )

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=502,
            detail="Weather provider returned an invalid response.",
        )

    return {
        "provider": "open_meteo_weather",
        "coordinates": {
            "latitude": payload.latitude,
            "longitude": payload.longitude,
        },
        "weather": result,
    }


# ===============================================================
# COPERNICUS STAC SATELLITE SEARCH
# ===============================================================

@app.post("/satellite/search")
def satellite_search(
    payload: SatelliteSearchRequest,
) -> Dict[str, Any]:
    if payload.datetime_end < payload.datetime_start:
        raise HTTPException(
            status_code=422,
            detail="The end date must not be earlier than the start date.",
        )

    provider = require_enabled_provider("copernicus_stac")

    stac_body = {
        "bbox": payload.bbox,
        "datetime": (
            f"{payload.datetime_start.isoformat()}T00:00:00Z/"
            f"{payload.datetime_end.isoformat()}T23:59:59Z"
        ),
        "collections": payload.collections,
        "limit": min(payload.limit, MAX_STAC_ITEMS),
    }

    result = _provider_json(
        provider.provider_id,
        "POST",
        "/stac/search",
        json_body=stac_body,
    )

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=502,
            detail="Satellite provider returned an invalid response.",
        )

    features = result.get("features", [])

    if not isinstance(features, list):
        features = []

    return {
        "provider": provider.provider_id,
        "count": len(features),
        "features": features[:MAX_STAC_ITEMS],
        "context": result.get("context"),
        "links": result.get("links", []),
    }


# ===============================================================
# NASA GIBS TILE URL
# ===============================================================

@app.post("/satellite/nasa-gibs/tile-url")
def nasa_gibs_tile_url(
    payload: NasaGibsTileRequest,
) -> Dict[str, Any]:
    require_enabled_provider("nasa_gibs")

    # The caller controls only validated tile parameters.
    # The destination hostname and path structure remain fixed.
    imagery_date = payload.imagery_date.isoformat()

    url = (
        "https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/"
        f"{payload.layer}/default/{imagery_date}/"
        f"{payload.z}/{payload.y}/{payload.x}.{payload.format}"
    )

    validate_provider_url(url)

    return {
        "provider": "nasa_gibs",
        "layer": payload.layer,
        "date": imagery_date,
        "tile": {
            "z": payload.z,
            "x": payload.x,
            "y": payload.y,
        },
        "format": payload.format,
        "url": url,
    }


# ===============================================================
# PROVIDER HEALTH CHECKS
# ===============================================================

@app.get("/providers/health")
def providers_health() -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []

    for provider in list_providers():
        if not provider.enabled:
            results.append({
                "provider_id": provider.provider_id,
                "enabled": False,
                "reachable": False,
                "status": "disabled",
            })
            continue

        started = time.monotonic()

        try:
            status_code, _, _ = http_client.request(
                provider,
                "GET",
                provider.health_path,
                max_response_bytes=128_000,
            )

            reachable = 200 <= status_code < 400

            results.append({
                "provider_id": provider.provider_id,
                "enabled": True,
                "reachable": reachable,
                "status": "reachable" if reachable else "unhealthy",
                "http_status": status_code,
                "latency_ms": round(
                    (time.monotonic() - started) * 1000,
                    2,
                ),
            })

        except ProviderError as exc:
            logger.info(
                "Provider health check failed: %s (%s)",
                provider.provider_id,
                type(exc).__name__,
            )

            results.append({
                "provider_id": provider.provider_id,
                "enabled": True,
                "reachable": False,
                "status": "unreachable",
                "latency_ms": round(
                    (time.monotonic() - started) * 1000,
                    2,
                ),
            })

        except Exception:
            logger.exception(
                "Unexpected health-check error for %s",
                provider.provider_id,
            )

            results.append({
                "provider_id": provider.provider_id,
                "enabled": True,
                "reachable": False,
                "status": "error",
            })

    return {
        "service": APP_NAME,
        "providers": results,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/providers/{provider_id}/health")
def provider_health(provider_id: str) -> Dict[str, Any]:
    provider = get_provider(provider_id)

    if not provider.enabled:
        return {
            "provider_id": provider.provider_id,
            "enabled": False,
            "reachable": False,
            "status": "disabled",
        }

    started = time.monotonic()

    try:
        status_code, _, _ = http_client.request(
            provider,
            "GET",
            provider.health_path,
            max_response_bytes=128_000,
        )

        reachable = 200 <= status_code < 400

        return {
            "provider_id": provider.provider_id,
            "enabled": True,
            "reachable": reachable,
            "status": "reachable" if reachable else "unhealthy",
            "http_status": status_code,
            "latency_ms": round(
                (time.monotonic() - started) * 1000,
                2,
            ),
        }

    except ProviderError as exc:
        logger.info(
            "Provider health check failed: %s (%s)",
            provider.provider_id,
            type(exc).__name__,
        )

        return {
            "provider_id": provider.provider_id,
            "enabled": True,
            "reachable": False,
            "status": "unreachable",
            "latency_ms": round(
                (time.monotonic() - started) * 1000,
                2,
            ),
        }


# ===============================================================
# CONTROLLED GENERIC PROVIDER REQUEST
# ===============================================================

@app.post("/provider/request")
def generic_provider_request(
    payload: GenericProviderRequest,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """
    Generic requests are deliberately protected.

    The caller cannot supply an arbitrary destination URL.
    The provider ID must already exist in the fixed registry.
    Only GET and POST are accepted.
    """
    require_api_token(authorization)

    provider = require_enabled_provider(payload.provider_id)

    if payload.method == "GET" and payload.body is not None:
        raise HTTPException(
            status_code=422,
            detail="GET requests cannot include a JSON body.",
        )

    if payload.method == "POST" and payload.body is None:
        body: Optional[Dict[str, Any]] = {}
    else:
        body = payload.body

    try:
        status_code, headers, response_body = http_client.request(
            provider,
            payload.method,
            payload.path,
            params=payload.params,
            json_body=body,
        )

    except ProviderTimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail="External provider timed out.",
        ) from exc

    except ProviderResponseTooLarge as exc:
        raise HTTPException(
            status_code=502,
            detail="External provider response exceeded the size limit.",
        ) from exc

    except ProviderSecurityError as exc:
        raise HTTPException(
            status_code=400,
            detail="Provider request failed security validation.",
        ) from exc

    except ProviderResponseError as exc:
        raise HTTPException(
            status_code=502,
            detail="External provider request failed.",
        ) from exc

    content_type = headers.get("content-type", "").lower()

    if "json" in content_type or "geo+json" in content_type:
        try:
            import json
            response_data: Any = json.loads(
                response_body.decode("utf-8")
            )
        except (UnicodeDecodeError, ValueError):
            response_data = {
                "message": "Provider returned invalid JSON."
            }
    else:
        # Do not return arbitrary HTML, binary data, or large raw payloads.
        response_data = {
            "content_type": content_type,
            "body_bytes": len(response_body),
            "message": (
                "Response was not JSON; raw content was not returned."
            ),
        }

    return {
        "provider_id": provider.provider_id,
        "method": payload.method,
        "status_code": status_code,
        "response": response_data,
    }


# ===============================================================
# SYSTEM MAP
# ===============================================================

@app.get("/system-map")
def system_map() -> Dict[str, Any]:
    providers = list_providers()

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "components": {
            "geocoding": "open_meteo_geocoding",
            "weather": "open_meteo_weather",
            "satellite_search": "copernicus_stac",
            "satellite_tiles": "nasa_gibs",
        },
        "security": {
            "redirects_disabled": True,
            "bounded_response_reading": True,
            "provider_urls_are_registry_controlled": True,
            "management_auth_configured": bool(ADMIN_TOKEN),
            "generic_api_auth_configured": bool(API_TOKEN),
            "local_http_enabled": ALLOW_LOCAL_HTTP,
        },
        "providers": [
            {
                "provider_id": p.provider_id,
                "type": p.provider_type,
                "enabled": p.enabled,
            }
            for p in providers
        ],
    }


# ===============================================================
# STARTUP VALIDATION
# ===============================================================

@app.on_event("startup")
def startup_validation() -> None:
    """
    Validate fixed provider URLs at startup.

    A provider validation failure is logged. The service remains
    available so local health and diagnostic routes can still run.
    Actual requests to invalid destinations will be rejected.
    """
    for provider in list_providers():
        try:
            _validate_provider_base_url(provider)
        except ProviderSecurityError:
            logger.error(
                "Provider URL failed startup security validation: %s",
                provider.provider_id,
            )

    if not ADMIN_TOKEN:
        logger.warning(
            "ARYA_EXTERNAL_ADMIN_TOKEN is not configured; "
            "provider enable/disable management will remain disabled."
        )

    if not API_TOKEN:
        logger.warning(
            "ARYA_EXTERNAL_API_TOKEN is not configured; "
            "/provider/request will remain disabled."
        )


# ===============================================================
# LOCAL EXECUTION
# ===============================================================

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("ARYA_EXTERNAL_HOST", "127.0.0.1")
    port = _env_int("ARYA_EXTERNAL_PORT", 8095, 1, 65535)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=os.getenv("ARYA_LOG_LEVEL", "info").lower(),
    )
