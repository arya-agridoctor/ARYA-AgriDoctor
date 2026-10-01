"""
===============================================================
 ARYA AgriDoctor — MASTER SYSTEM
 Version: 1.0.0
===============================================================

هسته مرکزی یکپارچه ARYA AgriDoctor

این فایل:
- main.py را تغییر نمی‌دهد.
- ماژول‌های موجود را حذف نمی‌کند.
- تمام سرویس‌ها را از یک نقطه مدیریت می‌کند.
- در صورت قطع یک سرویس، کل سیستم را از کار نمی‌اندازد.
- Health Check
- Retry
- Circuit Breaker
- HMAC داخلی
- Service Registry
- Provider Registry
- OWNER / Runtime
- Vision
- Voice / Language
- Agriculture AI
- Weather
- Geocoding
- Payment
- Updates
- Orchestration
- System Map
- Generic Service Proxy
را در یک هسته مرکزی جمع می‌کند.

پورت پیش‌فرض:
8030

اجرای مستقیم:
uvicorn arya_master_system:app --host 0.0.0.0 --port 8030
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


# ===============================================================
# 1. CONFIG
# ===============================================================

APP_NAME = "ARYA AgriDoctor MASTER SYSTEM"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_MASTER_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_MASTER_PORT",
        "8030",
    )
)

TIMEOUT = float(
    os.getenv(
        "ARYA_MASTER_TIMEOUT",
        "25",
    )
)

RETRIES = max(
    0,
    int(
        os.getenv(
            "ARYA_MASTER_RETRIES",
            "2",
        )
    ),
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_MASTER_MAX_REQUEST_BYTES",
        str(4 * 1024 * 1024),
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_MASTER_MAX_RESPONSE_BYTES",
        str(8 * 1024 * 1024),
    )
)

HEALTH_CACHE_SECONDS = float(
    os.getenv(
        "ARYA_MASTER_HEALTH_CACHE_SECONDS",
        "5",
    )
)

CIRCUIT_FAILURE_THRESHOLD = int(
    os.getenv(
        "ARYA_MASTER_CIRCUIT_FAILURE_THRESHOLD",
        "3",
    )
)

CIRCUIT_COOLDOWN_SECONDS = float(
    os.getenv(
        "ARYA_MASTER_CIRCUIT_COOLDOWN_SECONDS",
        "30",
    )
)

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

REQUIRE_INTERNAL_SIGNATURE = (
    os.getenv(
        "ARYA_MASTER_REQUIRE_INTERNAL_SIGNATURE",
        "false",
    ).lower()
    in {"1", "true", "yes", "on"}
)


# ===============================================================
# 2. SERVICE REGISTRY
# ===============================================================

SERVICES: Dict[str, Dict[str, Any]] = {

    "main": {
        "url": os.getenv(
            "ARYA_MAIN_API_URL",
            "http://127.0.0.1:8000",
        ),
        "health": "/health",
        "enabled": True,
        "group": "core",
    },

    "vision": {
        "url": os.getenv(
            "ARYA_VISION_URL",
            "http://127.0.0.1:8001",
        ),
        "health": "/health",
        "enabled": True,
        "group": "ai",
    },

    "voice_language": {
        "url": os.getenv(
            "ARYA_VOICE_LANGUAGE_URL",
            "http://127.0.0.1:8002",
        ),
        "health": "/health",
        "enabled": True,
        "group": "accessibility",
    },

    "agri_engine": {
        "url": os.getenv(
            "ARYA_AGRI_ENGINE_URL",
            "http://127.0.0.1:8003",
        ),
        "health": "/health",
        "enabled": True,
        "group": "agriculture",
    },

    "commerce_security": {
        "url": os.getenv(
            "ARYA_COMMERCE_URL",
            "http://127.0.0.1:8004",
        ),
        "health": "/health",
        "enabled": True,
        "group": "commerce",
    },

    "orchestrator": {
        "url": os.getenv(
            "ARYA_ORCHESTRATOR_URL",
            "http://127.0.0.1:8010",
        ),
        "health": "/health",
        "enabled": True,
        "group": "orchestration",
    },

    "data_update": {
        "url": os.getenv(
            "ARYA_DATA_UPDATE_URL",
            "http://127.0.0.1:8014",
        ),
        "health": "/health",
        "enabled": True,
        "group": "updates",
    },

    "owner_integration": {
        "url": os.getenv(
            "ARYA_OWNER_INTEGRATION_URL",
            "http://127.0.0.1:8015",
        ),
        "health": "/health",
        "enabled": True,
        "group": "owner",
    },

    "owner_runtime_gateway": {
        "url": os.getenv(
            "ARYA_RUNTIME_GATEWAY_URL",
            "http://127.0.0.1:8016",
        ),
        "health": "/health",
        "enabled": True,
        "group": "runtime",
    },

    "final_integration": {
        "url": os.getenv(
            "ARYA_FINAL_INTEGRATION_URL",
            "http://127.0.0.1:8027",
        ),
        "health": "/health",
        "enabled": True,
        "group": "compatibility",
    },
}


# ===============================================================
# 3. PROVIDER REGISTRY
# ===============================================================

PROVIDERS: Dict[str, Dict[str, Any]] = {

    "open_meteo_weather": {
        "type": "weather",
        "url": os.getenv(
            "ARYA_OPEN_METEO_WEATHER_URL",
            "https://api.open-meteo.com/v1/forecast",
        ),
        "enabled": True,
        "priority": 1,
    },

    "open_meteo_geocoding": {
        "type": "geocoding",
        "url": os.getenv(
            "ARYA_OPEN_METEO_GEOCODING_URL",
            "https://geocoding-api.open-meteo.com/v1/search",
        ),
        "enabled": True,
        "priority": 1,
    },
}


# ===============================================================
# 4. STATE
# ===============================================================

@dataclass
class CircuitState:
    failures: int = 0
    opened_at: float = 0.0


@dataclass
class HealthState:
    timestamp: float = 0.0
    result: Dict[str, Any] = field(
        default_factory=dict
    )


circuits: Dict[str, CircuitState] = defaultdict(
    CircuitState
)

health_cache: Dict[str, HealthState] = defaultdict(
    HealthState
)

request_counters: Dict[str, int] = defaultdict(int)

last_errors: Dict[str, str] = {}


# ===============================================================
# 5. FASTAPI
# ===============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Central Master Gateway for ARYA AgriDoctor"
    ),
)


# ===============================================================
# 6. SECURITY HELPERS
# ===============================================================

def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def host_resolves_to_blocked_address(
    hostname: str,
) -> bool:

    hostname = hostname.strip().lower()

    if hostname in {
        "localhost",
        "localhost.localdomain",
    }:
        return True

    try:
        records = socket.getaddrinfo(
            hostname,
            None,
        )
    except socket.gaierror:
        return False

    for record in records:

        address = record[4][0]

        try:
            ip = ipaddress.ip_address(
                address
            )
        except ValueError:
            continue

        if is_blocked_ip(ip):
            return True

    return False


def validate_internal_url(
    url: str,
) -> str:

    parsed = urlparse(url)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Unsupported internal URL scheme"
        )

    if not parsed.hostname:
        raise ValueError(
            "Missing hostname"
        )

    host = parsed.hostname.lower()

    # Local services are explicitly configured.
    if host in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        return url.rstrip("/")

    if host_resolves_to_blocked_address(
        host
    ):
        raise ValueError(
            "Unsafe internal destination"
        )

    return url.rstrip("/")


def validate_provider_url(
    url: str,
) -> str:

    parsed = urlparse(url)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Unsupported provider URL scheme"
        )

    if not parsed.hostname:
        raise ValueError(
            "Missing provider hostname"
        )

    if host_resolves_to_blocked_address(
        parsed.hostname
    ):
        raise ValueError(
            "Unsafe provider destination"
        )

    return url.rstrip("/")


def create_signature(
    method: str,
    path: str,
    body: bytes,
) -> str:

    if not INTERNAL_SECRET:
        return ""

    payload = (
        method.upper().encode()
        + b"\n"
        + path.encode()
        + b"\n"
        + body
    )

    return hmac.new(
        INTERNAL_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()


def verify_signature(
    request: Request,
    body: bytes,
) -> bool:

    if not INTERNAL_SECRET:
        return not REQUIRE_INTERNAL_SIGNATURE

    received = request.headers.get(
        "X-ARYA-Signature",
        "",
    )

    expected = create_signature(
        request.method,
        request.url.path,
        body,
    )

    return bool(received) and hmac.compare_digest(
        received,
        expected,
    )


# ===============================================================
# 7. CIRCUIT BREAKER
# ===============================================================

def circuit_is_open(
    service: str,
) -> bool:

    state = circuits[service]

    if state.opened_at == 0:
        return False

    if (
        time.time() - state.opened_at
        >= CIRCUIT_COOLDOWN_SECONDS
    ):
        state.failures = 0
        state.opened_at = 0
        return False

    return True


def record_success(
    service: str,
) -> None:

    state = circuits[service]

    state.failures = 0
    state.opened_at = 0


def record_failure(
    service: str,
    error: str,
) -> None:

    state = circuits[service]

    state.failures += 1

    last_errors[service] = str(
        error
    )

    if (
        state.failures
        >= CIRCUIT_FAILURE_THRESHOLD
    ):
        state.opened_at = time.time()


# ===============================================================
# 8. SAFE JSON
# ===============================================================

def parse_body(
    body: bytes,
) -> Any:

    if not body:
        return None

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request too large",
        )

    try:
        return json.loads(
            body.decode("utf-8")
        )
    except Exception:
        return {
            "_raw_text": body.decode(
                "utf-8",
                errors="replace",
            )
        }


# ===============================================================
# 9. CORE HTTP ENGINE
# ===============================================================

async def http_call(
    *,
    name: str,
    base_url: str,
    path: str = "",
    method: str = "GET",
    payload: Any = None,
    query: Optional[
        Dict[str, Any]
    ] = None,
    headers: Optional[
        Dict[str, str]
    ] = None,
    external: bool = False,
) -> Dict[str, Any]:

    if circuit_is_open(name):
        return {
            "ok": False,
            "service": name,
            "error": "circuit_open",
        }

    try:

        if external:
            base = validate_provider_url(
                base_url
            )
        else:
            base = validate_internal_url(
                base_url
            )

    except Exception as exc:

        record_failure(
            name,
            str(exc),
        )

        return {
            "ok": False,
            "service": name,
            "error": "invalid_destination",
            "message": str(exc),
        }

    if path:

        if not path.startswith("/"):
            path = "/" + path

        target = base + path

    else:
        target = base

    body = None

    if payload is not None:

        body = json.dumps(
            payload,
            ensure_ascii=False,
        ).encode(
            "utf-8"
        )

        if len(body) > MAX_REQUEST_BYTES:

            return {
                "ok": False,
                "service": name,
                "error": "request_too_large",
            }

    request_headers = dict(
        headers or {}
    )

    if (
        INTERNAL_SECRET
        and not external
    ):

        request_headers[
            "X-ARYA-Signature"
        ] = create_signature(
            method,
            urlparse(target).path or "/",
            body or b"",
        )

    last_error = None

    for attempt in range(
        RETRIES + 1
    ):

        try:

            async with httpx.AsyncClient(
                timeout=TIMEOUT,
                follow_redirects=False,
                limits=httpx.Limits(
                    max_connections=50,
                    max_keepalive_connections=20,
                ),
            ) as client:

                response = await client.request(
                    method=method.upper(),
                    url=target,
                    params=query,
                    content=body,
                    headers=request_headers,
                )

                raw = response.content

                if len(raw) > MAX_RESPONSE_BYTES:

                    record_failure(
                        name,
                        "response_too_large",
                    )

                    return {
                        "ok": False,
                        "service": name,
                        "error": "response_too_large",
                    }

                if response.status_code in {
                    301,
                    302,
                    303,
                    307,
                    308,
                }:

                    record_failure(
                        name,
                        "redirect_rejected",
                    )

                    return {
                        "ok": False,
                        "service": name,
                        "status_code": response.status_code,
                        "error": "redirect_rejected",
                    }

                try:
                    data = response.json()
                except Exception:
                    data = response.text

                if (
                    200
                    <= response.status_code
                    < 300
                ):

                    record_success(
                        name
                    )

                    return {
                        "ok": True,
                        "service": name,
                        "status_code": response.status_code,
                        "data": data,
                    }

                last_error = (
                    f"HTTP "
                    f"{response.status_code}: "
                    f"{data}"
                )

                if (
                    400
                    <= response.status_code
                    < 500
                ):
                    break

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
        ) as exc:

            last_error = str(exc)

            if attempt < RETRIES:
                await asyncio.sleep(
                    0.35
                    * (attempt + 1)
                )

        except Exception as exc:

            last_error = str(exc)
            break

    record_failure(
        name,
        last_error or "unknown_error",
    )

    return {
        "ok": False,
        "service": name,
        "error": "upstream_error",
        "message": (
            last_error
            or "Unknown upstream error"
        ),
    }


# ===============================================================
# 10. SERVICE CALLER
# ===============================================================

async def call_service(
    service: str,
    path: str,
    *,
    method: str = "POST",
    payload: Any = None,
    query: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:

    config = SERVICES.get(
        service
    )

    if not config:

        return {
            "ok": False,
            "service": service,
            "error": "service_not_registered",
        }

    if not config.get(
        "enabled",
        True,
    ):

        return {
            "ok": False,
            "service": service,
            "error": "service_disabled",
        }

    request_counters[
        service
    ] += 1

    return await http_call(
        name=service,
        base_url=config["url"],
        path=path,
        method=method,
        payload=payload,
        query=query,
    )


# ===============================================================
# 11. HEALTH
# ===============================================================

async def service_health(
    service: str,
) -> Dict[str, Any]:

    config = SERVICES.get(
        service
    )

    if not config:

        return {
            "service": service,
            "status": "unknown",
        }

    now = time.time()

    cached = health_cache[
        service
    ]

    if (
        cached.result
        and now - cached.timestamp
        < HEALTH_CACHE_SECONDS
    ):
        return cached.result

    if not config.get(
        "enabled",
        True,
    ):

        result = {
            "service": service,
            "status": "disabled",
            "enabled": False,
        }

    else:

        started = time.perf_counter()

        result = await call_service(
            service,
            config.get(
                "health",
                "/health",
            ),
            method="GET",
        )

        latency = round(
            (
                time.perf_counter()
                - started
            )
            * 1000,
            2,
        )

        result = {
            **result,
            "service": service,
            "latency_ms": latency,
            "enabled": True,
            "circuit_open":
                circuit_is_open(
                    service
                ),
        }

    health_cache[
        service
    ] = HealthState(
        timestamp=now,
        result=result,
    )

    return result


async def all_health():

    results = await asyncio.gather(
        *(
            service_health(name)
            for name in SERVICES
        ),
        return_exceptions=True,
    )

    output = {}

    for name, result in zip(
        SERVICES,
        results,
    ):

        if isinstance(
            result,
            Exception,
        ):

            output[name] = {
                "service": name,
                "status": "error",
                "message": str(result),
            }

        else:

            output[name] = result

    return output


# ===============================================================
# 12. MODELS
# ===============================================================

class MasterRequest(BaseModel):

    action: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    data: Dict[str, Any] = Field(
        default_factory=dict
    )


class ProviderRequest(BaseModel):

    provider: str

    params: Dict[str, Any] = Field(
        default_factory=dict
    )


# ===============================================================
# 13. ROOT
# ===============================================================

@app.get("/")
async def root():

    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "role": "master",
        "port": PORT,
    }


@app.get("/health")
async def health():

    return {
        "ok": True,
        "name": APP_NAME,
        "version": APP_VERSION,
        "services": await all_health(),
    }


@app.get("/status")
async def status():

    return {
        "ok": True,
        "version": APP_VERSION,

        "services": {

            name: {

                "enabled":
                    config.get(
                        "enabled",
                        True,
                    ),

                "group":
                    config.get(
                        "group"
                    ),

                "requests":
                    request_counters[
                        name
                    ],

                "circuit_open":
                    circuit_is_open(
                        name
                    ),

                "last_error":
                    last_errors.get(
                        name
                    ),

            }

            for name, config
            in SERVICES.items()
        },

        "providers": {

            name: {

                "enabled":
                    config.get(
                        "enabled",
                        True,
                    ),

                "type":
                    config.get(
                        "type"
                    ),

                "priority":
                    config.get(
                        "priority"
                    ),

            }

            for name, config
            in PROVIDERS.items()
        },
    }


# ===============================================================
# 14. SYSTEM MAP
# ===============================================================

@app.get("/system-map")
async def system_map():

    return {

        "name": APP_NAME,

        "version":
            APP_VERSION,

        "architecture": {

            "client":
                "Client",

            "master":
                "ARYA Master System",

            "orchestrator":
                "Orchestrator",

            "runtime":
                "OWNER Runtime Gateway",

            "owner":
                "OWNER Integration",

            "services":
                [
                    "Vision",
                    "Voice/Language",
                    "Agri Engine",
                    "Commerce/Security",
                    "Data Update",
                ],

            "providers":
                [
                    "Weather",
                    "Geocoding",
                    "Future Providers",
                ],

            "legacy_core":
                "backend/main.py",
        },

        "services":
            SERVICES,

        "providers":
            PROVIDERS,
    }


# ===============================================================
# 15. SERVICE REGISTRY
# ===============================================================

@app.get("/services")
async def services():

    return SERVICES


@app.post(
    "/services/{service}/enable"
)
async def enable_service(
    service: str,
):

    if service not in SERVICES:
        raise HTTPException(
            404,
            "Service not found",
        )

    SERVICES[
        service
    ]["enabled"] = True

    health_cache.pop(
        service,
        None,
    )

    return {
        "ok": True,
        "service": service,
        "enabled": True,
    }


@app.post(
    "/services/{service}/disable"
)
async def disable_service(
    service: str,
):

    if service not in SERVICES:
        raise HTTPException(
            404,
            "Service not found",
        )

    SERVICES[
        service
    ]["enabled"] = False

    health_cache.pop(
        service,
        None,
    )

    return {
        "ok": True,
        "service": service,
        "enabled": False,
    }


# ===============================================================
# 16. PROVIDERS
# ===============================================================

@app.get("/providers")
async def providers():

    return PROVIDERS


@app.post(
    "/providers/{provider}/enable"
)
async def enable_provider(
    provider: str,
):

    if provider not in PROVIDERS:
        raise HTTPException(
            404,
            "Provider not found",
        )

    PROVIDERS[
        provider
    ]["enabled"] = True

    return {
        "ok": True,
        "provider": provider,
        "enabled": True,
    }


@app.post(
    "/providers/{provider}/disable"
)
async def disable_provider(
    provider: str,
):

    if provider not in PROVIDERS:
        raise HTTPException(
            404,
            "Provider not found",
        )

    PROVIDERS[
        provider
    ]["enabled"] = False

    return {
        "ok": True,
        "provider": provider,
        "enabled": False,
    }


async def call_provider(
    provider: str,
    *,
    query: Optional[
        Dict[str, Any]
    ] = None,
    payload: Any = None,
    method: str = "GET",
):

    config = PROVIDERS.get(
        provider
    )

    if not config:

        return {
            "ok": False,
            "provider": provider,
            "error":
                "provider_not_registered",
        }

    if not config.get(
        "enabled",
        True,
    ):

        return {
            "ok": False,
            "provider": provider,
            "error":
                "provider_disabled",
        }

    return await http_call(
        name=f"provider:{provider}",
        base_url=config["url"],
        method=method,
        payload=payload,
        query=query,
        external=True,
    )


# ===============================================================
# 17. WEATHER
# ===============================================================

@app.get("/arya/weather")
async def weather(
    latitude: float,
    longitude: float,
    forecast_days: int = 7,
):

    forecast_days = max(
        1,
        min(
            forecast_days,
            16,
        ),
    )

    result = await call_provider(
        "open_meteo_weather",
        query={

            "latitude":
                latitude,

            "longitude":
                longitude,

            "forecast_days":
                forecast_days,

            "current":
                (
                    "temperature_2m,"
                    "relative_humidity_2m,"
                    "precipitation,"
                    "wind_speed_10m"
                ),

            "daily":
                (
                    "temperature_2m_max,"
                    "temperature_2m_min,"
                    "precipitation_sum,"
                    "weather_code"
                ),

            "timezone":
                "auto",
        },
    )

    return {
        "ok":
            result.get(
                "ok",
                False,
            ),

        "provider":
            "open_meteo_weather",

        "result":
            result,
    }


# ===============================================================
# 18. GEOCODING
# ===============================================================

@app.get("/arya/geocode")
async def geocode(
    name: str,
    count: int = 5,
    language: str = "en",
):

    count = max(
        1,
        min(
            count,
            20,
        ),
    )

    result = await call_provider(
        "open_meteo_geocoding",
        query={

            "name":
                name,

            "count":
                count,

            "language":
                language,

            "format":
                "json",
        },
    )

    return {
        "ok":
            result.get(
                "ok",
                False,
            ),

        "provider":
            "open_meteo_geocoding",

        "result":
            result,
    }


@app.post("/provider/call")
async def provider_call(
    request: ProviderRequest,
):

    return await call_provider(
        request.provider,
        query=request.params,
    )


# ===============================================================
# 19. ACTION MAP
# ===============================================================

ACTION_MAP = {

    "vision":
        (
            "vision",
            "/vision/analyze",
        ),

    "voice":
        (
            "voice_language",
            "/voice",
        ),

    "language":
        (
            "voice_language",
            "/language",
        ),

    "agri_analyze":
        (
            "agri_engine",
            "/agri/analyze",
        ),

    "diagnose":
        (
            "agri_engine",
            "/agri/diagnose",
        ),

    "recommend":
        (
            "agri_engine",
            "/agri/recommend",
        ),

    "crop_suitability":
        (
            "agri_engine",
            "/agri/crop-suitability",
        ),

    "payment":
        (
            "commerce_security",
            "/payment",
        ),

    "updates":
        (
            "data_update",
            "/updates",
        ),
}


async def execute_action(
    action: str,
    data: Dict[str, Any],
):

    target = ACTION_MAP.get(
        action
    )

    if not target:

        return {
            "ok": False,
            "action": action,
            "error":
                "unknown_action",
        }

    service, path = target

    return await call_service(
        service,
        path,
        payload=data,
    )


# ===============================================================
# 20. FULL AGRICULTURAL DOCTOR
# ===============================================================

async def full_diagnosis(
    data: Dict[str, Any],
):

    results = {}

    # Vision
    if (
        data.get("image")
        or data.get("image_url")
    ):

        results[
            "vision"
        ] = await call_service(
            "vision",
            "/vision/analyze",
            payload=data,
        )

    # Voice
    if (
        data.get("voice")
        or data.get("audio")
    ):

        results[
            "voice"
        ] = await call_service(
            "voice_language",
            "/voice",
            payload=data,
        )

    # Main agriculture diagnosis
    results[
        "agriculture"
    ] = await call_service(
        "agri_engine",
        "/agri/diagnose",
        payload=data,
    )

    # Fallback
    if not results[
        "agriculture"
    ].get("ok"):

        results[
            "agriculture_fallback"
        ] = await call_service(
            "agri_engine",
            "/agri/analyze",
            payload=data,
        )

    success = any(
        isinstance(
            value,
            dict,
        )
        and value.get("ok")
        for value
        in results.values()
    )

    return {

        "ok":
            success,

        "action":
            "full_diagnosis",

        "results":
            results,
    }


# ===============================================================
# 21. ORCHESTRATION
# ===============================================================

@app.post("/orchestrate")
async def orchestrate(
    request: MasterRequest,
):

    if request.action in {
        "doctor",
        "full_diagnosis",
        "complete_diagnosis",
    }:

        return await full_diagnosis(
            request.data
        )

    return await execute_action(
        request.action,
        request.data,
    )


# ===============================================================
# 22. ARYA MAIN API
# ===============================================================

@app.post("/arya/doctor")
async def arya_doctor(
    payload: Dict[str, Any],
):

    return await full_diagnosis(
        payload
    )


@app.post("/arya/diagnose")
async def arya_diagnose(
    payload: Dict[str, Any],
):

    return await full_diagnosis(
        payload
    )


@app.post("/arya/analyze")
async def arya_analyze(
    payload: Dict[str, Any],
):

    return await call_service(
        "agri_engine",
        "/agri/analyze",
        payload=payload,
    )


@app.post("/arya/recommend")
async def arya_recommend(
    payload: Dict[str, Any],
):

    return await call_service(
        "agri_engine",
        "/agri/recommend",
        payload=payload,
    )


@app.post("/arya/vision")
async def arya_vision(
    payload: Dict[str, Any],
):

    return await call_service(
        "vision",
        "/vision/analyze",
        payload=payload,
    )


@app.post("/arya/voice")
async def arya_voice(
    payload: Dict[str, Any],
):

    return await call_service(
        "voice_language",
        "/voice",
        payload=payload,
    )


@app.post("/arya/payment")
async def arya_payment(
    payload: Dict[str, Any],
):

    return await call_service(
        "commerce_security",
        "/payment",
        payload=payload,
    )


# ===============================================================
# 23. OWNER
# ===============================================================

@app.api_route(
    "/arya/owner/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def owner_proxy(
    path: str,
    request: Request,
):

    body = await request.body()

    return JSONResponse(
        content=await call_service(
            "owner_integration",
            "/" + path,
            method=request.method,
            payload=parse_body(body),
            query=dict(
                request.query_params
            ),
        )
    )


# ===============================================================
# 24. RUNTIME
# ===============================================================

@app.api_route(
    "/arya/runtime/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def runtime_proxy(
    path: str,
    request: Request,
):

    body = await request.body()

    return JSONResponse(
        content=await call_service(
            "owner_runtime_gateway",
            "/" + path,
            method=request.method,
            payload=parse_body(body),
            query=dict(
                request.query_params
            ),
        )
    )


# ===============================================================
# 25. DATA UPDATE
# ===============================================================

@app.api_route(
    "/arya/updates/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def update_proxy(
    path: str,
    request: Request,
):

    body = await request.body()

    return JSONResponse(
        content=await call_service(
            "data_update",
            "/" + path,
            method=request.method,
            payload=parse_body(body),
            query=dict(
                request.query_params
            ),
        )
    )


@app.post("/arya/updates")
async def arya_updates(
    payload: Dict[str, Any],
):

    return await call_service(
        "data_update",
        "/updates",
        payload=payload,
    )


@app.post("/arya/updates/run")
async def arya_updates_run(
    payload: Dict[str, Any],
):

    return await call_service(
        "data_update",
        "/updates/run",
        payload=payload,
    )


# ===============================================================
# 26. GENERIC SERVICE PROXY
# ===============================================================

@app.api_route(
    "/service/{service}/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def service_proxy(
    service: str,
    path: str,
    request: Request,
):

    if service not in SERVICES:

        raise HTTPException(
            404,
            "Service not found",
        )

    body = await request.body()

    return JSONResponse(
        content=await call_service(
            service,
            "/" + path,
            method=request.method,
            payload=parse_body(body),
            query=dict(
                request.query_params
            ),
        )
    )


# ===============================================================
# 27. INTERNAL MASTER CALL
# ===============================================================

@app.post("/internal/call")
async def internal_call(
    request: Request,
):

    body = await request.body()

    if (
        REQUIRE_INTERNAL_SIGNATURE
        and not verify_signature(
            request,
            body,
        )
    ):

        raise HTTPException(
            401,
            "Invalid internal signature",
        )

    data = parse_body(
        body
    )

    if not isinstance(
        data,
        dict,
    ):

        raise HTTPException(
            400,
            "JSON object required",
        )

    service = data.get(
        "service"
    )

    path = data.get(
        "path"
    )

    method = data.get(
        "method",
        "POST",
    )

    payload = data.get(
        "data"
    )

    if not service or not path:

        raise HTTPException(
            400,
            "service and path required",
        )

    return await call_service(
        service,
        path,
        method=method,
        payload=payload,
        query=data.get(
            "query"
        ),
    )


# ===============================================================
# 28. SECURITY MIDDLEWARE
# ===============================================================

@app.middleware("http")
async def security_middleware(
    request: Request,
    call_next,
):

    content_length = request.headers.get(
        "content-length"
    )

    if content_length:

        try:

            if (
                int(content_length)
                > MAX_REQUEST_BYTES
            ):

                return JSONResponse(
                    status_code=413,
                    content={
                        "ok": False,
                        "error":
                            "request_too_large",
                    },
                )

        except ValueError:
            pass

    if (
        request.url.path.startswith(
            "/internal/"
        )
        and REQUIRE_INTERNAL_SIGNATURE
    ):

        body = await request.body()

        if not verify_signature(
            request,
            body,
        ):

            return JSONResponse(
                status_code=401,
                content={
                    "ok": False,
                    "error":
                        "invalid_internal_signature",
                },
            )

    return await call_next(
        request
    )


# ===============================================================
# 29. GLOBAL ERROR HANDLER
# ===============================================================

@app.exception_handler(Exception)
async def global_error(
    request: Request,
    exc: Exception,
):

    return JSONResponse(
        status_code=500,
        content={
            "ok": False,
            "error":
                "master_internal_error",
            "message":
                str(exc),
            "path":
                request.url.path,
        },
    )


# ===============================================================
# 30. STARTUP
# ===============================================================

@app.on_event("startup")
async def startup():

    # Validate all configured services.
    for name, config in SERVICES.items():

        try:

            validate_internal_url(
                config["url"]
            )

        except Exception as exc:

            last_errors[
                name
            ] = str(exc)

    # Validate providers.
    for name, config in PROVIDERS.items():

        try:

            validate_provider_url(
                config["url"]
            )

        except Exception as exc:

            last_errors[
                "provider:" + name
            ] = str(exc)


@app.on_event("shutdown")
async def shutdown():

    health_cache.clear()


# ===============================================================
# 31. LOCAL RUN
# ===============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "arya_master_system:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
