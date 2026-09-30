"""
ARYA AgriDoctor
OWNER Runtime Gateway
Version: 1.0.0

Purpose:
- Runtime connection between OWNER Integration and ARYA services.
- Read active service/provider configuration.
- Route requests without modifying main.py.
- Centralize service discovery.
- Support OWNER-controlled enable/disable state.
- Provide safe internal service calls.
- Keep existing modules untouched.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# CONFIG
# ============================================================

SERVICE_NAME = "ARYA Owner Runtime Gateway"
SERVICE_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_RUNTIME_GATEWAY_HOST",
    "0.0.0.0",
)

PORT = int(
    os.getenv(
        "ARYA_RUNTIME_GATEWAY_PORT",
        "8016",
    )
)

OWNER_INTEGRATION_URL = os.getenv(
    "ARYA_OWNER_INTEGRATION_URL",
    "http://127.0.0.1:8015",
).rstrip("/")

INTERNAL_GATEWAY_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

DEFAULT_TIMEOUT = float(
    os.getenv(
        "ARYA_RUNTIME_TIMEOUT",
        "30",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_RUNTIME_MAX_RESPONSE_BYTES",
        str(10 * 1024 * 1024),
    )
)

MAX_RETRIES = int(
    os.getenv(
        "ARYA_RUNTIME_MAX_RETRIES",
        "2",
    )
)

LOG_LEVEL = os.getenv(
    "ARYA_RUNTIME_LOG_LEVEL",
    "INFO",
).upper()


logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger(SERVICE_NAME)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title=SERVICE_NAME,
    version=SERVICE_VERSION,
    description=(
        "Runtime gateway connecting OWNER-controlled "
        "ARYA services and external providers."
    ),
)


# ============================================================
# MODELS
# ============================================================

class RuntimeCallRequest(BaseModel):
    service_id: str = Field(
        min_length=1,
        max_length=100,
    )

    path: str = Field(
        min_length=1,
        max_length=1000,
    )

    method: str = Field(
        default="POST",
        min_length=3,
        max_length=10,
    )

    payload: Optional[Dict[str, Any]] = None

    query: Optional[Dict[str, Any]] = None

    headers: Optional[Dict[str, str]] = None


class ProviderCallRequest(BaseModel):
    provider_id: str = Field(
        min_length=1,
        max_length=100,
    )

    path: str = Field(
        default="/",
        max_length=1000,
    )

    method: str = Field(
        default="GET",
        min_length=3,
        max_length=10,
    )

    payload: Optional[Dict[str, Any]] = None

    query: Optional[Dict[str, Any]] = None

    headers: Optional[Dict[str, str]] = None


# ============================================================
# URL SECURITY
# ============================================================

def validate_target_url(
    url: str,
) -> None:

    parsed = urlparse(url)

    if parsed.scheme.lower() != "http" and parsed.scheme.lower() != "https":
        raise ValueError(
            "Only HTTP/HTTPS URLs are allowed"
        )

    hostname = parsed.hostname

    if not hostname:
        raise ValueError(
            "Target hostname is missing"
        )

    hostname_lower = hostname.lower()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
        "metadata",
    }

    if hostname_lower in blocked_names:
        raise ValueError(
            "Blocked target hostname"
        )

    try:
        addresses = socket.getaddrinfo(
            hostname,
            parsed.port or (
                443
                if parsed.scheme.lower() == "https"
                else 80
            ),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            "Target hostname cannot be resolved"
        ) from exc

    for address in addresses:

        ip_text = address[4][0]

        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            continue

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            continue

        # Public IP is allowed.
        # Internal service URLs are separately allowed below
        # through the trusted-service mechanism.


# ============================================================
# INTERNAL SERVICE URL VALIDATION
# ============================================================

def validate_internal_service_url(
    url: str,
) -> None:

    parsed = urlparse(url)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Invalid service URL scheme"
        )

    if not parsed.hostname:
        raise ValueError(
            "Service hostname is missing"
        )


# ============================================================
# OWNER INTEGRATION CLIENT
# ============================================================

class OwnerIntegrationClient:
    """
    Reads current runtime configuration from
    owner_integration.py.

    This gateway does not store its own copy of the
    service/provider configuration.
    """

    def __init__(
        self,
        base_url: str,
    ):
        self.base_url = base_url.rstrip("/")

    async def get_service(
        self,
        service_id: str,
    ) -> Dict[str, Any]:

        url = (
            f"{self.base_url}"
            f"/internal/service/"
            f"{service_id}"
        )

        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
        ) as client:

            response = await client.get(url)

        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=(
                    "OWNER Integration could not "
                    f"resolve service '{service_id}'"
                ),
            )

        return response.json()

    async def get_provider(
        self,
        provider_id: str,
    ) -> Dict[str, Any]:

        url = (
            f"{self.base_url}"
            f"/internal/provider/"
            f"{provider_id}"
        )

        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
        ) as client:

            response = await client.get(url)

        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=(
                    "OWNER Integration could not "
                    f"resolve provider '{provider_id}'"
                ),
            )

        return response.json()

    async def get_services(self) -> Dict[str, Any]:

        url = (
            f"{self.base_url}"
            "/runtime/services"
        )

        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
        ) as client:

            response = await client.get(url)

        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail="Cannot read runtime services",
            )

        return response.json()

    async def get_providers(self) -> Dict[str, Any]:

        url = (
            f"{self.base_url}"
            "/runtime/providers"
        )

        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
        ) as client:

            response = await client.get(url)

        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail="Cannot read runtime providers",
            )

        return response.json()


owner_client = OwnerIntegrationClient(
    OWNER_INTEGRATION_URL
)


# ============================================================
# HTTP CALLER
# ============================================================

async def perform_http_call(
    url: str,
    method: str,
    payload: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout_seconds: float = DEFAULT_TIMEOUT,
    retries: int = MAX_RETRIES,
    internal: bool = False,
) -> Dict[str, Any]:

    method = method.upper()

    allowed_methods = {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }

    if method not in allowed_methods:
        raise HTTPException(
            status_code=400,
            detail="Unsupported HTTP method",
        )

    if internal:
        validate_internal_service_url(url)
    else:
        try:
            validate_target_url(url)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            )

    request_headers = {
        "Accept": "application/json",
        "User-Agent": (
            "ARYA-AgriDoctor-"
            "OwnerRuntimeGateway/"
            f"{SERVICE_VERSION}"
        ),
    }

    if headers:
        for key, value in headers.items():

            # Prevent caller from overriding
            # transport/security headers.
            if key.lower() in {
                "host",
                "content-length",
                "transfer-encoding",
            }:
                continue

            request_headers[key] = value

    last_error: Optional[str] = None

    attempts = max(
        1,
        retries + 1,
    )

    for attempt in range(attempts):

        try:

            async with httpx.AsyncClient(
                timeout=timeout_seconds,
                follow_redirects=False,
                max_redirects=0,
            ) as client:

                response = await client.request(
                    method=method,
                    url=url,
                    json=payload
                    if method != "GET"
                    else None,
                    params=query,
                    headers=request_headers,
                )

                content_length = response.headers.get(
                    "content-length"
                )

                if content_length:

                    try:
                        if int(content_length) > MAX_RESPONSE_BYTES:
                            raise HTTPException(
                                status_code=502,
                                detail=(
                                    "External response exceeds "
                                    "configured size limit"
                                ),
                            )
                    except ValueError:
                        pass

                content = response.content

                if len(content) > MAX_RESPONSE_BYTES:
                    raise HTTPException(
                        status_code=502,
                        detail=(
                            "External response exceeds "
                            "configured size limit"
                        ),
                    )

                content_type = response.headers.get(
                    "content-type",
                    "",
                ).lower()

                if (
                    "application/json" in content_type
                    or "application/problem+json" in content_type
                ):
                    try:
                        data: Any = response.json()
                    except Exception:
                        data = {
                            "raw": content.decode(
                                "utf-8",
                                errors="replace",
                            )
                        }
                else:
                    data = {
                        "raw": content.decode(
                            "utf-8",
                            errors="replace",
                        )
                    }

                return {
                    "success": response.is_success,
                    "status_code": response.status_code,
                    "url": url,
                    "data": data,
                    "attempt": attempt + 1,
                }

        except HTTPException:
            raise

        except Exception as exc:

            last_error = str(exc)

            logger.warning(
                "Runtime call failed "
                "(attempt %s/%s): %s",
                attempt + 1,
                attempts,
                exc,
            )

            if attempt + 1 < attempts:
                await asyncio.sleep(
                    min(
                        2 ** attempt,
                        5,
                    )
                )

    raise HTTPException(
        status_code=502,
        detail=(
            "Runtime service call failed: "
            f"{last_error or 'unknown error'}"
        ),
    )


# ============================================================
# INTERNAL AUTH
# ============================================================

def verify_internal_secret(
    authorization: Optional[str],
) -> None:

    # If no internal secret is configured,
    # allow local development operation.
    if not INTERNAL_GATEWAY_SECRET:
        return

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Internal authentication required",
        )

    expected = (
        f"Bearer {INTERNAL_GATEWAY_SECRET}"
    )

    if authorization != expected:
        raise HTTPException(
            status_code=401,
            detail="Invalid internal authentication",
        )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root() -> Dict[str, Any]:

    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "running",
        "owner_integration": OWNER_INTEGRATION_URL,
    }


@app.get("/health")
async def health() -> Dict[str, Any]:

    try:

        services = await owner_client.get_services()

        providers = await owner_client.get_providers()

        return {
            "status": "healthy",
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "owner_integration": "connected",
            "active_services": services.get(
                "count",
                0,
            ),
            "active_providers": providers.get(
                "count",
                0,
            ),
        }

    except Exception as exc:

        logger.exception(
            "Gateway health check failed"
        )

        return {
            "status": "degraded",
            "service": SERVICE_NAME,
            "owner_integration": "unavailable",
            "error": str(exc),
        }


# ============================================================
# SERVICE DISCOVERY
# ============================================================

@app.get("/runtime/services")
async def runtime_services(
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    return await owner_client.get_services()


@app.get("/runtime/providers")
async def runtime_providers(
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    return await owner_client.get_providers()


# ============================================================
# SERVICE CALL
# ============================================================

@app.post("/runtime/call")
async def runtime_call(
    request: RuntimeCallRequest,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    service = await owner_client.get_service(
        request.service_id
    )

    base_url = str(
        service["base_url"]
    ).rstrip("/")

    path = request.path

    if not path.startswith("/"):
        path = "/" + path

    target_url = (
        base_url
        + path
    )

    result = await perform_http_call(
        url=target_url,
        method=request.method,
        payload=request.payload,
        query=request.query,
        headers=request.headers,
        timeout_seconds=float(
            service.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            service.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=True,
    )

    return {
        "gateway": SERVICE_NAME,
        "service_id": request.service_id,
        "result": result,
    }


# ============================================================
# PROVIDER CALL
# ============================================================

@app.post("/runtime/provider-call")
async def provider_call(
    request: ProviderCallRequest,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    provider = await owner_client.get_provider(
        request.provider_id
    )

    base_url = str(
        provider["base_url"]
    ).rstrip("/")

    path = request.path

    if not path.startswith("/"):
        path = "/" + path

    target_url = (
        base_url
        + path
    )

    result = await perform_http_call(
        url=target_url,
        method=request.method,
        payload=request.payload,
        query=request.query,
        headers=request.headers,
        timeout_seconds=float(
            provider.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            provider.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=False,
    )

    return {
        "gateway": SERVICE_NAME,
        "provider_id": request.provider_id,
        "result": result,
    }


# ============================================================
# SPECIALIZED ROUTES
# ============================================================

@app.post("/arya/analyze")
async def arya_analyze(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    service = await owner_client.get_service(
        "agri_engine"
    )

    base_url = str(
        service["base_url"]
    ).rstrip("/")

    result = await perform_http_call(
        url=base_url + "/agri/analyze",
        method="POST",
        payload=payload,
        timeout_seconds=float(
            service.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            service.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=True,
    )

    return result


@app.post("/arya/diagnose")
async def arya_diagnose(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    service = await owner_client.get_service(
        "agri_engine"
    )

    base_url = str(
        service["base_url"]
    ).rstrip("/")

    result = await perform_http_call(
        url=base_url + "/agri/diagnose",
        method="POST",
        payload=payload,
        timeout_seconds=float(
            service.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            service.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=True,
    )

    return result


@app.post("/arya/recommend")
async def arya_recommend(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    service = await owner_client.get_service(
        "agri_engine"
    )

    base_url = str(
        service["base_url"]
    ).rstrip("/")

    result = await perform_http_call(
        url=base_url + "/agri/recommend",
        method="POST",
        payload=payload,
        timeout_seconds=float(
            service.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            service.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=True,
    )

    return result


@app.post("/arya/vision")
async def arya_vision(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    service = await owner_client.get_service(
        "vision"
    )

    base_url = str(
        service["base_url"]
    ).rstrip("/")

    result = await perform_http_call(
        url=base_url + "/vision/analyze",
        method="POST",
        payload=payload,
        timeout_seconds=float(
            service.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            service.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=True,
    )

    return result


# ============================================================
# PAYMENT
# ============================================================

@app.post("/arya/payment")
async def arya_payment(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    service = await owner_client.get_service(
        "commerce_security"
    )

    base_url = str(
        service["base_url"]
    ).rstrip("/")

    result = await perform_http_call(
        url=base_url + "/commerce/payments/create",
        method="POST",
        payload=payload,
        timeout_seconds=float(
            service.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            service.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=True,
    )

    return result


# ============================================================
# DATA UPDATE
# ============================================================

@app.get("/arya/updates")
async def arya_updates(
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    service_url = os.getenv(
        "ARYA_DATA_UPDATE_URL",
        "http://127.0.0.1:8014",
    ).rstrip("/")

    result = await perform_http_call(
        url=service_url + "/updates/status",
        method="GET",
        timeout_seconds=DEFAULT_TIMEOUT,
        retries=MAX_RETRIES,
        internal=True,
    )

    return result


@app.post("/arya/updates/run")
async def arya_updates_run(
    payload: Optional[Dict[str, Any]] = None,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    service_url = os.getenv(
        "ARYA_DATA_UPDATE_URL",
        "http://127.0.0.1:8014",
    ).rstrip("/")

    result = await perform_http_call(
        url=service_url + "/updates/run",
        method="POST",
        payload=payload or {},
        timeout_seconds=DEFAULT_TIMEOUT,
        retries=MAX_RETRIES,
        internal=True,
    )

    return result


# ============================================================
# PROVIDER SHORTCUTS
# ============================================================

@app.get("/arya/weather")
async def arya_weather(
    latitude: float,
    longitude: float,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    provider = await owner_client.get_provider(
        "open_meteo_weather"
    )

    base_url = str(
        provider["base_url"]
    ).rstrip("/")

    result = await perform_http_call(
        url=base_url + "/v1/forecast",
        method="GET",
        query={
            "latitude": latitude,
            "longitude": longitude,
            "current": (
                "temperature_2m,"
                "relative_humidity_2m,"
                "precipitation,"
                "weather_code,"
                "wind_speed_10m"
            ),
            "daily": (
                "temperature_2m_max,"
                "temperature_2m_min,"
                "precipitation_sum,"
                "weather_code"
            ),
            "timezone": "auto",
        },
        timeout_seconds=float(
            provider.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            provider.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=False,
    )

    return result


@app.get("/arya/geocode")
async def arya_geocode(
    name: str,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    provider = await owner_client.get_provider(
        "open_meteo_geocoding"
    )

    base_url = str(
        provider["base_url"]
    ).rstrip("/")

    result = await perform_http_call(
        url=base_url + "/v1/search",
        method="GET",
        query={
            "name": name,
            "count": 10,
            "language": "en",
            "format": "json",
        },
        timeout_seconds=float(
            provider.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            provider.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=False,
    )

    return result


# ============================================================
# SYSTEM MAP
# ============================================================

@app.get("/arya/system-map")
async def system_map(
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    verify_internal_secret(
        authorization
    )

    services = await owner_client.get_services()
    providers = await owner_client.get_providers()

    return {
        "gateway": {
            "name": SERVICE_NAME,
            "version": SERVICE_VERSION,
        },
        "owner_integration": OWNER_INTEGRATION_URL,
        "services": services,
        "providers": providers,
        "connections": {
            "owner": True,
            "agri_engine": True,
            "vision": True,
            "commerce_security": True,
            "data_update": True,
            "external_providers": True,
        },
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event() -> None:

    logger.info(
        "%s v%s started",
        SERVICE_NAME,
        SERVICE_VERSION,
    )

    logger.info(
        "OWNER Integration URL: %s",
        OWNER_INTEGRATION_URL,
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level=LOG_LEVEL.lower(),
    )
