"""
ARYA AgriDoctor
Runtime Data & Provider Bridge
Version: 2.0.0

Purpose:
- Connect Data Update Manager and External Providers to Runtime Gateway.
- Keep existing core services untouched.
- Provide one runtime-facing interface for:
  * Weather
  * Geocoding
  * Satellite providers
  * Generic providers
  * Data sources
  * Automatic updates
  * Update status
  * Provider health
  * System map
  * Runtime discovery

Core services are NOT modified by this bridge:
- backend/main.py
- data_update.py
- external_providers.py
- owner_runtime_gateway.py
- orchestrator.py
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Runtime Data Provider Bridge"
APP_VERSION = "2.0.0"

HOST = os.getenv(
    "ARYA_DATA_PROVIDER_BRIDGE_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_DATA_PROVIDER_BRIDGE_PORT",
        "8018",
    )
)

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).rstrip("/")

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    os.getenv(
        "ARYA_BRIDGE_INTERNAL_SECRET",
        "",
    ),
).strip()

TIMEOUT = float(
    os.getenv(
        "ARYA_DATA_PROVIDER_BRIDGE_TIMEOUT",
        "60",
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_DATA_PROVIDER_BRIDGE_MAX_REQUEST_BYTES",
        str(10 * 1024 * 1024),
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_DATA_PROVIDER_BRIDGE_MAX_RESPONSE_BYTES",
        str(20 * 1024 * 1024),
    )
)

LOG_LEVEL = os.getenv(
    "ARYA_DATA_PROVIDER_BRIDGE_LOG_LEVEL",
    "INFO",
).upper()


logging.basicConfig(
    level=getattr(
        logging,
        LOG_LEVEL,
        logging.INFO,
    ),
    format=(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    ),
)

logger = logging.getLogger(
    "arya.runtime_data_provider_bridge"
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Runtime bridge for ARYA Data Update "
        "and External Provider services."
    ),
)


# ============================================================
# Models
# ============================================================

class PayloadRequest(BaseModel):
    payload: Dict[str, Any] = Field(
        default_factory=dict
    )
    request_id: Optional[str] = None


class ProviderRequest(BaseModel):
    provider_id: str = Field(
        ...,
        min_length=1,
        max_length=200,
    )
    payload: Dict[str, Any] = Field(
        default_factory=dict
    )
    request_id: Optional[str] = None


class SourceRequest(BaseModel):
    source_id: str = Field(
        ...,
        min_length=1,
        max_length=200,
    )
    payload: Dict[str, Any] = Field(
        default_factory=dict
    )
    request_id: Optional[str] = None


# ============================================================
# Request ID
# ============================================================

def make_request_id(
    value: Optional[str] = None,
) -> str:

    if value:
        value = value.strip()

        if value:
            return value[:128]

    return str(uuid.uuid4())


# ============================================================
# Headers
# ============================================================

def build_headers(
    request_id: str,
    incoming_authorization: Optional[str] = None,
) -> Dict[str, str]:

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-ARYA-Request-ID": request_id,
        "User-Agent": (
            "ARYA-Runtime-Data-Provider-Bridge/"
            f"{APP_VERSION}"
        ),
    }

    if incoming_authorization:
        headers["Authorization"] = (
            incoming_authorization
        )

    elif INTERNAL_SECRET:
        headers["Authorization"] = (
            f"Bearer {INTERNAL_SECRET}"
        )

        headers["X-ARYA-Internal-Secret"] = (
            INTERNAL_SECRET
        )

    return headers


# ============================================================
# Request size
# ============================================================

async def validate_request_size(
    request: Request,
) -> None:

    content_length = request.headers.get(
        "content-length"
    )

    if not content_length:
        return

    try:
        size = int(content_length)
    except ValueError:
        return

    if size > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "error": "request_too_large",
                "max_bytes": MAX_REQUEST_BYTES,
            },
        )


# ============================================================
# Runtime Gateway caller
# ============================================================

async def call_gateway(
    path: str,
    *,
    payload: Optional[Dict[str, Any]] = None,
    request_id: str,
    method: str = "POST",
    params: Optional[Dict[str, Any]] = None,
    authorization: Optional[str] = None,
) -> Any:

    if not path.startswith("/"):
        path = "/" + path

    method = method.upper()

    url = (
        f"{RUNTIME_GATEWAY_URL}{path}"
    )

    headers = build_headers(
        request_id=request_id,
        incoming_authorization=authorization,
    )

    started = time.monotonic()

    try:

        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=False,
        ) as client:

            if method in {
                "GET",
                "HEAD",
                "DELETE",
            }:

                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                )

            else:

                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=payload or {},
                )

    except httpx.TimeoutException as exc:

        logger.error(
            "Runtime Gateway timeout: %s",
            url,
        )

        raise HTTPException(
            status_code=504,
            detail={
                "error": "runtime_gateway_timeout",
                "message": str(exc),
                "request_id": request_id,
            },
        ) from exc

    except httpx.RequestError as exc:

        logger.error(
            "Runtime Gateway unreachable: %s",
            url,
        )

        raise HTTPException(
            status_code=502,
            detail={
                "error": "runtime_gateway_unreachable",
                "message": str(exc),
                "gateway": RUNTIME_GATEWAY_URL,
                "request_id": request_id,
            },
        ) from exc

    elapsed = round(
        time.monotonic() - started,
        4,
    )

    content_length = response.headers.get(
        "content-length"
    )

    if content_length:

        try:

            if (
                int(content_length)
                > MAX_RESPONSE_BYTES
            ):
                raise HTTPException(
                    status_code=502,
                    detail={
                        "error": "response_too_large",
                        "request_id": request_id,
                    },
                )

        except ValueError:
            pass

    if len(response.content) > MAX_RESPONSE_BYTES:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "response_too_large",
                "request_id": request_id,
            },
        )

    content_type = response.headers.get(
        "content-type",
        "",
    ).lower()

    if not response.content:

        data: Any = {}

    elif "json" in content_type:

        try:
            data = response.json()
        except Exception:
            data = {
                "raw": response.text[:10000],
            }

    else:

        data = {
            "raw": response.text[:10000],
        }

    if response.status_code >= 400:

        logger.warning(
            "Runtime Gateway returned %s for %s",
            response.status_code,
            path,
        )

        raise HTTPException(
            status_code=response.status_code,
            detail={
                "error": "runtime_gateway_error",
                "gateway_status": (
                    response.status_code
                ),
                "response": data,
                "request_id": request_id,
                "elapsed_seconds": elapsed,
            },
        )

    return data


# ============================================================
# Middleware
# ============================================================

@app.middleware("http")
async def request_middleware(
    request: Request,
    call_next,
):

    request_id = (
        request.headers.get(
            "X-ARYA-Request-ID"
        )
        or str(uuid.uuid4())
    )

    request.state.arya_request_id = request_id

    await validate_request_size(
        request
    )

    started = time.monotonic()

    response = await call_next(
        request
    )

    elapsed = round(
        time.monotonic() - started,
        4,
    )

    response.headers[
        "X-ARYA-Request-ID"
    ] = request_id

    response.headers[
        "X-ARYA-Elapsed"
    ] = str(elapsed)

    return response


# ============================================================
# Root
# ============================================================

@app.get("/")
async def root():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "port": PORT,
        "capabilities": [
            "weather",
            "geocode",
            "satellite",
            "provider",
            "provider_health",
            "providers_health",
            "sources",
            "source_fetch",
            "updates",
            "data_update",
            "system_map",
        ],
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health():

    request_id = str(uuid.uuid4())

    try:

        data = await call_gateway(
            "/health",
            request_id=request_id,
            method="GET",
        )

        return {
            "service": APP_NAME,
            "version": APP_VERSION,
            "status": "healthy",
            "runtime_gateway": "reachable",
            "gateway": data,
            "request_id": request_id,
        }

    except HTTPException as exc:

        return {
            "service": APP_NAME,
            "version": APP_VERSION,
            "status": "degraded",
            "runtime_gateway": "unreachable",
            "error": exc.detail,
            "request_id": request_id,
        }


# ============================================================
# Weather
# ============================================================

@app.get("/weather")
async def weather_get(
    latitude: float,
    longitude: float,
    authorization: Optional[str] = None,
):

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/weather",
        method="GET",
        params={
            "latitude": latitude,
            "longitude": longitude,
        },
        request_id=request_id,
        authorization=authorization,
    )


@app.post("/weather")
async def weather_post(
    request: PayloadRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    payload = dict(
        request.payload
    )

    latitude = payload.pop(
        "latitude",
        None,
    )

    longitude = payload.pop(
        "longitude",
        None,
    )

    if (
        latitude is not None
        and longitude is not None
    ):

        return await call_gateway(
            "/arya/weather",
            method="GET",
            params={
                "latitude": latitude,
                "longitude": longitude,
                **payload,
            },
            request_id=request_id,
        )

    return await call_gateway(
        "/arya/weather",
        method="POST",
        payload=request.payload,
        request_id=request_id,
    )


# ============================================================
# Geocoding
# ============================================================

@app.get("/geocode")
async def geocode_get(
    name: str,
):

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/geocode",
        method="GET",
        params={
            "name": name,
        },
        request_id=request_id,
    )


@app.post("/geocode")
async def geocode_post(
    request: PayloadRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    payload = dict(
        request.payload
    )

    name = payload.pop(
        "name",
        None,
    )

    if name is not None:

        return await call_gateway(
            "/arya/geocode",
            method="GET",
            params={
                "name": name,
                **payload,
            },
            request_id=request_id,
        )

    return await call_gateway(
        "/arya/geocode",
        method="POST",
        payload=request.payload,
        request_id=request_id,
    )


# ============================================================
# Satellite
# ============================================================

@app.post("/satellite")
async def satellite(
    request: PayloadRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    return await call_gateway(
        "/arya/satellite",
        payload=request.payload,
        request_id=request_id,
    )


# ============================================================
# Generic provider
# ============================================================

@app.post("/provider")
async def provider(
    request: ProviderRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    payload = {
        "provider_id": request.provider_id,
        "payload": request.payload,
        "request_id": request_id,
    }

    return await call_gateway(
        "/arya/provider",
        payload=payload,
        request_id=request_id,
    )


# ============================================================
# Provider health
# ============================================================

@app.post("/provider/health")
async def provider_health(
    request: ProviderRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    payload = {
        "provider_id": request.provider_id,
    }

    return await call_gateway(
        "/arya/provider/health",
        payload=payload,
        request_id=request_id,
    )


# ============================================================
# All provider health
# ============================================================

@app.get("/providers/health")
async def providers_health():

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/providers/health",
        method="GET",
        request_id=request_id,
    )


# ============================================================
# Provider list
# ============================================================

@app.get("/providers")
async def providers():

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/providers",
        method="GET",
        request_id=request_id,
    )


# ============================================================
# Data source list
# ============================================================

@app.get("/sources")
async def sources():

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/sources",
        method="GET",
        request_id=request_id,
    )


# ============================================================
# Data source fetch
# ============================================================

@app.post("/sources/fetch")
async def source_fetch(
    request: SourceRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    payload = {
        "source_id": request.source_id,
        "payload": request.payload,
    }

    return await call_gateway(
        "/arya/source/fetch",
        payload=payload,
        request_id=request_id,
    )


# ============================================================
# Update status
# ============================================================

@app.get("/updates/status")
async def updates_status():

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/updates",
        method="GET",
        request_id=request_id,
    )


# ============================================================
# Run updates
# ============================================================

@app.post("/updates/run")
async def updates_run(
    request: PayloadRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    return await call_gateway(
        "/arya/updates/run",
        method="POST",
        payload=request.payload,
        request_id=request_id,
    )


# ============================================================
# Data update manager
# ============================================================

@app.post("/data/update")
async def data_update(
    request: PayloadRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    return await call_gateway(
        "/arya/data/update",
        method="POST",
        payload=request.payload,
        request_id=request_id,
    )


# ============================================================
# Data status
# ============================================================

@app.get("/data/status")
async def data_status():

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/data/status",
        method="GET",
        request_id=request_id,
    )


# ============================================================
# Unified data request
# ============================================================

@app.post("/data/request")
async def unified_data_request(
    request: PayloadRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    return await call_gateway(
        "/arya/data/request",
        method="POST",
        payload=request.payload,
        request_id=request_id,
    )


# ============================================================
# System map
# ============================================================

@app.get("/system-map")
async def system_map():

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/system-map",
        method="GET",
        request_id=request_id,
    )


# ============================================================
# Contract
# ============================================================

@app.get("/contract")
async def contract():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "port": PORT,
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "routes": {
            "weather_get": "GET /weather",
            "weather_post": "POST /weather",
            "geocode_get": "GET /geocode",
            "geocode_post": "POST /geocode",
            "satellite": "POST /satellite",
            "provider": "POST /provider",
            "provider_health": (
                "POST /provider/health"
            ),
            "providers_health": (
                "GET /providers/health"
            ),
            "providers": "GET /providers",
            "sources": "GET /sources",
            "source_fetch": (
                "POST /sources/fetch"
            ),
            "updates_status": (
                "GET /updates/status"
            ),
            "updates_run": (
                "POST /updates/run"
            ),
            "data_update": (
                "POST /data/update"
            ),
            "data_status": (
                "GET /data/status"
            ),
            "data_request": (
                "POST /data/request"
            ),
            "system_map": (
                "GET /system-map"
            ),
            "health": "GET /health",
        },
        "core_files_modified": False,
    }


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup_event():

    logger.info(
        "%s v%s started",
        APP_NAME,
        APP_VERSION,
    )

    logger.info(
        "Runtime Gateway: %s",
        RUNTIME_GATEWAY_URL,
    )


# ============================================================
# Standalone execution
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        reload=False,
    )
