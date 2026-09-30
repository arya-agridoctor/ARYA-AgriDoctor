"""
ARYA AgriDoctor
Runtime Data & Provider Bridge v1.0.0

Purpose:
- Connect Data Update Manager and External Providers to Runtime Gateway.
- Keep existing modules unchanged.
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

No modification is made to:
- backend/main.py
- data_update.py
- external_providers.py
- owner_runtime_gateway.py
- orchestrator.py
"""

from __future__ import annotations

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
APP_VERSION = "1.0.0"

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

TIMEOUT = float(
    os.getenv(
        "ARYA_DATA_PROVIDER_BRIDGE_TIMEOUT",
        "60",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_DATA_PROVIDER_BRIDGE_MAX_RESPONSE_BYTES",
        str(10 * 1024 * 1024),
    )
)

INTERNAL_SECRET = os.getenv(
    "ARYA_BRIDGE_INTERNAL_SECRET",
    "",
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Runtime bridge for ARYA Data Update and "
        "External Provider services."
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
    request_id: Optional[str] = None


# ============================================================
# Request ID
# ============================================================

def make_request_id(
    value: Optional[str] = None,
) -> str:
    if value:
        return value[:200]

    return str(uuid.uuid4())


# ============================================================
# Gateway headers
# ============================================================

def build_headers(
    request_id: str,
) -> Dict[str, str]:

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-ARYA-Request-ID": request_id,
    }

    if INTERNAL_SECRET:
        headers["X-ARYA-Internal-Secret"] = INTERNAL_SECRET

    return headers


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
) -> Any:

    if not path.startswith("/"):
        path = "/" + path

    url = f"{RUNTIME_GATEWAY_URL}{path}"

    headers = build_headers(request_id)

    started = time.monotonic()

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=False,
        ) as client:

            if method.upper() == "GET":
                response = await client.get(
                    url,
                    headers=headers,
                    params=params,
                )
            else:
                response = await client.post(
                    url,
                    headers=headers,
                    json=payload or {},
                )

    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail={
                "error": "runtime_gateway_timeout",
                "message": str(exc),
                "request_id": request_id,
            },
        )

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "runtime_gateway_unreachable",
                "message": str(exc),
                "gateway": RUNTIME_GATEWAY_URL,
                "request_id": request_id,
            },
        )

    elapsed = round(
        time.monotonic() - started,
        4,
    )

    if len(response.content) > MAX_RESPONSE_BYTES:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "response_too_large",
                "request_id": request_id,
            },
        )

    try:
        data = response.json()
    except Exception:
        data = {
            "raw": response.text[:10000],
        }

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail={
                "error": "runtime_gateway_error",
                "gateway_status": response.status_code,
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
        request.headers.get("X-ARYA-Request-ID")
        or str(uuid.uuid4())
    )

    started = time.monotonic()

    response = await call_next(request)

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
# Root / Health
# ============================================================

@app.get("/")
async def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "port": PORT,
    }


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
            "status": "healthy",
            "runtime_gateway": "reachable",
            "gateway": data,
            "request_id": request_id,
        }

    except HTTPException as exc:

        return {
            "service": APP_NAME,
            "status": "degraded",
            "runtime_gateway": "unreachable",
            "error": exc.detail,
            "request_id": request_id,
        }


# ============================================================
# Weather
# ============================================================

@app.post("/weather")
async def weather(
    request: PayloadRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    return await call_gateway(
        "/arya/weather",
        payload=request.payload,
        request_id=request_id,
    )


# ============================================================
# Geocoding
# ============================================================

@app.post("/geocode")
async def geocode(
    request: PayloadRequest,
):

    request_id = make_request_id(
        request.request_id
    )

    return await call_gateway(
        "/arya/geocode",
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
# Generic external provider
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
        request_id=request_id,
        method="GET",
    )


# ============================================================
# Provider list
# ============================================================

@app.get("/providers")
async def providers():

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/providers",
        request_id=request_id,
        method="GET",
    )


# ============================================================
# Data source list
# ============================================================

@app.get("/sources")
async def sources():

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/sources",
        request_id=request_id,
        method="GET",
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
        payload={},
        request_id=request_id,
        method="GET",
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
        request_id=request_id,
        method="GET",
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
        payload=request.payload,
        request_id=request_id,
    )


# ============================================================
# Runtime system map
# ============================================================

@app.get("/system-map")
async def system_map():

    request_id = str(uuid.uuid4())

    return await call_gateway(
        "/arya/system-map",
        request_id=request_id,
        method="GET",
    )


# ============================================================
# Application entry point
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "runtime_data_provider_bridge:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
