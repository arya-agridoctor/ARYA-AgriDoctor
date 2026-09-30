"""
ARYA AgriDoctor
Orchestrator Runtime Bridge v1.0.0

Purpose:
- Connect the existing Orchestrator to owner_runtime_gateway.py
- Keep existing orchestrator.py unchanged
- Provide a stable runtime-facing bridge
- Centralize calls for analysis, diagnosis, recommendation,
  vision, payment, weather, geocoding and updates
- No modification of backend/main.py or existing modules

Default:
    Host: 127.0.0.1
    Port: 8017

Environment:
    ARYA_ORCHESTRATOR_BRIDGE_HOST
    ARYA_ORCHESTRATOR_BRIDGE_PORT
    ARYA_RUNTIME_GATEWAY_URL
    ARYA_BRIDGE_TIMEOUT
    ARYA_BRIDGE_MAX_RESPONSE_BYTES
    ARYA_BRIDGE_INTERNAL_SECRET
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

APP_NAME = "ARYA Orchestrator Runtime Bridge"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_ORCHESTRATOR_BRIDGE_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_ORCHESTRATOR_BRIDGE_PORT",
        "8017",
    )
)

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).rstrip("/")

TIMEOUT = float(
    os.getenv(
        "ARYA_BRIDGE_TIMEOUT",
        "60",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_BRIDGE_MAX_RESPONSE_BYTES",
        str(10 * 1024 * 1024),
    )
)

INTERNAL_SECRET = os.getenv(
    "ARYA_BRIDGE_INTERNAL_SECRET",
    "",
)


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Runtime bridge between the existing ARYA Orchestrator "
        "and the OWNER Runtime Gateway."
    ),
)


# ============================================================
# Models
# ============================================================

class RuntimeRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class AnalyzeRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class DiagnoseRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class RecommendRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class VisionRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class PaymentRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class WeatherRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class GeocodeRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class UpdateRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


# ============================================================
# Helpers
# ============================================================

def make_request_id(value: Optional[str] = None) -> str:
    if value:
        return value[:200]
    return str(uuid.uuid4())


def normalize_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path

    if path != "/" and path.endswith("/"):
        path = path[:-1]

    return path


def build_headers(request_id: str) -> Dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-ARYA-Request-ID": request_id,
    }

    if INTERNAL_SECRET:
        headers["X-ARYA-Internal-Secret"] = INTERNAL_SECRET

    return headers


async def call_runtime_gateway(
    path: str,
    payload: Dict[str, Any],
    request_id: str,
    method: str = "POST",
) -> Dict[str, Any]:

    path = normalize_path(path)

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
                    params=payload,
                )
            else:
                response = await client.post(
                    url,
                    headers=headers,
                    json=payload,
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

    content_length = len(response.content)

    if content_length > MAX_RESPONSE_BYTES:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "runtime_response_too_large",
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

    if isinstance(data, dict):
        data.setdefault(
            "_arya_bridge",
            {
                "request_id": request_id,
                "elapsed_seconds": elapsed,
            },
        )

    return data


# ============================================================
# Middleware
# ============================================================

@app.middleware("http")
async def request_logging_middleware(
    request: Request,
    call_next,
):
    started = time.monotonic()

    request_id = request.headers.get(
        "X-ARYA-Request-ID"
    ) or str(uuid.uuid4())

    response = await call_next(request)

    elapsed = round(
        time.monotonic() - started,
        4,
    )

    response.headers["X-ARYA-Request-ID"] = request_id
    response.headers["X-ARYA-Elapsed"] = str(elapsed)

    return response


# ============================================================
# Basic routes
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
        data = await call_runtime_gateway(
            "/health",
            {},
            request_id,
            method="GET",
        )

        return {
            "service": APP_NAME,
            "status": "healthy",
            "runtime_gateway": "reachable",
            "gateway_response": data,
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


@app.get("/runtime/info")
async def runtime_info():
    request_id = str(uuid.uuid4())

    return await call_runtime_gateway(
        "/arya/system-map",
        {},
        request_id,
        method="GET",
    )


# ============================================================
# Generic runtime action
# ============================================================

@app.post("/runtime/call")
async def runtime_call(
    request: RuntimeRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    action = request.action.strip()

    action_map = {
        "analyze": "/arya/analyze",
        "diagnose": "/arya/diagnose",
        "recommend": "/arya/recommend",
        "vision": "/arya/vision",
        "payment": "/arya/payment",
        "weather": "/arya/weather",
        "geocode": "/arya/geocode",
        "updates": "/arya/updates",
        "updates_run": "/arya/updates/run",
    }

    path = action_map.get(action)

    if not path:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_action",
                "action": action,
                "supported_actions": sorted(
                    action_map.keys()
                ),
                "request_id": request_id,
            },
        )

    return await call_runtime_gateway(
        path,
        request.payload,
        request_id,
    )


# ============================================================
# Agricultural analysis
# ============================================================

@app.post("/arya/analyze")
async def analyze(
    request: AnalyzeRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    return await call_runtime_gateway(
        "/arya/analyze",
        request.payload,
        request_id,
    )


@app.post("/arya/diagnose")
async def diagnose(
    request: DiagnoseRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    return await call_runtime_gateway(
        "/arya/diagnose",
        request.payload,
        request_id,
    )


@app.post("/arya/recommend")
async def recommend(
    request: RecommendRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    return await call_runtime_gateway(
        "/arya/recommend",
        request.payload,
        request_id,
    )


# ============================================================
# Vision
# ============================================================

@app.post("/arya/vision")
async def vision(
    request: VisionRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    return await call_runtime_gateway(
        "/arya/vision",
        request.payload,
        request_id,
    )


# ============================================================
# Commerce / Payment
# ============================================================

@app.post("/arya/payment")
async def payment(
    request: PaymentRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    return await call_runtime_gateway(
        "/arya/payment",
        request.payload,
        request_id,
    )


# ============================================================
# Weather
# ============================================================

@app.post("/arya/weather")
async def weather(
    request: WeatherRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    return await call_runtime_gateway(
        "/arya/weather",
        request.payload,
        request_id,
    )


# ============================================================
# Geocoding / Location
# ============================================================

@app.post("/arya/geocode")
async def geocode(
    request: GeocodeRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    return await call_runtime_gateway(
        "/arya/geocode",
        request.payload,
        request_id,
    )


# ============================================================
# Data Updates
# ============================================================

@app.post("/arya/updates")
async def updates(
    request: UpdateRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    return await call_runtime_gateway(
        "/arya/updates",
        request.payload,
        request_id,
    )


@app.post("/arya/updates/run")
async def updates_run(
    request: UpdateRequest,
):
    request_id = make_request_id(
        request.request_id
    )

    return await call_runtime_gateway(
        "/arya/updates/run",
        request.payload,
        request_id,
    )


# ============================================================
# System Map
# ============================================================

@app.get("/arya/system-map")
async def system_map():
    request_id = str(uuid.uuid4())

    return await call_runtime_gateway(
        "/arya/system-map",
        {},
        request_id,
        method="GET",
    )


# ============================================================
# Local execution
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "orchestrator_runtime_bridge:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
