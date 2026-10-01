"""
ARYA AgriDoctor
Runtime Orchestrator
Version: 1.0.0

Purpose:
- Connect the ARYA Orchestrator layer to Owner Runtime Gateway.
- Keep runtime service/provider discovery outside main.py.
- Provide a stable API for Android/Windows clients in later stages.
- Route agricultural, vision, voice, payment, weather, geocode and update
  requests through the Runtime Gateway.
- Do not store provider secrets in this module.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Runtime Orchestrator"
APP_VERSION = "1.0.0"

HOST = os.getenv("ARYA_RUNTIME_ORCHESTRATOR_HOST", "127.0.0.1")
PORT = int(os.getenv("ARYA_RUNTIME_ORCHESTRATOR_PORT", "8017"))

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).rstrip("/")

REQUEST_TIMEOUT = float(
    os.getenv("ARYA_RUNTIME_ORCHESTRATOR_TIMEOUT", "60")
)

MAX_RESPONSE_BYTES = int(
    os.getenv("ARYA_RUNTIME_ORCHESTRATOR_MAX_RESPONSE_BYTES", "10485760")
)

INTERNAL_SECRET = os.getenv(
    "ARYA_RUNTIME_ORCHESTRATOR_SECRET",
    "",
).strip()


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Final runtime orchestration layer for ARYA AgriDoctor. "
        "Routes requests through the Owner Runtime Gateway."
    ),
)


# ============================================================
# Models
# ============================================================

class RuntimeRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)
    payload: Dict[str, Any] = Field(default_factory=dict)


class DoctorRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class AnalyzeRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class DiagnoseRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class RecommendRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class VisionRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class VoiceRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class PaymentRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class WeatherRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class GeocodeRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class UpdateRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


# ============================================================
# Runtime client
# ============================================================

class RuntimeGatewayClient:
    """
    HTTP client for Owner Runtime Gateway.

    This module deliberately does not contain provider credentials.
    Provider/service configuration remains under OWNER-managed layers.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _headers(self, request_id: str) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ARYA-Request-ID": request_id,
        }

        if INTERNAL_SECRET:
            headers["X-ARYA-Internal-Secret"] = INTERNAL_SECRET

        return headers

    async def request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        request_id = str(uuid.uuid4())
        url = f"{self.base_url}/{path.lstrip('/')}"

        started = time.monotonic()

        try:
            async with httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
            ) as client:

                response = await client.request(
                    method=method.upper(),
                    url=url,
                    json=payload or {},
                    headers=self._headers(request_id),
                )

        except httpx.TimeoutException as exc:
            raise HTTPException(
                status_code=504,
                detail={
                    "error": "runtime_gateway_timeout",
                    "request_id": request_id,
                },
            ) from exc

        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "runtime_gateway_connection_failed",
                    "request_id": request_id,
                    "message": str(exc),
                },
            ) from exc

        elapsed_ms = round(
            (time.monotonic() - started) * 1000,
            2,
        )

        if len(response.content) > MAX_RESPONSE_BYTES:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "runtime_gateway_response_too_large",
                    "request_id": request_id,
                },
            )

        if response.status_code >= 400:
            try:
                body = response.json()
            except Exception:
                body = response.text[:2000]

            raise HTTPException(
                status_code=response.status_code,
                detail={
                    "error": "runtime_gateway_error",
                    "request_id": request_id,
                    "gateway_status": response.status_code,
                    "gateway_response": body,
                    "elapsed_ms": elapsed_ms,
                },
            )

        try:
            body = response.json()
        except Exception:
            body = {
                "success": True,
                "data": response.text,
            }

        if isinstance(body, dict):
            body.setdefault("request_id", request_id)
            body.setdefault("elapsed_ms", elapsed_ms)

        return body


gateway = RuntimeGatewayClient(RUNTIME_GATEWAY_URL)


# ============================================================
# Internal helpers
# ============================================================

async def gateway_call(
    path: str,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return await gateway.request(
        "POST",
        path,
        payload or {},
    )


# ============================================================
# Root / health
# ============================================================

@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "architecture": "ARYA -> Runtime Orchestrator -> Owner Runtime Gateway",
    }


@app.get("/health")
async def health() -> Dict[str, Any]:
    gateway_status = "unknown"

    try:
        result = await gateway.request(
            "GET",
            "/health",
            {},
        )
        gateway_status = (
            "online"
            if isinstance(result, dict)
            else "unknown"
        )
    except Exception:
        gateway_status = "offline"

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "runtime_gateway": gateway_status,
        "runtime_gateway_url": RUNTIME_GATEWAY_URL,
    }


# ============================================================
# Runtime discovery
# ============================================================

@app.get("/runtime/services")
async def runtime_services() -> Dict[str, Any]:
    return await gateway.request(
        "GET",
        "/runtime/services",
        {},
    )


@app.get("/runtime/providers")
async def runtime_providers() -> Dict[str, Any]:
    return await gateway.request(
        "GET",
        "/runtime/providers",
        {},
    )


@app.get("/runtime/system-map")
async def runtime_system_map() -> Dict[str, Any]:
    return await gateway.request(
        "GET",
        "/arya/system-map",
        {},
    )


# ============================================================
# Generic runtime action
# ============================================================

@app.post("/runtime/call")
async def runtime_call(
    request: RuntimeRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/runtime/call",
        {
            "action": request.action,
            "payload": request.payload,
        },
    )


# ============================================================
# ARYA Doctor
# ============================================================

@app.post("/arya/doctor")
async def arya_doctor(
    request: DoctorRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/analyze",
        request.payload,
    )


# ============================================================
# Agricultural analysis
# ============================================================

@app.post("/arya/analyze")
async def arya_analyze(
    request: AnalyzeRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/analyze",
        request.payload,
    )


@app.post("/arya/diagnose")
async def arya_diagnose(
    request: DiagnoseRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/diagnose",
        request.payload,
    )


@app.post("/arya/recommend")
async def arya_recommend(
    request: RecommendRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/recommend",
        request.payload,
    )


# ============================================================
# Vision
# ============================================================

@app.post("/arya/vision")
async def arya_vision(
    request: VisionRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/vision",
        request.payload,
    )


# ============================================================
# Voice / language
# ============================================================

@app.post("/arya/voice")
async def arya_voice(
    request: VoiceRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/voice",
        request.payload,
    )


# ============================================================
# Commerce / payment
# ============================================================

@app.post("/arya/payment")
async def arya_payment(
    request: PaymentRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/payment",
        request.payload,
    )


# ============================================================
# Weather
# ============================================================

@app.post("/arya/weather")
async def arya_weather(
    request: WeatherRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/weather",
        request.payload,
    )


# ============================================================
# Geocoding / location
# ============================================================

@app.post("/arya/geocode")
async def arya_geocode(
    request: GeocodeRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/geocode",
        request.payload,
    )


# ============================================================
# Data updates
# ============================================================

@app.post("/arya/updates")
async def arya_updates(
    request: UpdateRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/updates",
        request.payload,
    )


@app.post("/arya/updates/run")
async def arya_updates_run(
    request: UpdateRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/updates/run",
        request.payload,
    )


# ============================================================
# Service information
# ============================================================

@app.get("/info")
async def info() -> Dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "runtime_gateway_url": RUNTIME_GATEWAY_URL,
        "routes": {
            "doctor": "/arya/doctor",
            "analyze": "/arya/analyze",
            "diagnose": "/arya/diagnose",
            "recommend": "/arya/recommend",
            "vision": "/arya/vision",
            "voice": "/arya/voice",
            "payment": "/arya/payment",
            "weather": "/arya/weather",
            "geocode": "/arya/geocode",
            "updates": "/arya/updates",
            "updates_run": "/arya/updates/run",
            "runtime_call": "/runtime/call",
        },
    }


# ============================================================
# Application entry point
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "runtime_orchestrator:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
