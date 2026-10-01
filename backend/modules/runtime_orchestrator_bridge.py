"""
ARYA AgriDoctor
Runtime Orchestrator Bridge
Version: 1.0.0

Purpose:
- Connect the final Orchestrator layer to owner_runtime_gateway.py
- Keep main.py and existing modules untouched
- Provide a stable API boundary for Android / Windows clients
- Forward agricultural, vision, voice, payment, weather and update actions
- Support health checks and runtime system mapping
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

APP_NAME = "ARYA Runtime Orchestrator Bridge"
APP_VERSION = "1.0.0"

HOST = os.getenv("ARYA_RUNTIME_BRIDGE_HOST", "127.0.0.1")
PORT = int(os.getenv("ARYA_RUNTIME_BRIDGE_PORT", "8017"))

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).rstrip("/")

REQUEST_TIMEOUT = float(
    os.getenv("ARYA_RUNTIME_BRIDGE_TIMEOUT", "45")
)

MAX_RESPONSE_BYTES = int(
    os.getenv("ARYA_RUNTIME_BRIDGE_MAX_RESPONSE", str(10 * 1024 * 1024))
)

INTERNAL_SECRET = os.getenv(
    "ARYA_RUNTIME_BRIDGE_SECRET",
    "",
)

USER_AGENT = "ARYA-Runtime-Orchestrator-Bridge/1.0.0"


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Final runtime bridge between ARYA Orchestrator "
        "and Owner Runtime Gateway."
    ),
)


# ============================================================
# Models
# ============================================================

class BridgeRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class DoctorRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class RuntimeCallRequest(BaseModel):
    service: str = Field(..., min_length=1, max_length=100)
    path: str = Field(..., min_length=1, max_length=500)
    method: str = Field(default="POST", min_length=3, max_length=10)
    payload: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


# ============================================================
# Runtime client
# ============================================================

class RuntimeGatewayClient:
    """
    HTTP client for owner_runtime_gateway.py.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = REQUEST_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self, request_id: str) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
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
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:

        request_id = request_id or str(uuid.uuid4())

        clean_path = "/" + path.lstrip("/")
        url = f"{self.base_url}{clean_path}"

        start = time.monotonic()

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,
                headers=self._headers(request_id),
            ) as client:

                response = await client.request(
                    method.upper(),
                    url,
                    json=payload or {},
                )

                elapsed = round(
                    (time.monotonic() - start) * 1000,
                    2,
                )

                content_length = len(response.content)

                if content_length > MAX_RESPONSE_BYTES:
                    raise HTTPException(
                        status_code=502,
                        detail="Runtime Gateway response is too large.",
                    )

                if response.status_code >= 400:
                    detail: Any

                    try:
                        detail = response.json()
                    except Exception:
                        detail = response.text[:4000]

                    raise HTTPException(
                        status_code=502,
                        detail={
                            "message": "Runtime Gateway returned an error.",
                            "gateway_status": response.status_code,
                            "gateway_response": detail,
                            "request_id": request_id,
                        },
                    )

                try:
                    data = response.json()
                except Exception:
                    data = {
                        "raw": response.text,
                    }

                if isinstance(data, dict):
                    data.setdefault(
                        "bridge_request_id",
                        request_id,
                    )
                    data.setdefault(
                        "bridge_elapsed_ms",
                        elapsed,
                    )
                    return data

                return {
                    "data": data,
                    "bridge_request_id": request_id,
                    "bridge_elapsed_ms": elapsed,
                }

        except HTTPException:
            raise

        except httpx.TimeoutException as exc:
            raise HTTPException(
                status_code=504,
                detail={
                    "message": "Runtime Gateway timeout.",
                    "request_id": request_id,
                },
            ) from exc

        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502,
                detail={
                    "message": "Runtime Gateway connection failed.",
                    "error": str(exc),
                    "request_id": request_id,
                },
            ) from exc

        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Unexpected bridge error.",
                    "error": str(exc),
                    "request_id": request_id,
                },
            ) from exc


gateway = RuntimeGatewayClient(RUNTIME_GATEWAY_URL)


# ============================================================
# Request ID middleware
# ============================================================

@app.middleware("http")
async def request_id_middleware(
    request: Request,
    call_next,
):
    request_id = request.headers.get(
        "X-ARYA-Request-ID"
    ) or str(uuid.uuid4())

    request.state.arya_request_id = request_id

    response = await call_next(request)

    response.headers["X-ARYA-Request-ID"] = request_id

    return response


# ============================================================
# Root
# ============================================================

@app.get("/")
async def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "architecture": {
            "client": "Android / Windows",
            "bridge": "runtime_orchestrator_bridge",
            "gateway": "owner_runtime_gateway",
            "orchestrator": "orchestrator",
            "main_backend": "main.py",
        },
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health():
    request_id = str(uuid.uuid4())

    try:
        result = await gateway.request(
            "GET",
            "/health",
            request_id=request_id,
        )

        return {
            "status": "healthy",
            "bridge": "online",
            "runtime_gateway": "online",
            "gateway_response": result,
            "request_id": request_id,
        }

    except HTTPException as exc:
        return {
            "status": "degraded",
            "bridge": "online",
            "runtime_gateway": "unavailable",
            "error": exc.detail,
            "request_id": request_id,
        }


# ============================================================
# System map
# ============================================================

@app.get("/system-map")
async def system_map():
    request_id = str(uuid.uuid4())

    return await gateway.request(
        "GET",
        "/arya/system-map",
        request_id=request_id,
    )


# ============================================================
# Runtime services
# ============================================================

@app.get("/services")
async def services():
    request_id = str(uuid.uuid4())

    return await gateway.request(
        "GET",
        "/runtime/services",
        request_id=request_id,
    )


@app.get("/providers")
async def providers():
    request_id = str(uuid.uuid4())

    return await gateway.request(
        "GET",
        "/runtime/providers",
        request_id=request_id,
    )


# ============================================================
# Generic orchestration
# ============================================================

@app.post("/orchestrate")
async def orchestrate(
    body: BridgeRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    payload = dict(body.payload)

    payload.setdefault(
        "action",
        body.action,
    )

    payload.setdefault(
        "request_id",
        request_id,
    )

    return await gateway.request(
        "POST",
        "/orchestrate",
        payload,
        request_id,
    )


# ============================================================
# Unified ARYA Doctor
# ============================================================

@app.post("/arya/doctor")
async def arya_doctor(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    payload = dict(body.payload)

    payload.setdefault(
        "request_id",
        request_id,
    )

    return await gateway.request(
        "POST",
        "/arya/doctor",
        payload,
        request_id,
    )


# ============================================================
# Agricultural analysis
# ============================================================

@app.post("/arya/analyze")
async def arya_analyze(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/analyze",
        body.payload,
        request_id,
    )


# ============================================================
# Diagnosis
# ============================================================

@app.post("/arya/diagnose")
async def arya_diagnose(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/diagnose",
        body.payload,
        request_id,
    )


# ============================================================
# Recommendation
# ============================================================

@app.post("/arya/recommend")
async def arya_recommend(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/recommend",
        body.payload,
        request_id,
    )


# ============================================================
# Vision
# ============================================================

@app.post("/arya/vision")
async def arya_vision(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/vision",
        body.payload,
        request_id,
    )


# ============================================================
# Voice
# ============================================================

@app.post("/arya/voice")
async def arya_voice(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/voice",
        body.payload,
        request_id,
    )


# ============================================================
# Payment
# ============================================================

@app.post("/arya/payment")
async def arya_payment(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/payment",
        body.payload,
        request_id,
    )


# ============================================================
# Weather
# ============================================================

@app.post("/arya/weather")
async def arya_weather(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/weather",
        body.payload,
        request_id,
    )


# ============================================================
# Geocoding
# ============================================================

@app.post("/arya/geocode")
async def arya_geocode(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/geocode",
        body.payload,
        request_id,
    )


# ============================================================
# Data updates
# ============================================================

@app.post("/arya/updates")
async def arya_updates(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/updates",
        body.payload,
        request_id,
    )


@app.post("/arya/updates/run")
async def arya_updates_run(
    body: DoctorRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    return await gateway.request(
        "POST",
        "/arya/updates/run",
        body.payload,
        request_id,
    )


# ============================================================
# Direct runtime call
# ============================================================

@app.post("/runtime/call")
async def runtime_call(
    body: RuntimeCallRequest,
    request: Request,
):
    request_id = (
        body.request_id
        or getattr(
            request.state,
            "arya_request_id",
            None,
        )
        or str(uuid.uuid4())
    )

    payload = {
        "service": body.service,
        "path": body.path,
        "method": body.method.upper(),
        "payload": body.payload,
    }

    return await gateway.request(
        "POST",
        "/runtime/call",
        payload,
        request_id,
    )


# ============================================================
# Information
# ============================================================

@app.get("/info")
async def info():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "runtime_gateway_url": RUNTIME_GATEWAY_URL,
        "features": [
            "unified_doctor",
            "agricultural_analysis",
            "diagnosis",
            "recommendation",
            "vision",
            "voice",
            "payment",
            "weather",
            "geocoding",
            "automatic_updates",
            "runtime_service_discovery",
            "runtime_provider_discovery",
            "generic_runtime_call",
            "request_id_tracking",
        ],
    }


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup_event():
    print("=" * 70)
    print(f"{APP_NAME} {APP_VERSION}")
    print("=" * 70)
    print(f"Host: {HOST}")
    print(f"Port: {PORT}")
    print(f"Runtime Gateway: {RUNTIME_GATEWAY_URL}")
    print("Status: READY")
    print("=" * 70)


# ============================================================
# Local execution
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "runtime_orchestrator_bridge:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
