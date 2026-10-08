
ARYA AgriDoctor
Client Runtime Bridge
Version: 1.0.0

Purpose:
    Connect the Android/Windows Client API Gateway to the
    ARYA Final Integration Layer.

Architecture:

    Android / Windows Client
              ↓
    Client API Gateway
              ↓
    Client Runtime Bridge
              ↓
    Final Integration
              ↓
    Unified API / Runtime / Services / Main API

Important:
    - backend/main.py is NOT modified.
    - Existing modules are NOT modified.
    - This is an independent integration module.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Client Runtime Bridge"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_CLIENT_RUNTIME_BRIDGE_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_CLIENT_RUNTIME_BRIDGE_PORT",
        "8028",
    )
)

CLIENT_API_GATEWAY_URL = os.getenv(
    "ARYA_CLIENT_API_GATEWAY_URL",
    "http://127.0.0.1:8021",
).rstrip("/")

FINAL_INTEGRATION_URL = os.getenv(
    "ARYA_FINAL_INTEGRATION_URL",
    "http://127.0.0.1:8027",
).rstrip("/")

UNIFIED_API_URL = os.getenv(
    "ARYA_UNIFIED_API_URL",
    "http://127.0.0.1:8023",
).rstrip("/")

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).rstrip("/")

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

REQUEST_TIMEOUT = float(
    os.getenv(
        "ARYA_CLIENT_RUNTIME_BRIDGE_TIMEOUT",
        "30",
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_CLIENT_RUNTIME_BRIDGE_MAX_REQUEST_BYTES",
        str(10 * 1024 * 1024),
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_CLIENT_RUNTIME_BRIDGE_MAX_RESPONSE_BYTES",
        str(10 * 1024 * 1024),
    )
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Client-to-runtime integration bridge for "
        "ARYA AgriDoctor Android and Windows clients."
    ),
)


# ============================================================
# Runtime State
# ============================================================

_started_at = time.time()

_request_count = 0
_error_count = 0


# ============================================================
# Models
# ============================================================

class ClientRequest(BaseModel):
    action: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = None

    device_id: Optional[str] = None

    client_id: Optional[str] = None


class RuntimeRequest(BaseModel):
    action: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = None


# ============================================================
# Utility
# ============================================================

def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def request_id(value: Optional[str]) -> str:
    return value or str(uuid.uuid4())


def sign_body(body: bytes) -> str:
    if not INTERNAL_SECRET:
        return ""

    return hmac.new(
        INTERNAL_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()


def build_headers(
    body: bytes,
    rid: str,
) -> Dict[str, str]:

    headers = {
        "Content-Type": "application/json",
        "X-ARYA-Internal": "1",
        "X-ARYA-Request-ID": rid,
        "X-ARYA-Bridge": APP_NAME,
        "X-ARYA-Bridge-Version": APP_VERSION,
    }

    signature = sign_body(body)

    if signature:
        headers["X-ARYA-Signature"] = signature

    return headers


def approved_url(url: str) -> bool:

    approved = {
        CLIENT_API_GATEWAY_URL,
        FINAL_INTEGRATION_URL,
        UNIFIED_API_URL,
        RUNTIME_GATEWAY_URL,
    }

    return url.rstrip("/") in approved


async def request_service(
    method: str,
    url: str,
    *,
    payload: Optional[Dict[str, Any]] = None,
    rid: Optional[str] = None,
) -> Any:

    if not approved_url(url):
        raise HTTPException(
            status_code=500,
            detail=(
                "Target URL is not an approved "
                "ARYA internal service."
            ),
        )

    rid = request_id(rid)

    body = b""

    if payload is not None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        if len(body) > MAX_REQUEST_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Request body is too large.",
            )

    headers = build_headers(
        body,
        rid,
    )

    try:

        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            follow_redirects=False,
        ) as client:

            response = await client.request(
                method.upper(),
                url,
                content=(
                    body
                    if payload is not None
                    else None
                ),
                headers=headers,
            )

    except httpx.TimeoutException:

        raise HTTPException(
            status_code=504,
            detail="ARYA internal service timeout.",
        )

    except httpx.RequestError as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "ARYA internal service connection "
                f"failed: {exc}"
            ),
        )

    if len(response.content) > MAX_RESPONSE_BYTES:

        raise HTTPException(
            status_code=502,
            detail=(
                "ARYA internal service response "
                "is too large."
            ),
        )

    content_type = response.headers.get(
        "content-type",
        "",
    ).lower()

    if "application/json" in content_type:

        try:
            result = response.json()

        except Exception:

            result = {
                "raw": response.text,
            }

    else:

        result = {
            "raw": response.text,
        }

    if response.status_code >= 400:

        raise HTTPException(
            status_code=response.status_code,
            detail=result,
        )

    return result


async def get_service(
    base_url: str,
    path: str,
    rid: Optional[str] = None,
) -> Any:

    return await request_service(
        "GET",
        f"{base_url}{path}",
        rid=rid,
    )


async def post_service(
    base_url: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    rid: Optional[str] = None,
) -> Any:

    return await request_service(
        "POST",
        f"{base_url}{path}",
        payload=payload or {},
        rid=rid,
    )


# ============================================================
# Root
# ============================================================

@app.get("/")
async def root():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "port": PORT,
        "started_at": utc_now(),

        "connections": {
            "client_api_gateway": CLIENT_API_GATEWAY_URL,
            "final_integration": FINAL_INTEGRATION_URL,
            "unified_api": UNIFIED_API_URL,
            "runtime_gateway": RUNTIME_GATEWAY_URL,
        },
    }


# ============================================================
# Health
# ============================================================

async def check(
    name: str,
    url: str,
) -> Dict[str, Any]:

    started = time.perf_counter()

    try:

        result = await get_service(
            url,
            "/health",
        )

        return {
            "service": name,
            "url": url,
            "status": "online",
            "latency_ms": round(
                (
                    time.perf_counter()
                    - started
                ) * 1000,
                2,
            ),
            "response": result,
            "checked_at": utc_now(),
        }

    except Exception as exc:

        return {
            "service": name,
            "url": url,
            "status": "offline",
            "latency_ms": round(
                (
                    time.perf_counter()
                    - started
                ) * 1000,
                2,
            ),
            "error": str(exc),
            "checked_at": utc_now(),
        }


@app.get("/health")
async def health():

    services = {
        "client_api_gateway": CLIENT_API_GATEWAY_URL,
        "final_integration": FINAL_INTEGRATION_URL,
        "unified_api": UNIFIED_API_URL,
        "runtime_gateway": RUNTIME_GATEWAY_URL,
    }

    results = []

    for name, url in services.items():

        results.append(
            await check(
                name,
                url,
            )
        )

    online = sum(
        1
        for item in results
        if item["status"] == "online"
    )

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": (
            "healthy"
            if online == len(results)
            else "degraded"
        ),
        "online": online,
        "total": len(results),
        "services": results,
        "timestamp": utc_now(),
    }


# ============================================================
# Client Gateway Status
# ============================================================

@app.get("/client/status")
async def client_status():

    return await get_service(
        CLIENT_API_GATEWAY_URL,
        "/health",
    )


# ============================================================
# Final Integration Status
# ============================================================

@app.get("/integration/status")
async def integration_status():

    return await get_service(
        FINAL_INTEGRATION_URL,
        "/status",
    )


@app.get("/integration/system-map")
async def integration_system_map():

    return await get_service(
        FINAL_INTEGRATION_URL,
        "/system-map",
    )


# ============================================================
# Client Runtime
# ============================================================

@app.post("/client/runtime")
async def client_runtime(
    request: ClientRequest,
):

    global _request_count

    _request_count += 1

    rid = request_id(
        request.request_id
    )

    payload = {
        "action": request.action,
        "payload": request.payload,
        "request_id": rid,
        "device_id": request.device_id,
        "client_id": request.client_id,
    }

    result = await post_service(
        FINAL_INTEGRATION_URL,
        "/runtime/call",
        payload,
        rid,
    )

    return {
        "success": True,
        "request_id": rid,
        "action": request.action,
        "result": result,
        "timestamp": utc_now(),
    }


# ============================================================
# Agricultural Doctor
# ============================================================

async def doctor(
    route: str,
    request: ClientRequest,
):

    global _request_count

    _request_count += 1

    rid = request_id(
        request.request_id
    )

    payload = {
        "action": request.action,
        "payload": request.payload,
        "request_id": rid,
        "device_id": request.device_id,
        "client_id": request.client_id,
    }

    result = await post_service(
        FINAL_INTEGRATION_URL,
        route,
        payload,
        rid,
    )

    return {
        "success": True,
        "request_id": rid,
        "action": request.action,
        "result": result,
        "timestamp": utc_now(),
    }


@app.post("/client/doctor")
async def client_doctor(
    request: ClientRequest,
):

    return await doctor(
        "/arya/doctor",
        request,
    )


@app.post("/client/analyze")
async def client_analyze(
    request: ClientRequest,
):

    return await doctor(
        "/arya/analyze",
        request,
    )


@app.post("/client/diagnose")
async def client_diagnose(
    request: ClientRequest,
):

    return await doctor(
        "/arya/diagnose",
        request,
    )


@app.post("/client/recommend")
async def client_recommend(
    request: ClientRequest,
):

    return await doctor(
        "/arya/recommend",
        request,
    )


@app.post("/client/vision")
async def client_vision(
    request: ClientRequest,
):

    return await doctor(
        "/arya/vision",
        request,
    )


# ============================================================
# Weather / Location
# ============================================================

@app.post("/client/weather")
async def client_weather(
    request: ClientRequest,
):

    return await doctor(
        "/arya/weather",
        request,
    )


@app.post("/client/geocode")
async def client_geocode(
    request: ClientRequest,
):

    return await doctor(
        "/arya/geocode",
        request,
    )


# ============================================================
# Payment
# ============================================================

@app.post("/client/payment")
async def client_payment(
    request: ClientRequest,
):

    return await doctor(
        "/arya/payment",
        request,
    )


# ============================================================
# Data Updates
# ============================================================

@app.post("/client/updates")
async def client_updates(
    request: ClientRequest,
):

    return await doctor(
        "/arya/updates",
        request,
    )


@app.post("/client/updates/run")
async def client_updates_run(
    request: ClientRequest,
):

    return await doctor(
        "/arya/updates/run",
        request,
    )


# ============================================================
# Runtime Configuration
# ============================================================

@app.get("/client/config")
async def client_config():

    return await get_service(
        FINAL_INTEGRATION_URL,
        "/config",
    )


@app.get("/client/features")
async def client_features():

    return await get_service(
        FINAL_INTEGRATION_URL,
        "/features",
    )


@app.get("/client/providers")
async def client_providers():

    return await get_service(
        FINAL_INTEGRATION_URL,
        "/providers",
    )


@app.get("/client/runtime/services")
async def client_runtime_services():

    return await get_service(
        FINAL_INTEGRATION_URL,
        "/runtime/services",
    )


# ============================================================
# Runtime Service Control
# ============================================================

@app.post(
    "/client/runtime/services/{service_id}/start"
)
async def client_start_service(
    service_id: str,
):

    return await post_service(
        FINAL_INTEGRATION_URL,
        f"/runtime/services/{service_id}/start",
    )


@app.post(
    "/client/runtime/services/{service_id}/stop"
)
async def client_stop_service(
    service_id: str,
):

    return await post_service(
        FINAL_INTEGRATION_URL,
        f"/runtime/services/{service_id}/stop",
    )


@app.post(
    "/client/runtime/services/{service_id}/restart"
)
async def client_restart_service(
    service_id: str,
):

    return await post_service(
        FINAL_INTEGRATION_URL,
        f"/runtime/services/{service_id}/restart",
    )


# ============================================================
# Full Runtime Control
# ============================================================

@app.post("/client/runtime/start-all")
async def client_start_all():

    return await post_service(
        FINAL_INTEGRATION_URL,
        "/runtime/start-all",
    )


@app.post("/client/runtime/stop-all")
async def client_stop_all():

    return await post_service(
        FINAL_INTEGRATION_URL,
        "/runtime/stop-all",
    )


@app.post("/client/runtime/restart-all")
async def client_restart_all():

    return await post_service(
        FINAL_INTEGRATION_URL,
        "/runtime/restart-all",
    )


# ============================================================
# Main API Compatibility
# ============================================================

@app.get("/client/main/health")
async def client_main_health():

    return await get_service(
        FINAL_INTEGRATION_URL,
        "/main/health",
    )


@app.post("/client/main/request")
async def client_main_request(
    request: ClientRequest,
):

    rid = request_id(
        request.request_id
    )

    payload = {
        "action": request.action,
        "payload": request.payload,
        "request_id": rid,
    }

    return await post_service(
        FINAL_INTEGRATION_URL,
        "/main/request",
        payload,
        rid,
    )


# ============================================================
# Runtime Gateway
# ============================================================

@app.post("/client/runtime-gateway")
async def client_runtime_gateway(
    request: RuntimeRequest,
):

    rid = request_id(
        request.request_id
    )

    payload = {
        "action": request.action,
        "payload": request.payload,
        "request_id": rid,
    }

    result = await post_service(
        RUNTIME_GATEWAY_URL,
        "/runtime/call",
        payload,
        rid,
    )

    return {
        "success": True,
        "request_id": rid,
        "result": result,
        "timestamp": utc_now(),
    }


# ============================================================
# Unified API
# ============================================================

@app.post("/client/unified")
async def client_unified(
    request: ClientRequest,
):

    rid = request_id(
        request.request_id
    )

    payload = {
        "action": request.action,
        "payload": request.payload,
        "request_id": rid,
        "device_id": request.device_id,
        "client_id": request.client_id,
    }

    result = await post_service(
        FINAL_INTEGRATION_URL,
        "/api/unified",
        payload,
        rid,
    )

    return {
        "success": True,
        "request_id": rid,
        "result": result,
        "timestamp": utc_now(),
    }


# ============================================================
# Client System Map
# ============================================================

@app.get("/client/system-map")
async def client_system_map():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": utc_now(),

        "client_flow": [
            "ANDROID",
            "WINDOWS",
            "CLIENT_API_GATEWAY",
            "CLIENT_RUNTIME_BRIDGE",
            "FINAL_INTEGRATION",
            "UNIFIED_API",
            "RUNTIME_CONFIG",
            "SERVICE_RUNTIME",
            "RUNTIME_GATEWAY",
            "ARYA_SERVICES",
            "MAIN_API",
        ],

        "services": {
            "client_api_gateway": CLIENT_API_GATEWAY_URL,
            "client_runtime_bridge": (
                f"http://{HOST}:{PORT}"
            ),
            "final_integration": FINAL_INTEGRATION_URL,
            "unified_api": UNIFIED_API_URL,
            "runtime_gateway": RUNTIME_GATEWAY_URL,
        },
    }


# ============================================================
# Statistics
# ============================================================

@app.get("/stats")
async def stats():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "requests": _request_count,
        "errors": _error_count,
        "uptime_seconds": round(
            time.time() - _started_at,
            2,
        ),
        "timestamp": utc_now(),
    }


# ============================================================
# API Contract
# ============================================================

@app.get("/contract")
async def contract():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,

        "purpose": (
            "Bridge Android/Windows client traffic "
            "to ARYA runtime and integration services."
        ),

        "routes": {
            "health": "/health",
            "client_status": "/client/status",
            "integration_status": "/integration/status",
            "integration_system_map": (
                "/integration/system-map"
            ),
            "client_runtime": "/client/runtime",
            "doctor": "/client/doctor",
            "analyze": "/client/analyze",
            "diagnose": "/client/diagnose",
            "recommend": "/client/recommend",
            "vision": "/client/vision",
            "weather": "/client/weather",
            "geocode": "/client/geocode",
            "payment": "/client/payment",
            "updates": "/client/updates",
            "updates_run": "/client/updates/run",
            "config": "/client/config",
            "features": "/client/features",
            "providers": "/client/providers",
            "runtime_services": (
                "/client/runtime/services"
            ),
            "runtime_gateway": (
                "/client/runtime-gateway"
            ),
            "unified": "/client/unified",
            "system_map": "/client/system-map",
            "stats": "/stats",
        },

        "security": {
            "internal_hmac": bool(
                INTERNAL_SECRET
            ),
            "arbitrary_url_proxy": False,
            "redirects": False,
            "request_limit_bytes": (
                MAX_REQUEST_BYTES
            ),
            "response_limit_bytes": (
                MAX_RESPONSE_BYTES
            ),
        },
    }


# ============================================================
# Error Handler
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    global _error_count

    _error_count += 1

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "service": APP_NAME,
            "error": str(exc),
            "request_id": request.headers.get(
                "X-ARYA-Request-ID"
            ),
            "timestamp": utc_now(),
        },
    )


# ============================================================
# Startup / Shutdown
# ============================================================

@app.on_event("startup")
async def startup_event():

    app.state.started_at = utc_now()


@app.on_event("shutdown")
async def shutdown_event():

    pass


# ============================================================
# Local Execution
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "arya_client_runtime_bridge:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
