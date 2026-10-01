"""
ARYA AgriDoctor
Final Integration Layer
Version: 1.1.0

Purpose:
    Final integration/orchestration layer for the ARYA backend.

Architecture:

    CLIENT
       ↓
    CLIENT API GATEWAY
       ↓
    ARYA FINAL INTEGRATION
       ↓
    ARYA UNIFIED API
       ↓
    RUNTIME CONFIG BRIDGE
       ↓
    SERVICE RUNTIME / RUNTIME GATEWAY
       ↓
    ARYA SERVICES
       ↓
    MAIN API BRIDGE
       ↓
    backend/main.py

Important:
    - backend/main.py is NOT modified.
    - Existing modules are NOT modified.
    - This module is independent.
    - Internal URLs are configuration driven.
    - No arbitrary user supplied URLs are proxied.
    - Request/response limits are enforced.
    - Internal HMAC signing is supported.
"""

from __future__ import annotations

import asyncio
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

APP_NAME = "ARYA Final Integration"
APP_VERSION = "1.1.0"

HOST = os.getenv(
    "ARYA_FINAL_INTEGRATION_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_PORT",
        "8027",
    )
)


# ------------------------------------------------------------
# Core services
# ------------------------------------------------------------

UNIFIED_API_URL = os.getenv(
    "ARYA_UNIFIED_API_URL",
    "http://127.0.0.1:8023",
).rstrip("/")

SERVICE_RUNTIME_URL = os.getenv(
    "ARYA_SERVICE_RUNTIME_URL",
    "http://127.0.0.1:8024",
).rstrip("/")

CENTRAL_CONFIG_URL = os.getenv(
    "ARYA_CENTRAL_CONFIG_URL",
    "http://127.0.0.1:8025",
).rstrip("/")

RUNTIME_CONFIG_BRIDGE_URL = os.getenv(
    "ARYA_RUNTIME_CONFIG_BRIDGE_URL",
    "http://127.0.0.1:8026",
).rstrip("/")

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).rstrip("/")

CLIENT_API_GATEWAY_URL = os.getenv(
    "ARYA_CLIENT_API_GATEWAY_URL",
    "http://127.0.0.1:8021",
).rstrip("/")

MAIN_API_BRIDGE_URL = os.getenv(
    "ARYA_MAIN_API_BRIDGE_URL",
    "http://127.0.0.1:8022",
).rstrip("/")


# ------------------------------------------------------------
# Security
# ------------------------------------------------------------

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

REQUIRE_INTERNAL_SIGNATURE = (
    os.getenv(
        "ARYA_FINAL_REQUIRE_INTERNAL_SIGNATURE",
        "false",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)


# ------------------------------------------------------------
# Limits
# ------------------------------------------------------------

REQUEST_TIMEOUT = float(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_TIMEOUT",
        "30",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_MAX_RESPONSE_BYTES",
        str(10 * 1024 * 1024),
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_MAX_REQUEST_BYTES",
        str(10 * 1024 * 1024),
    )
)

HEALTH_CACHE_SECONDS = int(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_HEALTH_CACHE_SECONDS",
        "10",
    )
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Final integration layer connecting ARYA client, "
        "unified API, runtime, configuration and main API layers."
    ),
)


# ============================================================
# Runtime State
# ============================================================

_started_at = time.time()

_health_cache: Dict[str, Dict[str, Any]] = {}

_state_lock = asyncio.Lock()


# ============================================================
# Models
# ============================================================

class IntegrationRequest(BaseModel):
    action: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = None


class ServiceActionRequest(BaseModel):
    service_id: str = Field(
        ...,
        min_length=1,
        max_length=150,
    )


class BroadcastRequest(BaseModel):
    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = None


# ============================================================
# Utility
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_request_id() -> str:
    return str(uuid.uuid4())


def safe_json(value: Any) -> Any:
    try:
        json.dumps(
            value,
            ensure_ascii=False,
        )
        return value

    except Exception:
        return str(value)


def normalize_request_id(
    request_id: Optional[str],
) -> str:

    if request_id:
        request_id = str(request_id).strip()

        if request_id:
            return request_id[:200]

    return new_request_id()


# ============================================================
# Internal Security
# ============================================================

def sign_body(body: bytes) -> str:

    if not INTERNAL_SECRET:
        return ""

    return hmac.new(
        INTERNAL_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()


def internal_headers(
    body: bytes = b"",
    request_id: Optional[str] = None,
) -> Dict[str, str]:

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-ARYA-Internal": "1",
        "X-ARYA-Request-ID": (
            request_id or new_request_id()
        ),
    }

    signature = sign_body(body)

    if signature:
        headers["X-ARYA-Signature"] = signature

    return headers


def verify_internal_signature(
    body: bytes,
    signature: Optional[str],
) -> bool:

    if not INTERNAL_SECRET:
        return not REQUIRE_INTERNAL_SIGNATURE

    if not signature:
        return False

    expected = sign_body(body)

    return hmac.compare_digest(
        expected,
        signature.strip(),
    )


# ============================================================
# Approved Internal Services
# ============================================================

def approved_services() -> Dict[str, str]:

    return {
        "unified_api": UNIFIED_API_URL,
        "service_runtime": SERVICE_RUNTIME_URL,
        "central_config": CENTRAL_CONFIG_URL,
        "runtime_config_bridge": RUNTIME_CONFIG_BRIDGE_URL,
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "client_api_gateway": CLIENT_API_GATEWAY_URL,
        "main_api_bridge": MAIN_API_BRIDGE_URL,
    }


def validate_internal_url(
    url: str,
) -> bool:

    normalized = url.rstrip("/")

    return normalized in {
        value.rstrip("/")
        for value in approved_services().values()
    }


# ============================================================
# HTTP Client
# ============================================================

async def http_request(
    method: str,
    url: str,
    *,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: Optional[float] = None,
    request_id: Optional[str] = None,
) -> Any:

    if not validate_internal_url(url):

        raise HTTPException(
            status_code=500,
            detail=(
                "Target URL is not an approved "
                "ARYA internal service."
            ),
        )

    body = b""

    if json_body is not None:

        try:
            body = json.dumps(
                json_body,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")

        except Exception:

            raise HTTPException(
                status_code=400,
                detail="Request payload is not JSON serializable.",
            )

        if len(body) > MAX_REQUEST_BYTES:

            raise HTTPException(
                status_code=413,
                detail="Request body is too large.",
            )

    headers = internal_headers(
        body,
        request_id=request_id,
    )

    try:

        async with httpx.AsyncClient(
            timeout=timeout or REQUEST_TIMEOUT,
            follow_redirects=False,
        ) as client:

            response = await client.request(
                method.upper(),
                url,
                content=(
                    body
                    if json_body is not None
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
                "ARYA internal service connection failed: "
                f"{str(exc)}"
            ),
        )

    if len(response.content) > MAX_RESPONSE_BYTES:

        raise HTTPException(
            status_code=502,
            detail=(
                "Internal service response is too large."
            ),
        )

    content_type = response.headers.get(
        "content-type",
        "",
    ).lower()

    if "application/json" in content_type:

        try:
            data = response.json()

        except Exception:

            data = {
                "raw": response.text,
            }

    else:

        data = {
            "raw": response.text,
        }

    if response.status_code >= 400:

        raise HTTPException(
            status_code=response.status_code,
            detail=safe_json(data),
        )

    return data


async def service_get(
    base_url: str,
    path: str = "",
    *,
    request_id: Optional[str] = None,
) -> Any:

    return await http_request(
        "GET",
        f"{base_url}{path}",
        request_id=request_id,
    )


async def service_post(
    base_url: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    *,
    request_id: Optional[str] = None,
) -> Any:

    return await http_request(
        "POST",
        f"{base_url}{path}",
        json_body=payload or {},
        request_id=request_id,
    )


# ============================================================
# Incoming Internal Signature
# ============================================================

async def verify_incoming_request(
    request: Request,
) -> Optional[str]:

    if not REQUIRE_INTERNAL_SIGNATURE:

        return None

    body = await request.body()

    signature = request.headers.get(
        "X-ARYA-Signature",
    )

    if not verify_internal_signature(
        body,
        signature,
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid ARYA internal signature.",
        )

    return request.headers.get(
        "X-ARYA-Request-ID",
    )


# ============================================================
# Health
# ============================================================

async def check_service(
    name: str,
    base_url: str,
) -> Dict[str, Any]:

    now = time.time()

    cached = _health_cache.get(name)

    if cached:

        if (
            now - cached["timestamp"]
            <= HEALTH_CACHE_SECONDS
        ):

            return cached["result"]

    started = time.perf_counter()

    try:

        result = await service_get(
            base_url,
            "/health",
        )

        elapsed = round(
            (
                time.perf_counter()
                - started
            ) * 1000,
            2,
        )

        health = {
            "service": name,
            "url": base_url,
            "status": "online",
            "latency_ms": elapsed,
            "response": result,
            "checked_at": utc_now(),
        }

    except Exception as exc:

        health = {
            "service": name,
            "url": base_url,
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

    _health_cache[name] = {
        "timestamp": now,
        "result": health,
    }

    return health


async def all_health() -> Dict[str, Any]:

    services = approved_services()

    results = await asyncio.gather(
        *[
            check_service(
                name,
                url,
            )
            for name, url in services.items()
        ],
        return_exceptions=False,
    )

    online = sum(
        1
        for item in results
        if item.get("status") == "online"
    )

    total = len(results)

    if online == total:

        status = "healthy"

    elif online > 0:

        status = "degraded"

    else:

        status = "offline"

    return {
        "status": status,
        "total_services": total,
        "online_services": online,
        "offline_services": total - online,
        "services": results,
        "checked_at": utc_now(),
    }


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
        "started_at": datetime.fromtimestamp(
            _started_at,
            timezone.utc,
        ).isoformat(),
        "architecture": approved_services(),
        "security": {
            "internal_secret_configured": bool(
                INTERNAL_SECRET
            ),
            "signature_required": (
                REQUIRE_INTERNAL_SIGNATURE
            ),
        },
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health():

    result = await all_health()

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        **result,
    }


# ============================================================
# System Map
# ============================================================

@app.get("/system-map")
async def system_map():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": utc_now(),

        "layers": {

            "client": {
                "client_api_gateway":
                    CLIENT_API_GATEWAY_URL,
            },

            "integration": {
                "final_integration":
                    f"http://{HOST}:{PORT}",
            },

            "api": {
                "unified_api":
                    UNIFIED_API_URL,

                "main_api_bridge":
                    MAIN_API_BRIDGE_URL,
            },

            "configuration": {
                "central_config":
                    CENTRAL_CONFIG_URL,

                "runtime_config_bridge":
                    RUNTIME_CONFIG_BRIDGE_URL,
            },

            "runtime": {
                "service_runtime":
                    SERVICE_RUNTIME_URL,

                "runtime_gateway":
                    RUNTIME_GATEWAY_URL,
            },
        },

        "flow": [
            "CLIENT",
            "CLIENT_API_GATEWAY",
            "ARYA_FINAL_INTEGRATION",
            "ARYA_UNIFIED_API",
            "ARYA_RUNTIME_CONFIG_BRIDGE",
            "ARYA_SERVICE_RUNTIME",
            "ARYA_RUNTIME_GATEWAY",
            "ARYA_SERVICES",
            "ARYA_MAIN_API_BRIDGE",
            "ARYA_MAIN_API",
        ],
    }


# ============================================================
# Configuration
# ============================================================

@app.get("/config")
async def get_config():

    return {
        "service": APP_NAME,
        "timestamp": utc_now(),
        "config": await service_get(
            RUNTIME_CONFIG_BRIDGE_URL,
            "/config",
        ),
    }


@app.get("/runtime/config")
async def runtime_config():

    return await service_get(
        RUNTIME_CONFIG_BRIDGE_URL,
        "/runtime/config",
    )


@app.get("/providers")
async def providers():

    return await service_get(
        RUNTIME_CONFIG_BRIDGE_URL,
        "/providers",
    )


@app.get("/features")
async def features():

    return await service_get(
        RUNTIME_CONFIG_BRIDGE_URL,
        "/features",
    )


# ============================================================
# Runtime Services
# ============================================================

@app.get("/runtime/services")
async def runtime_services():

    return await service_get(
        RUNTIME_CONFIG_BRIDGE_URL,
        "/runtime/services",
    )


@app.post(
    "/runtime/services/{service_id}/start"
)
async def start_service(
    service_id: str,
):

    return await service_post(
        RUNTIME_CONFIG_BRIDGE_URL,
        f"/runtime/services/{service_id}/start",
    )


@app.post(
    "/runtime/services/{service_id}/stop"
)
async def stop_service(
    service_id: str,
):

    return await service_post(
        RUNTIME_CONFIG_BRIDGE_URL,
        f"/runtime/services/{service_id}/stop",
    )


@app.post(
    "/runtime/services/{service_id}/restart"
)
async def restart_service(
    service_id: str,
):

    return await service_post(
        RUNTIME_CONFIG_BRIDGE_URL,
        f"/runtime/services/{service_id}/restart",
    )


@app.post("/runtime/start-all")
async def start_all():

    return await service_post(
        RUNTIME_CONFIG_BRIDGE_URL,
        "/runtime/start-all",
    )


@app.post("/runtime/stop-all")
async def stop_all():

    return await service_post(
        RUNTIME_CONFIG_BRIDGE_URL,
        "/runtime/stop-all",
    )


@app.post("/runtime/restart-all")
async def restart_all():

    return await service_post(
        RUNTIME_CONFIG_BRIDGE_URL,
        "/runtime/restart-all",
    )


@app.get("/runtime/system-map")
async def runtime_system_map():

    return await service_get(
        RUNTIME_CONFIG_BRIDGE_URL,
        "/runtime/system-map",
    )


# ============================================================
# Unified API Proxy
# ============================================================

@app.post("/api/unified")
async def unified_api_proxy(
    request: Request,
):

    request_id = (
        request.headers.get(
            "X-ARYA-Request-ID"
        )
        or new_request_id()
    )

    raw = await request.body()

    if len(raw) > MAX_REQUEST_BYTES:

        raise HTTPException(
            status_code=413,
            detail="Request body is too large.",
        )

    try:

        payload = json.loads(
            raw.decode("utf-8")
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid JSON body.",
        )

    return await service_post(
        UNIFIED_API_URL,
        "/api",
        payload,
        request_id=request_id,
    )


# ============================================================
# Runtime Gateway Proxy
# ============================================================

@app.post("/runtime/call")
async def runtime_call(
    request: Request,
):

    request_id = (
        request.headers.get(
            "X-ARYA-Request-ID"
        )
        or new_request_id()
    )

    raw = await request.body()

    if len(raw) > MAX_REQUEST_BYTES:

        raise HTTPException(
            status_code=413,
            detail="Request body is too large.",
        )

    try:

        payload = json.loads(
            raw.decode("utf-8")
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid JSON body.",
        )

    return await service_post(
        RUNTIME_GATEWAY_URL,
        "/runtime/call",
        payload,
        request_id=request_id,
    )


# ============================================================
# Main API Bridge
# ============================================================

@app.get("/main/health")
async def main_health():

    return await service_get(
        MAIN_API_BRIDGE_URL,
        "/internal/main-api/health",
    )


@app.post("/main/request")
async def main_request(
    request: Request,
):

    request_id = (
        request.headers.get(
            "X-ARYA-Request-ID"
        )
        or new_request_id()
    )

    raw = await request.body()

    if len(raw) > MAX_REQUEST_BYTES:

        raise HTTPException(
            status_code=413,
            detail="Request body is too large.",
        )

    try:

        payload = json.loads(
            raw.decode("utf-8")
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid JSON body.",
        )

    return await service_post(
        MAIN_API_BRIDGE_URL,
        "/internal/main-api/request",
        payload,
        request_id=request_id,
    )


# ============================================================
# Agricultural Doctor
# ============================================================

async def doctor_action(
    action: str,
    payload: Dict[str, Any],
    request_id: Optional[str] = None,
):

    rid = normalize_request_id(
        request_id
    )

    body = {
        "action": action,
        "payload": payload,
        "request_id": rid,
    }

    try:

        result = await service_post(
            UNIFIED_API_URL,
            "/arya/doctor",
            body,
            request_id=rid,
        )

        return {
            "success": True,
            "request_id": rid,
            "action": action,
            "result": result,
            "timestamp": utc_now(),
        }

    except HTTPException:

        raise

    except Exception as exc:

        return JSONResponse(
            status_code=502,
            content={
                "success": False,
                "request_id": rid,
                "action": action,
                "error": str(exc),
                "timestamp": utc_now(),
            },
        )


@app.post("/arya/doctor")
async def arya_doctor(
    request: IntegrationRequest,
):

    return await doctor_action(
        "doctor",
        request.payload,
        request.request_id,
    )


@app.post("/arya/analyze")
async def arya_analyze(
    request: IntegrationRequest,
):

    return await doctor_action(
        "analyze",
        request.payload,
        request.request_id,
    )


@app.post("/arya/diagnose")
async def arya_diagnose(
    request: IntegrationRequest,
):

    return await doctor_action(
        "diagnose",
        request.payload,
        request.request_id,
    )


@app.post("/arya/recommend")
async def arya_recommend(
    request: IntegrationRequest,
):

    return await doctor_action(
        "recommend",
        request.payload,
        request.request_id,
    )


@app.post("/arya/vision")
async def arya_vision(
    request: IntegrationRequest,
):

    return await doctor_action(
        "vision",
        request.payload,
        request.request_id,
    )


@app.post("/arya/weather")
async def arya_weather(
    request: IntegrationRequest,
):

    return await doctor_action(
        "weather",
        request.payload,
        request.request_id,
    )


@app.post("/arya/geocode")
async def arya_geocode(
    request: IntegrationRequest,
):

    return await doctor_action(
        "geocode",
        request.payload,
        request.request_id,
    )


@app.post("/arya/payment")
async def arya_payment(
    request: IntegrationRequest,
):

    return await doctor_action(
        "payment",
        request.payload,
        request.request_id,
    )


@app.post("/arya/updates")
async def arya_updates(
    request: IntegrationRequest,
):

    return await doctor_action(
        "updates",
        request.payload,
        request.request_id,
    )


@app.post("/arya/updates/run")
async def arya_updates_run(
    request: IntegrationRequest,
):

    return await doctor_action(
        "updates_run",
        request.payload,
        request.request_id,
    )


# ============================================================
# Full System Status
# ============================================================

@app.get("/status")
async def status():

    async def get_runtime():

        try:

            return await service_get(
                SERVICE_RUNTIME_URL,
                "/services",
            )

        except Exception as exc:

            return {
                "status": "unavailable",
                "error": str(exc),
            }

    async def get_config_status():

        try:

            return await service_get(
                RUNTIME_CONFIG_BRIDGE_URL,
                "/status",
            )

        except Exception as exc:

            return {
                "status": "unavailable",
                "error": str(exc),
            }

    health_result, runtime_result, config_result = (
        await asyncio.gather(
            all_health(),
            get_runtime(),
            get_config_status(),
        )
    )

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": utc_now(),

        "health": health_result,

        "runtime": runtime_result,

        "configuration": config_result,

        "uptime_seconds": round(
            time.time() - _started_at,
            2,
        ),

        "architecture": approved_services(),
    }


# ============================================================
# Integration Contract
# ============================================================

@app.get("/contract")
async def contract():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,

        "purpose": (
            "Final integration layer connecting "
            "ARYA client, API, configuration, "
            "runtime and agricultural services."
        ),

        "routes": {

            "health": "/health",

            "system_map":
                "/system-map",

            "status":
                "/status",

            "config":
                "/config",

            "runtime_config":
                "/runtime/config",

            "providers":
                "/providers",

            "features":
                "/features",

            "runtime_services":
                "/runtime/services",

            "runtime_start_all":
                "/runtime/start-all",

            "runtime_stop_all":
                "/runtime/stop-all",

            "runtime_restart_all":
                "/runtime/restart-all",

            "runtime_system_map":
                "/runtime/system-map",

            "unified_api":
                "/api/unified",

            "runtime_call":
                "/runtime/call",

            "main_health":
                "/main/health",

            "main_request":
                "/main/request",

            "doctor":
                "/arya/doctor",

            "analyze":
                "/arya/analyze",

            "diagnose":
                "/arya/diagnose",

            "recommend":
                "/arya/recommend",

            "vision":
                "/arya/vision",

            "weather":
                "/arya/weather",

            "geocode":
                "/arya/geocode",

            "payment":
                "/arya/payment",

            "updates":
                "/arya/updates",

            "updates_run":
                "/arya/updates/run",
        },

        "principles": [

            "No modification of backend/main.py",

            "No deletion of existing services",

            "Internal service URLs are configuration driven",

            "Internal requests support HMAC authentication",

            "No arbitrary user supplied URLs are proxied",

            "Request size is limited",

            "Response size is limited",

            "Health results are cached",

            "Request IDs are propagated",

            "Existing modules remain independent",

            "Future providers can be added without "
            "changing backend/main.py",
        ],
    }


# ============================================================
# Security Information
# ============================================================

@app.get("/security")
async def security_status():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": utc_now(),

        "internal_secret_configured": bool(
            INTERNAL_SECRET
        ),

        "signature_required": (
            REQUIRE_INTERNAL_SIGNATURE
        ),

        "request_limit_bytes":
            MAX_REQUEST_BYTES,

        "response_limit_bytes":
            MAX_RESPONSE_BYTES,

        "redirects_allowed": False,

        "arbitrary_proxy_urls": False,
    }


# ============================================================
# Error Handling
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

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
# Startup
# ============================================================

@app.on_event("startup")
async def startup_event():

    app.state.started_at = utc_now()

    async with _state_lock:

        _health_cache.clear()


# ============================================================
# Shutdown
# ============================================================

@app.on_event("shutdown")
async def shutdown_event():

    async with _state_lock:

        _health_cache.clear()


# ============================================================
# Local Execution
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "arya_final_integration:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
