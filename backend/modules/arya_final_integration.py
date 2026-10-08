"""
ARYA AgriDoctor
Final Integration Layer
Version: 2.0.0

Purpose:
    Stable final integration/orchestration layer for ARYA.

Important:
    - backend/main.py is NOT modified.
    - Existing services are NOT deleted.
    - Internal URLs are configuration driven.
    - No arbitrary user supplied URLs are proxied.
    - Request/response limits are enforced.
    - Canonical internal authentication is supported.
    - Legacy X-ARYA-Internal-Secret authentication is preserved.
    - HMAC authentication is fail-closed when explicitly required.
    - Request IDs are propagated.
    - Unified API route compatibility is preserved.
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
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Final Integration"
APP_VERSION = "2.0.0"

HOST = os.getenv(
    "ARYA_FINAL_INTEGRATION_HOST",
    "0.0.0.0",
)

PORT = int(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_PORT",
        "8027",
    )
)

# ------------------------------------------------------------
# Internal services
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


# ============================================================
# Security
# ============================================================

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
).strip()

REQUIRE_INTERNAL_SIGNATURE = (
    os.getenv(
        "ARYA_FINAL_REQUIRE_INTERNAL_SIGNATURE",
        "false",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)

REQUIRE_INTERNAL_HEADER = (
    os.getenv(
        "ARYA_FINAL_REQUIRE_INTERNAL_HEADER",
        "false",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)

SEND_LEGACY_INTERNAL_SECRET = (
    os.getenv(
        "ARYA_FINAL_SEND_LEGACY_INTERNAL_SECRET",
        "true",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)


# ============================================================
# Limits / resilience
# ============================================================

REQUEST_TIMEOUT = float(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_TIMEOUT",
        "30",
    )
)

CONNECT_TIMEOUT = float(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_CONNECT_TIMEOUT",
        "10",
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_MAX_REQUEST_BYTES",
        str(10 * 1024 * 1024),
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_MAX_RESPONSE_BYTES",
        str(16 * 1024 * 1024),
    )
)

HEALTH_CACHE_SECONDS = float(
    os.getenv(
        "ARYA_FINAL_INTEGRATION_HEALTH_CACHE_SECONDS",
        "10",
    )
)

MAX_RETRIES = max(
    0,
    int(
        os.getenv(
            "ARYA_FINAL_INTEGRATION_MAX_RETRIES",
            "1",
        )
    ),
)

CIRCUIT_FAILURE_THRESHOLD = max(
    1,
    int(
        os.getenv(
            "ARYA_FINAL_INTEGRATION_CIRCUIT_THRESHOLD",
            "3",
        )
    ),
)

CIRCUIT_COOLDOWN_SECONDS = max(
    1.0,
    float(
        os.getenv(
            "ARYA_FINAL_INTEGRATION_CIRCUIT_COOLDOWN",
            "30",
        )
    ),
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Final integration layer connecting ARYA client, "
        "unified API, runtime, configuration and main API."
    ),
)


# ============================================================
# Runtime state
# ============================================================

_started_at = time.time()

_health_cache: Dict[str, Dict[str, Any]] = {}

_failure_state: Dict[str, Dict[str, Any]] = {}

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


def normalize_request_id(
    request_id: Optional[str],
) -> str:

    if request_id:
        value = str(request_id).strip()

        if value:
            return value[:200]

    return new_request_id()


def safe_json(value: Any) -> Any:

    try:
        json.dumps(
            value,
            ensure_ascii=False,
        )
        return value

    except Exception:
        return str(value)


def serialize_payload(
    payload: Any,
) -> bytes:

    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=(
                "Request payload is not JSON serializable: "
                f"{exc}"
            ),
        )


def validate_payload_size(
    body: bytes,
) -> None:

    if len(body) > MAX_REQUEST_BYTES:

        raise HTTPException(
            status_code=413,
            detail="Request body is too large.",
        )


# ============================================================
# Approved internal services
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


def validate_internal_target(
    url: str,
) -> None:

    if not validate_internal_url(url):

        raise HTTPException(
            status_code=500,
            detail=(
                "Target URL is not an approved "
                "ARYA internal service."
            ),
        )


# ============================================================
# HMAC security
# ============================================================

def sign_body(
    body: bytes,
) -> str:

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

    rid = normalize_request_id(
        request_id
    )

    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-ARYA-Internal": "1",
        "X-ARYA-Request-ID": rid,
    }

    if INTERNAL_SECRET:

        signature = sign_body(body)

        headers["X-ARYA-Signature"] = signature

        if SEND_LEGACY_INTERNAL_SECRET:

            headers[
                "X-ARYA-Internal-Secret"
            ] = INTERNAL_SECRET

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
# Incoming request security
# ============================================================

async def verify_incoming_request(
    request: Request,
) -> str:

    request_id = normalize_request_id(
        request.headers.get(
            "X-ARYA-Request-ID"
        )
    )

    body = await request.body()

    validate_payload_size(body)

    internal_header = (
        request.headers.get(
            "X-ARYA-Internal",
            "",
        ).strip().lower()
    )

    if REQUIRE_INTERNAL_HEADER:

        if internal_header not in {
            "1",
            "true",
            "yes",
            "on",
        }:

            raise HTTPException(
                status_code=401,
                detail="ARYA internal header is required.",
            )

    if REQUIRE_INTERNAL_SIGNATURE:

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

    return request_id


# ============================================================
# Circuit breaker
# ============================================================

def circuit_is_open(
    service_name: str,
) -> bool:

    state = _failure_state.get(
        service_name
    )

    if not state:
        return False

    opened_at = state.get(
        "opened_at"
    )

    if not opened_at:
        return False

    if (
        time.time() - opened_at
        >= CIRCUIT_COOLDOWN_SECONDS
    ):

        state["opened_at"] = None
        state["failures"] = 0

        return False

    return True


def record_success(
    service_name: str,
) -> None:

    state = _failure_state.setdefault(
        service_name,
        {
            "failures": 0,
            "opened_at": None,
        },
    )

    state["failures"] = 0
    state["opened_at"] = None


def record_failure(
    service_name: str,
) -> None:

    state = _failure_state.setdefault(
        service_name,
        {
            "failures": 0,
            "opened_at": None,
        },
    )

    state["failures"] = int(
        state.get("failures", 0)
    ) + 1

    if (
        state["failures"]
        >= CIRCUIT_FAILURE_THRESHOLD
    ):

        state["opened_at"] = time.time()


def service_name_from_url(
    url: str,
) -> str:

    for name, value in approved_services().items():

        if url.rstrip("/") == value.rstrip("/"):
            return name

    return url


# ============================================================
# HTTP client
# ============================================================

async def http_request(
    method: str,
    url: str,
    *,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: Optional[float] = None,
    request_id: Optional[str] = None,
) -> Any:

    validate_internal_target(url)

    method_upper = method.upper()

    service_name = service_name_from_url(
        url
    )

    if circuit_is_open(service_name):

        raise HTTPException(
            status_code=503,
            detail=(
                f"ARYA internal service circuit is open: "
                f"{service_name}"
            ),
        )

    body = b""

    if json_body is not None:

        body = serialize_payload(
            json_body
        )

        validate_payload_size(body)

    headers = internal_headers(
        body,
        request_id=request_id,
    )

    request_timeout = httpx.Timeout(
        timeout or REQUEST_TIMEOUT,
        connect=CONNECT_TIMEOUT,
    )

    attempts = 1

    if method_upper in {
        "GET",
        "HEAD",
        "OPTIONS",
    }:

        attempts += MAX_RETRIES

    last_error: Optional[Exception] = None

    for attempt in range(attempts):

        try:

            async with httpx.AsyncClient(
                timeout=request_timeout,
                follow_redirects=False,
                max_redirects=0,
            ) as client:

                response = await client.request(
                    method_upper,
                    url,
                    content=(
                        body
                        if json_body is not None
                        else None
                    ),
                    headers=headers,
                )

            if len(response.content) > MAX_RESPONSE_BYTES:

                record_failure(service_name)

                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Internal service response "
                        "is too large."
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

            if response.status_code >= 500:

                record_failure(service_name)

                if attempt + 1 < attempts:

                    await asyncio.sleep(
                        0.25 * (attempt + 1)
                    )

                    continue

            elif response.status_code < 400:

                record_success(service_name)

            if response.status_code >= 400:

                raise HTTPException(
                    status_code=response.status_code,
                    detail=safe_json(data),
                )

            return data

        except HTTPException:
            raise

        except httpx.TimeoutException as exc:

            last_error = exc
            record_failure(service_name)

            if attempt + 1 < attempts:

                await asyncio.sleep(
                    0.25 * (attempt + 1)
                )

                continue

            raise HTTPException(
                status_code=504,
                detail=(
                    "ARYA internal service timeout."
                ),
            )

        except httpx.RequestError as exc:

            last_error = exc
            record_failure(service_name)

            if attempt + 1 < attempts:

                await asyncio.sleep(
                    0.25 * (attempt + 1)
                )

                continue

            raise HTTPException(
                status_code=502,
                detail=(
                    "ARYA internal service connection "
                    f"failed: {str(exc)}"
                ),
            )

    raise HTTPException(
        status_code=502,
        detail=(
            "ARYA internal request failed: "
            f"{last_error}"
        ),
    )


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

        health = {
            "service": name,
            "url": base_url,
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
        ]
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
            "signature_required":
                REQUIRE_INTERNAL_SIGNATURE,
            "internal_header_required":
                REQUIRE_INTERNAL_HEADER,
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
# Runtime services
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
# Unified API compatibility proxy
# ============================================================

async def unified_action(
    action: str,
    payload: Dict[str, Any],
    request_id: Optional[str] = None,
) -> Any:

    rid = normalize_request_id(
        request_id
    )

    # Canonical Unified API routes.
    routes = {
        "doctor":
            "/api/v1/doctor",

        "analyze":
            "/api/v1/doctor/analyze",

        "diagnose":
            "/api/v1/doctor/diagnose",

        "recommend":
            "/api/v1/doctor/recommend",

        "vision":
            "/api/v1/vision",

        "weather":
            "/api/v1/weather",

        "geocode":
            "/api/v1/geocode",

        "payment":
            "/api/v1/payment",

        "updates":
            "/api/v1/updates",

        "updates_run":
            "/api/v1/updates/run",

        "voice":
            "/api/v1/voice",
    }

    route = routes.get(action)

    if route is None:

        raise HTTPException(
            status_code=400,
            detail=f"Unsupported ARYA action: {action}",
        )

    envelope = {
        "action": action,
        "payload": payload,
        "request_id": rid,
    }

    try:

        return await service_post(
            UNIFIED_API_URL,
            route,
            envelope,
            request_id=rid,
        )

    except HTTPException as exc:

        # Compatibility fallback for older Unified API
        # deployments that still expose /api or /arya/doctor.
        if exc.status_code not in {
            404,
            405,
        }:

            raise

        legacy_routes = {
            "doctor": "/arya/doctor",
            "analyze": "/arya/analyze",
            "diagnose": "/arya/diagnose",
            "recommend": "/arya/recommend",
            "vision": "/arya/vision",
            "weather": "/arya/weather",
            "geocode": "/arya/geocode",
            "payment": "/arya/payment",
            "updates": "/arya/updates",
            "updates_run": "/arya/updates/run",
            "voice": "/arya/voice",
        }

        legacy_route = legacy_routes.get(
            action
        )

        if legacy_route:

            return await service_post(
                UNIFIED_API_URL,
                legacy_route,
                envelope,
                request_id=rid,
            )

        raise


@app.post("/api/unified")
async def unified_api_proxy(
    request: Request,
):

    request_id = await verify_incoming_request(
        request
    )

    raw = await request.body()

    if not raw:

        payload: Dict[str, Any] = {}

    else:

        try:

            payload = json.loads(
                raw.decode("utf-8")
            )

        except Exception:

            raise HTTPException(
                status_code=400,
                detail="Invalid JSON body.",
            )

    if not isinstance(payload, dict):

        raise HTTPException(
            status_code=400,
            detail="JSON body must be an object.",
        )

    action = str(
        payload.get(
            "action",
            "doctor",
        )
    )

    inner_payload = payload.get(
        "payload",
        payload,
    )

    if not isinstance(
        inner_payload,
        dict,
    ):

        inner_payload = {
            "value": inner_payload,
        }

    return await unified_action(
        action,
        inner_payload,
        payload.get(
            "request_id",
            request_id,
        ),
    )


# ============================================================
# Runtime Gateway proxy
# ============================================================

@app.post("/runtime/call")
async def runtime_call(
    request: Request,
):

    request_id = await verify_incoming_request(
        request
    )

    raw = await request.body()

    try:

        payload = json.loads(
            raw.decode("utf-8")
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid JSON body.",
        )

    if not isinstance(payload, dict):

        raise HTTPException(
            status_code=400,
            detail="JSON body must be an object.",
        )

    return await service_post(
        RUNTIME_GATEWAY_URL,
        "/runtime/call",
        payload,
        request_id=payload.get(
            "request_id",
            request_id,
        ),
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

    request_id = await verify_incoming_request(
        request
    )

    raw = await request.body()

    try:

        payload = json.loads(
            raw.decode("utf-8")
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid JSON body.",
        )

    if not isinstance(payload, dict):

        raise HTTPException(
            status_code=400,
            detail="JSON body must be an object.",
        )

    return await service_post(
        MAIN_API_BRIDGE_URL,
        "/internal/main-api/request",
        payload,
        request_id=payload.get(
            "request_id",
            request_id,
        ),
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

    result = await unified_action(
        action,
        payload,
        rid,
    )

    return {
        "success": True,
        "request_id": rid,
        "action": action,
        "result": result,
        "timestamp": utc_now(),
    }


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


@app.post("/arya/voice")
async def arya_voice(
    request: IntegrationRequest,
):

    return await doctor_action(
        "voice",
        request.payload,
        request.request_id,
    )


# ============================================================
# Full system status
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
        "security": {
            "internal_secret_configured":
                bool(INTERNAL_SECRET),
            "signature_required":
                REQUIRE_INTERNAL_SIGNATURE,
            "internal_header_required":
                REQUIRE_INTERNAL_HEADER,
        },
    }


# ============================================================
# Integration Contract
# ============================================================

@app.get("/contract")
async def contract():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,

        "routes": {
            "health": "/health",
            "system_map": "/system-map",
            "status": "/status",
            "config": "/config",
            "runtime_config": "/runtime/config",
            "providers": "/providers",
            "features": "/features",

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

            "voice":
                "/arya/voice",

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
            "backend/main.py remains unchanged",
            "Existing services remain available",
            "No arbitrary proxy URLs",
            "Internal URLs are configuration driven",
            "HMAC authentication is supported",
            "Legacy internal secret authentication is preserved",
            "Request IDs are propagated",
            "Request size is limited",
            "Response size is limited",
            "Safe retry is limited to idempotent requests",
            "Circuit breaker protects failing internal services",
            "Unified API route compatibility is preserved",
            "Voice compatibility route is available",
            "Android and Windows clients can use the same integration layer",
        ],
    }


# ============================================================
# Security information
# ============================================================

@app.get("/security")
async def security_status():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": utc_now(),

        "internal_secret_configured":
            bool(INTERNAL_SECRET),

        "signature_required":
            REQUIRE_INTERNAL_SIGNATURE,

        "internal_header_required":
            REQUIRE_INTERNAL_HEADER,

        "legacy_secret_forwarding":
            SEND_LEGACY_INTERNAL_SECRET,

        "request_limit_bytes":
            MAX_REQUEST_BYTES,

        "response_limit_bytes":
            MAX_RESPONSE_BYTES,

        "redirects_allowed":
            False,

        "arbitrary_proxy_urls":
            False,

        "max_retries":
            MAX_RETRIES,

        "circuit_failure_threshold":
            CIRCUIT_FAILURE_THRESHOLD,

        "circuit_cooldown_seconds":
            CIRCUIT_COOLDOWN_SECONDS,
    }


# ============================================================
# Circuit status
# ============================================================

@app.get("/security/circuits")
async def circuit_status():

    result: Dict[str, Any] = {}

    for name, state in _failure_state.items():

        result[name] = {
            "failures":
                state.get("failures", 0),

            "open":
                circuit_is_open(name),

            "opened_at":
                state.get("opened_at"),
        }

    return {
        "service": APP_NAME,
        "timestamp": utc_now(),
        "circuits": result,
    }


# ============================================================
# Error handling
# ============================================================

@app.exception_handler(
    HTTPException
)
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
):

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "service": APP_NAME,
            "error": safe_json(
                exc.detail
            ),
            "request_id":
                request.headers.get(
                    "X-ARYA-Request-ID"
                ),
            "timestamp": utc_now(),
        },
    )


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
            "request_id":
                request.headers.get(
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
        _failure_state.clear()


# ============================================================
# Shutdown
# ============================================================

@app.on_event("shutdown")
async def shutdown_event():

    async with _state_lock:

        _health_cache.clear()


# ============================================================
# Local execution
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "arya_final_integration:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
