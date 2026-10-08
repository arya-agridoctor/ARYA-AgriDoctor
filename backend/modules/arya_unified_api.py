"""
ARYA Unified API
================
Version: 2.0.0

Final API composition layer for ARYA AgriDoctor.

Purpose:
- Provide one unified backend entry point for Android and Windows clients.
- Connect Client API Gateway to the existing runtime/API layers.
- Keep main.py untouched.
- Preserve all existing /api/v1 routes.
- Preserve legacy compatibility routes.
- Support HMAC + legacy internal-secret authentication.
- Propagate request IDs.
- Normalize canonical ARYA action contracts.
- Provide voice/payment compatibility routes.
- Provide health, contract, service-map and system information.
- Never accept arbitrary upstream URLs from clients.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Unified API"
APP_VERSION = "2.0.0"

HOST = os.getenv("ARYA_UNIFIED_API_HOST", "127.0.0.1")
PORT = int(os.getenv("ARYA_UNIFIED_API_PORT", "8023"))

CLIENT_API_GATEWAY_URL = os.getenv(
    "ARYA_CLIENT_API_GATEWAY_URL",
    "http://127.0.0.1:8021",
).rstrip("/")

UNIFIED_API_TIMEOUT = float(
    os.getenv("ARYA_UNIFIED_API_TIMEOUT", "45")
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_UNIFIED_API_MAX_RESPONSE_BYTES",
        "10485760",
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_UNIFIED_API_MAX_REQUEST_BYTES",
        "5242880",
    )
)

UNIFIED_API_SECRET = os.getenv(
    "ARYA_UNIFIED_API_SECRET",
    "",
)

INTERNAL_GATEWAY_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

REQUEST_TTL = int(
    os.getenv(
        "ARYA_UNIFIED_API_REQUEST_TTL",
        "60",
    )
)

REQUIRE_INTERNAL_SIGNATURE = (
    os.getenv(
        "ARYA_UNIFIED_API_REQUIRE_SIGNATURE",
        "false",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Unified API composition layer for ARYA AgriDoctor. "
        "This service does not replace main.py or specialist services."
    ),
)


# ============================================================
# Runtime helpers
# ============================================================

def now_ts() -> int:
    return int(time.time())


def new_request_id() -> str:
    return uuid.uuid4().hex


def constant_time_equal(a: str, b: str) -> bool:
    if not a or not b:
        return False

    try:
        return hmac.compare_digest(
            a.encode("utf-8"),
            b.encode("utf-8"),
        )
    except Exception:
        return False


def sign_payload(
    timestamp: str,
    body: bytes,
    secret: str,
) -> str:
    message = timestamp.encode("utf-8") + b"." + body

    return hmac.new(
        secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()


def verify_signature(
    timestamp: Optional[str],
    signature: Optional[str],
    body: bytes,
    secret: str,
) -> bool:
    if not secret:
        return False

    if not timestamp or not signature:
        return False

    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False

    if abs(now_ts() - ts) > REQUEST_TTL:
        return False

    expected = sign_payload(
        timestamp,
        body,
        secret,
    )

    provided = signature.strip()

    if provided.lower().startswith("sha256="):
        provided = provided[7:]

    return constant_time_equal(
        expected,
        provided,
    )


def verify_incoming_request(
    timestamp: Optional[str],
    signature: Optional[str],
    internal_secret: Optional[str],
    body: bytes,
) -> bool:
    """
    Accept the canonical HMAC contract and preserve compatibility
    with the existing internal-secret contract.

    Priority:
    1. HMAC using ARYA_UNIFIED_API_SECRET.
    2. HMAC using ARYA_INTERNAL_GATEWAY_SECRET.
    3. Legacy X-ARYA-Internal-Secret.
    """

    if UNIFIED_API_SECRET:
        if verify_signature(
            timestamp,
            signature,
            body,
            UNIFIED_API_SECRET,
        ):
            return True

        if REQUIRE_INTERNAL_SIGNATURE:
            return False

    if INTERNAL_GATEWAY_SECRET:
        if verify_signature(
            timestamp,
            signature,
            body,
            INTERNAL_GATEWAY_SECRET,
        ):
            return True

    if (
        INTERNAL_GATEWAY_SECRET
        and internal_secret
        and constant_time_equal(
            internal_secret,
            INTERNAL_GATEWAY_SECRET,
        )
    ):
        return True

    if (
        not UNIFIED_API_SECRET
        and not INTERNAL_GATEWAY_SECRET
        and not REQUIRE_INTERNAL_SIGNATURE
    ):
        return True

    return False


def validate_relative_path(path: str) -> bool:
    if not path:
        return True

    if path.startswith(("http://", "https://")):
        return False

    if "\\" in path:
        return False

    parts = path.split("/")

    if ".." in parts:
        return False

    return True


def build_request_headers(
    request: Optional[Request] = None,
    request_id: Optional[str] = None,
) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": f"{APP_NAME}/{APP_VERSION}",
        "X-ARYA-Internal": "true",
        "X-ARYA-Request-ID": request_id or new_request_id(),
    }

    if INTERNAL_GATEWAY_SECRET:
        headers["X-ARYA-Internal-Secret"] = (
            INTERNAL_GATEWAY_SECRET
        )

    if request is not None:
        authorization = request.headers.get("authorization")
        if authorization:
            headers["Authorization"] = authorization

        content_type = request.headers.get("content-type")
        if content_type:
            headers["Content-Type"] = content_type

        client_id = request.headers.get("x-client-id")
        if client_id:
            headers["X-Client-ID"] = client_id

        device_id = request.headers.get("x-device-id")
        if device_id:
            headers["X-Device-ID"] = device_id

        language = request.headers.get("accept-language")
        if language:
            headers["Accept-Language"] = language

    return headers


# ============================================================
# Controlled gateway forwarding
# ============================================================

async def gateway_request(
    method: str,
    path: str,
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    request_id: Optional[str] = None,
) -> Any:

    if not validate_relative_path(path):
        raise HTTPException(
            status_code=400,
            detail="Invalid gateway path",
        )

    normalized_path = "/" + path.lstrip("/")

    url = (
        CLIENT_API_GATEWAY_URL
        + normalized_path
    )

    outgoing_headers = build_request_headers(
        request_id=request_id,
    )

    if headers:
        for key, value in headers.items():
            if value:
                outgoing_headers[key] = value

    timeout = httpx.Timeout(
        UNIFIED_API_TIMEOUT,
        connect=min(
            15.0,
            UNIFIED_API_TIMEOUT,
        ),
    )

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as client:

            response = await client.request(
                method=method.upper(),
                url=url,
                content=body,
                headers=outgoing_headers,
            )

    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail="Client API Gateway timeout",
        ) from exc

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail="Client API Gateway unavailable",
        ) from exc

    if len(response.content) > MAX_RESPONSE_BYTES:
        raise HTTPException(
            status_code=502,
            detail="Gateway response exceeds configured limit",
        )

    content_type = response.headers.get(
        "content-type",
        "",
    ).lower()

    if "application/json" in content_type:
        try:
            data = response.json()
        except ValueError:
            data = {
                "raw": response.text[:10000],
            }
    else:
        data = {
            "raw": response.text[:10000],
        }

    if response.status_code >= 400:
        return JSONResponse(
            status_code=response.status_code,
            content=data,
        )

    return data


# ============================================================
# Request middleware
# ============================================================

@app.middleware("http")
async def request_size_middleware(
    request: Request,
    call_next,
):
    content_length = request.headers.get(
        "content-length"
    )

    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": (
                            "Request body exceeds "
                            "configured limit"
                        )
                    },
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={
                    "detail": "Invalid Content-Length"
                },
            )

    return await call_next(request)


# ============================================================
# Incoming internal authentication
# ============================================================

async def verify_internal_route_request(
    request: Request,
) -> str:

    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body too large",
        )

    timestamp = request.headers.get(
        "x-arya-timestamp"
    )

    signature = request.headers.get(
        "x-arya-signature"
    )

    internal_secret = request.headers.get(
        "x-arya-internal-secret"
    )

    if not verify_incoming_request(
        timestamp=timestamp,
        signature=signature,
        internal_secret=internal_secret,
        body=body,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid internal API authentication",
        )

    return request.headers.get(
        "x-arya-request-id",
        new_request_id(),
    )


# ============================================================
# Root / Health
# ============================================================

@app.get("/")
async def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "role": "unified_api",
        "main_api_untouched": True,
        "client_gateway": CLIENT_API_GATEWAY_URL,
        "timestamp": now_ts(),
    }


@app.get("/health")
async def health():
    gateway_status = "configured"

    try:
        result = await gateway_request(
            "GET",
            "/health",
        )

        if isinstance(result, dict):
            gateway_status = result.get(
                "status",
                "online",
            )
        else:
            gateway_status = "online"

    except HTTPException:
        gateway_status = "unavailable"

    return {
        "status": "online",
        "service": APP_NAME,
        "version": APP_VERSION,
        "client_api_gateway": gateway_status,
        "timestamp": now_ts(),
    }


# ============================================================
# API health compatibility
# ============================================================

@app.get("/api/v1/health")
async def unified_health():
    return await health()


# ============================================================
# Contract
# ============================================================

@app.get("/api/v1/contract")
async def api_contract():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "base_path": "/api/v1",
        "authentication": {
            "client_session": True,
            "hmac_supported": bool(
                UNIFIED_API_SECRET
                or INTERNAL_GATEWAY_SECRET
            ),
            "legacy_internal_secret_supported": bool(
                INTERNAL_GATEWAY_SECRET
            ),
        },
        "routes": {
            "login": "/api/v1/auth/login",
            "logout": "/api/v1/auth/logout",
            "me": "/api/v1/auth/me",
            "doctor": "/api/v1/doctor",
            "analyze": "/api/v1/analyze",
            "diagnose": "/api/v1/diagnose",
            "recommend": "/api/v1/recommend",
            "vision": "/api/v1/vision",
            "voice": "/api/v1/voice",
            "weather": "/api/v1/weather",
            "geocode": "/api/v1/geocode",
            "payment": "/api/v1/payment",
            "updates": "/api/v1/updates",
            "updates_run": "/api/v1/updates/run",
            "runtime": "/api/v1/runtime/{path}",
            "system_map": "/api/v1/system-map",
            "services": "/api/v1/services",
            "info": "/api/v1/info",
            "health": "/api/v1/health",
        },
        "compatibility": {
            "api_unified": "/api/unified",
            "legacy_arya_routes": True,
        },
        "architecture": {
            "client": [
                "Android",
                "Windows",
            ],
            "gateway": "client_api_gateway",
            "runtime": "owner_runtime_gateway",
            "legacy_core": "main.py",
            "specialists": [
                "vision",
                "voice_language",
                "agri_engine",
                "commerce_security",
            ],
        },
    }


# ============================================================
# Authentication forwarding
# ============================================================

@app.post("/api/v1/auth/login")
async def auth_login(
    request: Request,
):
    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body too large",
        )

    headers = build_request_headers(
        request=request,
    )

    return await gateway_request(
        "POST",
        "/client/login",
        body=body,
        headers=headers,
        request_id=headers.get(
            "X-ARYA-Request-ID"
        ),
    )


@app.post("/api/v1/auth/logout")
async def auth_logout(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/client/logout",
    )


@app.get("/api/v1/auth/me")
async def auth_me(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/client/me",
    )


# ============================================================
# Common authenticated forwarding
# ============================================================

async def forward_authenticated(
    request: Request,
    gateway_path: str,
) -> Any:

    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body too large",
        )

    headers = build_request_headers(
        request=request,
    )

    return await gateway_request(
        request.method,
        gateway_path,
        body=body if body else None,
        headers=headers,
        request_id=headers.get(
            "X-ARYA-Request-ID"
        ),
    )


# ============================================================
# Canonical Doctor / AI routes
# ============================================================

@app.api_route(
    "/api/v1/doctor",
    methods=["GET", "POST"],
)
async def doctor(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/doctor",
    )


@app.api_route(
    "/api/v1/doctor/analyze",
    methods=["POST"],
)
async def doctor_analyze(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/doctor/analyze",
    )


@app.api_route(
    "/api/v1/doctor/diagnose",
    methods=["POST"],
)
async def doctor_diagnose(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/doctor/diagnose",
    )


@app.api_route(
    "/api/v1/doctor/recommend",
    methods=["POST"],
)
async def doctor_recommend(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/doctor/recommend",
    )


# ============================================================
# Legacy AI route compatibility
# ============================================================

@app.post("/api/v1/analyze")
async def analyze(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/analyze",
    )


@app.post("/api/v1/diagnose")
async def diagnose(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/diagnose",
    )


@app.post("/api/v1/recommend")
async def recommend(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/recommend",
    )


# ============================================================
# Vision
# ============================================================

@app.post("/api/v1/vision")
async def vision(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/vision",
    )


# ============================================================
# Voice
# ============================================================

@app.api_route(
    "/api/v1/voice",
    methods=[
        "POST",
        "GET",
    ],
)
async def voice(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/voice",
    )


@app.api_route(
    "/api/v1/voice/{voice_path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def voice_subroute(
    voice_path: str,
    request: Request,
):
    if not validate_relative_path(voice_path):
        raise HTTPException(
            status_code=400,
            detail="Invalid voice path",
        )

    return await forward_authenticated(
        request,
        "/api/v1/voice/" + voice_path,
    )


# ============================================================
# Weather / Geocode
# ============================================================

@app.post("/api/v1/weather")
async def weather(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/weather",
    )


@app.post("/api/v1/geocode")
async def geocode(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/geocode",
    )


# ============================================================
# Payment
# ============================================================

@app.api_route(
    "/api/v1/payment",
    methods=[
        "GET",
        "POST",
    ],
)
async def payment(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/payment",
    )


@app.api_route(
    "/api/v1/payment/{payment_path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def payment_subroute(
    payment_path: str,
    request: Request,
):
    if not validate_relative_path(payment_path):
        raise HTTPException(
            status_code=400,
            detail="Invalid payment path",
        )

    return await forward_authenticated(
        request,
        "/api/v1/payment/" + payment_path,
    )


# ============================================================
# Updates
# ============================================================

@app.get("/api/v1/updates")
async def updates(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/updates",
    )


@app.post("/api/v1/updates/run")
async def updates_run(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/updates/run",
    )


# ============================================================
# System Map
# ============================================================

@app.get("/api/v1/system-map")
async def system_map(
    request: Request,
):
    return await forward_authenticated(
        request,
        "/api/v1/system-map",
    )


# ============================================================
# Generic Runtime Forwarder
# ============================================================

@app.api_route(
    "/api/v1/runtime/{runtime_path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def runtime_forward(
    runtime_path: str,
    request: Request,
):
    if not validate_relative_path(runtime_path):
        raise HTTPException(
            status_code=400,
            detail="Invalid runtime path",
        )

    return await forward_authenticated(
        request,
        "/api/v1/runtime/" + runtime_path,
    )


# ============================================================
# Unified compatibility route
# ============================================================

@app.api_route(
    "/api/unified",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def unified_compatibility(
    request: Request,
):
    """
    Compatibility endpoint for Final Integration and older clients.

    It forwards the request to the corresponding canonical
    /api/v1 contract without exposing an arbitrary upstream.
    """

    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body too large",
        )

    payload: Dict[str, Any] = {}

    if body:
        try:
            decoded = json.loads(
                body.decode("utf-8")
            )

            if isinstance(decoded, dict):
                payload = decoded

        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}

    action = str(
        payload.get("action", "")
    ).strip().lower()

    action_map = {
        "doctor": "/api/v1/doctor",
        "analyze": "/api/v1/doctor/analyze",
        "diagnose": "/api/v1/doctor/diagnose",
        "recommend": "/api/v1/doctor/recommend",
        "vision": "/api/v1/vision",
        "voice": "/api/v1/voice",
        "weather": "/api/v1/weather",
        "geocode": "/api/v1/geocode",
        "payment": "/api/v1/payment",
        "updates": "/api/v1/updates",
        "updates_run": "/api/v1/updates/run",
    }

    target = action_map.get(
        action,
        "/api/v1/doctor",
    )

    if payload.get("payload") is not None:
        forwarded_payload = payload["payload"]

        try:
            forwarded_body = json.dumps(
                forwarded_payload,
                ensure_ascii=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail="Invalid unified payload",
            ) from exc
    else:
        forwarded_body = body

    headers = build_request_headers(
        request=request,
        request_id=payload.get(
            "request_id"
        ) or request.headers.get(
            "x-arya-request-id"
        ),
    )

    if forwarded_body:
        headers["Content-Type"] = "application/json"

    return await gateway_request(
        request.method,
        target,
        body=(
            forwarded_body
            if forwarded_body
            else None
        ),
        headers=headers,
        request_id=headers.get(
            "X-ARYA-Request-ID"
        ),
    )


# ============================================================
# Legacy /arya compatibility
# ============================================================

@app.api_route(
    "/arya/{action:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def legacy_arya_route(
    action: str,
    request: Request,
):
    """
    Compatibility for older ARYA gateway callers.

    No arbitrary host is accepted.
    """

    if not validate_relative_path(action):
        raise HTTPException(
            status_code=400,
            detail="Invalid ARYA path",
        )

    action_clean = action.strip("/")

    aliases = {
        "doctor": "/api/v1/doctor",
        "analyze": "/api/v1/doctor/analyze",
        "diagnose": "/api/v1/doctor/diagnose",
        "recommend": "/api/v1/doctor/recommend",
        "vision": "/api/v1/vision",
        "voice": "/api/v1/voice",
        "weather": "/api/v1/weather",
        "geocode": "/api/v1/geocode",
        "payment": "/api/v1/payment",
        "updates": "/api/v1/updates",
        "updates/run": "/api/v1/updates/run",
    }

    target = aliases.get(
        action_clean,
        "/api/v1/" + action_clean,
    )

    return await forward_authenticated(
        request,
        target,
    )


# ============================================================
# Service Map
# ============================================================

@app.get("/api/v1/services")
async def services():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "services": [
            {
                "id": "client_api_gateway",
                "role": "client_auth_and_api",
                "url": CLIENT_API_GATEWAY_URL,
            },
            {
                "id": "owner_runtime_gateway",
                "role": "runtime_orchestration",
                "managed_by": "client_api_gateway",
            },
            {
                "id": "main_api",
                "role": "legacy_core_api",
                "managed_by": "arya_main_api_bridge",
                "modified": False,
            },
            {
                "id": "agri_engine",
                "role": "agricultural_reasoning",
            },
            {
                "id": "vision",
                "role": "image_analysis",
            },
            {
                "id": "voice_language",
                "role": "voice_and_language",
            },
            {
                "id": "commerce_security",
                "role": "payments_and_commerce",
            },
            {
                "id": "data_update",
                "role": "automatic_data_updates",
            },
            {
                "id": "external_providers",
                "role": "external_data_providers",
            },
            {
                "id": "owner_manager",
                "role": "owner_control",
            },
            {
                "id": "owner_provider_control",
                "role": "provider_control",
            },
            {
                "id": "internal_service_security",
                "role": "service_to_service_security",
            },
        ],
        "timestamp": now_ts(),
    }


# ============================================================
# System Information
# ============================================================

@app.get("/api/v1/info")
async def info():
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "type": "api_composition_layer",
        "production_ready": False,
        "testing_completed": False,
        "main_py_modified": False,
        "target_clients": [
            "Android",
            "Windows",
        ],
        "timestamp": now_ts(),
    }


# ============================================================
# Error handler
# ============================================================

@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request,
    exc: Exception,
):
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "service": APP_NAME,
            "request_id": new_request_id(),
        },
    )


# ============================================================
# Local execution
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "arya_unified_api:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
