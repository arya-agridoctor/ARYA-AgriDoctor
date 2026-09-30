"""
ARYA Unified API
================
Version: 1.0.0

Final API composition layer for ARYA AgriDoctor.

Purpose:
- Provide one unified backend entry point for Android and Windows clients.
- Connect Client API Gateway to Runtime Gateway.
- Keep existing main.py untouched.
- Keep all existing specialist services untouched.
- Expose a stable /api/v1 contract.
- Provide service discovery, health and system-map endpoints.
- Forward authenticated client requests to the existing Client API Gateway.

Environment:
    ARYA_UNIFIED_API_HOST
    ARYA_UNIFIED_API_PORT
    ARYA_CLIENT_API_GATEWAY_URL
    ARYA_UNIFIED_API_TIMEOUT
    ARYA_UNIFIED_API_MAX_RESPONSE_BYTES
    ARYA_UNIFIED_API_MAX_REQUEST_BYTES
    ARYA_UNIFIED_API_SECRET
    ARYA_INTERNAL_GATEWAY_SECRET

Default:
    Host: 127.0.0.1
    Port: 8023
    Client Gateway: http://127.0.0.1:8021
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
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Unified API"
APP_VERSION = "1.0.0"

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
    os.getenv("ARYA_UNIFIED_API_MAX_RESPONSE_BYTES", "10485760")
)

MAX_REQUEST_BYTES = int(
    os.getenv("ARYA_UNIFIED_API_MAX_REQUEST_BYTES", "5242880")
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
    os.getenv("ARYA_UNIFIED_API_REQUEST_TTL", "60")
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Unified API composition layer for ARYA AgriDoctor. "
        "This service does not replace main.py or existing specialist services."
    ),
)


# ============================================================
# Models
# ============================================================

class UnifiedRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: int


# ============================================================
# Runtime helpers
# ============================================================

def now_ts() -> int:
    return int(time.time())


def request_id() -> str:
    return uuid.uuid4().hex


def constant_time_equal(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


def sign_payload(timestamp: str, body: bytes, secret: str) -> str:
    message = timestamp.encode() + b"." + body
    return hmac.new(
        secret.encode(),
        message,
        hashlib.sha256,
    ).hexdigest()


def verify_incoming_signature(
    timestamp: Optional[str],
    signature: Optional[str],
    body: bytes,
) -> bool:
    """
    Optional HMAC verification.

    If ARYA_UNIFIED_API_SECRET is not configured, signature verification
    is skipped. This allows local development while still supporting
    hardened production deployment.
    """

    if not UNIFIED_API_SECRET:
        return True

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
        UNIFIED_API_SECRET,
    )

    provided = signature.strip()

    if provided.lower().startswith("sha256="):
        provided = provided[7:]

    return constant_time_equal(expected, provided)


def validate_target_url(url: str) -> bool:
    """
    This service intentionally accepts only the configured Client Gateway URL.

    It does not allow clients to provide arbitrary target URLs.
    """

    return url.rstrip("/") == CLIENT_API_GATEWAY_URL


async def gateway_request(
    method: str,
    path: str,
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    """
    Controlled forwarding to Client API Gateway.

    No arbitrary URL supplied by the client is accepted.
    """

    url = CLIENT_API_GATEWAY_URL + "/" + path.lstrip("/")

    if not validate_target_url(
        url.rsplit("/", 1)[0]
        if path.strip("/")
        else url
    ):
        raise HTTPException(
            status_code=500,
            detail="Configured gateway validation failed",
        )

    outgoing_headers: Dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": "ARYA-Unified-API/1.0",
        "X-ARYA-Request-ID": request_id(),
    }

    if headers:
        for key, value in headers.items():
            if value:
                outgoing_headers[key] = value

    if INTERNAL_GATEWAY_SECRET:
        outgoing_headers["X-ARYA-Internal-Secret"] = (
            INTERNAL_GATEWAY_SECRET
        )

    timeout = httpx.Timeout(
        UNIFIED_API_TIMEOUT,
        connect=min(15.0, UNIFIED_API_TIMEOUT),
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
# Middleware
# ============================================================

@app.middleware("http")
async def request_size_middleware(
    request: Request,
    call_next,
):
    content_length = request.headers.get("content-length")

    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": "Request body exceeds configured limit"
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
            "hmac_supported": bool(UNIFIED_API_SECRET),
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
            "weather": "/api/v1/weather",
            "geocode": "/api/v1/geocode",
            "updates": "/api/v1/updates",
            "system_map": "/api/v1/system-map",
            "health": "/api/v1/health",
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
# Unified Health
# ============================================================

@app.get("/api/v1/health")
async def unified_health():
    return await health()


# ============================================================
# Authentication forwarding
# ============================================================

@app.post("/api/v1/auth/login")
async def auth_login(
    request: Request,
    x_arya_timestamp: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Timestamp",
    ),
    x_arya_signature: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Signature",
    ),
):
    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body too large",
        )

    if not verify_incoming_signature(
        x_arya_timestamp,
        x_arya_signature,
        body,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid API signature",
        )

    return await gateway_request(
        "POST",
        "/client/login",
        body=body,
        headers={
            "Content-Type": request.headers.get(
                "content-type",
                "application/json",
            ),
        },
    )


@app.post("/api/v1/auth/logout")
async def auth_logout(
    authorization: Optional[str] = Header(
        default=None,
    ),
):
    headers = {}

    if authorization:
        headers["Authorization"] = authorization

    return await gateway_request(
        "POST",
        "/client/logout",
        headers=headers,
    )


@app.get("/api/v1/auth/me")
async def auth_me(
    authorization: Optional[str] = Header(
        default=None,
    ),
):
    headers = {}

    if authorization:
        headers["Authorization"] = authorization

    return await gateway_request(
        "GET",
        "/client/me",
        headers=headers,
    )


# ============================================================
# Common authenticated forwarding helper
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

    headers: Dict[str, str] = {}

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

    return await gateway_request(
        request.method,
        gateway_path,
        body=body if body else None,
        headers=headers,
    )


# ============================================================
# Doctor / AI
# ============================================================

@app.post("/api/v1/doctor")
async def doctor(request: Request):
    return await forward_authenticated(
        request,
        "/api/v1/doctor",
    )


@app.post("/api/v1/analyze")
async def analyze(request: Request):
    return await forward_authenticated(
        request,
        "/api/v1/analyze",
    )


@app.post("/api/v1/diagnose")
async def diagnose(request: Request):
    return await forward_authenticated(
        request,
        "/api/v1/diagnose",
    )


@app.post("/api/v1/recommend")
async def recommend(request: Request):
    return await forward_authenticated(
        request,
        "/api/v1/recommend",
    )


# ============================================================
# Vision
# ============================================================

@app.post("/api/v1/vision")
async def vision(request: Request):
    return await forward_authenticated(
        request,
        "/api/v1/vision",
    )


# ============================================================
# Location / Weather
# ============================================================

@app.post("/api/v1/weather")
async def weather(request: Request):
    return await forward_authenticated(
        request,
        "/api/v1/weather",
    )


@app.post("/api/v1/geocode")
async def geocode(request: Request):
    return await forward_authenticated(
        request,
        "/api/v1/geocode",
    )


# ============================================================
# Updates
# ============================================================

@app.get("/api/v1/updates")
async def updates(
    authorization: Optional[str] = Header(
        default=None,
    ),
):
    headers = {}

    if authorization:
        headers["Authorization"] = authorization

    return await gateway_request(
        "GET",
        "/api/v1/updates",
        headers=headers,
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
    authorization: Optional[str] = Header(
        default=None,
    ),
):
    headers = {}

    if authorization:
        headers["Authorization"] = authorization

    return await gateway_request(
        "GET",
        "/api/v1/system-map",
        headers=headers,
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
    """
    Controlled compatibility route.

    The client cannot specify a host or arbitrary URL.
    Only a relative path is accepted and forwarded to the existing
    Client API Gateway runtime endpoint.
    """

    if runtime_path.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="Absolute URLs are not allowed",
        )

    if ".." in runtime_path.split("/"):
        raise HTTPException(
            status_code=400,
            detail="Invalid runtime path",
        )

    return await forward_authenticated(
        request,
        "/api/v1/runtime/" + runtime_path,
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
# Error handlers
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
            "request_id": request_id(),
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
