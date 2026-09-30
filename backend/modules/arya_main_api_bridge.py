"""
ARYA AgriDoctor
ARYA Main API Bridge
Version: 1.0.0

Purpose:
- Connect Client API Gateway to the existing ARYA main.py service
- Keep main.py unchanged
- Provide a controlled bridge between the new API layer and the
  existing ARYA core backend
- Support Android and Windows through the Client API Gateway
- Forward authenticated requests
- Preserve request IDs
- Enforce response-size and timeout limits
- Provide health and system information
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Main API Bridge"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_MAIN_BRIDGE_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_MAIN_BRIDGE_PORT",
        "8022",
    )
)

# Existing ARYA main.py service.
# This can be changed through environment variables without
# modifying the source code.
ARYA_MAIN_API_URL = os.getenv(
    "ARYA_MAIN_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

INTERNAL_GATEWAY_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

MAIN_API_SECRET = os.getenv(
    "ARYA_MAIN_API_SECRET",
    "",
)

REQUEST_TIMEOUT = float(
    os.getenv(
        "ARYA_MAIN_BRIDGE_TIMEOUT",
        "60",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_MAIN_BRIDGE_MAX_RESPONSE_BYTES",
        str(10 * 1024 * 1024),
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_MAIN_BRIDGE_MAX_REQUEST_BYTES",
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
        "Controlled bridge between the new ARYA API infrastructure "
        "and the existing ARYA main.py backend."
    ),
)


# ============================================================
# Models
# ============================================================

class MainAPIRequest(BaseModel):
    method: str = Field(
        default="GET",
        min_length=3,
        max_length=10,
    )

    path: str = Field(
        min_length=1,
        max_length=500,
    )

    query: Dict[str, Any] = Field(
        default_factory=dict
    )

    body: Optional[Any] = None

    headers: Dict[str, str] = Field(
        default_factory=dict
    )


# ============================================================
# Helpers
# ============================================================

def utc_timestamp() -> str:
    return str(int(time.time()))


def request_id() -> str:
    return str(uuid.uuid4())


def secure_equal(
    first: str,
    second: str,
) -> bool:
    return hmac.compare_digest(
        first.encode("utf-8"),
        second.encode("utf-8"),
    )


def body_hash(
    body: bytes,
) -> str:
    return hashlib.sha256(body).hexdigest()


def normalize_path(
    path: str,
) -> str:
    path = path.strip()

    if not path:
        return "/"

    if not path.startswith("/"):
        path = "/" + path

    return path


def validate_path(
    path: str,
) -> str:
    path = normalize_path(path)

    if "://" in path:
        raise HTTPException(
            status_code=400,
            detail="Absolute URLs are not allowed.",
        )

    if "\x00" in path:
        raise HTTPException(
            status_code=400,
            detail="Invalid path.",
        )

    return path


# ============================================================
# Internal Authentication
# ============================================================

def require_internal_secret(
    supplied_secret: Optional[str],
):
    if not INTERNAL_GATEWAY_SECRET:
        raise HTTPException(
            status_code=503,
            detail=(
                "ARYA_INTERNAL_GATEWAY_SECRET "
                "is not configured."
            ),
        )

    if not supplied_secret:
        raise HTTPException(
            status_code=401,
            detail="Internal authentication required.",
        )

    if not secure_equal(
        supplied_secret,
        INTERNAL_GATEWAY_SECRET,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid internal authentication.",
        )


# ============================================================
# Main API Request
# ============================================================

async def call_main_api(
    method: str,
    path: str,
    query: Optional[Dict[str, Any]] = None,
    body: Any = None,
    forwarded_headers: Optional[Dict[str, str]] = None,
    request_id_value: Optional[str] = None,
):
    path = validate_path(path)

    url = (
        ARYA_MAIN_API_URL
        + path
    )

    method = method.upper()

    allowed_methods = {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    }

    if method not in allowed_methods:
        raise HTTPException(
            status_code=405,
            detail="HTTP method not supported.",
        )

    headers = {
        "X-ARYA-Bridge": APP_VERSION,
        "X-ARYA-Request-ID": (
            request_id_value
            or request_id()
        ),
    }

    if MAIN_API_SECRET:
        headers[
            "X-ARYA-Main-Bridge-Secret"
        ] = MAIN_API_SECRET

    if forwarded_headers:
        safe_headers = {
            key: value
            for key, value in forwarded_headers.items()
            if key.lower()
            not in {
                "host",
                "content-length",
                "connection",
                "transfer-encoding",
            }
        }

        headers.update(safe_headers)

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            follow_redirects=False,
        ) as client:

            response = await client.request(
                method=method,
                url=url,
                params=query or {},
                json=body
                if body is not None
                else None,
                headers=headers,
            )

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="ARYA main API timeout.",
        )

    except httpx.ConnectError:
        raise HTTPException(
            status_code=502,
            detail="ARYA main API is unavailable.",
        )

    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "ARYA main API communication error: "
                + str(exc)
            ),
        )

    if len(response.content) > MAX_RESPONSE_BYTES:
        raise HTTPException(
            status_code=502,
            detail="ARYA main API response is too large.",
        )

    content_type = (
        response.headers.get(
            "content-type",
            "",
        )
        .lower()
    )

    if (
        "application/json"
        in content_type
    ):
        try:
            response_body = response.json()
        except Exception:
            response_body = {
                "raw": response.text
            }
    else:
        response_body = {
            "raw": response.text
        }

    return {
        "status_code": response.status_code,
        "headers": {
            "content-type": response.headers.get(
                "content-type"
            ),
        },
        "body": response_body,
    }


# ============================================================
# Root / Health
# ============================================================

@app.get("/")
def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "main_api": ARYA_MAIN_API_URL,
        "main_file_unchanged": True,
    }


@app.get("/health")
async def health(
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    result = await call_main_api(
        method="GET",
        path="/health",
        request_id_value=request_id(),
    )

    return {
        "bridge": "healthy",
        "main_api": result,
        "time": utc_timestamp(),
    }


# ============================================================
# Main API Proxy
# ============================================================

@app.post("/internal/main-api/request")
async def main_api_request(
    payload: MainAPIRequest,
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    raw_body = await request.body()

    if len(raw_body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body is too large.",
        )

    current_request_id = (
        x_arya_request_id
        or request_id()
    )

    result = await call_main_api(
        method=payload.method,
        path=payload.path,
        query=payload.query,
        body=payload.body,
        forwarded_headers=payload.headers,
        request_id_value=current_request_id,
    )

    return {
        "request_id": current_request_id,
        "main_api": result,
    }


# ============================================================
# Convenience Routes
# ============================================================

@app.get("/internal/main-api/health")
async def main_api_health(
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    return await call_main_api(
        method="GET",
        path="/health",
        request_id_value=request_id(),
    )


@app.get("/internal/main-api/")
async def main_api_root(
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    return await call_main_api(
        method="GET",
        path="/",
        request_id_value=request_id(),
    )


# ============================================================
# Existing ARYA API Compatibility Routes
# ============================================================

@app.post("/internal/arya/analyze")
async def arya_analyze(
    payload: Dict[str, Any],
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    rid = (
        x_arya_request_id
        or request_id()
    )

    return {
        "request_id": rid,
        "result": await call_main_api(
            method="POST",
            path="/ai/analyze",
            body=payload,
            request_id_value=rid,
        ),
    }


@app.post("/internal/arya/vision")
async def arya_vision(
    payload: Dict[str, Any],
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    rid = (
        x_arya_request_id
        or request_id()
    )

    return {
        "request_id": rid,
        "result": await call_main_api(
            method="POST",
            path="/vision/analyze",
            body=payload,
            request_id_value=rid,
        ),
    }


@app.post("/internal/arya/weather")
async def arya_weather(
    payload: Dict[str, Any],
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    rid = (
        x_arya_request_id
        or request_id()
    )

    return {
        "request_id": rid,
        "result": await call_main_api(
            method="POST",
            path="/weather",
            body=payload,
            request_id_value=rid,
        ),
    }


@app.post("/internal/arya/geocode")
async def arya_geocode(
    payload: Dict[str, Any],
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    rid = (
        x_arya_request_id
        or request_id()
    )

    return {
        "request_id": rid,
        "result": await call_main_api(
            method="POST",
            path="/location/geocode",
            body=payload,
            request_id_value=rid,
        ),
    }


# ============================================================
# System Information
# ============================================================

@app.get("/internal/system-map")
def system_map(
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    return {
        "bridge": APP_NAME,
        "version": APP_VERSION,
        "main_api": ARYA_MAIN_API_URL,
        "components": {
            "client_api_gateway": "8021",
            "arya_main_api_bridge": str(PORT),
            "runtime_gateway": "8016",
            "owner_integration": "8015",
            "orchestrator_bridge": "8017",
            "runtime_data_provider_bridge": "8018",
            "owner_provider_control": "8019",
            "internal_service_security": "8020",
        },
        "main_py_modified": False,
    }


# ============================================================
# API Contract
# ============================================================

@app.get("/internal/contract")
def contract(
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
):
    require_internal_secret(
        x_arya_internal_secret
    )

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "purpose": (
            "Bridge new API infrastructure "
            "to existing ARYA main.py."
        ),
        "main_api_url": ARYA_MAIN_API_URL,
        "main_py_modified": False,
        "features": [
            "controlled_proxy",
            "internal_authentication",
            "request_id_propagation",
            "timeout_control",
            "response_size_control",
            "redirect_disabled",
            "method_validation",
            "path_validation",
        ],
    }


# ============================================================
# Run
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "arya_main_api_bridge:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
