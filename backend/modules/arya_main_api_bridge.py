"""
ARYA AgriDoctor
ARYA Main API Bridge
Version: 2.0.0

Purpose:
- Connect ARYA API infrastructure to the existing main.py.
- Keep backend/main.py unchanged.
- Support Android and Windows.
- Preserve request IDs.
- Support canonical HMAC authentication.
- Preserve legacy X-ARYA-Internal-Secret authentication.
- Enforce request/response limits.
- Enforce timeouts.
- Disable redirects.
- Validate internal paths.
- Never proxy arbitrary external URLs.
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

APP_NAME = "ARYA Main API Bridge"
APP_VERSION = "2.0.0"

HOST = os.getenv(
    "ARYA_MAIN_BRIDGE_HOST",
    "0.0.0.0",
)

PORT = int(
    os.getenv(
        "ARYA_MAIN_BRIDGE_PORT",
        "8022",
    )
)

# Existing ARYA main.py service.
ARYA_MAIN_API_URL = os.getenv(
    "ARYA_MAIN_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")


# ============================================================
# Internal security
# ============================================================

INTERNAL_GATEWAY_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
).strip()

MAIN_API_SECRET = os.getenv(
    "ARYA_MAIN_API_SECRET",
    "",
).strip()

REQUIRE_INTERNAL_SIGNATURE = (
    os.getenv(
        "ARYA_MAIN_BRIDGE_REQUIRE_SIGNATURE",
        "false",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)

REQUIRE_INTERNAL_HEADER = (
    os.getenv(
        "ARYA_MAIN_BRIDGE_REQUIRE_INTERNAL_HEADER",
        "false",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)

ALLOW_LEGACY_INTERNAL_SECRET = (
    os.getenv(
        "ARYA_MAIN_BRIDGE_ALLOW_LEGACY_SECRET",
        "true",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)


# ============================================================
# Limits
# ============================================================

REQUEST_TIMEOUT = float(
    os.getenv(
        "ARYA_MAIN_BRIDGE_TIMEOUT",
        "60",
    )
)

CONNECT_TIMEOUT = float(
    os.getenv(
        "ARYA_MAIN_BRIDGE_CONNECT_TIMEOUT",
        "10",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_MAIN_BRIDGE_MAX_RESPONSE_BYTES",
        str(16 * 1024 * 1024),
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
        "Controlled bridge between ARYA API infrastructure "
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
        default_factory=dict,
    )

    body: Optional[Any] = None

    headers: Dict[str, str] = Field(
        default_factory=dict,
    )


# ============================================================
# Helpers
# ============================================================

def utc_timestamp() -> str:
    return str(int(time.time()))


def request_id() -> str:
    return str(uuid.uuid4())


def normalize_request_id(
    value: Optional[str],
) -> str:

    if value:

        value = str(value).strip()

        if value:
            return value[:200]

    return request_id()


def secure_equal(
    first: str,
    second: str,
) -> bool:

    try:

        return hmac.compare_digest(
            first.encode("utf-8"),
            second.encode("utf-8"),
        )

    except Exception:

        return False


def body_hash(
    body: bytes,
) -> str:

    return hashlib.sha256(
        body
    ).hexdigest()


def sign_body(
    body: bytes,
) -> str:

    if not INTERNAL_GATEWAY_SECRET:
        return ""

    return hmac.new(
        INTERNAL_GATEWAY_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()


def normalize_path(
    path: str,
) -> str:

    value = str(path).strip()

    if not value:
        return "/"

    if not value.startswith("/"):
        value = "/" + value

    return value


def validate_path(
    path: str,
) -> str:

    value = normalize_path(path)

    if "://" in value:

        raise HTTPException(
            status_code=400,
            detail="Absolute URLs are not allowed.",
        )

    if "\x00" in value:

        raise HTTPException(
            status_code=400,
            detail="Invalid path.",
        )

    if "\\" in value:

        raise HTTPException(
            status_code=400,
            detail="Invalid path.",
        )

    return value


def validate_body_size(
    body: bytes,
) -> None:

    if len(body) > MAX_REQUEST_BYTES:

        raise HTTPException(
            status_code=413,
            detail="Request body is too large.",
        )


# ============================================================
# Incoming internal authentication
# ============================================================

def verify_internal_auth(
    *,
    internal_secret: Optional[str],
    signature: Optional[str],
    internal_header: Optional[str],
    body: bytes,
) -> None:

    if REQUIRE_INTERNAL_HEADER:

        if (
            not internal_header
            or internal_header.strip().lower()
            not in {
                "1",
                "true",
                "yes",
                "on",
            }
        ):

            raise HTTPException(
                status_code=401,
                detail=(
                    "ARYA internal authentication header "
                    "is required."
                ),
            )

    if REQUIRE_INTERNAL_SIGNATURE:

        if not INTERNAL_GATEWAY_SECRET:

            raise HTTPException(
                status_code=503,
                detail=(
                    "ARYA_INTERNAL_GATEWAY_SECRET "
                    "is not configured."
                ),
            )

        if not signature:

            raise HTTPException(
                status_code=401,
                detail=(
                    "ARYA internal HMAC signature is required."
                ),
            )

        expected = sign_body(body)

        if not secure_equal(
            expected,
            signature.strip(),
        ):

            raise HTTPException(
                status_code=401,
                detail="Invalid ARYA internal signature.",
            )

        return

    # --------------------------------------------------------
    # Backward compatibility.
    # --------------------------------------------------------
    #
    # When signature enforcement is disabled, the bridge
    # continues accepting the old secret contract.
    #
    # This prevents the new Final Integration layer from
    # breaking older internal callers.
    # --------------------------------------------------------

    if ALLOW_LEGACY_INTERNAL_SECRET:

        if not INTERNAL_GATEWAY_SECRET:

            raise HTTPException(
                status_code=503,
                detail=(
                    "ARYA_INTERNAL_GATEWAY_SECRET "
                    "is not configured."
                ),
            )

        if not internal_secret:

            raise HTTPException(
                status_code=401,
                detail=(
                    "Internal authentication required."
                ),
            )

        if not secure_equal(
            internal_secret,
            INTERNAL_GATEWAY_SECRET,
        ):

            raise HTTPException(
                status_code=401,
                detail=(
                    "Invalid internal authentication."
                ),
            )

        return

    # If legacy authentication is disabled and HMAC is not
    # required, still require a valid configured secret.
    if INTERNAL_GATEWAY_SECRET:

        if not signature:

            raise HTTPException(
                status_code=401,
                detail=(
                    "ARYA internal authentication "
                    "is required."
                ),
            )

        expected = sign_body(body)

        if not secure_equal(
            expected,
            signature.strip(),
        ):

            raise HTTPException(
                status_code=401,
                detail=(
                    "Invalid ARYA internal signature."
                ),
            )

        return

    raise HTTPException(
        status_code=503,
        detail=(
            "No ARYA internal authentication method "
            "is configured."
        ),
    )


# ============================================================
# Outgoing headers to main.py
# ============================================================

def build_main_headers(
    *,
    request_id_value: str,
    forwarded_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:

    headers: Dict[str, str] = {
        "Accept": "application/json",
        "X-ARYA-Bridge": APP_VERSION,
        "X-ARYA-Request-ID": request_id_value,
    }

    if MAIN_API_SECRET:

        headers[
            "X-ARYA-Main-Bridge-Secret"
        ] = MAIN_API_SECRET

    if forwarded_headers:

        blocked = {
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "x-arya-internal-secret",
            "x-arya-signature",
        }

        for key, value in forwarded_headers.items():

            if key.lower() in blocked:
                continue

            headers[key] = value

    return headers


# ============================================================
# Main API request
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

    rid = normalize_request_id(
        request_id_value
    )

    headers = build_main_headers(
        request_id_value=rid,
        forwarded_headers=forwarded_headers,
    )

    request_kwargs: Dict[str, Any] = {
        "method": method,
        "url": url,
        "params": query or {},
        "headers": headers,
    }

    if body is not None:

        try:

            serialized = json.dumps(
                body,
                ensure_ascii=False,
            ).encode("utf-8")

        except Exception as exc:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Request body is not JSON serializable: "
                    f"{exc}"
                ),
            )

        validate_body_size(serialized)

        request_kwargs["content"] = serialized

        request_kwargs["headers"][
            "Content-Type"
        ] = "application/json"

    try:

        timeout = httpx.Timeout(
            REQUEST_TIMEOUT,
            connect=CONNECT_TIMEOUT,
        )

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            max_redirects=0,
        ) as client:

            response = await client.request(
                **request_kwargs
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

    except httpx.RequestError as exc:

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
            detail=(
                "ARYA main API response is too large."
            ),
        )

    content_type = (
        response.headers.get(
            "content-type",
            "",
        )
        .lower()
    )

    if "application/json" in content_type:

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
            "content-type":
                response.headers.get(
                    "content-type"
                ),
        },
        "body": response_body,
    }


# ============================================================
# Root
# ============================================================

@app.get("/")
async def root():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "port": PORT,
        "main_api": ARYA_MAIN_API_URL,
        "main_file_unchanged": True,
        "security": {
            "internal_secret_configured":
                bool(INTERNAL_GATEWAY_SECRET),
            "signature_required":
                REQUIRE_INTERNAL_SIGNATURE,
            "internal_header_required":
                REQUIRE_INTERNAL_HEADER,
            "legacy_secret_allowed":
                ALLOW_LEGACY_INTERNAL_SECRET,
        },
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health(
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):

    body = await request.body()

    validate_body_size(body)

    verify_internal_auth(
        internal_secret=x_arya_internal_secret,
        signature=x_arya_signature,
        internal_header=x_arya_internal,
        body=body,
    )

    rid = normalize_request_id(
        x_arya_request_id
    )

    result = await call_main_api(
        method="GET",
        path="/health",
        request_id_value=rid,
    )

    return {
        "bridge": "healthy",
        "request_id": rid,
        "main_api": result,
        "time": utc_timestamp(),
    }


# ============================================================
# Main API proxy
# ============================================================

@app.post("/internal/main-api/request")
async def main_api_request(
    payload: MainAPIRequest,
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):

    raw_body = await request.body()

    validate_body_size(raw_body)

    verify_internal_auth(
        internal_secret=x_arya_internal_secret,
        signature=x_arya_signature,
        internal_header=x_arya_internal,
        body=raw_body,
    )

    current_request_id = normalize_request_id(
        x_arya_request_id
        or payload.request_id
        if hasattr(payload, "request_id")
        else x_arya_request_id
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
# Main API health compatibility
# ============================================================

@app.get("/internal/main-api/health")
async def main_api_health(
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):

    body = await request.body()

    validate_body_size(body)

    verify_internal_auth(
        internal_secret=x_arya_internal_secret,
        signature=x_arya_signature,
        internal_header=x_arya_internal,
        body=body,
    )

    rid = normalize_request_id(
        x_arya_request_id
    )

    return await call_main_api(
        method="GET",
        path="/health",
        request_id_value=rid,
    )


# ============================================================
# Main API root compatibility
# ============================================================

@app.get("/internal/main-api/")
async def main_api_root(
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):

    body = await request.body()

    validate_body_size(body)

    verify_internal_auth(
        internal_secret=x_arya_internal_secret,
        signature=x_arya_signature,
        internal_header=x_arya_internal,
        body=body,
    )

    rid = normalize_request_id(
        x_arya_request_id
    )

    return await call_main_api(
        method="GET",
        path="/",
        request_id_value=rid,
    )


# ============================================================
# Existing ARYA API compatibility
# ============================================================

async def authenticated_arya_proxy(
    *,
    path: str,
    payload: Dict[str, Any],
    request: Request,
    x_arya_internal_secret: Optional[str],
    x_arya_signature: Optional[str],
    x_arya_internal: Optional[str],
    x_arya_request_id: Optional[str],
):

    raw_body = await request.body()

    validate_body_size(raw_body)

    verify_internal_auth(
        internal_secret=x_arya_internal_secret,
        signature=x_arya_signature,
        internal_header=x_arya_internal,
        body=raw_body,
    )

    rid = normalize_request_id(
        x_arya_request_id
    )

    return {
        "request_id": rid,
        "result": await call_main_api(
            method="POST",
            path=path,
            body=payload,
            request_id_value=rid,
        ),
    }


@app.post("/internal/arya/analyze")
async def arya_analyze(
    payload: Dict[str, Any],
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):

    return await authenticated_arya_proxy(
        path="/ai/analyze",
        payload=payload,
        request=request,
        x_arya_internal_secret=x_arya_internal_secret,
        x_arya_signature=x_arya_signature,
        x_arya_internal=x_arya_internal,
        x_arya_request_id=x_arya_request_id,
    )


@app.post("/internal/arya/vision")
async def arya_vision(
    payload: Dict[str, Any],
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):

    return await authenticated_arya_proxy(
        path="/vision/analyze",
        payload=payload,
        request=request,
        x_arya_internal_secret=x_arya_internal_secret,
        x_arya_signature=x_arya_signature,
        x_arya_internal=x_arya_internal,
        x_arya_request_id=x_arya_request_id,
    )


@app.post("/internal/arya/weather")
async def arya_weather(
    payload: Dict[str, Any],
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):

    return await authenticated_arya_proxy(
        path="/weather",
        payload=payload,
        request=request,
        x_arya_internal_secret=x_arya_internal_secret,
        x_arya_signature=x_arya_signature,
        x_arya_internal=x_arya_internal,
        x_arya_request_id=x_arya_request_id,
    )


@app.post("/internal/arya/geocode")
async def arya_geocode(
    payload: Dict[str, Any],
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
):

    return await authenticated_arya_proxy(
        path="/location/geocode",
        payload=payload,
        request=request,
        x_arya_internal_secret=x_arya_internal_secret,
        x_arya_signature=x_arya_signature,
        x_arya_internal=x_arya_internal,
        x_arya_request_id=x_arya_request_id,
    )


# ============================================================
# System information
# ============================================================

@app.get("/internal/system-map")
async def system_map(
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
):

    body = await request.body()

    validate_body_size(body)

    verify_internal_auth(
        internal_secret=x_arya_internal_secret,
        signature=x_arya_signature,
        internal_header=x_arya_internal,
        body=body,
    )

    return {
        "bridge": APP_NAME,
        "version": APP_VERSION,
        "port": PORT,
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

        "security": {
            "hmac_supported": True,
            "signature_required":
                REQUIRE_INTERNAL_SIGNATURE,
            "legacy_secret_allowed":
                ALLOW_LEGACY_INTERNAL_SECRET,
        },
    }


# ============================================================
# API Contract
# ============================================================

@app.get("/internal/contract")
async def contract(
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
):

    body = await request.body()

    validate_body_size(body)

    verify_internal_auth(
        internal_secret=x_arya_internal_secret,
        signature=x_arya_signature,
        internal_header=x_arya_internal,
        body=body,
    )

    return {
        "service": APP_NAME,
        "version": APP_VERSION,

        "purpose": (
            "Bridge ARYA API infrastructure "
            "to existing backend/main.py."
        ),

        "main_api_url":
            ARYA_MAIN_API_URL,

        "main_py_modified":
            False,

        "features": [
            "controlled_proxy",
            "internal_hmac_authentication",
            "legacy_secret_compatibility",
            "request_id_propagation",
            "timeout_control",
            "request_size_control",
            "response_size_control",
            "redirect_disabled",
            "method_validation",
            "path_validation",
            "arbitrary_url_proxy_disabled",
        ],

        "authentication_headers": [
            "X-ARYA-Internal",
            "X-ARYA-Internal-Secret",
            "X-ARYA-Signature",
            "X-ARYA-Request-ID",
        ],
    }


# ============================================================
# Security status
# ============================================================

@app.get("/internal/security")
async def security_status(
    request: Request,
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_internal: Optional[str] = Header(
        default=None
    ),
):

    body = await request.body()

    validate_body_size(body)

    verify_internal_auth(
        internal_secret=x_arya_internal_secret,
        signature=x_arya_signature,
        internal_header=x_arya_internal,
        body=body,
    )

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "internal_secret_configured":
            bool(INTERNAL_GATEWAY_SECRET),
        "main_api_secret_configured":
            bool(MAIN_API_SECRET),
        "signature_supported": True,
        "signature_required":
            REQUIRE_INTERNAL_SIGNATURE,
        "internal_header_required":
            REQUIRE_INTERNAL_HEADER,
        "legacy_secret_allowed":
            ALLOW_LEGACY_INTERNAL_SECRET,
        "request_limit_bytes":
            MAX_REQUEST_BYTES,
        "response_limit_bytes":
            MAX_RESPONSE_BYTES,
        "redirects_allowed": False,
        "arbitrary_proxy_urls": False,
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
            "error": exc.detail,
            "request_id":
                request.headers.get(
                    "X-ARYA-Request-ID"
                ),
            "timestamp": utc_timestamp(),
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
            "timestamp": utc_timestamp(),
        },
    )


# ============================================================
# Local execution
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "arya_main_api_bridge:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
