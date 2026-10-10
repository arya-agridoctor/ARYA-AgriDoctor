"""
ARYA AgriDoctor
Runtime Orchestrator Bridge
Version: 1.1.0

Purpose:
- Connect the final Orchestrator layer to owner_runtime_gateway.py.
- Keep main.py and existing modules untouched.
- Provide a stable API boundary for Android / Windows clients.
- Forward agricultural, vision, voice, payment, weather and update actions.
- Support health checks and runtime system mapping.
- Match OWNER Runtime Gateway v2.0.0 request contracts.
- Preserve existing public bridge routes.
- Propagate request IDs and internal authentication.
- Apply request and response size limits.
- Avoid exposing internal exception details.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "ARYA Runtime Orchestrator Bridge"
APP_VERSION = "1.1.0"

HOST = os.getenv(
    "ARYA_RUNTIME_BRIDGE_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_RUNTIME_BRIDGE_PORT",
        "8017",
    )
)

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).rstrip("/")

REQUEST_TIMEOUT = float(
    os.getenv(
        "ARYA_RUNTIME_BRIDGE_TIMEOUT",
        "45",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_RUNTIME_BRIDGE_MAX_RESPONSE",
        str(10 * 1024 * 1024),
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_RUNTIME_BRIDGE_MAX_REQUEST",
        str(5 * 1024 * 1024),
    )
)

INTERNAL_SECRET = os.getenv(
    "ARYA_RUNTIME_BRIDGE_SECRET",
    "",
)

REQUIRE_BRIDGE_AUTH = (
    os.getenv(
        "ARYA_RUNTIME_BRIDGE_REQUIRE_AUTH",
        "false",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)

USER_AGENT = (
    f"ARYA-Runtime-Orchestrator-Bridge/{APP_VERSION}"
)

REQUEST_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9._:-]{1,128}$"
)

LOG_LEVEL = os.getenv(
    "ARYA_RUNTIME_BRIDGE_LOG_LEVEL",
    "INFO",
).upper()

logging.basicConfig(
    level=getattr(
        logging,
        LOG_LEVEL,
        logging.INFO,
    ),
    format=(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    ),
)

logger = logging.getLogger(APP_NAME)


# ============================================================
# CONFIGURATION VALIDATION
# ============================================================

def validate_configuration() -> None:
    if not 1 <= PORT <= 65535:
        raise RuntimeError(
            "ARYA_RUNTIME_BRIDGE_PORT must be between 1 and 65535"
        )

    if REQUEST_TIMEOUT <= 0:
        raise RuntimeError(
            "ARYA_RUNTIME_BRIDGE_TIMEOUT must be positive"
        )

    if MAX_REQUEST_BYTES <= 0:
        raise RuntimeError(
            "ARYA_RUNTIME_BRIDGE_MAX_REQUEST must be positive"
        )

    if MAX_RESPONSE_BYTES <= 0:
        raise RuntimeError(
            "ARYA_RUNTIME_BRIDGE_MAX_RESPONSE must be positive"
        )

    parsed = urlsplit(RUNTIME_GATEWAY_URL)

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(
            "ARYA_RUNTIME_GATEWAY_URL is invalid"
        )


validate_configuration()


# ============================================================
# REQUEST ID HELPERS
# ============================================================

def create_request_id() -> str:
    return uuid.uuid4().hex


def normalize_request_id(
    candidate: Optional[str],
) -> str:
    if (
        candidate
        and REQUEST_ID_PATTERN.fullmatch(candidate)
    ):
        return candidate

    return create_request_id()


def request_id_for(
    request: Request,
    supplied_id: Optional[str] = None,
) -> str:
    if supplied_id:
        return normalize_request_id(supplied_id)

    existing = getattr(
        request.state,
        "arya_request_id",
        None,
    )

    return normalize_request_id(existing)


# ============================================================
# BRIDGE AUTHENTICATION
# ============================================================

def authenticate_bridge_request(
    request: Request,
) -> None:
    """
    Optional client-to-bridge authentication.

    Enable with:
        ARYA_RUNTIME_BRIDGE_REQUIRE_AUTH=true

    When enabled, configure:
        ARYA_RUNTIME_BRIDGE_SECRET=<shared secret>

    Clients must send:
        Authorization: Bearer <shared secret>

    This is separate from Gateway authentication.
    """

    if not REQUIRE_BRIDGE_AUTH:
        return

    if not INTERNAL_SECRET:
        raise HTTPException(
            status_code=503,
            detail=(
                "Bridge authentication is required "
                "but no bridge secret is configured"
            ),
        )

    authorization = request.headers.get(
        "authorization",
        "",
    )

    expected = f"Bearer {INTERNAL_SECRET}"

    if not hmac.compare_digest(
        authorization.encode("utf-8"),
        expected.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid bridge authentication",
        )


# ============================================================
# FASTAPI LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(
    application: FastAPI,
):
    logger.info(
        "%s v%s starting",
        APP_NAME,
        APP_VERSION,
    )

    logger.info(
        "Runtime Gateway: %s",
        RUNTIME_GATEWAY_URL,
    )

    yield

    logger.info(
        "%s shutting down",
        APP_NAME,
    )


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Runtime bridge between ARYA clients, "
        "the ARYA orchestrator and OWNER Runtime Gateway."
    ),
    lifespan=lifespan,
)


# ============================================================
# MODELS
# ============================================================

class BridgeRequest(BaseModel):
    action: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = Field(
        default=None,
        max_length=128,
    )


class DoctorRequest(BaseModel):
    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = Field(
        default=None,
        max_length=128,
    )


class RuntimeCallRequest(BaseModel):
    service: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    path: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )

    method: str = Field(
        default="POST",
        min_length=3,
        max_length=10,
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = Field(
        default=None,
        max_length=128,
    )


# ============================================================
# REQUEST ID MIDDLEWARE
# ============================================================

@app.middleware("http")
async def request_id_middleware(
    request: Request,
    call_next,
):
    incoming_id = request.headers.get(
        "X-ARYA-Request-ID"
    )

    request_id = normalize_request_id(
        incoming_id
    )

    request.state.arya_request_id = request_id

    content_length = request.headers.get(
        "content-length"
    )

    if content_length:
        try:
            declared_size = int(content_length)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_content_length",
                    "request_id": request_id,
                },
                headers={
                    "X-ARYA-Request-ID": request_id,
                },
            )

        if declared_size < 0:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_content_length",
                    "request_id": request_id,
                },
                headers={
                    "X-ARYA-Request-ID": request_id,
                },
            )

        if declared_size > MAX_REQUEST_BYTES:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "request_body_too_large",
                    "request_id": request_id,
                },
                headers={
                    "X-ARYA-Request-ID": request_id,
                },
            )

    response = await call_next(request)

    response.headers[
        "X-ARYA-Request-ID"
    ] = request_id

    return response


# ============================================================
# HTTP RESPONSE HELPERS
# ============================================================

def safe_error_detail(
    response: httpx.Response,
) -> Any:
    """
    Return a bounded Gateway error without exposing
    unbounded response content.
    """

    content = response.content

    if len(content) > 4000:
        content = content[:4000]

    try:
        decoded = json.loads(
            content.decode(
                "utf-8",
                errors="replace",
            )
        )

        return decoded

    except (ValueError, TypeError):
        return content.decode(
            "utf-8",
            errors="replace",
        )


def validate_gateway_path(
    path: str,
) -> str:
    """
    Accept relative API paths only.
    """

    if not path:
        raise HTTPException(
            status_code=400,
            detail="Gateway path is required",
        )

    if "\\" in path:
        raise HTTPException(
            status_code=400,
            detail="Invalid Gateway path",
        )

    if path.startswith(
        ("http://", "https://", "//"),
    ):
        raise HTTPException(
            status_code=400,
            detail="Absolute Gateway URLs are not allowed",
        )

    if any(
        part == ".."
        for part in path.split("/")
    ):
        raise HTTPException(
            status_code=400,
            detail="Parent path traversal is not allowed",
        )

    return "/" + path.lstrip("/")


# ============================================================
# RUNTIME GATEWAY CLIENT
# ============================================================

class RuntimeGatewayClient:
    """
    HTTP client for owner_runtime_gateway.py.

    This client uses the route contract provided by
    OWNER Runtime Gateway v2.0.0.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = REQUEST_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(
        self,
        request_id: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "X-ARYA-Request-ID": request_id,
        }

        if INTERNAL_SECRET:
            headers[
                "X-ARYA-Internal-Secret"
            ] = INTERNAL_SECRET

        if extra_headers:
            protected_headers = {
                "host",
                "content-length",
                "transfer-encoding",
                "connection",
                "x-arya-internal-secret",
                "authorization",
            }

            for key, value in extra_headers.items():
                if key.lower() in protected_headers:
                    continue

                headers[key] = value

        return headers

    async def request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
        query: Optional[Dict[str, Any]] = None,
        raw_body: Optional[bytes] = None,
        content_type: Optional[str] = None,
    ) -> Dict[str, Any]:

        request_id = normalize_request_id(
            request_id
        )

        clean_path = validate_gateway_path(path)
        url = f"{self.base_url}{clean_path}"

        method = method.upper()

        if method not in {
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            raise HTTPException(
                status_code=400,
                detail="Unsupported HTTP method",
            )

        headers = self._headers(
            request_id
        )

        if content_type:
            headers["Content-Type"] = content_type
        elif payload is not None:
            headers["Content-Type"] = "application/json"

        start = time.monotonic()

        try:
            timeout = httpx.Timeout(
                self.timeout,
                connect=min(
                    15.0,
                    self.timeout,
                ),
            )

            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                headers=headers,
            ) as client:

                request_kwargs: Dict[str, Any] = {
                    "params": query,
                }

                if raw_body is not None:
                    if len(raw_body) > MAX_REQUEST_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail="Request body too large",
                        )

                    request_kwargs["content"] = raw_body

                elif method in {
                    "POST",
                    "PUT",
                    "PATCH",
                    "DELETE",
                }:
                    request_kwargs["json"] = (
                        payload
                        if payload is not None
                        else {}
                    )

                async with client.stream(
                    method,
                    url,
                    **request_kwargs,
                ) as response:

                    body_chunks = []
                    received_bytes = 0

                    content_length = response.headers.get(
                        "content-length"
                    )

                    if content_length:
                        try:
                            declared_response_size = int(
                                content_length
                            )
                        except ValueError:
                            declared_response_size = None

                        if (
                            declared_response_size is not None
                            and declared_response_size
                            > MAX_RESPONSE_BYTES
                        ):
                            raise HTTPException(
                                status_code=502,
                                detail=(
                                    "Runtime Gateway response "
                                    "exceeds configured size limit"
                                ),
                            )

                    async for chunk in response.aiter_bytes():
                        received_bytes += len(chunk)

                        if received_bytes > MAX_RESPONSE_BYTES:
                            raise HTTPException(
                                status_code=502,
                                detail=(
                                    "Runtime Gateway response "
                                    "exceeds configured size limit"
                                ),
                            )

                        body_chunks.append(chunk)

                    response_body = b"".join(
                        body_chunks
                    )

                    elapsed_ms = round(
                        (
                            time.monotonic()
                            - start
                        ) * 1000,
                        2,
                    )

                    if response.status_code >= 400:
                        logger.warning(
                            "Gateway returned HTTP %s "
                            "for request %s",
                            response.status_code,
                            request_id,
                        )

                        raise HTTPException(
                            status_code=502,
                            detail={
                                "message": (
                                    "Runtime Gateway returned "
                                    "an error"
                                ),
                                "gateway_status": (
                                    response.status_code
                                ),
                                "gateway_response": (
                                    safe_error_detail(
                                        httpx.Response(
                                            status_code=(
                                                response.status_code
                                            ),
                                            content=response_body,
                                        )
                                    )
                                ),
                                "request_id": request_id,
                            },
                        )

                    try:
                        data: Any = json.loads(
                            response_body.decode(
                                "utf-8"
                            )
                        )

                    except (
                        UnicodeDecodeError,
                        ValueError,
                    ):
                        data = {
                            "raw": response_body.decode(
                                "utf-8",
                                errors="replace",
                            )
                        }

                    if isinstance(data, dict):
                        data.setdefault(
                            "bridge_request_id",
                            request_id,
                        )

                        data.setdefault(
                            "bridge_elapsed_ms",
                            elapsed_ms,
                        )

                        return data

                    return {
                        "data": data,
                        "bridge_request_id": request_id,
                        "bridge_elapsed_ms": elapsed_ms,
                    }

        except HTTPException:
            raise

        except httpx.TimeoutException as exc:
            logger.warning(
                "Gateway timeout for request %s",
                request_id,
            )

            raise HTTPException(
                status_code=504,
                detail={
                    "message": "Runtime Gateway timeout",
                    "request_id": request_id,
                },
            ) from exc

        except httpx.RequestError as exc:
            logger.warning(
                "Gateway connection failed for request %s: %s",
                request_id,
                type(exc).__name__,
            )

            raise HTTPException(
                status_code=502,
                detail={
                    "message": (
                        "Runtime Gateway connection failed"
                    ),
                    "request_id": request_id,
                },
            ) from exc

        except Exception as exc:
            logger.exception(
                "Unexpected bridge request failure"
            )

            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Unexpected bridge error",
                    "request_id": request_id,
                },
            ) from exc


gateway = RuntimeGatewayClient(
    RUNTIME_GATEWAY_URL
)


# ============================================================
# REQUEST BODY PARSER
# ============================================================

async def read_request_json(
    request: Request,
) -> Dict[str, Any]:
    """
    Read and validate a JSON object within the configured
    body limit.
    """

    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body too large",
        )

    if not body:
        return {}

    try:
        decoded = json.loads(
            body.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        raise HTTPException(
            status_code=400,
            detail="Request body must contain valid JSON",
        ) from exc

    if not isinstance(decoded, dict):
        raise HTTPException(
            status_code=422,
            detail="Request JSON must be an object",
        )

    return decoded


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root(
    request: Request,
):
    authenticate_bridge_request(request)

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "architecture": {
            "client": "Android / Windows",
            "bridge": "runtime_orchestrator_bridge",
            "gateway": "owner_runtime_gateway",
            "orchestrator": "orchestrator",
            "main_backend": "main.py",
        },
        "request_id": request_id_for(request),
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health(
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(request)

    try:
        result = await gateway.request(
            "GET",
            "/health",
            request_id=request_id,
        )

        gateway_healthy = (
            result.get("status")
            in {"healthy", "ok", "running", "online"}
        )

        return {
            "status": (
                "healthy"
                if gateway_healthy
                else "degraded"
            ),
            "bridge": "online",
            "runtime_gateway": (
                "online"
                if gateway_healthy
                else "reachable"
            ),
            "gateway_response": result,
            "request_id": request_id,
        }

    except HTTPException:
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "bridge": "online",
                "runtime_gateway": "unavailable",
                "request_id": request_id,
            },
        )


# ============================================================
# SYSTEM MAP
# ============================================================

@app.get("/system-map")
async def system_map(
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(request)

    return await gateway.request(
        "GET",
        "/arya/system-map",
        request_id=request_id,
    )


# ============================================================
# RUNTIME SERVICES
# ============================================================

@app.get("/services")
async def services(
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(request)

    return await gateway.request(
        "GET",
        "/runtime/services",
        request_id=request_id,
    )


@app.get("/providers")
async def providers(
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(request)

    return await gateway.request(
        "GET",
        "/runtime/providers",
        request_id=request_id,
    )


# ============================================================
# GENERIC ORCHESTRATION
# ============================================================

@app.post("/orchestrate")
async def orchestrate(
    body: BridgeRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
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

    # OWNER Runtime Gateway v2.0.0 does not define a direct
    # POST /orchestrate route. Its compatibility route
    # /runtime/{runtime_path:path} forwards to the configured
    # orchestrator service. Therefore use /runtime/orchestrate.
    return await gateway.request(
        "POST",
        "/runtime/orchestrate",
        payload,
        request_id,
    )


# ============================================================
# UNIFIED ARYA DOCTOR
# ============================================================

@app.post("/arya/doctor")
async def arya_doctor(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    payload = dict(body.payload)

    payload.setdefault(
        "request_id",
        request_id,
    )

    # The supplied Gateway version does not expose a direct
    # /arya/doctor route. Forward this request through its
    # orchestrator compatibility route.
    return await gateway.request(
        "POST",
        "/runtime/arya/doctor",
        payload,
        request_id,
    )


# ============================================================
# AGRICULTURAL ANALYSIS
# ============================================================

@app.post("/arya/analyze")
async def arya_analyze(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    payload = dict(body.payload)

    payload.setdefault(
        "request_id",
        request_id,
    )

    return await gateway.request(
        "POST",
        "/arya/analyze",
        payload,
        request_id,
    )


# ============================================================
# DIAGNOSIS
# ============================================================

@app.post("/arya/diagnose")
async def arya_diagnose(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    payload = dict(body.payload)

    payload.setdefault(
        "request_id",
        request_id,
    )

    return await gateway.request(
        "POST",
        "/arya/diagnose",
        payload,
        request_id,
    )


# ============================================================
# RECOMMENDATION
# ============================================================

@app.post("/arya/recommend")
async def arya_recommend(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    payload = dict(body.payload)

    payload.setdefault(
        "request_id",
        request_id,
    )

    return await gateway.request(
        "POST",
        "/arya/recommend",
        payload,
        request_id,
    )


# ============================================================
# VISION
# ============================================================

@app.post("/arya/vision")
async def arya_vision(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    payload = dict(body.payload)

    payload.setdefault(
        "request_id",
        request_id,
    )

    return await gateway.request(
        "POST",
        "/arya/vision",
        payload,
        request_id,
    )


# ============================================================
# VOICE
# ============================================================

@app.post("/arya/voice")
async def arya_voice(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    payload = dict(body.payload)

    payload.setdefault(
        "request_id",
        request_id,
    )

    # The current Gateway /arya/voice implementation accepts
    # POST requests. This forwards the JSON payload unchanged.
    # Raw multipart/audio forwarding requires the Gateway itself
    # to forward the original request body to voice_language.
    return await gateway.request(
        "POST",
        "/arya/voice",
        payload,
        request_id,
    )


# ============================================================
# PAYMENT
# ============================================================

@app.post("/arya/payment")
async def arya_payment(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    payload = dict(body.payload)

    payload.setdefault(
        "request_id",
        request_id,
    )

    return await gateway.request(
        "POST",
        "/arya/payment",
        payload,
        request_id,
    )


# ============================================================
# WEATHER
# ============================================================

@app.post("/arya/weather")
async def arya_weather(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    payload = body.payload

    latitude = payload.get(
        "latitude",
        payload.get("lat"),
    )

    longitude = payload.get(
        "longitude",
        payload.get("lon", payload.get("lng")),
    )

    if latitude is None or longitude is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "Weather requests require latitude "
                "and longitude"
            ),
        )

    try:
        latitude = float(latitude)
        longitude = float(longitude)

    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid latitude or longitude",
        ) from exc

    if not -90 <= latitude <= 90:
        raise HTTPException(
            status_code=422,
            detail="Latitude must be between -90 and 90",
        )

    if not -180 <= longitude <= 180:
        raise HTTPException(
            status_code=422,
            detail="Longitude must be between -180 and 180",
        )

    return await gateway.request(
        "GET",
        "/arya/weather",
        request_id=request_id,
        query={
            "latitude": latitude,
            "longitude": longitude,
        },
    )


# ============================================================
# GEOCODING
# ============================================================

@app.post("/arya/geocode")
async def arya_geocode(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    name = (
        body.payload.get("name")
        or body.payload.get("location")
        or body.payload.get("place")
    )

    if not isinstance(name, str) or not name.strip():
        raise HTTPException(
            status_code=422,
            detail="A non-empty location name is required",
        )

    return await gateway.request(
        "GET",
        "/arya/geocode",
        request_id=request_id,
        query={
            "name": name.strip(),
        },
    )


# ============================================================
# DATA UPDATE STATUS
# ============================================================

@app.post("/arya/updates")
async def arya_updates(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    # Gateway v2.0.0 defines GET /arya/updates for status.
    # This bridge POST route is retained for compatibility.
    return await gateway.request(
        "GET",
        "/arya/updates",
        request_id=request_id,
    )


# ============================================================
# RUN DATA UPDATE
# ============================================================

@app.post("/arya/updates/run")
async def arya_updates_run(
    body: DoctorRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    payload = dict(body.payload)

    payload.setdefault(
        "request_id",
        request_id,
    )

    return await gateway.request(
        "POST",
        "/arya/updates/run",
        payload,
        request_id,
    )


# ============================================================
# DIRECT RUNTIME CALL
# ============================================================

@app.post("/runtime/call")
async def runtime_call(
    body: RuntimeCallRequest,
    request: Request,
):
    authenticate_bridge_request(request)

    request_id = request_id_for(
        request,
        body.request_id,
    )

    method = body.method.upper()

    if method not in {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        raise HTTPException(
            status_code=400,
            detail="Unsupported runtime HTTP method",
        )

    if (
        body.path.startswith(
            ("http://", "https://", "//"),
        )
        or "\\" in body.path
        or any(
            part == ".."
            for part in body.path.split("/")
        )
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid runtime service path",
        )

    # Gateway v2.0.0 expects service_id, not service.
    # Its RuntimeCallRequest also supports query and headers.
    payload = {
        "service_id": body.service,
        "path": body.path,
        "method": method,
        "payload": body.payload,
    }

    return await gateway.request(
        "POST",
        "/runtime/call",
        payload,
        request_id,
    )


# ============================================================
# INFORMATION
# ============================================================

@app.get("/info")
async def info(
    request: Request,
):
    authenticate_bridge_request(request)

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
            "request_size_limit",
            "response_size_limit",
        ],
    }


# ============================================================
# HTTP EXCEPTION HANDLER
# ============================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
):
    request_id = normalize_request_id(
        getattr(
            request.state,
            "arya_request_id",
            None,
        )
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "request_failed",
            "detail": exc.detail,
            "request_id": request_id,
        },
        headers={
            "X-ARYA-Request-ID": request_id,
        },
    )


# ============================================================
# GENERIC EXCEPTION HANDLER
# ============================================================

@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request,
    exc: Exception,
):
    request_id = normalize_request_id(
        getattr(
            request.state,
            "arya_request_id",
            None,
        )
    )

    logger.exception(
        "Unhandled bridge error; request_id=%s",
        request_id,
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected bridge error occurred",
            "request_id": request_id,
        },
        headers={
            "X-ARYA-Request-ID": request_id,
        },
    )


# ============================================================
# LOCAL EXECUTION
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level=LOG_LEVEL.lower(),
        reload=False,
    )
