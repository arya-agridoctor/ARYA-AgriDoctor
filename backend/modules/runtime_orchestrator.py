"""
ARYA AgriDoctor
Runtime Orchestrator
Version: 1.1.0

Purpose:
- Connect ARYA Orchestrator to Owner Runtime Gateway.
- Keep runtime service/provider discovery outside main.py.
- Provide a stable API for Android/Windows clients.
- Route agricultural, vision, voice, payment, weather, geocode and update
  requests through the Runtime Gateway.
- Do not store provider secrets in this module.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Runtime Orchestrator"
APP_VERSION = "1.1.0"

HOST = os.getenv(
    "ARYA_RUNTIME_ORCHESTRATOR_HOST",
    "127.0.0.1",
).strip() or "127.0.0.1"


def read_int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default

    return max(minimum, min(value, maximum))


def read_float_env(
    name: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default

    if value != value or value in (float("inf"), float("-inf")):
        value = default

    return max(minimum, min(value, maximum))


PORT = read_int_env(
    "ARYA_RUNTIME_ORCHESTRATOR_PORT",
    8017,
    1,
    65535,
)

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).strip().rstrip("/")

REQUEST_TIMEOUT = read_float_env(
    "ARYA_RUNTIME_ORCHESTRATOR_TIMEOUT",
    60.0,
    1.0,
    300.0,
)

MAX_RESPONSE_BYTES = read_int_env(
    "ARYA_RUNTIME_ORCHESTRATOR_MAX_RESPONSE_BYTES",
    10 * 1024 * 1024,
    1024,
    100 * 1024 * 1024,
)

MAX_REQUEST_BYTES = read_int_env(
    "ARYA_RUNTIME_ORCHESTRATOR_MAX_REQUEST_BYTES",
    10 * 1024 * 1024,
    1024,
    100 * 1024 * 1024,
)

INTERNAL_SECRET = os.getenv(
    "ARYA_RUNTIME_ORCHESTRATOR_SECRET",
    "",
).strip()

LOG_LEVEL = os.getenv(
    "ARYA_RUNTIME_ORCHESTRATOR_LOG_LEVEL",
    "INFO",
).upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger("arya.runtime_orchestrator")


# ============================================================
# Gateway URL validation
# ============================================================

def validate_gateway_url(value: str) -> str:
    """
    Validate the configured Gateway URL.

    Loopback/private hosts are allowed because this application commonly
    communicates with services on the same machine or private network.
    This function does not perform DNS resolution or outbound requests.
    """
    if not value:
        raise RuntimeError("ARYA_RUNTIME_GATEWAY_URL is empty")

    if len(value) > 2048:
        raise RuntimeError("ARYA_RUNTIME_GATEWAY_URL is too long")

    if any(ord(character) < 32 for character in value):
        raise RuntimeError("ARYA_RUNTIME_GATEWAY_URL contains control characters")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("ARYA_RUNTIME_GATEWAY_URL is invalid") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise RuntimeError("Runtime Gateway URL must use HTTP or HTTPS")

    if not parsed.hostname:
        raise RuntimeError("Runtime Gateway URL must include a hostname")

    if parsed.username is not None or parsed.password is not None:
        raise RuntimeError("Gateway credentials must not be embedded in the URL")

    if parsed.query or parsed.fragment:
        raise RuntimeError(
            "Runtime Gateway URL must not contain a query or fragment"
        )

    if port is not None and not 1 <= port <= 65535:
        raise RuntimeError("Runtime Gateway URL contains an invalid port")

    return value.rstrip("/")


RUNTIME_GATEWAY_URL = validate_gateway_url(RUNTIME_GATEWAY_URL)


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Runtime orchestration layer for ARYA AgriDoctor. "
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
# Response and validation helpers
# ============================================================

def validate_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail="payload must be a JSON object",
        )

    try:
        json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="payload must contain valid JSON-compatible values",
        )

    return payload


def validate_action(action: str) -> str:
    action = str(action or "").strip()

    if not action:
        raise HTTPException(
            status_code=400,
            detail="action is required",
        )

    if len(action) > 100:
        raise HTTPException(
            status_code=400,
            detail="action is too long",
        )

    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", action):
        raise HTTPException(
            status_code=400,
            detail="action contains invalid characters",
        )

    return action


def parse_json_response(response: httpx.Response) -> Any:
    try:
        return response.json()
    except (ValueError, json.JSONDecodeError):
        return {
            "success": True,
            "data": response.text,
        }


def safe_error_body(response: httpx.Response) -> Any:
    """
    Return a bounded error body without exposing arbitrary upstream text
    in the public error message.
    """
    content_type = response.headers.get("content-type", "").lower()

    if "application/json" in content_type:
        try:
            body = response.json()

            if isinstance(body, dict):
                # Preserve structured upstream errors while avoiding an
                # unbounded response body in the outgoing error.
                return {
                    str(key)[:100]: value
                    for key, value in list(body.items())[:30]
                }

            return body
        except (ValueError, json.JSONDecodeError):
            pass

    return {
        "message": "Runtime Gateway returned a non-JSON error response"
    }


# ============================================================
# Runtime client
# ============================================================

class RuntimeGatewayClient:
    """
    HTTP client for Owner Runtime Gateway.

    Provider credentials are not stored here. The optional internal
    credential is used only to authenticate this service to the Gateway.
    """

    def __init__(self, base_url: str):
        self.base_url = validate_gateway_url(base_url)
        self._client: Optional[httpx.AsyncClient] = None

    async def start(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(REQUEST_TIMEOUT),
                follow_redirects=False,
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                ),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _headers(self, request_id: str) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ARYA-Request-ID": request_id,
        }

        # This header must match the authentication contract implemented
        # by the actual Runtime Gateway.
        if INTERNAL_SECRET:
            headers["X-ARYA-Internal-Secret"] = INTERNAL_SECRET

        return headers

    async def request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        if not path.startswith("/"):
            path = "/" + path

        if "://" in path or path.startswith("//"):
            raise HTTPException(
                status_code=400,
                detail="Invalid Gateway path",
            )

        request_id = str(uuid.uuid4())
        url = f"{self.base_url}{path}"

        started = time.monotonic()
        request_payload = validate_payload(payload or {})

        if self._client is None:
            await self.start()

        assert self._client is not None

        try:
            # Stream the response so the configured response-size limit
            # can be enforced before reading an unlimited response body.
            async with self._client.stream(
                method=method.upper(),
                url=url,
                json=request_payload,
                headers=self._headers(request_id),
            ) as response:

                content_length = response.headers.get("content-length")

                if content_length:
                    try:
                        declared_length = int(content_length)
                    except ValueError:
                        declared_length = -1

                    if declared_length > MAX_RESPONSE_BYTES:
                        raise HTTPException(
                            status_code=502,
                            detail={
                                "error": "runtime_gateway_response_too_large",
                                "request_id": request_id,
                            },
                        )

                chunks = []
                total_bytes = 0

                async for chunk in response.aiter_bytes():
                    total_bytes += len(chunk)

                    if total_bytes > MAX_RESPONSE_BYTES:
                        raise HTTPException(
                            status_code=502,
                            detail={
                                "error": "runtime_gateway_response_too_large",
                                "request_id": request_id,
                            },
                        )

                    chunks.append(chunk)

                response_content = b"".join(chunks)

                elapsed_ms = round(
                    (time.monotonic() - started) * 1000,
                    2,
                )

                content_type = response.headers.get(
                    "content-type",
                    "",
                ).lower()

                if response.status_code >= 400:
                    upstream_body: Any

                    if "application/json" in content_type:
                        try:
                            upstream_body = json.loads(
                                response_content.decode(
                                    response.encoding or "utf-8",
                                    errors="replace",
                                )
                            )
                        except (ValueError, json.JSONDecodeError):
                            upstream_body = {
                                "message": "Runtime Gateway returned an invalid JSON error"
                            }
                    else:
                        upstream_body = {
                            "message": "Runtime Gateway returned an error"
                        }

                    raise HTTPException(
                        status_code=(
                            response.status_code
                            if 400 <= response.status_code < 600
                            else 502
                        ),
                        detail={
                            "error": "runtime_gateway_error",
                            "request_id": request_id,
                            "gateway_status": response.status_code,
                            "gateway_response": upstream_body,
                            "elapsed_ms": elapsed_ms,
                        },
                    )

                try:
                    body = json.loads(
                        response_content.decode(
                            response.encoding or "utf-8",
                            errors="replace",
                        )
                    )
                except (ValueError, json.JSONDecodeError):
                    body = {
                        "success": True,
                        "data": response_content.decode(
                            response.encoding or "utf-8",
                            errors="replace",
                        ),
                    }

                if isinstance(body, dict):
                    body.setdefault("request_id", request_id)
                    body.setdefault("elapsed_ms", elapsed_ms)
                    return body

                return {
                    "success": True,
                    "data": body,
                    "request_id": request_id,
                    "elapsed_ms": elapsed_ms,
                }

        except HTTPException:
            raise

        except httpx.TimeoutException as exc:
            logger.warning(
                "Runtime Gateway timeout; request_id=%s",
                request_id,
            )

            raise HTTPException(
                status_code=504,
                detail={
                    "error": "runtime_gateway_timeout",
                    "request_id": request_id,
                },
            ) from exc

        except httpx.HTTPError as exc:
            # Log the technical exception internally; do not disclose
            # raw exception details to the public caller.
            logger.warning(
                "Runtime Gateway connection failed; request_id=%s; error_type=%s",
                request_id,
                type(exc).__name__,
            )

            raise HTTPException(
                status_code=502,
                detail={
                    "error": "runtime_gateway_connection_failed",
                    "request_id": request_id,
                },
            ) from exc

        except (OSError, UnicodeError) as exc:
            logger.warning(
                "Runtime Gateway processing failure; request_id=%s; error_type=%s",
                request_id,
                type(exc).__name__,
            )

            raise HTTPException(
                status_code=502,
                detail={
                    "error": "runtime_gateway_processing_failed",
                    "request_id": request_id,
                },
            ) from exc


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
        validate_payload(payload or {}),
    )


# ============================================================
# Request-size protection
# ============================================================

@app.middleware("http")
async def request_size_limit(
    request: Request,
    call_next,
):
    content_length = request.headers.get("content-length")

    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            return HTTPException(
                status_code=400,
                detail="Invalid Content-Length header",
            )

        if declared_length < 0:
            return HTTPException(
                status_code=400,
                detail="Invalid Content-Length header",
            )

        if declared_length > MAX_REQUEST_BYTES:
            return HTTPException(
                status_code=413,
                detail="Request body too large",
            )

    return await call_next(request)


# ============================================================
# Lifecycle
# ============================================================

@app.on_event("startup")
async def startup_event() -> None:
    await gateway.start()

    logger.info(
        "%s started; gateway configured=%s",
        APP_NAME,
        bool(RUNTIME_GATEWAY_URL),
    )

    if not INTERNAL_SECRET:
        logger.warning(
            "ARYA_RUNTIME_ORCHESTRATOR_SECRET is not configured. "
            "Gateway authentication may reject requests."
        )


@app.on_event("shutdown")
async def shutdown_event() -> None:
    await gateway.close()


# ============================================================
# Root / health
# ============================================================

@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "architecture": (
            "ARYA -> Runtime Orchestrator -> Owner Runtime Gateway"
        ),
    }


@app.get("/health")
async def health() -> Dict[str, Any]:
    gateway_status = "offline"

    try:
        result = await gateway.request("GET", "/health")

        if isinstance(result, dict):
            gateway_status = "online"
        else:
            gateway_status = "degraded"

    except HTTPException as exc:
        gateway_status = (
            "degraded"
            if exc.status_code in (401, 403)
            else "offline"
        )

    except Exception:
        logger.exception("Unexpected Runtime Gateway health-check failure")
        gateway_status = "offline"

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "runtime_gateway": gateway_status,
    }


# ============================================================
# Runtime discovery
# ============================================================

@app.get("/runtime/services")
async def runtime_services() -> Dict[str, Any]:
    return await gateway.request(
        "GET",
        "/runtime/services",
    )


@app.get("/runtime/providers")
async def runtime_providers() -> Dict[str, Any]:
    return await gateway.request(
        "GET",
        "/runtime/providers",
    )


@app.get("/runtime/system-map")
async def runtime_system_map() -> Dict[str, Any]:
    return await gateway.request(
        "GET",
        "/arya/system-map",
    )


# ============================================================
# Generic runtime action
# ============================================================

@app.post("/runtime/call")
async def runtime_call(
    request: RuntimeRequest,
) -> Dict[str, Any]:

    action = validate_action(request.action)
    payload = validate_payload(request.payload)

    return await gateway_call(
        "/runtime/call",
        {
            "action": action,
            "payload": payload,
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
        validate_payload(request.payload),
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
        validate_payload(request.payload),
    )


@app.post("/arya/diagnose")
async def arya_diagnose(
    request: DiagnoseRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/diagnose",
        validate_payload(request.payload),
    )


@app.post("/arya/recommend")
async def arya_recommend(
    request: RecommendRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/recommend",
        validate_payload(request.payload),
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
        validate_payload(request.payload),
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
        validate_payload(request.payload),
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
        validate_payload(request.payload),
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
        validate_payload(request.payload),
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
        validate_payload(request.payload),
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
        validate_payload(request.payload),
    )


@app.post("/arya/updates/run")
async def arya_updates_run(
    request: UpdateRequest,
) -> Dict[str, Any]:

    return await gateway_call(
        "/arya/updates/run",
        validate_payload(request.payload),
    )


# ============================================================
# Service information
# ============================================================

@app.get("/info")
async def info() -> Dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
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
            "runtime_services": "/runtime/services",
            "runtime_providers": "/runtime/providers",
            "runtime_system_map": "/runtime/system-map",
        },
    }


# ============================================================
# Application entry point
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        reload=False,
    )
