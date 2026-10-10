"""
ARYA AgriDoctor
Final Control Center
Version: 1.1.0

Independent final control/orchestration layer.

Security improvements:
- Restrict generic service calls to configured services and safe paths.
- Add optional control-center API key authentication.
- Validate request IDs, HTTP methods and paths.
- Avoid exposing internal exception details.
- Correct health-check status evaluation.
- Limit downstream response size.
- Preserve existing public endpoint names.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import logging
import os
import re
import time
import uuid
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ConfigDict


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "ARYA Final Control Center"
APP_VERSION = "1.1.0"

HOST = os.getenv("ARYA_CONTROL_CENTER_HOST", "127.0.0.1")

PORT = int(os.getenv("ARYA_CONTROL_CENTER_PORT", "8020"))

REQUEST_TIMEOUT = float(
    os.getenv("ARYA_CONTROL_CENTER_TIMEOUT", "45")
)

HEALTH_TIMEOUT = float(
    os.getenv("ARYA_CONTROL_CENTER_HEALTH_TIMEOUT", "8")
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_CONTROL_CENTER_MAX_RESPONSE",
        str(15 * 1024 * 1024),
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_CONTROL_CENTER_MAX_REQUEST",
        str(2 * 1024 * 1024),
    )
)

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
).strip()

# If configured, clients must send:
# X-ARYA-Control-Key: <secret>
CONTROL_API_KEY = os.getenv(
    "ARYA_CONTROL_CENTER_API_KEY",
    "",
).strip()

# Keep False only when authentication is enforced by a trusted
# reverse proxy or another external security layer.
ALLOW_UNAUTHENTICATED_CONTROL = (
    os.getenv(
        "ARYA_CONTROL_CENTER_ALLOW_UNAUTHENTICATED",
        "false",
    ).strip().lower()
    in {"1", "true", "yes"}
)

REQUEST_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9._:-]{1,128}$"
)

ALLOWED_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}

logger = logging.getLogger("arya.final_control_center")


# ============================================================
# EXISTING ARYA SERVICES
# ============================================================

SERVICES: Dict[str, str] = {
    "vision": os.getenv(
        "ARYA_VISION_URL",
        "http://127.0.0.1:8001",
    ),

    "voice_language": os.getenv(
        "ARYA_VOICE_LANGUAGE_URL",
        "http://127.0.0.1:8002",
    ),

    "agri_engine": os.getenv(
        "ARYA_AGRI_ENGINE_URL",
        "http://127.0.0.1:8003",
    ),

    "commerce_security": os.getenv(
        "ARYA_COMMERCE_SECURITY_URL",
        "http://127.0.0.1:8004",
    ),

    "orchestrator": os.getenv(
        "ARYA_ORCHESTRATOR_URL",
        "http://127.0.0.1:8010",
    ),

    "owner_integration": os.getenv(
        "ARYA_OWNER_INTEGRATION_URL",
        "http://127.0.0.1:8015",
    ),

    "runtime_gateway": os.getenv(
        "ARYA_RUNTIME_GATEWAY_URL",
        "http://127.0.0.1:8016",
    ),
}


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Independent final control and orchestration layer "
        "for ARYA AgriDoctor."
    ),
)


# ============================================================
# REQUEST MODELS
# ============================================================

class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


class ServiceCallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    path: str = Field(
        "/",
        min_length=1,
        max_length=500,
    )

    method: str = Field(
        "POST",
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


class DoctorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = Field(
        default=None,
        max_length=128,
    )


# ============================================================
# SECURITY HELPERS
# ============================================================

def _is_loopback_url(url: str) -> bool:
    """
    Check whether a configured URL points to a loopback address.

    Hostnames other than localhost are not assumed to be loopback.
    """
    try:
        parsed = urlsplit(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        if hostname.lower() == "localhost":
            return True

        try:
            return ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            return False

    except Exception:
        return False


def _validate_service_configuration() -> None:
    """
    Reject malformed service URLs at startup.

    Non-loopback service URLs require an explicit opt-in because
    internal service credentials may be forwarded to them.
    """
    allow_remote = (
        os.getenv(
            "ARYA_CONTROL_CENTER_ALLOW_REMOTE_SERVICES",
            "false",
        ).strip().lower()
        in {"1", "true", "yes"}
    )

    for name, url in SERVICES.items():
        parsed = urlsplit(url)

        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeError(
                f"Invalid configured URL for service: {name}"
            )

        if not _is_loopback_url(url) and not allow_remote:
            raise RuntimeError(
                f"Remote service '{name}' requires "
                "ARYA_CONTROL_CENTER_ALLOW_REMOTE_SERVICES=true"
            )


def _authenticate(request: Request) -> None:
    """
    Authenticate access to the control center.

    When CONTROL_API_KEY is configured, the matching header is
    mandatory. Without a key, access is denied unless an explicit
    external-security deployment mode has been enabled.
    """
    if not CONTROL_API_KEY:
        if ALLOW_UNAUTHENTICATED_CONTROL:
            return

        raise HTTPException(
            status_code=503,
            detail=(
                "Control-center authentication is not configured."
            ),
        )

    supplied = request.headers.get(
        "X-ARYA-Control-Key",
        "",
    )

    if not supplied or not hmac.compare_digest(
        supplied,
        CONTROL_API_KEY,
    ):
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


def _validate_request_id(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    if not REQUEST_ID_PATTERN.fullmatch(value):
        raise HTTPException(
            status_code=400,
            detail="Invalid request ID.",
        )

    return value


def get_request_id(
    supplied: Optional[str],
    request: Optional[Request] = None,
) -> str:
    supplied = _validate_request_id(supplied)

    if supplied:
        return supplied

    if request is not None:
        header_value = _validate_request_id(
            request.headers.get("X-ARYA-Request-ID")
        )

        if header_value:
            return header_value

    return str(uuid.uuid4())


def _validate_path(path: str) -> str:
    """
    Reject URL overrides, path traversal, control characters,
    query strings and fragments in generic service-call paths.
    """
    if not path or len(path) > 500:
        raise HTTPException(
            status_code=400,
            detail="Invalid service path.",
        )

    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise HTTPException(
            status_code=400,
            detail="Invalid service path.",
        )

    if "\\" in path:
        raise HTTPException(
            status_code=400,
            detail="Invalid service path.",
        )

    parsed = urlsplit(path)

    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise HTTPException(
            status_code=400,
            detail="Only relative service paths are allowed.",
        )

    segments = path.split("/")

    if any(segment in {".", ".."} for segment in segments):
        raise HTTPException(
            status_code=400,
            detail="Path traversal is not allowed.",
        )

    return "/" + path.lstrip("/")


def build_headers(request_id: str) -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": f"ARYA-Final-Control-Center/{APP_VERSION}",
        "X-ARYA-Request-ID": request_id,
    }

    if INTERNAL_SECRET:
        headers["X-ARYA-Internal-Secret"] = INTERNAL_SECRET

    return headers


# ============================================================
# REQUEST SIZE MIDDLEWARE
# ============================================================

@app.middleware("http")
async def request_security_middleware(
    request: Request,
    call_next,
):
    request_id = request.headers.get("X-ARYA-Request-ID")

    try:
        request_id = _validate_request_id(request_id)
    except HTTPException:
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid request ID."},
        )

    request_id = request_id or str(uuid.uuid4())
    request.state.arya_request_id = request_id

    content_length = request.headers.get("content-length")

    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large."},
                    headers={"X-ARYA-Request-ID": request_id},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length."},
                headers={"X-ARYA-Request-ID": request_id},
            )

    response = await call_next(request)

    response.headers["X-ARYA-Request-ID"] = request_id

    return response


# ============================================================
# SERVICE HELPERS
# ============================================================

def get_service_url(service: str) -> str:
    url = SERVICES.get(service)

    if not url:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "Unknown ARYA service.",
                "service": service,
            },
        )

    return url.rstrip("/")


# ============================================================
# GENERIC SERVICE CALL
# ============================================================

async def call_service(
    service: str,
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]],
    request_id: str,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:

    base_url = get_service_url(service)

    clean_path = _validate_path(path)

    method = method.upper()

    if method not in ALLOWED_METHODS:
        raise HTTPException(
            status_code=405,
            detail="HTTP method is not allowed.",
        )

    if timeout is None:
        effective_timeout = REQUEST_TIMEOUT
    else:
        effective_timeout = min(
            max(float(timeout), 0.1),
            REQUEST_TIMEOUT,
        )

    url = base_url + clean_path
    started = time.monotonic()

    try:
        async with httpx.AsyncClient(
            timeout=effective_timeout,
            follow_redirects=False,
            headers=build_headers(request_id),
            trust_env=False,
        ) as client:

            response = await client.request(
                method,
                url,
                json=payload if method != "GET" else None,
            )

        elapsed = round(
            (time.monotonic() - started) * 1000,
            2,
        )

        if len(response.content) > MAX_RESPONSE_BYTES:
            raise HTTPException(
                status_code=502,
                detail="ARYA service response exceeded maximum size.",
            )

        try:
            data: Any = response.json()
        except ValueError:
            data = response.text[:10000]

        if response.status_code >= 400:
            logger.warning(
                "Downstream service error: service=%s status=%s request_id=%s",
                service,
                response.status_code,
                request_id,
            )

            raise HTTPException(
                status_code=502,
                detail={
                    "message": "Downstream ARYA service returned an error.",
                    "service": service,
                    "status_code": response.status_code,
                    "response": data,
                    "request_id": request_id,
                },
            )

        return {
            "ok": True,
            "service": service,
            "status_code": response.status_code,
            "elapsed_ms": elapsed,
            "request_id": request_id,
            "data": data,
        }

    except HTTPException:
        raise

    except httpx.TimeoutException as exc:
        logger.warning(
            "Downstream timeout: service=%s request_id=%s",
            service,
            request_id,
        )

        raise HTTPException(
            status_code=504,
            detail={
                "message": "ARYA service timeout.",
                "service": service,
                "request_id": request_id,
            },
        ) from exc

    except httpx.HTTPError as exc:
        logger.warning(
            "Downstream connection error: service=%s type=%s request_id=%s",
            service,
            type(exc).__name__,
            request_id,
        )

        raise HTTPException(
            status_code=502,
            detail={
                "message": "ARYA service is unreachable.",
                "service": service,
                "request_id": request_id,
            },
        ) from exc


# ============================================================
# HEALTH
# ============================================================

async def check_service_health(
    name: str,
    url: str,
) -> Dict[str, Any]:

    started = time.monotonic()
    request_id = str(uuid.uuid4())

    try:
        async with httpx.AsyncClient(
            timeout=HEALTH_TIMEOUT,
            follow_redirects=False,
            headers=build_headers(request_id),
            trust_env=False,
        ) as client:

            response = await client.get(
                f"{url.rstrip('/')}/health"
            )

        elapsed = round(
            (time.monotonic() - started) * 1000,
            2,
        )

        # A successful health check must return 2xx.
        online = 200 <= response.status_code < 300

        return {
            "service": name,
            "url": url,
            "online": online,
            "status_code": response.status_code,
            "elapsed_ms": elapsed,
        }

    except Exception as exc:
        logger.warning(
            "Health check failed: service=%s type=%s",
            name,
            type(exc).__name__,
        )

        return {
            "service": name,
            "url": url,
            "online": False,
            "status_code": None,
            "error": "Health check failed.",
        }


async def check_all_services() -> Dict[str, Any]:
    results = await asyncio.gather(
        *(
            check_service_health(name, url)
            for name, url in SERVICES.items()
        )
    )

    online = sum(
        1
        for result in results
        if result.get("online", False)
    )

    total = len(results)

    return {
        "control_center": "online",
        "services_online": online,
        "services_total": total,
        "all_online": online == total,
        "services": results,
    }


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "role": "final-independent-control-layer",
        "main_py_modified": False,
        "existing_modules_modified": False,
        "port": PORT,
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health(request: Request):
    _authenticate(request)
    return await check_all_services()


# ============================================================
# SERVICES
# ============================================================

@app.get("/services")
async def services(request: Request):
    _authenticate(request)

    return {
        "services": SERVICES,
        "count": len(SERVICES),
    }


# ============================================================
# SYSTEM STATUS
# ============================================================

@app.get("/system/status")
async def system_status(request: Request):
    _authenticate(request)

    health_result = await check_all_services()

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": (
            "online"
            if health_result["all_online"]
            else "degraded"
        ),
        "health": health_result,
        "architecture": {
            "client": "Android / Windows",
            "control_center": "arya_final_control_center",
            "runtime_gateway": SERVICES["runtime_gateway"],
            "owner_integration": SERVICES["owner_integration"],
            "orchestrator": SERVICES["orchestrator"],
            "agri_engine": SERVICES["agri_engine"],
            "vision": SERVICES["vision"],
            "voice_language": SERVICES["voice_language"],
            "commerce_security": SERVICES["commerce_security"],
        },
    }


# ============================================================
# GENERIC SERVICE CALL
# ============================================================

@app.post("/service/call")
async def service_call(
    body: ServiceCallRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(
        body.request_id,
        request,
    )

    return await call_service(
        service=body.service,
        method=body.method,
        path=body.path,
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# UNIFIED DOCTOR
# ============================================================

@app.post("/arya/doctor")
async def arya_doctor(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="orchestrator",
        method="POST",
        path="/arya/doctor",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# ORCHESTRATION
# ============================================================

@app.post("/arya/orchestrate")
async def arya_orchestrate(
    body: ActionRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    payload = dict(body.payload)
    payload.setdefault("action", body.action)
    payload.setdefault("request_id", request_id)

    return await call_service(
        service="orchestrator",
        method="POST",
        path="/orchestrate",
        payload=payload,
        request_id=request_id,
    )


# ============================================================
# AGRICULTURAL ANALYSIS
# ============================================================

@app.post("/arya/analyze")
async def arya_analyze(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="agri_engine",
        method="POST",
        path="/agri/analyze",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# DIAGNOSIS
# ============================================================

@app.post("/arya/diagnose")
async def arya_diagnose(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="agri_engine",
        method="POST",
        path="/agri/diagnose",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# RECOMMENDATION
# ============================================================

@app.post("/arya/recommend")
async def arya_recommend(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="agri_engine",
        method="POST",
        path="/agri/recommend",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# VISION
# ============================================================

@app.post("/arya/vision")
async def arya_vision(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="vision",
        method="POST",
        path="/vision/analyze",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# VOICE / LANGUAGE
# ============================================================

@app.post("/arya/voice")
async def arya_voice(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="voice_language",
        method="POST",
        path="/voice",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# PAYMENT
# ============================================================

@app.post("/arya/payment")
async def arya_payment(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="commerce_security",
        method="POST",
        path="/commerce/payment",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# WEATHER
# ============================================================

@app.post("/arya/weather")
async def arya_weather(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="runtime_gateway",
        method="POST",
        path="/arya/weather",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# GEOCODING
# ============================================================

@app.post("/arya/geocode")
async def arya_geocode(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="runtime_gateway",
        method="POST",
        path="/arya/geocode",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# DATA UPDATE
# ============================================================

@app.post("/arya/updates")
async def arya_updates(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="runtime_gateway",
        method="POST",
        path="/arya/updates",
        payload=body.payload,
        request_id=request_id,
    )


@app.post("/arya/updates/run")
async def arya_updates_run(
    body: DoctorRequest,
    request: Request,
):
    _authenticate(request)

    request_id = get_request_id(body.request_id, request)

    return await call_service(
        service="runtime_gateway",
        method="POST",
        path="/arya/updates/run",
        payload=body.payload,
        request_id=request_id,
    )


# ============================================================
# OWNER STATUS
# ============================================================

@app.get("/owner/status")
async def owner_status(request: Request):
    _authenticate(request)

    request_id = get_request_id(None, request)

    return await call_service(
        service="owner_integration",
        method="GET",
        path="/owner/status",
        payload=None,
        request_id=request_id,
    )


# ============================================================
# RUNTIME SERVICES
# ============================================================

@app.get("/runtime/services")
async def runtime_services(request: Request):
    _authenticate(request)

    request_id = get_request_id(None, request)

    return await call_service(
        service="runtime_gateway",
        method="GET",
        path="/runtime/services",
        payload=None,
        request_id=request_id,
    )


# ============================================================
# RUNTIME PROVIDERS
# ============================================================

@app.get("/runtime/providers")
async def runtime_providers(request: Request):
    _authenticate(request)

    request_id = get_request_id(None, request)

    return await call_service(
        service="runtime_gateway",
        method="GET",
        path="/runtime/providers",
        payload=None,
        request_id=request_id,
    )


# ============================================================
# INFORMATION
# ============================================================

@app.get("/info")
async def info(request: Request):
    _authenticate(request)

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "purpose": (
            "Single independent control layer "
            "for existing ARYA services."
        ),
        "existing_files_changed": False,
        "main_py_changed": False,
        "domains": [
            "orchestration",
            "agriculture",
            "diagnosis",
            "recommendation",
            "vision",
            "voice",
            "language",
            "weather",
            "geocoding",
            "providers",
            "automatic_updates",
            "commerce",
            "owner",
            "runtime",
            "health",
        ],
        "configured_services": list(SERVICES.keys()),
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():
    _validate_service_configuration()

    if not CONTROL_API_KEY and not ALLOW_UNAUTHENTICATED_CONTROL:
        logger.warning(
            "Control API key is not configured. "
            "Protected endpoints will return HTTP 503."
        )

    logger.info("=" * 72)
    logger.info("%s %s", APP_NAME, APP_VERSION)
    logger.info("Host: %s", HOST)
    logger.info("Port: %s", PORT)
    logger.info("main.py: UNCHANGED")
    logger.info("Existing modules: UNCHANGED")
    logger.info("=" * 72)


# ============================================================
# LOCAL EXECUTION
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "arya_final_control_center:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
