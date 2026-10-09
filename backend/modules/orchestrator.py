"""
ARYA AgriDoctor
Orchestrator / Unified API Gateway
Version: 1.1.0

این فایل لایه هماهنگ‌کننده ARYA است.
به main.py و ماژول‌های موجود دست نمی‌زند.

قابلیت‌ها:
- مسیریابی درخواست‌ها به سرویس‌های ARYA
- هماهنگی تحلیل کشاورزی، تصویر و صدا
- بررسی سلامت سرویس‌ها
- مدیریت خطا و زمان انتظار
- ثبت درخواست‌ها و زمان پاسخ
- تنظیم آدرس سرویس‌ها از طریق متغیرهای محیطی
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, ConfigDict


# ============================================================
# Configuration
# ============================================================

SERVICE_NAME = "ARYA Orchestrator"
SERVICE_VERSION = "1.1.0"

HOST = os.getenv("ARYA_ORCHESTRATOR_HOST", "0.0.0.0")

try:
    PORT = int(os.getenv("ARYA_ORCHESTRATOR_PORT", "8010"))
except ValueError:
    PORT = 8010

if not 1 <= PORT <= 65535:
    PORT = 8010

LOG_LEVEL = os.getenv(
    "ARYA_ORCHESTRATOR_LOG_LEVEL",
    "INFO",
).upper()

if LOG_LEVEL not in logging._nameToLevel:
    LOG_LEVEL = "INFO"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("arya.orchestrator")


# ============================================================
# App
# ============================================================

app = FastAPI(
    title="ARYA AgriDoctor Orchestrator",
    description=(
        "Unified orchestration layer for ARYA AgriDoctor services. "
        "Coordinates Vision, Voice & Language, Agricultural Engine, "
        "and Commerce & Security services."
    ),
    version=SERVICE_VERSION,
)


# ============================================================
# Service Registry
# ============================================================

class ServiceDefinition(BaseModel):
    name: str
    base_url: str
    health_path: str = "/health"
    enabled: bool = True
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)

    model_config = ConfigDict(extra="forbid")


def normalize_base_url(value: str) -> str:
    """
    Validate and normalize a configured service URL.

    Production deployments should use HTTPS for remote services.
    Local HTTP is allowed for localhost and loopback addresses.
    """

    value = value.strip().rstrip("/")

    parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Service URL must use HTTP or HTTPS.")

    if not parsed.hostname:
        raise ValueError("Service URL must contain a hostname.")

    if parsed.username or parsed.password:
        raise ValueError(
            "Credentials must not be embedded in service URLs."
        )

    hostname = parsed.hostname.lower()

    local_hosts = {
        "localhost",
        "127.0.0.1",
        "::1",
    }

    if parsed.scheme == "http" and hostname not in local_hosts:
        raise ValueError(
            "Remote service URLs must use HTTPS."
        )

    if parsed.query or parsed.fragment:
        raise ValueError(
            "Service base URLs cannot contain a query or fragment."
        )

    return value


def create_service(
    name: str,
    environment_variable: str,
    default_url: str,
) -> ServiceDefinition:

    raw_url = os.getenv(
        environment_variable,
        default_url,
    )

    try:
        base_url = normalize_base_url(raw_url)
    except ValueError as exc:
        logger.error(
            "Invalid URL for service %s: %s",
            name,
            exc,
        )

        base_url = default_url

    try:
        timeout = float(
            os.getenv(
                f"ARYA_{name.upper()}_TIMEOUT",
                "30",
            )
        )
    except ValueError:
        timeout = 30.0

    timeout = max(1.0, min(timeout, 120.0))

    return ServiceDefinition(
        name=name,
        base_url=base_url,
        enabled=os.getenv(
            f"ARYA_{name.upper()}_ENABLED",
            "true",
        ).lower() in {"1", "true", "yes", "on"},
        timeout_seconds=timeout,
    )


DEFAULT_SERVICES: Dict[str, ServiceDefinition] = {
    "vision": create_service(
        "vision",
        "ARYA_VISION_URL",
        "http://127.0.0.1:8001",
    ),
    "voice_language": create_service(
        "voice_language",
        "ARYA_VOICE_LANGUAGE_URL",
        "http://127.0.0.1:8002",
    ),
    "agri_engine": create_service(
        "agri_engine",
        "ARYA_AGRI_ENGINE_URL",
        "http://127.0.0.1:8003",
    ),
    "commerce_security": create_service(
        "commerce_security",
        "ARYA_COMMERCE_SECURITY_URL",
        "http://127.0.0.1:8004",
    ),
}

service_registry: Dict[str, ServiceDefinition] = {
    name: definition.model_copy(deep=True)
    for name, definition in DEFAULT_SERVICES.items()
}


# ============================================================
# Request Models
# ============================================================

class OrchestrationRequest(BaseModel):
    action: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    user_id: Optional[int] = None
    device_id: Optional[str] = None

    language: Optional[str] = None
    country: Optional[str] = None

    location: Optional[Dict[str, Any]] = None

    farm: Optional[Dict[str, Any]] = None
    crop: Optional[Dict[str, Any]] = None
    soil: Optional[Dict[str, Any]] = None
    water: Optional[Dict[str, Any]] = None
    weather: Optional[Dict[str, Any]] = None

    image: Optional[Dict[str, Any]] = None
    voice: Optional[Dict[str, Any]] = None

    payment: Optional[Dict[str, Any]] = None

    data: Dict[str, Any] = Field(default_factory=dict)


class ServiceCallResult(BaseModel):
    service: str
    success: bool
    status_code: Optional[int] = None
    response: Any = None
    error: Optional[str] = None
    elapsed_ms: float = 0.0


# ============================================================
# Runtime State
# ============================================================

started_at = time.time()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def request_id() -> str:
    return str(uuid.uuid4())


# ============================================================
# HTTP Client
# ============================================================

async def call_service(
    service_name: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    method: str = "POST",
) -> ServiceCallResult:

    service = service_registry.get(service_name)

    if service is None:
        return ServiceCallResult(
            service=service_name,
            success=False,
            error="Service is not registered.",
        )

    if not service.enabled:
        return ServiceCallResult(
            service=service_name,
            success=False,
            error="Service is disabled.",
        )

    method = method.upper()

    if method not in {"GET", "POST"}:
        return ServiceCallResult(
            service=service_name,
            success=False,
            error="Unsupported HTTP method.",
        )

    if not path.startswith("/") or path.startswith("//"):
        return ServiceCallResult(
            service=service_name,
            success=False,
            error="Invalid service path.",
        )

    started = time.perf_counter()

    url = service.base_url.rstrip("/") + path

    try:
        timeout = httpx.Timeout(
            service.timeout_seconds,
            connect=min(service.timeout_seconds, 10.0),
        )

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as client:

            if method == "GET":
                response = await client.get(url)
            else:
                response = await client.post(
                    url,
                    json=payload or {},
                )

        elapsed = (
            time.perf_counter() - started
        ) * 1000

        try:
            response_data = response.json()
        except (ValueError, UnicodeDecodeError):
            response_data = response.text[:20000]

        return ServiceCallResult(
            service=service_name,
            success=200 <= response.status_code < 300,
            status_code=response.status_code,
            response=response_data,
            error=(
                None
                if 200 <= response.status_code < 300
                else f"Service returned HTTP {response.status_code}."
            ),
            elapsed_ms=round(elapsed, 2),
        )

    except httpx.TimeoutException:
        elapsed = (
            time.perf_counter() - started
        ) * 1000

        logger.warning(
            "Service timeout: %s %s",
            service_name,
            path,
        )

        return ServiceCallResult(
            service=service_name,
            success=False,
            error="Service request timed out.",
            elapsed_ms=round(elapsed, 2),
        )

    except httpx.RequestError:
        elapsed = (
            time.perf_counter() - started
        ) * 1000

        logger.warning(
            "Service connection failed: %s %s",
            service_name,
            path,
            exc_info=True,
        )

        return ServiceCallResult(
            service=service_name,
            success=False,
            error="Unable to connect to the service.",
            elapsed_ms=round(elapsed, 2),
        )

    except Exception:
        elapsed = (
            time.perf_counter() - started
        ) * 1000

        logger.exception(
            "Unexpected service error: %s %s",
            service_name,
            path,
        )

        return ServiceCallResult(
            service=service_name,
            success=False,
            error="Unexpected service communication error.",
            elapsed_ms=round(elapsed, 2),
        )


# ============================================================
# Action Routing
# ============================================================

VISION_ACTIONS = {
    "vision",
    "image",
    "image_analysis",
    "diagnose_image",
    "plant_image",
    "disease_image",
}

VOICE_ACTIONS = {
    "voice",
    "speech",
    "speech_to_text",
    "text_to_speech",
    "translate",
    "language",
}

AGRI_ACTIONS = {
    "agri",
    "agriculture",
    "analyze",
    "diagnose",
    "recommend",
    "crop_suitability",
    "soil",
    "water",
    "crop",
    "farm",
}

COMMERCE_ACTIONS = {
    "payment",
    "payments",
    "subscription",
    "activation",
    "device",
    "commerce",
    "security",
}

COMPOSITE_ACTIONS = {
    "full_diagnosis",
    "complete_diagnosis",
    "doctor",
    "agri_doctor",
}


def normalize_action(action: str) -> str:
    return (
        action.strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


def detect_services(action: str) -> list[str]:

    normalized = normalize_action(action)

    if normalized in COMPOSITE_ACTIONS:
        return [
            "vision",
            "voice_language",
            "agri_engine",
        ]

    services: list[str] = []

    if normalized in VISION_ACTIONS:
        services.append("vision")

    if normalized in VOICE_ACTIONS:
        services.append("voice_language")

    if normalized in AGRI_ACTIONS:
        services.append("agri_engine")

    if normalized in COMMERCE_ACTIONS:
        services.append("commerce_security")

    return services


# ============================================================
# Payload Builders
# ============================================================

def build_common_payload(
    request: OrchestrationRequest,
    rid: str,
) -> Dict[str, Any]:

    return {
        "request_id": rid,
        "timestamp": utc_now(),
        "user_id": request.user_id,
        "device_id": request.device_id,
        "language": request.language,
        "country": request.country,
        "location": request.location,
        "farm": request.farm,
        "crop": request.crop,
        "soil": request.soil,
        "water": request.water,
        "weather": request.weather,
        "image": request.image,
        "voice": request.voice,
        "payment": request.payment,
        "data": dict(request.data),
    }


# ============================================================
# Result Helpers
# ============================================================

def serialize_result(
    result: ServiceCallResult,
) -> Dict[str, Any]:
    return result.model_dump()


def summarize_results(
    results: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:

    total = len(results)

    succeeded = sum(
        1
        for item in results.values()
        if item.get("success") is True
    )

    failed = total - succeeded

    if total == 0 or succeeded == 0:
        status = "failed"
    elif failed:
        status = "partial"
    else:
        status = "success"

    return {
        "success": succeeded > 0,
        "status": status,
        "total_services": total,
        "successful_services": succeeded,
        "failed_services": failed,
    }


# ============================================================
# Orchestration Engine
# ============================================================

async def orchestrate(
    request: OrchestrationRequest,
) -> Dict[str, Any]:

    rid = request_id()

    action = normalize_action(request.action)

    selected_services = detect_services(action)

    if not selected_services:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_action",
                "action": request.action,
                "message": (
                    "No ARYA service is registered "
                    "for this action."
                ),
            },
        )

    payload = build_common_payload(
        request,
        rid,
    )

    results: Dict[str, Dict[str, Any]] = {}

    # --------------------------------------------------------
    # Composite agricultural diagnosis
    # --------------------------------------------------------

    if action in COMPOSITE_ACTIONS:

        if request.image:
            vision_result = await call_service(
                "vision",
                "/vision/analyze",
                payload,
            )

            results["vision"] = serialize_result(
                vision_result
            )

            if vision_result.success:
                payload["data"]["vision_result"] = (
                    vision_result.response
                )

        if request.voice:
            voice_result = await call_service(
                "voice_language",
                "/voice/process",
                payload,
            )

            results["voice_language"] = serialize_result(
                voice_result
            )

            if voice_result.success:
                payload["data"]["voice_result"] = (
                    voice_result.response
                )

        agri_result = await call_service(
            "agri_engine",
            "/agri/analyze",
            payload,
        )

        results["agri_engine"] = serialize_result(
            agri_result
        )

        summary = summarize_results(results)

        return {
            **summary,
            "request_id": rid,
            "action": action,
            "services": selected_services,
            "results": results,
            "timestamp": utc_now(),
        }

    # --------------------------------------------------------
    # Normal routing
    # --------------------------------------------------------

    for service_name in selected_services:

        if service_name == "vision":
            path = "/vision/analyze"

        elif service_name == "voice_language":
            path = "/voice/process"

        elif service_name == "agri_engine":

            if action == "diagnose":
                path = "/agri/diagnose"

            elif action == "recommend":
                path = "/agri/recommend"

            elif action == "crop_suitability":
                path = "/agri/crop-suitability"

            else:
                path = "/agri/analyze"

        elif service_name == "commerce_security":
            path = "/commerce/process"

        else:
            results[service_name] = (
                ServiceCallResult(
                    service=service_name,
                    success=False,
                    error="No route is configured for this service.",
                ).model_dump()
            )
            continue

        result = await call_service(
            service_name,
            path,
            payload,
        )

        results[service_name] = serialize_result(result)

    summary = summarize_results(results)

    return {
        **summary,
        "request_id": rid,
        "action": action,
        "services": selected_services,
        "results": results,
        "timestamp": utc_now(),
    }


# ============================================================
# API Routes
# ============================================================

@app.get("/")
async def root():

    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "online",
        "timestamp": utc_now(),
        "services": list(service_registry.keys()),
    }


@app.get("/health")
async def health():

    async def check_one(
        name: str,
        definition: ServiceDefinition,
    ):
        result = await call_service(
            name,
            definition.health_path,
            method="GET",
        )

        return name, {
            "enabled": definition.enabled,
            "success": result.success,
            "status_code": result.status_code,
            "elapsed_ms": result.elapsed_ms,
            "error": result.error,
        }

    checks = await asyncio.gather(
        *[
            check_one(name, definition)
            for name, definition in service_registry.items()
        ]
    )

    service_status = dict(checks)

    enabled_services = [
        item
        for item in service_status.values()
        if item["enabled"]
    ]

    healthy_count = sum(
        1
        for item in enabled_services
        if item["success"]
    )

    if not enabled_services or healthy_count == 0:
        overall_status = "degraded"
    elif healthy_count < len(enabled_services):
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": overall_status,
        "uptime_seconds": round(
            time.time() - started_at,
            2,
        ),
        "services": service_status,
        "timestamp": utc_now(),
    }


@app.get("/services")
async def services():

    return {
        "services": {
            name: definition.model_dump()
            for name, definition in service_registry.items()
        },
        "timestamp": utc_now(),
    }


@app.post("/orchestrate")
async def orchestrate_endpoint(
    request: OrchestrationRequest,
):

    return await orchestrate(request)


@app.post("/arya/doctor")
async def arya_doctor(
    request: OrchestrationRequest,
):

    request.action = "agri_doctor"

    return await orchestrate(request)


@app.post("/arya/analyze")
async def arya_analyze(
    request: OrchestrationRequest,
):

    request.action = "analyze"

    return await orchestrate(request)


@app.post("/arya/diagnose")
async def arya_diagnose(
    request: OrchestrationRequest,
):

    request.action = "diagnose"

    return await orchestrate(request)


@app.post("/arya/recommend")
async def arya_recommend(
    request: OrchestrationRequest,
):

    request.action = "recommend"

    return await orchestrate(request)


@app.post("/arya/vision")
async def arya_vision(
    request: OrchestrationRequest,
):

    request.action = "vision"

    return await orchestrate(request)


@app.post("/arya/voice")
async def arya_voice(
    request: OrchestrationRequest,
):

    request.action = "voice"

    return await orchestrate(request)


@app.post("/arya/payment")
async def arya_payment(
    request: OrchestrationRequest,
):

    request.action = "payment"

    return await orchestrate(request)


# ============================================================
# Request Logging Middleware
# ============================================================

@app.middleware("http")
async def request_logging_middleware(
    request: Request,
    call_next,
):

    started = time.perf_counter()

    try:
        response = await call_next(request)

        elapsed = (
            time.perf_counter() - started
        ) * 1000

        logger.info(
            "%s %s -> %s (%.2f ms)",
            request.method,
            request.url.path,
            response.status_code,
            elapsed,
        )

        return response

    except Exception:
        elapsed = (
            time.perf_counter() - started
        ) * 1000

        logger.exception(
            "%s %s failed after %.2f ms",
            request.method,
            request.url.path,
            elapsed,
        )

        raise


# ============================================================
# Optional Standalone Execution
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        reload=False,
    )
