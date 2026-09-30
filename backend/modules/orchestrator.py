"""
ARYA AgriDoctor
Orchestrator / Unified API Gateway
Version: 1.0.0

این فایل لایه هماهنگ‌کننده ARYA است.
به main.py و ماژول‌های موجود دست نمی‌زند.
"""

from __future__ import annotations

import os
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

SERVICE_NAME = "ARYA Orchestrator"
SERVICE_VERSION = "1.0.0"

HOST = os.getenv("ARYA_ORCHESTRATOR_HOST", "0.0.0.0")
PORT = int(os.getenv("ARYA_ORCHESTRATOR_PORT", "8010"))

LOG_LEVEL = os.getenv("ARYA_ORCHESTRATOR_LOG_LEVEL", "INFO").upper()

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
    timeout_seconds: float = 30.0


DEFAULT_SERVICES = {
    "vision": ServiceDefinition(
        name="vision",
        base_url=os.getenv(
            "ARYA_VISION_URL",
            "http://127.0.0.1:8001",
        ),
    ),
    "voice_language": ServiceDefinition(
        name="voice_language",
        base_url=os.getenv(
            "ARYA_VOICE_LANGUAGE_URL",
            "http://127.0.0.1:8002",
        ),
    ),
    "agri_engine": ServiceDefinition(
        name="agri_engine",
        base_url=os.getenv(
            "ARYA_AGRI_ENGINE_URL",
            "http://127.0.0.1:8003",
        ),
    ),
    "commerce_security": ServiceDefinition(
        name="commerce_security",
        base_url=os.getenv(
            "ARYA_COMMERCE_SECURITY_URL",
            "http://127.0.0.1:8004",
        ),
    ),
}


service_registry: Dict[str, ServiceDefinition] = dict(DEFAULT_SERVICES)


# ============================================================
# Request Models
# ============================================================

class OrchestrationRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)

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

    if not service:
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

    started = time.perf_counter()

    try:
        import httpx

        url = service.base_url.rstrip("/") + "/" + path.lstrip("/")

        timeout = httpx.Timeout(service.timeout_seconds)

        async with httpx.AsyncClient(timeout=timeout) as client:

            if method.upper() == "GET":
                response = await client.get(url)
            else:
                response = await client.post(
                    url,
                    json=payload or {},
                )

        elapsed = (time.perf_counter() - started) * 1000

        try:
            response_data = response.json()
        except Exception:
            response_data = response.text

        return ServiceCallResult(
            service=service_name,
            success=200 <= response.status_code < 300,
            status_code=response.status_code,
            response=response_data,
            elapsed_ms=round(elapsed, 2),
        )

    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000

        logger.exception(
            "Service call failed: %s %s",
            service_name,
            path,
        )

        return ServiceCallResult(
            service=service_name,
            success=False,
            error=str(exc),
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


def normalize_action(action: str) -> str:
    return action.strip().lower().replace("-", "_").replace(" ", "_")


def detect_services(action: str) -> list[str]:

    normalized = normalize_action(action)

    services: list[str] = []

    if normalized in VISION_ACTIONS:
        services.append("vision")

    if normalized in VOICE_ACTIONS:
        services.append("voice_language")

    if normalized in AGRI_ACTIONS:
        services.append("agri_engine")

    if normalized in COMMERCE_ACTIONS:
        services.append("commerce_security")

    # Composite agricultural diagnosis:
    # image/voice + agricultural reasoning.
    if normalized in {
        "full_diagnosis",
        "complete_diagnosis",
        "doctor",
        "agri_doctor",
    }:
        services = [
            "vision",
            "voice_language",
            "agri_engine",
        ]

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
        "data": request.data,
    }


# ============================================================
# Orchestration Engine
# ============================================================

async def orchestrate(
    request: OrchestrationRequest,
) -> Dict[str, Any]:

    rid = request_id()

    action = normalize_action(request.action)

    services = detect_services(action)

    if not services:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_action",
                "action": request.action,
                "message": "No ARYA service is registered for this action.",
            },
        )

    payload = build_common_payload(request, rid)

    results: Dict[str, Any] = {}

    # --------------------------------------------------------
    # Composite agricultural diagnosis
    # --------------------------------------------------------

    if action in {
        "full_diagnosis",
        "complete_diagnosis",
        "doctor",
        "agri_doctor",
    }:

        vision_result = None

        if request.image:
            vision_result = await call_service(
                "vision",
                "/vision/analyze",
                payload,
            )

            results["vision"] = vision_result.model_dump()

            if vision_result.success:
                payload["data"]["vision_result"] = vision_result.response

        if request.voice:
            voice_result = await call_service(
                "voice_language",
                "/voice/process",
                payload,
            )

            results["voice_language"] = voice_result.model_dump()

            if voice_result.success:
                payload["data"]["voice_result"] = voice_result.response

        agri_result = await call_service(
            "agri_engine",
            "/agri/analyze",
            payload,
        )

        results["agri_engine"] = agri_result.model_dump()

        return {
            "success": any(
                item.get("success")
                for item in results.values()
            ),
            "request_id": rid,
            "action": action,
            "services": services,
            "results": results,
            "timestamp": utc_now(),
        }

    # --------------------------------------------------------
    # Normal routing
    # --------------------------------------------------------

    for service_name in services:

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
            path = "/"

        result = await call_service(
            service_name,
            path,
            payload,
        )

        results[service_name] = result.model_dump()

    success = any(
        item.get("success")
        for item in results.values()
    )

    return {
        "success": success,
        "request_id": rid,
        "action": action,
        "services": services,
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

    service_status = {}

    for name, service in service_registry.items():

        result = await call_service(
            name,
            service.health_path,
            method="GET",
        )

        service_status[name] = {
            "enabled": service.enabled,
            "success": result.success,
            "status_code": result.status_code,
            "elapsed_ms": result.elapsed_ms,
            "error": result.error,
        }

    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "online",
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

    response = await call_next(request)

    elapsed = (time.perf_counter() - started) * 1000

    logger.info(
        "%s %s -> %s (%.2f ms)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed,
    )

    return response


# ============================================================
# Optional Standalone Execution
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "orchestrator:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
