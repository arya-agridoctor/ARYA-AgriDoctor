"""
ARYA AgriDoctor
Orchestrator Runtime Bridge
Version: 2.0.0

Purpose:
- Connect ARYA Orchestrator to OWNER Runtime Gateway.
- Keep orchestrator.py untouched.
- Route unified ARYA requests through OWNER-controlled runtime.
- Preserve existing action semantics.
- Provide stable Android / Windows API routes.
- Support agriculture, diagnosis, recommendation, vision,
  voice, payment, weather, geocoding and data updates.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# CONFIGURATION
# ============================================================

SERVICE_NAME = "ARYA Orchestrator Runtime Bridge"
SERVICE_VERSION = "2.0.0"

HOST = os.getenv(
    "ARYA_ORCHESTRATOR_BRIDGE_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_ORCHESTRATOR_BRIDGE_PORT",
        "8017",
    )
)

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).rstrip("/")

INTERNAL_GATEWAY_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
).strip()

DEFAULT_TIMEOUT = float(
    os.getenv(
        "ARYA_BRIDGE_TIMEOUT",
        "60",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_BRIDGE_MAX_RESPONSE_BYTES",
        str(20 * 1024 * 1024),
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_BRIDGE_MAX_REQUEST_BYTES",
        str(20 * 1024 * 1024),
    )
)

LOG_LEVEL = os.getenv(
    "ARYA_BRIDGE_LOG_LEVEL",
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

logger = logging.getLogger(
    "arya.orchestrator_runtime_bridge"
)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title=SERVICE_NAME,
    description=(
        "Runtime bridge between the ARYA "
        "Orchestrator and OWNER Runtime Gateway."
    ),
    version=SERVICE_VERSION,
)


# ============================================================
# MODELS
# ============================================================

class OrchestrationRequest(BaseModel):
    action: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    request_id: Optional[str] = None

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

    data: Dict[str, Any] = Field(
        default_factory=dict
    )


class RuntimeResponse(BaseModel):
    success: bool
    request_id: str
    action: str
    timestamp: str
    elapsed_ms: float
    gateway: str
    result: Any = None
    error: Optional[str] = None


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def create_request_id(
    supplied: Optional[str] = None,
) -> str:

    if supplied:
        value = supplied.strip()

        if value:
            return value[:128]

    return str(uuid.uuid4())


def normalize_action(
    action: str,
) -> str:

    return (
        action
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


def build_payload(
    request: OrchestrationRequest,
    request_id: str,
) -> Dict[str, Any]:

    return {
        "request_id": request_id,
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


def internal_headers(
    authorization: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Dict[str, str]:

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": (
            "ARYA-Orchestrator-Runtime-Bridge/"
            f"{SERVICE_VERSION}"
        ),
    }

    if request_id:
        headers["X-ARYA-Request-ID"] = request_id

    if authorization:
        headers["Authorization"] = authorization

    elif INTERNAL_GATEWAY_SECRET:
        headers["Authorization"] = (
            f"Bearer {INTERNAL_GATEWAY_SECRET}"
        )

        headers["X-ARYA-Internal-Secret"] = (
            INTERNAL_GATEWAY_SECRET
        )

    return headers


# ============================================================
# REQUEST SIZE
# ============================================================

async def validate_request_size(
    request: Request,
) -> None:

    content_length = request.headers.get(
        "content-length"
    )

    if not content_length:
        return

    try:
        size = int(content_length)
    except ValueError:
        return

    if size > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                "Request exceeds configured "
                "maximum size"
            ),
        )


# ============================================================
# RUNTIME GATEWAY CLIENT
# ============================================================

class RuntimeGatewayClient:
    """
    OWNER Runtime Gateway remains the routing authority.

    This bridge does not duplicate service configuration.
    """

    def __init__(
        self,
        base_url: str,
    ):
        self.base_url = base_url.rstrip("/")

    async def request(
        self,
        path: str,
        method: str = "POST",
        payload: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:

        method = method.upper()

        url = (
            self.base_url
            + "/"
            + path.lstrip("/")
        )

        headers = internal_headers(
            authorization=authorization,
            request_id=request_id,
        )

        try:

            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=False,
            ) as client:

                response = await client.request(
                    method=method,
                    url=url,
                    json=(
                        payload
                        if method not in {
                            "GET",
                            "HEAD",
                        }
                        else None
                    ),
                    params=query,
                    headers=headers,
                )

                content_length = response.headers.get(
                    "content-length"
                )

                if content_length:
                    try:
                        if (
                            int(content_length)
                            > MAX_RESPONSE_BYTES
                        ):
                            raise HTTPException(
                                status_code=502,
                                detail=(
                                    "Runtime Gateway "
                                    "response exceeds "
                                    "configured limit"
                                ),
                            )
                    except ValueError:
                        pass

                content = response.content

                if len(content) > MAX_RESPONSE_BYTES:
                    raise HTTPException(
                        status_code=502,
                        detail=(
                            "Runtime Gateway response "
                            "exceeds configured limit"
                        ),
                    )

                content_type = response.headers.get(
                    "content-type",
                    "",
                ).lower()

                if "json" in content_type:

                    try:
                        result = response.json()
                    except Exception:
                        result = {
                            "raw": content.decode(
                                "utf-8",
                                errors="replace",
                            )
                        }

                elif not content:

                    result = {}

                else:

                    result = {
                        "raw": content.decode(
                            "utf-8",
                            errors="replace",
                        )
                    }

                if not response.is_success:

                    raise HTTPException(
                        status_code=502,
                        detail={
                            "runtime_gateway_status":
                                response.status_code,
                            "runtime_gateway_response":
                                result,
                        },
                    )

                return result

        except HTTPException:
            raise

        except (
            httpx.TimeoutException,
        ) as exc:

            logger.error(
                "Runtime Gateway timeout: %s",
                url,
            )

            raise HTTPException(
                status_code=504,
                detail=(
                    "Runtime Gateway timeout"
                ),
            ) from exc

        except (
            httpx.RequestError,
        ) as exc:

            logger.error(
                "Runtime Gateway unavailable: %s",
                url,
            )

            raise HTTPException(
                status_code=502,
                detail=(
                    "Runtime Gateway unavailable"
                ),
            ) from exc

        except Exception as exc:

            logger.exception(
                "Runtime Gateway request failed"
            )

            raise HTTPException(
                status_code=502,
                detail=(
                    "Runtime Gateway request failed: "
                    f"{str(exc)}"
                ),
            ) from exc


runtime_gateway = RuntimeGatewayClient(
    RUNTIME_GATEWAY_URL
)


# ============================================================
# ACTION ROUTING
# ============================================================

AGRI_ACTIONS = {
    "agri",
    "agriculture",
    "analyze",
    "analysis",
    "diagnose",
    "diagnosis",
    "recommend",
    "recommendation",
    "crop_suitability",
    "soil",
    "water",
    "crop",
    "farm",
}

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

PAYMENT_ACTIONS = {
    "payment",
    "payments",
    "subscription",
    "activation",
    "device",
    "commerce",
    "security",
}

DOCTOR_ACTIONS = {
    "doctor",
    "agri_doctor",
    "full_diagnosis",
    "complete_diagnosis",
}


def detect_action_route(
    action: str,
) -> str:

    action = normalize_action(
        action
    )

    if action in DOCTOR_ACTIONS:
        return "doctor"

    if action in VISION_ACTIONS:
        return "vision"

    if action in VOICE_ACTIONS:
        return "voice"

    if action in PAYMENT_ACTIONS:
        return "payment"

    if action in AGRI_ACTIONS:
        return "agri"

    raise HTTPException(
        status_code=400,
        detail={
            "error": "unsupported_action",
            "action": action,
            "message": (
                "No supported ARYA runtime "
                "route exists for this action."
            ),
        },
    )


# ============================================================
# SPECIALIZED CALLS
# ============================================================

async def call_agri_engine(
    action: str,
    payload: Dict[str, Any],
    authorization: Optional[str],
    request_id: Optional[str],
) -> Dict[str, Any]:

    normalized = normalize_action(
        action
    )

    if normalized in {
        "diagnose",
        "diagnosis",
    }:
        gateway_path = "/arya/diagnose"

    elif normalized in {
        "recommend",
        "recommendation",
    }:
        gateway_path = "/arya/recommend"

    else:
        gateway_path = "/arya/analyze"

    return await runtime_gateway.request(
        path=gateway_path,
        method="POST",
        payload=payload,
        authorization=authorization,
        request_id=request_id,
    )


async def call_vision(
    payload: Dict[str, Any],
    authorization: Optional[str],
    request_id: Optional[str],
) -> Dict[str, Any]:

    return await runtime_gateway.request(
        path="/arya/vision",
        method="POST",
        payload=payload,
        authorization=authorization,
        request_id=request_id,
    )


async def call_payment(
    payload: Dict[str, Any],
    authorization: Optional[str],
    request_id: Optional[str],
) -> Dict[str, Any]:

    return await runtime_gateway.request(
        path="/arya/payment",
        method="POST",
        payload=payload,
        authorization=authorization,
        request_id=request_id,
    )


async def call_voice(
    payload: Dict[str, Any],
    authorization: Optional[str],
    request_id: Optional[str],
) -> Dict[str, Any]:

    # OWNER Runtime Gateway currently exposes the
    # generic runtime compatibility route for voice.
    return await runtime_gateway.request(
        path="/runtime/call",
        method="POST",
        payload={
            "service_id": "voice_language",
            "path": "/voice/process",
            "method": "POST",
            "payload": payload,
            "request_id": request_id,
        },
        authorization=authorization,
        request_id=request_id,
    )


# ============================================================
# DOCTOR FLOW
# ============================================================

async def execute_doctor_flow(
    payload: Dict[str, Any],
    authorization: Optional[str],
    request_id: str,
) -> Dict[str, Any]:

    results: Dict[str, Any] = {}

    # --------------------------------------------------------
    # Vision
    # --------------------------------------------------------

    if payload.get("image"):

        vision_result = await call_vision(
            payload=payload,
            authorization=authorization,
            request_id=request_id,
        )

        results["vision"] = vision_result

        if isinstance(
            vision_result,
            dict,
        ):
            payload.setdefault(
                "data",
                {},
            )["vision_result"] = (
                vision_result
            )

    # --------------------------------------------------------
    # Voice
    # --------------------------------------------------------

    if payload.get("voice"):

        voice_result = await call_voice(
            payload=payload,
            authorization=authorization,
            request_id=request_id,
        )

        results["voice_language"] = (
            voice_result
        )

        if isinstance(
            voice_result,
            dict,
        ):
            payload.setdefault(
                "data",
                {},
            )["voice_result"] = (
                voice_result
            )

    # --------------------------------------------------------
    # Agricultural analysis
    # --------------------------------------------------------

    agri_result = await call_agri_engine(
        action="analyze",
        payload=payload,
        authorization=authorization,
        request_id=request_id,
    )

    results["agri_engine"] = agri_result

    return {
        "success": True,
        "results": results,
    }


# ============================================================
# GENERAL EXECUTION
# ============================================================

async def execute_request(
    request: OrchestrationRequest,
    authorization: Optional[str],
) -> RuntimeResponse:

    started = time.perf_counter()

    request_id = create_request_id(
        request.request_id
    )

    action = normalize_action(
        request.action
    )

    route = detect_action_route(
        action
    )

    payload = build_payload(
        request,
        request_id,
    )

    try:

        if route == "doctor":

            result = await execute_doctor_flow(
                payload=payload,
                authorization=authorization,
                request_id=request_id,
            )

        elif route == "vision":

            result = await call_vision(
                payload=payload,
                authorization=authorization,
                request_id=request_id,
            )

        elif route == "voice":

            result = await call_voice(
                payload=payload,
                authorization=authorization,
                request_id=request_id,
            )

        elif route == "payment":

            result = await call_payment(
                payload=payload,
                authorization=authorization,
                request_id=request_id,
            )

        elif route == "agri":

            result = await call_agri_engine(
                action=action,
                payload=payload,
                authorization=authorization,
                request_id=request_id,
            )

        else:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Unsupported runtime route"
                ),
            )

        elapsed = (
            time.perf_counter()
            - started
        ) * 1000

        return RuntimeResponse(
            success=True,
            request_id=request_id,
            action=action,
            timestamp=utc_now(),
            elapsed_ms=round(
                elapsed,
                2,
            ),
            gateway=RUNTIME_GATEWAY_URL,
            result=result,
        )

    except HTTPException as exc:

        elapsed = (
            time.perf_counter()
            - started
        ) * 1000

        detail = exc.detail

        return RuntimeResponse(
            success=False,
            request_id=request_id,
            action=action,
            timestamp=utc_now(),
            elapsed_ms=round(
                elapsed,
                2,
            ),
            gateway=RUNTIME_GATEWAY_URL,
            error=str(detail),
        )

    except Exception as exc:

        logger.exception(
            "Orchestration bridge failed"
        )

        elapsed = (
            time.perf_counter()
            - started
        ) * 1000

        return RuntimeResponse(
            success=False,
            request_id=request_id,
            action=action,
            timestamp=utc_now(),
            elapsed_ms=round(
                elapsed,
                2,
            ),
            gateway=RUNTIME_GATEWAY_URL,
            error=str(exc),
        )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root() -> Dict[str, Any]:

    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "online",
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "port": PORT,
        "timestamp": utc_now(),
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health() -> Dict[str, Any]:

    started = time.perf_counter()

    try:

        result = await runtime_gateway.request(
            path="/health",
            method="GET",
        )

        elapsed = (
            time.perf_counter()
            - started
        ) * 1000

        return {
            "status": "healthy",
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "runtime_gateway": "connected",
            "gateway_response": result,
            "elapsed_ms": round(
                elapsed,
                2,
            ),
            "timestamp": utc_now(),
        }

    except Exception as exc:

        elapsed = (
            time.perf_counter()
            - started
        ) * 1000

        return {
            "status": "degraded",
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "runtime_gateway": "unavailable",
            "error": str(exc),
            "elapsed_ms": round(
                elapsed,
                2,
            ),
            "timestamp": utc_now(),
        }


# ============================================================
# SYSTEM MAP
# ============================================================

@app.get("/system-map")
async def system_map(
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    result = await runtime_gateway.request(
        path="/arya/system-map",
        method="GET",
        authorization=authorization,
    )

    return {
        "bridge": {
            "name": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "port": PORT,
        },
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "system": result,
        "timestamp": utc_now(),
    }


# ============================================================
# DISCOVERY / CONTRACT
# ============================================================

@app.get("/contract")
async def contract() -> Dict[str, Any]:

    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "port": PORT,
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "routes": {
            "orchestrate": "POST /orchestrate",
            "doctor": "POST /arya/doctor",
            "analyze": "POST /arya/analyze",
            "diagnose": "POST /arya/diagnose",
            "recommend": "POST /arya/recommend",
            "vision": "POST /arya/vision",
            "voice": "POST /arya/voice",
            "payment": "POST /arya/payment",
            "weather": "GET /arya/weather",
            "geocode": "GET /arya/geocode",
            "updates": "GET /arya/updates",
            "updates_run": "POST /arya/updates/run",
            "health": "GET /health",
            "system_map": "GET /system-map",
        },
        "main_py": {
            "modified": False,
        },
        "timestamp": utc_now(),
    }


# ============================================================
# GENERIC ORCHESTRATION
# ============================================================

@app.post("/orchestrate")
async def orchestrate_endpoint(
    request: OrchestrationRequest,
    raw_request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> RuntimeResponse:

    await validate_request_size(
        raw_request
    )

    return await execute_request(
        request=request,
        authorization=authorization,
    )


# ============================================================
# ARYA DOCTOR
# ============================================================

@app.post("/arya/doctor")
async def arya_doctor(
    request: OrchestrationRequest,
    raw_request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> RuntimeResponse:

    await validate_request_size(
        raw_request
    )

    request.action = "agri_doctor"

    return await execute_request(
        request=request,
        authorization=authorization,
    )


# ============================================================
# ARYA ANALYZE
# ============================================================

@app.post("/arya/analyze")
async def arya_analyze(
    request: OrchestrationRequest,
    raw_request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> RuntimeResponse:

    await validate_request_size(
        raw_request
    )

    request.action = "analyze"

    return await execute_request(
        request=request,
        authorization=authorization,
    )


# ============================================================
# ARYA DIAGNOSE
# ============================================================

@app.post("/arya/diagnose")
async def arya_diagnose(
    request: OrchestrationRequest,
    raw_request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> RuntimeResponse:

    await validate_request_size(
        raw_request
    )

    request.action = "diagnose"

    return await execute_request(
        request=request,
        authorization=authorization,
    )


# ============================================================
# ARYA RECOMMEND
# ============================================================

@app.post("/arya/recommend")
async def arya_recommend(
    request: OrchestrationRequest,
    raw_request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> RuntimeResponse:

    await validate_request_size(
        raw_request
    )

    request.action = "recommend"

    return await execute_request(
        request=request,
        authorization=authorization,
    )


# ============================================================
# ARYA VISION
# ============================================================

@app.post("/arya/vision")
async def arya_vision(
    request: OrchestrationRequest,
    raw_request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> RuntimeResponse:

    await validate_request_size(
        raw_request
    )

    request.action = "vision"

    return await execute_request(
        request=request,
        authorization=authorization,
    )


# ============================================================
# ARYA VOICE
# ============================================================

@app.post("/arya/voice")
async def arya_voice(
    request: OrchestrationRequest,
    raw_request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> RuntimeResponse:

    await validate_request_size(
        raw_request
    )

    request.action = "voice"

    return await execute_request(
        request=request,
        authorization=authorization,
    )


# ============================================================
# ARYA PAYMENT
# ============================================================

@app.post("/arya/payment")
async def arya_payment(
    request: OrchestrationRequest,
    raw_request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> RuntimeResponse:

    await validate_request_size(
        raw_request
    )

    request.action = "payment"

    return await execute_request(
        request=request,
        authorization=authorization,
    )


# ============================================================
# WEATHER
# ============================================================

@app.get("/arya/weather")
async def arya_weather(
    latitude: float,
    longitude: float,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    return await runtime_gateway.request(
        path="/arya/weather",
        method="GET",
        query={
            "latitude": latitude,
            "longitude": longitude,
        },
        authorization=authorization,
    )


# ============================================================
# GEOCODING
# ============================================================

@app.get("/arya/geocode")
async def arya_geocode(
    name: str,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    return await runtime_gateway.request(
        path="/arya/geocode",
        method="GET",
        query={
            "name": name,
        },
        authorization=authorization,
    )


# ============================================================
# DATA UPDATES
# ============================================================

@app.get("/arya/updates")
async def arya_updates(
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    return await runtime_gateway.request(
        path="/arya/updates",
        method="GET",
        authorization=authorization,
    )


@app.post("/arya/updates/run")
async def arya_updates_run(
    payload: Optional[Dict[str, Any]] = None,
    authorization: Optional[str] = Header(
        default=None
    ),
) -> Dict[str, Any]:

    return await runtime_gateway.request(
        path="/arya/updates/run",
        method="POST",
        payload=payload or {},
        authorization=authorization,
    )


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event() -> None:

    logger.info(
        "%s v%s started",
        SERVICE_NAME,
        SERVICE_VERSION,
    )

    logger.info(
        "Runtime Gateway: %s",
        RUNTIME_GATEWAY_URL,
    )


# ============================================================
# STANDALONE EXECUTION
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level=LOG_LEVEL.lower(),
    )
