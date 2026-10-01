"""
ARYA AgriDoctor
Final Control Center
Version: 1.0.0

Independent final control/orchestration layer.

IMPORTANT:
- main.py is NOT modified.
- Existing modules are NOT modified.
- This file only coordinates existing services.
- Existing service URLs can be changed through environment variables.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "ARYA Final Control Center"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_CONTROL_CENTER_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_CONTROL_CENTER_PORT",
        "8020",
    )
)

REQUEST_TIMEOUT = float(
    os.getenv(
        "ARYA_CONTROL_CENTER_TIMEOUT",
        "45",
    )
)

HEALTH_TIMEOUT = float(
    os.getenv(
        "ARYA_CONTROL_CENTER_HEALTH_TIMEOUT",
        "8",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_CONTROL_CENTER_MAX_RESPONSE",
        str(15 * 1024 * 1024),
    )
)

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)


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

    action: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = None


class ServiceCallRequest(BaseModel):

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

    request_id: Optional[str] = None


class DoctorRequest(BaseModel):

    payload: Dict[str, Any] = Field(
        default_factory=dict,
    )

    request_id: Optional[str] = None


# ============================================================
# REQUEST ID
# ============================================================

def get_request_id(
    supplied: Optional[str],
    request: Optional[Request] = None,
) -> str:

    if supplied:
        return supplied

    if request is not None:

        value = request.headers.get(
            "X-ARYA-Request-ID"
        )

        if value:
            return value

    return str(uuid.uuid4())


# ============================================================
# SERVICE HELPERS
# ============================================================

def get_service_url(
    service: str,
) -> str:

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


def build_headers(
    request_id: str,
) -> Dict[str, str]:

    headers = {

        "Accept": "application/json",

        "Content-Type": "application/json",

        "User-Agent":
            f"ARYA-Final-Control-Center/{APP_VERSION}",

        "X-ARYA-Request-ID":
            request_id,
    }

    if INTERNAL_SECRET:

        headers[
            "X-ARYA-Internal-Secret"
        ] = INTERNAL_SECRET

    return headers


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

    base_url = get_service_url(
        service
    )

    clean_path = (
        "/"
        + path.lstrip("/")
    )

    url = (
        base_url
        + clean_path
    )

    started = time.monotonic()

    try:

        async with httpx.AsyncClient(
            timeout=(
                timeout
                or REQUEST_TIMEOUT
            ),
            follow_redirects=False,
            headers=build_headers(
                request_id
            ),
        ) as client:

            response = await client.request(
                method.upper(),
                url,
                json=payload or {},
            )

        elapsed = round(
            (
                time.monotonic()
                - started
            )
            * 1000,
            2,
        )

        if len(response.content) > MAX_RESPONSE_BYTES:

            raise HTTPException(
                status_code=502,
                detail=(
                    "ARYA service response "
                    "exceeded maximum size."
                ),
            )

        try:

            data: Any = response.json()

        except Exception:

            data = response.text[:10000]

        if response.status_code >= 400:

            raise HTTPException(
                status_code=502,
                detail={

                    "message":
                        "Downstream ARYA service returned an error.",

                    "service":
                        service,

                    "status_code":
                        response.status_code,

                    "response":
                        data,

                    "request_id":
                        request_id,
                },
            )

        return {

            "ok": True,

            "service":
                service,

            "status_code":
                response.status_code,

            "elapsed_ms":
                elapsed,

            "request_id":
                request_id,

            "data":
                data,
        }

    except HTTPException:

        raise

    except httpx.TimeoutException as exc:

        raise HTTPException(
            status_code=504,
            detail={

                "message":
                    "ARYA service timeout.",

                "service":
                    service,

                "request_id":
                    request_id,
            },
        ) from exc

    except httpx.HTTPError as exc:

        raise HTTPException(
            status_code=502,
            detail={

                "message":
                    "ARYA service is unreachable.",

                "service":
                    service,

                "error":
                    str(exc),

                "request_id":
                    request_id,
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

    request_id = str(
        uuid.uuid4()
    )

    try:

        async with httpx.AsyncClient(
            timeout=HEALTH_TIMEOUT,
            follow_redirects=False,
            headers=build_headers(
                request_id
            ),
        ) as client:

            response = await client.get(
                f"{url.rstrip('/')}/health"
            )

        elapsed = round(
            (
                time.monotonic()
                - started
            )
            * 1000,
            2,
        )

        return {

            "service":
                name,

            "url":
                url,

            "online":
                response.status_code < 500,

            "status_code":
                response.status_code,

            "elapsed_ms":
                elapsed,
        }

    except Exception as exc:

        return {

            "service":
                name,

            "url":
                url,

            "online":
                False,

            "status_code":
                None,

            "error":
                str(exc),
        }


async def check_all_services():

    results = await asyncio.gather(

        *(
            check_service_health(
                name,
                url,
            )

            for name, url
            in SERVICES.items()
        )
    )

    online = sum(

        1

        for result
        in results

        if result.get(
            "online",
            False,
        )
    )

    total = len(
        results
    )

    return {

        "control_center":
            "online",

        "services_online":
            online,

        "services_total":
            total,

        "all_online":
            online == total,

        "services":
            results,
    }


# ============================================================
# REQUEST ID MIDDLEWARE
# ============================================================

@app.middleware("http")
async def request_id_middleware(
    request: Request,
    call_next,
):

    request_id = (
        request.headers.get(
            "X-ARYA-Request-ID"
        )
        or str(uuid.uuid4())
    )

    request.state.arya_request_id = (
        request_id
    )

    response = await call_next(
        request
    )

    response.headers[
        "X-ARYA-Request-ID"
    ] = request_id

    return response


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    return {

        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "status":
            "online",

        "role":
            "final-independent-control-layer",

        "main_py_modified":
            False,

        "existing_modules_modified":
            False,

        "port":
            PORT,
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return await check_all_services()


# ============================================================
# SERVICES
# ============================================================

@app.get("/services")
async def services():

    return {

        "services":
            SERVICES,

        "count":
            len(SERVICES),
    }


# ============================================================
# SYSTEM STATUS
# ============================================================

@app.get("/system/status")
async def system_status():

    health_result = (
        await check_all_services()
    )

    return {

        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "status":
            (
                "online"
                if health_result["all_online"]
                else "degraded"
            ),

        "health":
            health_result,

        "architecture": {

            "client":
                "Android / Windows",

            "control_center":
                "arya_final_control_center",

            "runtime_gateway":
                SERVICES[
                    "runtime_gateway"
                ],

            "owner_integration":
                SERVICES[
                    "owner_integration"
                ],

            "orchestrator":
                SERVICES[
                    "orchestrator"
                ],

            "agri_engine":
                SERVICES[
                    "agri_engine"
                ],

            "vision":
                SERVICES[
                    "vision"
                ],

            "voice_language":
                SERVICES[
                    "voice_language"
                ],

            "commerce_security":
                SERVICES[
                    "commerce_security"
                ],
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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

    payload = dict(
        body.payload
    )

    payload.setdefault(
        "action",
        body.action,
    )

    payload.setdefault(
        "request_id",
        request_id,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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

    request_id = get_request_id(
        body.request_id,
        request,
    )

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
async def owner_status():

    request_id = str(
        uuid.uuid4()
    )

    return await call_service(

        service="owner_integration",

        method="GET",

        path="/owner/status",

        payload={},

        request_id=request_id,
    )


# ============================================================
# RUNTIME SERVICES
# ============================================================

@app.get("/runtime/services")
async def runtime_services():

    request_id = str(
        uuid.uuid4()
    )

    return await call_service(

        service="runtime_gateway",

        method="GET",

        path="/runtime/services",

        payload={},

        request_id=request_id,
    )


# ============================================================
# RUNTIME PROVIDERS
# ============================================================

@app.get("/runtime/providers")
async def runtime_providers():

    request_id = str(
        uuid.uuid4()
    )

    return await call_service(

        service="runtime_gateway",

        method="GET",

        path="/runtime/providers",

        payload={},

        request_id=request_id,
    )


# ============================================================
# INFORMATION
# ============================================================

@app.get("/info")
async def info():

    return {

        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "purpose":
            (
                "Single independent control layer "
                "for existing ARYA services."
            ),

        "existing_files_changed":
            False,

        "main_py_changed":
            False,

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

        "configured_services":
            list(
                SERVICES.keys()
            ),
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    print(
        "=" * 72
    )

    print(
        f"{APP_NAME} {APP_VERSION}"
    )

    print(
        "=" * 72
    )

    print(
        f"Host: {HOST}"
    )

    print(
        f"Port: {PORT}"
    )

    print(
        "main.py: UNCHANGED"
    )

    print(
        "Existing modules: UNCHANGED"
    )

    print(
        "=" * 72
    )


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
