"""
ARYA AgriDoctor — MASTER GATEWAY
Version: 3.0.0

Central gateway for the real ARYA AgriDoctor backend.

Rules:
- backend/main.py is NOT modified by this file.
- Real backend routes are used.
- No speculative AI/weather/location routes.
- Generic proxy keeps future backend routes accessible.
- Compatibility routes are provided for existing ARYA clients.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
from collections import defaultdict
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response


# ===============================================================
# CONFIG
# ===============================================================

APP_NAME = "ARYA AgriDoctor MASTER GATEWAY"
APP_VERSION = "3.0.0"

BACKEND_URL = os.getenv(
    "ARYA_BACKEND_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

HOST = os.getenv(
    "ARYA_MASTER_HOST",
    "0.0.0.0",
)

PORT = int(
    os.getenv(
        "ARYA_MASTER_PORT",
        "8030",
    )
)

TIMEOUT = float(
    os.getenv(
        "ARYA_MASTER_TIMEOUT",
        "30",
    )
)

RETRIES = max(
    0,
    int(
        os.getenv(
            "ARYA_MASTER_RETRIES",
            "2",
        )
    ),
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_MASTER_MAX_REQUEST_BYTES",
        str(8 * 1024 * 1024),
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_MASTER_MAX_RESPONSE_BYTES",
        str(16 * 1024 * 1024),
    )
)

CIRCUIT_FAILURE_THRESHOLD = max(
    1,
    int(
        os.getenv(
            "ARYA_MASTER_CIRCUIT_FAILURE_THRESHOLD",
            "3",
        )
    ),
)

CIRCUIT_COOLDOWN = max(
    1.0,
    float(
        os.getenv(
            "ARYA_MASTER_CIRCUIT_COOLDOWN_SECONDS",
            "30",
        )
    ),
)

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

REQUIRE_SIGNATURE = (
    os.getenv(
        "ARYA_MASTER_REQUIRE_INTERNAL_SIGNATURE",
        "false",
    ).lower()
    in {
        "1",
        "true",
        "yes",
        "on",
    }
)

OPENAPI_CACHE_SECONDS = max(
    1.0,
    float(
        os.getenv(
            "ARYA_MASTER_OPENAPI_CACHE_SECONDS",
            "15",
        )
    ),
)

CORS_ORIGINS = [
    item.strip()
    for item in os.getenv(
        "ARYA_MASTER_CORS",
        "*",
    ).split(",")
    if item.strip()
]


# ===============================================================
# FASTAPI
# ===============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Single gateway for the real "
        "ARYA AgriDoctor backend."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=(
        CORS_ORIGINS != ["*"]
    ),
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===============================================================
# STATE
# ===============================================================

class Circuit:

    def __init__(self) -> None:
        self.failures = 0
        self.opened_at = 0.0


backend_circuit = Circuit()

stats = defaultdict(int)

last_error: Optional[str] = None

_openapi_cache: dict[str, Any] = {}

_openapi_cached_at = 0.0


# ===============================================================
# BASIC HELPERS
# ===============================================================

def backend_url(
    path: str,
) -> str:

    if not path.startswith("/"):
        path = "/" + path

    return BACKEND_URL + path


def clean_headers(
    headers: httpx.Headers,
) -> dict[str, str]:

    excluded = {
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    }

    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in excluded
    }


def safe_json_response(
    response: httpx.Response,
) -> JSONResponse:

    try:
        data = response.json()
    except Exception:
        data = {
            "ok": response.is_success,
            "status_code":
                response.status_code,
            "text":
                response.text,
        }

    return JSONResponse(
        content=data,
        status_code=response.status_code,
    )


# ===============================================================
# CIRCUIT BREAKER
# ===============================================================

def circuit_open() -> bool:

    if not backend_circuit.opened_at:
        return False

    if (
        time.time()
        - backend_circuit.opened_at
        >= CIRCUIT_COOLDOWN
    ):
        backend_circuit.failures = 0
        backend_circuit.opened_at = 0.0
        return False

    return True


def circuit_success() -> None:

    backend_circuit.failures = 0
    backend_circuit.opened_at = 0.0


def circuit_failure(
    error: str,
) -> None:

    global last_error

    last_error = str(error)

    backend_circuit.failures += 1

    if (
        backend_circuit.failures
        >= CIRCUIT_FAILURE_THRESHOLD
    ):
        backend_circuit.opened_at = time.time()


# ===============================================================
# HMAC
# ===============================================================

def make_signature(
    method: str,
    path: str,
    body: bytes,
) -> str:

    if not INTERNAL_SECRET:
        return ""

    message = (
        method.upper().encode("utf-8")
        + b"\n"
        + path.encode("utf-8")
        + b"\n"
        + body
    )

    return hmac.new(
        INTERNAL_SECRET.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()


def verify_signature(
    request: Request,
    body: bytes,
) -> bool:

    if not INTERNAL_SECRET:
        return not REQUIRE_SIGNATURE

    received = request.headers.get(
        "X-ARYA-Signature",
        "",
    )

    expected = make_signature(
        request.method,
        request.url.path,
        body,
    )

    return (
        bool(received)
        and hmac.compare_digest(
            received,
            expected,
        )
    )


# ===============================================================
# RAW BACKEND REQUEST
# ===============================================================

async def raw_backend_call(
    method: str,
    path: str,
    *,
    body: bytes = b"",
    query: Optional[
        list[tuple[str, str]]
    ] = None,
    headers: Optional[
        dict[str, str]
    ] = None,
    retry: bool = True,
) -> httpx.Response:

    if circuit_open():
        raise HTTPException(
            status_code=503,
            detail={
                "ok": False,
                "error":
                    "backend_circuit_open",
            },
        )

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "ok": False,
                "error":
                    "request_too_large",
            },
        )

    method = method.upper()

    retryable_methods = {
        "GET",
        "HEAD",
        "OPTIONS",
    }

    attempts = (
        RETRIES + 1
        if (
            retry
            and method
            in retryable_methods
        )
        else 1
    )

    target = backend_url(path)

    request_headers = dict(
        headers or {}
    )

    if INTERNAL_SECRET:

        request_headers[
            "X-ARYA-Gateway"
        ] = "ARYA-MASTER"

        request_headers[
            "X-ARYA-Signature"
        ] = make_signature(
            method,
            path,
            body,
        )

    last_exc: Optional[
        Exception
    ] = None

    for attempt in range(attempts):

        try:

            async with httpx.AsyncClient(
                timeout=TIMEOUT,
                follow_redirects=False,
                limits=httpx.Limits(
                    max_connections=50,
                    max_keepalive_connections=20,
                ),
            ) as client:

                response = await client.request(
                    method=method,
                    url=target,
                    content=body,
                    params=query,
                    headers=request_headers,
                )

            if (
                len(response.content)
                > MAX_RESPONSE_BYTES
            ):

                circuit_failure(
                    "backend_response_too_large"
                )

                raise HTTPException(
                    status_code=502,
                    detail={
                        "ok": False,
                        "error":
                            "backend_response_too_large",
                    },
                )

            if (
                response.status_code
                in {
                    502,
                    503,
                    504,
                }
                and attempt + 1 < attempts
            ):

                await asyncio.sleep(
                    0.35 * (attempt + 1)
                )

                continue

            if response.status_code < 500:
                circuit_success()
            else:
                circuit_failure(
                    "backend_http_"
                    + str(
                        response.status_code
                    )
                )

            return response

        except HTTPException:
            raise

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.ConnectError,
        ) as exc:

            last_exc = exc

            circuit_failure(
                str(exc)
            )

            if (
                attempt + 1
                < attempts
            ):

                await asyncio.sleep(
                    0.35 * (attempt + 1)
                )

                continue

    raise HTTPException(
        status_code=502,
        detail={
            "ok": False,
            "error":
                "backend_unreachable",
            "message":
                str(
                    last_exc
                    or "unknown error"
                ),
        },
    )


# ===============================================================
# JSON BACKEND REQUEST
# ===============================================================

async def backend_json(
    method: str,
    path: str,
    *,
    body: Any = None,
    query: Optional[
        list[tuple[str, str]]
    ] = None,
) -> Any:

    raw = b""

    headers = {
        "Accept":
            "application/json",
    }

    if body is not None:

        raw = json.dumps(
            body,
            ensure_ascii=False,
        ).encode("utf-8")

        headers[
            "Content-Type"
        ] = "application/json"

    response = await raw_backend_call(
        method,
        path,
        body=raw,
        query=query,
        headers=headers,
    )

    try:
        return response.json()
    except Exception:
        return {
            "status_code":
                response.status_code,
            "text":
                response.text,
        }


# ===============================================================
# GENERIC PROXY
# ===============================================================

async def proxy_request(
    request: Request,
    path: str,
) -> Response:

    body = await request.body()

    if (
        REQUIRE_SIGNATURE
        and request.url.path.startswith(
            "/internal/"
        )
        and not verify_signature(
            request,
            body,
        )
    ):

        return JSONResponse(
            status_code=401,
            content={
                "ok": False,
                "error":
                    "invalid_internal_signature",
            },
        )

    query = [
        (key, value)
        for key, value
        in request.query_params.multi_items()
    ]

    response = await raw_backend_call(
        request.method,
        path,
        body=body,
        query=query,
        headers=clean_headers(
            request.headers
        ),
    )

    response_headers = clean_headers(
        response.headers
    )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
    )


# ===============================================================
# OPENAPI DISCOVERY
# ===============================================================

async def load_openapi(
    force: bool = False,
) -> dict[str, Any]:

    global _openapi_cache
    global _openapi_cached_at

    if (
        not force
        and _openapi_cache
        and (
            time.time()
            - _openapi_cached_at
            < OPENAPI_CACHE_SECONDS
        )
    ):
        return _openapi_cache

    try:

        response = await raw_backend_call(
            "GET",
            "/openapi.json",
            retry=True,
        )

        if response.status_code == 200:

            data = response.json()

            if isinstance(data, dict):

                _openapi_cache = data

                _openapi_cached_at = (
                    time.time()
                )

                return data

    except Exception:
        pass

    return _openapi_cache


def route_exists(
    openapi: dict[str, Any],
    path: str,
    method: str,
) -> bool:

    item = (
        openapi
        .get("paths", {})
        .get(path)
    )

    if not isinstance(
        item,
        dict,
    ):
        return False

    return (
        method.lower()
        in item
    )


# ===============================================================
# QUERY HELPERS
# ===============================================================

def query_pairs(
    request: Request,
) -> list[tuple[str, str]]:

    return [
        (key, value)
        for key, value
        in request.query_params.multi_items()
    ]


def query_dict(
    request: Request,
) -> dict[str, str]:

    result: dict[str, str] = {}

    for key, value in (
        request.query_params.multi_items()
    ):
        result[key] = value

    return result


async def json_payload(
    request: Request,
) -> dict[str, Any]:

    body = await request.body()

    if not body:
        return query_dict(request)

    try:
        value = json.loads(
            body.decode("utf-8")
        )

        if isinstance(value, dict):
            return value

        return {
            "value": value,
        }

    except Exception:

        return query_dict(request)


# ===============================================================
# ROOT
# ===============================================================

@app.get("/")
async def root():

    return {
        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "status":
            "running",

        "backend":
            BACKEND_URL,
    }


# ===============================================================
# HEALTH
# ===============================================================

@app.get("/health")
async def health():

    started = time.perf_counter()

    try:

        response = await raw_backend_call(
            "GET",
            "/health",
            retry=True,
        )

        healthy = (
            200
            <= response.status_code
            < 300
        )

        return {
            "ok":
                healthy,

            "master":
                "ok",

            "backend": {
                "ok":
                    healthy,

                "status_code":
                    response.status_code,
            },

            "latency_ms":
                round(
                    (
                        time.perf_counter()
                        - started
                    )
                    * 1000,
                    2,
                ),
        }

    except Exception as exc:

        return {
            "ok": False,
            "master": "ok",
            "backend": {
                "ok": False,
                "error": str(exc),
            },
            "latency_ms":
                round(
                    (
                        time.perf_counter()
                        - started
                    )
                    * 1000,
                    2,
                ),
        }


# ===============================================================
# STATUS
# ===============================================================

@app.get("/status")
async def status():

    openapi = await load_openapi()

    paths = (
        openapi.get(
            "paths",
            {},
        )
        if openapi
        else {}
    )

    return {
        "ok": True,

        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "backend":
            BACKEND_URL,

        "backend_circuit_open":
            circuit_open(),

        "backend_failures":
            backend_circuit.failures,

        "last_error":
            last_error,

        "route_count":
            len(paths),

        "request_count":
            dict(stats),
    }


# ===============================================================
# SYSTEM MAP
# ===============================================================

@app.get("/system-map")
async def system_map():

    openapi = await load_openapi()

    return {
        "name":
            APP_NAME,

        "version":
            APP_VERSION,

        "architecture": {

            "client":
                "ARYA Android / Windows",

            "master":
                "arya_master_system.py",

            "backend":
                "backend/main.py",

            "ai":
                "/ai/analyze",

            "recommendations":
                "/recommendations",

            "weather": [
                "/weather/current",
                "/weather/forecast",
                "/weather/observation",
            ],

            "location": [
                "/location",
                "/location/reverse",
            ],

            "storage":
                "backend SQLite",
        },

        "backend":
            BACKEND_URL,

        "routes":
            sorted(
                openapi.get(
                    "paths",
                    {},
                ).keys()
            )
            if openapi
            else [],
    }


# ===============================================================
# BACKEND ROUTES
# ===============================================================

@app.get("/backend-routes")
async def backend_routes():

    openapi = await load_openapi()

    paths = (
        openapi.get(
            "paths",
            {},
        )
        if openapi
        else {}
    )

    return {
        "ok":
            bool(openapi),

        "count":
            len(paths),

        "routes": {
            path:
                sorted(
                    [
                        method.upper()
                        for method in methods
                        if method.lower()
                        in {
                            "get",
                            "post",
                            "put",
                            "patch",
                            "delete",
                            "options",
                            "head",
                        }
                    ]
                )

            for path, methods
            in paths.items()

            if isinstance(
                methods,
                dict,
            )
        },
    }


@app.post(
    "/backend-routes/refresh"
)
async def refresh_backend_routes():

    openapi = await load_openapi(
        force=True
    )

    return {
        "ok":
            bool(openapi),

        "count":
            (
                len(
                    openapi.get(
                        "paths",
                        {},
                    )
                )
                if openapi
                else 0
            ),
    }


# ===============================================================
# REAL WEATHER COMPATIBILITY ROUTES
# ===============================================================

@app.get(
    "/arya/weather/current"
)
async def arya_weather_current(
    request: Request,
):

    stats[
        "/arya/weather/current"
    ] += 1

    return await proxy_request(
        request,
        "/weather/current",
    )


@app.get(
    "/arya/weather/forecast"
)
async def arya_weather_forecast(
    request: Request,
):

    stats[
        "/arya/weather/forecast"
    ] += 1

    return await proxy_request(
        request,
        "/weather/forecast",
    )


@app.post(
    "/arya/weather/observation"
)
async def arya_weather_observation(
    request: Request,
):

    stats[
        "/arya/weather/observation"
    ] += 1

    return await proxy_request(
        request,
        "/weather/observation",
    )


# ===============================================================
# WEATHER LEGACY ROUTE
# ===============================================================

@app.api_route(
    "/arya/weather",
    methods=[
        "GET",
        "POST",
    ],
)
async def arya_weather(
    request: Request,
):

    """
    Compatibility endpoint.

    GET:
        forwards to /weather/current

    POST:
        forwards to /weather/observation
    """

    stats[
        "/arya/weather"
    ] += 1

    if request.method.upper() == "GET":

        return await proxy_request(
            request,
            "/weather/current",
        )

    return await proxy_request(
        request,
        "/weather/observation",
    )


# ===============================================================
# REAL LOCATION COMPATIBILITY ROUTES
# ===============================================================

@app.post(
    "/arya/location"
)
async def arya_location(
    request: Request,
):

    stats[
        "/arya/location"
    ] += 1

    return await proxy_request(
        request,
        "/location",
    )


@app.get(
    "/arya/location/reverse"
)
async def arya_location_reverse(
    request: Request,
):

    stats[
        "/arya/location/reverse"
    ] += 1

    return await proxy_request(
        request,
        "/location/reverse",
    )


# ===============================================================
# LOCATION LEGACY ROUTES
# ===============================================================

@app.api_route(
    "/arya/geocode",
    methods=[
        "GET",
        "POST",
    ],
)
async def arya_geocode(
    request: Request,
):

    stats[
        "/arya/geocode"
    ] += 1

    if request.method.upper() == "GET":

        return await proxy_request(
            request,
            "/location/reverse",
        )

    return await proxy_request(
        request,
        "/location",
    )


@app.api_route(
    "/arya/location/resolve",
    methods=[
        "GET",
        "POST",
    ],
)
async def arya_location_resolve(
    request: Request,
):

    stats[
        "/arya/location/resolve"
    ] += 1

    if request.method.upper() == "GET":

        return await proxy_request(
            request,
            "/location/reverse",
        )

    return await proxy_request(
        request,
        "/location",
    )


# ===============================================================
# REAL AI COMPATIBILITY ROUTES
# ===============================================================

@app.api_route(
    "/arya/doctor",
    methods=[
        "POST",
    ],
)
async def arya_doctor(
    request: Request,
):

    stats[
        "/arya/doctor"
    ] += 1

    return await proxy_request(
        request,
        "/ai/analyze",
    )


@app.api_route(
    "/arya/diagnose",
    methods=[
        "POST",
    ],
)
async def arya_diagnose(
    request: Request,
):

    stats[
        "/arya/diagnose"
    ] += 1

    return await proxy_request(
        request,
        "/ai/analyze",
    )


@app.api_route(
    "/arya/analyze",
    methods=[
        "POST",
    ],
)
async def arya_analyze(
    request: Request,
):

    stats[
        "/arya/analyze"
    ] += 1

    return await proxy_request(
        request,
        "/ai/analyze",
    )


# ===============================================================
# REAL RECOMMENDATION COMPATIBILITY
# ===============================================================

@app.post(
    "/arya/recommend"
)
async def arya_recommend(
    request: Request,
):

    stats[
        "/arya/recommend"
    ] += 1

    return await proxy_request(
        request,
        "/recommendations",
    )


@app.post(
    "/arya/recommendations"
)
async def arya_recommendations(
    request: Request,
):

    stats[
        "/arya/recommendations"
    ] += 1

    return await proxy_request(
        request,
        "/recommendations",
    )


# ===============================================================
# REAL BACKEND DIRECT ROUTE ALIASES
# ===============================================================

@app.api_route(
    "/api/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def api_proxy(
    path: str,
    request: Request,
):

    target = "/" + path

    stats[
        "/api/" + path
    ] += 1

    return await proxy_request(
        request,
        target,
    )


@app.api_route(
    "/backend/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def backend_proxy(
    path: str,
    request: Request,
):

    target = "/" + path

    stats[
        "/backend/" + path
    ] += 1

    return await proxy_request(
        request,
        target,
    )


# ===============================================================
# INTERNAL PROXY
# ===============================================================

@app.api_route(
    "/internal/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def internal_proxy(
    path: str,
    request: Request,
):

    stats[
        "/internal/" + path
    ] += 1

    return await proxy_request(
        request,
        "/" + path,
    )


# ===============================================================
# COMMON DIRECT BACKEND ALIASES
# ===============================================================

@app.api_route(
    "/arya/auth/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def arya_auth_proxy(
    path: str,
    request: Request,
):

    stats[
        "/arya/auth/" + path
    ] += 1

    return await proxy_request(
        request,
        "/auth/" + path,
    )


@app.api_route(
    "/arya/farms/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def arya_farms_proxy(
    path: str,
    request: Request,
):

    stats[
        "/arya/farms/" + path
    ] += 1

    return await proxy_request(
        request,
        "/farms/" + path,
    )


@app.api_route(
    "/arya/lands/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def arya_lands_proxy(
    path: str,
    request: Request,
):

    stats[
        "/arya/lands/" + path
    ] += 1

    return await proxy_request(
        request,
        "/lands/" + path,
    )


@app.api_route(
    "/arya/crops/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def arya_crops_proxy(
    path: str,
    request: Request,
):

    stats[
        "/arya/crops/" + path
    ] += 1

    return await proxy_request(
        request,
        "/crops/" + path,
    )


@app.api_route(
    "/arya/media/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def arya_media_proxy(
    path: str,
    request: Request,
):

    stats[
        "/arya/media/" + path
    ] += 1

    return await proxy_request(
        request,
        "/media/" + path,
    )


# ===============================================================
# STARTUP
# ===============================================================

@app.on_event(
    "startup"
)
async def startup():

    await load_openapi(
        force=True
    )


# ===============================================================
# SHUTDOWN
# ===============================================================

@app.on_event(
    "shutdown"
)
async def shutdown():

    _openapi_cache.clear()


# ===============================================================
# LOCAL RUN
# ===============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "arya_master_system:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
