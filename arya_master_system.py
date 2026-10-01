"""
ARYA AgriDoctor — MASTER GATEWAY
Version: 2.0.0

Central gateway for the real ARYA AgriDoctor backend.

Important:
- backend/main.py is NOT modified by this file.
- The master discovers the real backend routes from /openapi.json.
- Generic proxy routes allow future backend endpoints without adding
  another master wrapper.
- Compatibility routes are provided for legacy /arya/* clients.
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
APP_VERSION = "2.0.0"

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


# ===============================================================
# FASTAPI
# ===============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Single gateway for the real "
        "ARYA AgriDoctor backend"
    ),
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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
# HELPERS
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
        for key, value
        in headers.items()
        if key.lower()
        not in excluded
    }


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


def success() -> None:

    backend_circuit.failures = 0
    backend_circuit.opened_at = 0.0


def failure(
    error: str,
) -> None:

    global last_error

    last_error = str(error)

    backend_circuit.failures += 1

    if (
        backend_circuit.failures
        >= CIRCUIT_FAILURE_THRESHOLD
    ):

        backend_circuit.opened_at = (
            time.time()
        )


# ===============================================================
# HMAC
# ===============================================================

def signature(
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

    expected = signature(
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

    if (
        len(body)
        > MAX_REQUEST_BYTES
    ):

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

    target = backend_url(
        path
    )

    request_headers = dict(
        headers or {}
    )

    if INTERNAL_SECRET:

        request_headers[
            "X-ARYA-Gateway"
        ] = "ARYA-MASTER"

        request_headers[
            "X-ARYA-Signature"
        ] = signature(
            method,
            path,
            body,
        )

    last_exc: Optional[
        Exception
    ] = None

    for attempt in range(
        attempts
    ):

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

                failure(
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
                and attempt + 1
                < attempts
            ):

                await asyncio.sleep(
                    0.35
                    * (attempt + 1)
                )

                continue

            if (
                200
                <= response.status_code
                < 500
            ):

                success()

            elif (
                response.status_code
                >= 500
            ):

                failure(
                    "backend_http_"
                    + str(
                        response.status_code
                    )
                )

            else:

                success()

            return response

        except HTTPException:

            raise

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.ConnectError,
        ) as exc:

            last_exc = exc

            failure(
                str(exc)
            )

            if (
                attempt + 1
                < attempts
            ):

                await asyncio.sleep(
                    0.35
                    * (attempt + 1)
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
        ).encode(
            "utf-8"
        )

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
        (
            key,
            value,
        )

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

    content_type = response.headers.get(
        "content-type"
    )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
        media_type=content_type,
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

        if (
            response.status_code
            == 200
        ):

            data = response.json()

            if isinstance(
                data,
                dict,
            ):

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
        .get(
            "paths",
            {}
        )
        .get(
            path
        )
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


async def resolve_candidate(
    candidates: list[str],
    method: str,
) -> Optional[str]:

    openapi = await load_openapi()

    for path in candidates:

        if route_exists(
            openapi,
            path,
            method,
        ):

            return path

    if not openapi:

        if candidates:
            return candidates[0]

    return None


# ===============================================================
# QUERY
# ===============================================================

def query_to_dict(
    request: Request,
) -> dict[str, Any]:

    result: dict[
        str,
        Any,
    ] = {}

    for key, value in (
        request
        .query_params
        .multi_items()
    ):

        result[key] = value

    return result


# ===============================================================
# COMPATIBILITY ROUTER
# ===============================================================

async def compatibility_json_request(
    request: Request,
    candidates: list[str],
    *,
    default_body:
        Optional[
            dict[str, Any]
        ] = None,
) -> Response:

    method = request.method.upper()

    body = await request.body()

    if body:

        try:

            payload = json.loads(
                body.decode(
                    "utf-8"
                )
            )

        except Exception:

            payload = (
                default_body
                or {}
            )

    else:

        payload = (
            default_body
            or query_to_dict(
                request
            )
        )

    target_method = method

    if method == "GET":

        target_method = "POST"

    target = await resolve_candidate(
        candidates,
        target_method,
    )

    if not target:

        return JSONResponse(
            status_code=404,
            content={
                "ok": False,
                "error":
                    "compatible_backend_route_not_found",
                "candidates":
                    candidates,
            },
        )

    if (
        target_method
        == "GET"
    ):

        result = await backend_json(
            "GET",
            target,
            query=[
                (
                    str(k),
                    str(v),
                )

                for k, v
                in payload.items()
            ],
        )

    else:

        result = await backend_json(
            "POST",
            target,
            body=payload,
        )

    return JSONResponse(
        content=result,
        status_code=200,
    )


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

    started = (
        time.perf_counter()
    )

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
            "ok":
                False,

            "master":
                "ok",

            "backend": {
                "ok":
                    False,

                "error":
                    str(exc),
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
            {}
        )
        if openapi
        else {}
    )

    return {

        "ok":
            True,

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

            "weather":
                "backend /weather",

            "location":
                "backend /location/resolve",

            "ai":
                "backend AI endpoints "
                "discovered from OpenAPI",

            "storage":
                "backend SQLite",
        },

        "backend":
            BACKEND_URL,

        "routes":
            sorted(
                openapi.get(
                    "paths",
                    {}
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
            {}
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

                        for method
                        in methods

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
                        {}
                    )
                )
                if openapi
                else 0
            ),
    }


# ===============================================================
# WEATHER
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

    return await compatibility_json_request(
        request,
        [
            "/weather",
        ],
    )


# ===============================================================
# GEOCODING / LOCATION
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

    return await compatibility_json_request(
        request,
        [
            "/location/resolve",
        ],
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

    return await compatibility_json_request(
        request,
        [
            "/location/resolve",
        ],
    )


# ===============================================================
# AGRICULTURAL COMPATIBILITY
# ===============================================================

async def compatibility_ai(
    request: Request,
    candidates: list[str],
) -> Response:

    return await compatibility_json_request(
        request,
        candidates,
    )


@app.api_route(
    "/arya/doctor",
    methods=[
        "POST",
        "GET",
    ],
)
async def arya_doctor(
    request: Request,
):

    return await compatibility_ai(
        request,
        [
            "/ai/ask",
            "/ask",
            "/agri/ask",
            "/agri/analyze",
            "/analyze",
        ],
    )


@app.api_route(
    "/arya/diagnose",
    methods=[
        "POST",
        "GET",
    ],
)
async def arya_diagnose(
    request: Request,
):

    return await compatibility_ai(
        request,
        [
            "/ai/ask",
            "/ask",
            "/agri/diagnose",
            "/agri/analyze",
            "/analyze",
        ],
    )


@app.api_route(
    "/arya/analyze",
    methods=[
        "POST",
        "GET",
    ],
)
async def arya_analyze(
    request: Request,
):

    return await compatibility_ai(
        request,
        [
            "/agri/analyze",
            "/analyze",
            "/ai/ask",
            "/ask",
        ],
    )


@app.api_route(
    "/arya/recommend",
    methods=[
        "POST",
        "GET",
    ],
)
async def arya_recommend(
    request: Request,
):

    return await compatibility_ai(
        request,
        [
            "/agri/recommend",
            "/recommend",
            "/ai/ask",
            "/ask",
        ],
    )


@app.api_route(
    "/arya/region-analysis",
    methods=[
        "POST",
        "GET",
    ],
)
async def arya_region_analysis(
    request: Request,
):

    return await compatibility_ai(
        request,
        [
            "/region/analyze",
            "/region-analysis",
            "/ai/region",
            "/ai/ask",
        ],
    )


# ===============================================================
# GENERIC API PROXY
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

    stats[
        "/api/" + path
    ] += 1

    return await proxy_request(
        request,
        "/" + path,
    )


# ===============================================================
# BACKEND PROXY
# ===============================================================

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

    stats[
        "/backend/" + path
    ] += 1

    return await proxy_request(
        request,
        "/" + path,
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
