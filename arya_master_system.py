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

APP_NAME = "ARYA AgriDoctor MASTER GATEWAY"
APP_VERSION = "2.0.0"

BACKEND_URL = os.getenv(
    "ARYA_BACKEND_URL",
    "http://127.0.0.1:8000"
).rstrip("/")

HOST = os.getenv(
    "ARYA_MASTER_HOST",
    "0.0.0.0"
)

PORT = int(
    os.getenv(
        "ARYA_MASTER_PORT",
        "8030"
    )
)

TIMEOUT = float(
    os.getenv(
        "ARYA_MASTER_TIMEOUT",
        "30"
    )
)

RETRIES = max(
    0,
    int(
        os.getenv(
            "ARYA_MASTER_RETRIES",
            "2"
        )
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_MASTER_MAX_REQUEST_BYTES",
        str(8 * 1024 * 1024)
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_MASTER_MAX_RESPONSE_BYTES",
        str(16 * 1024 * 1024)
    )
)

CIRCUIT_THRESHOLD = max(
    1,
    int(
        os.getenv(
            "ARYA_MASTER_CIRCUIT_FAILURE_THRESHOLD",
            "3"
        )
    )
)

CIRCUIT_COOLDOWN = max(
    1.0,
    float(
        os.getenv(
            "ARYA_MASTER_CIRCUIT_COOLDOWN_SECONDS",
            "30"
        )
    )
)

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    ""
)

REQUIRE_SIGNATURE = os.getenv(
    "ARYA_MASTER_REQUIRE_INTERNAL_SIGNATURE",
    "false"
).lower() in {
    "1",
    "true",
    "yes",
    "on",
}

OPENAPI_CACHE_SECONDS = max(
    1.0,
    float(
        os.getenv(
            "ARYA_MASTER_OPENAPI_CACHE_SECONDS",
            "15"
        )
    )
)

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


class Circuit:

    def __init__(self):
        self.failures = 0
        self.opened_at = 0.0


circuit = Circuit()

stats = defaultdict(int)

last_error: Optional[str] = None

_openapi: dict[str, Any] = {}

_openapi_at = 0.0


def make_url(path: str) -> str:
    return BACKEND_URL + (
        path
        if path.startswith("/")
        else "/" + path
    )


def safe_headers(
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
        k: v
        for k, v in headers.items()
        if k.lower() not in excluded
    }


def is_open() -> bool:

    if not circuit.opened_at:
        return False

    if (
        time.time() - circuit.opened_at
        >= CIRCUIT_COOLDOWN
    ):
        circuit.failures = 0
        circuit.opened_at = 0.0
        return False

    return True


def mark_success() -> None:

    circuit.failures = 0
    circuit.opened_at = 0.0


def mark_failure(error: str) -> None:

    global last_error

    last_error = str(error)

    circuit.failures += 1

    if circuit.failures >= CIRCUIT_THRESHOLD:
        circuit.opened_at = time.time()


def make_signature(
    method: str,
    path: str,
    body: bytes,
) -> str:

    if not INTERNAL_SECRET:
        return ""

    msg = (
        method.upper().encode()
        + b"\n"
        + path.encode()
        + b"\n"
        + body
    )

    return hmac.new(
        INTERNAL_SECRET.encode(),
        msg,
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

    return bool(received) and hmac.compare_digest(
        received,
        expected,
    )


async def call_backend(
    method: str,
    path: str,
    *,
    body: bytes = b"",
    query=None,
    headers=None,
    retry=True,
) -> httpx.Response:

    if is_open():
        raise HTTPException(
            503,
            {
                "ok": False,
                "error": "backend_circuit_open",
            },
        )

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            413,
            {
                "ok": False,
                "error": "request_too_large",
            },
        )

    method = method.upper()

    attempts = (
        RETRIES + 1
        if retry
        and method in {
            "GET",
            "HEAD",
            "OPTIONS",
        }
        else 1
    )

    req_headers = dict(headers or {})

    if INTERNAL_SECRET:
        req_headers[
            "X-ARYA-Gateway"
        ] = "ARYA-MASTER"

        req_headers[
            "X-ARYA-Signature"
        ] = make_signature(
            method,
            path,
            body,
        )

    last_exc = None

    for attempt in range(attempts):

        try:

            async with httpx.AsyncClient(
                timeout=TIMEOUT,
                follow_redirects=False,
            ) as client:

                response = await client.request(
                    method,
                    make_url(path),
                    content=body,
                    params=query,
                    headers=req_headers,
                )

            if (
                len(response.content)
                > MAX_RESPONSE_BYTES
            ):
                mark_failure(
                    "response_too_large"
                )

                raise HTTPException(
                    502,
                    {
                        "ok": False,
                        "error":
                            "backend_response_too_large",
                    },
                )

            if response.status_code >= 500:

                mark_failure(
                    f"backend_http_"
                    f"{response.status_code}"
                )

                if attempt + 1 < attempts:

                    await asyncio.sleep(
                        0.35 * (attempt + 1)
                    )

                    continue

            else:
                mark_success()

            return response

        except HTTPException:
            raise

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
        ) as exc:

            last_exc = exc

            mark_failure(str(exc))

            if attempt + 1 < attempts:

                await asyncio.sleep(
                    0.35 * (attempt + 1)
                )

    raise HTTPException(
        502,
        {
            "ok": False,
            "error": "backend_unreachable",
            "message": str(
                last_exc or "unknown error"
            ),
        },
    )


async def json_backend(
    method: str,
    path: str,
    payload: Any = None,
    query=None,
) -> Any:

    body = b""

    headers = {
        "Accept": "application/json",
    }

    if payload is not None:

        body = json.dumps(
            payload,
            ensure_ascii=False,
        ).encode("utf-8")

        headers[
            "Content-Type"
        ] = "application/json"

    response = await call_backend(
        method,
        path,
        body=body,
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


async def load_openapi(
    force=False,
) -> dict[str, Any]:

    global _openapi
    global _openapi_at

    if (
        _openapi
        and not force
        and (
            time.time()
            - _openapi_at
            < OPENAPI_CACHE_SECONDS
        )
    ):
        return _openapi

    try:

        response = await call_backend(
            "GET",
            "/openapi.json",
        )

        if response.status_code == 200:

            data = response.json()

            if isinstance(data, dict):

                _openapi = data

                _openapi_at = time.time()

    except Exception:
        pass

    return _openapi


def route_exists(
    spec: dict[str, Any],
    path: str,
    method: str,
) -> bool:

    item = (
        spec
        .get("paths", {})
        .get(path)
    )

    return (
        isinstance(item, dict)
        and method.lower() in item
    )


async def choose(
    candidates: list[str],
    method: str,
) -> Optional[str]:

    spec = await load_openapi()

    for path in candidates:

        if route_exists(
            spec,
            path,
            method,
        ):
            return path

    if not spec:
        return (
            candidates[0]
            if candidates
            else None
        )

    return None


# ============================================================
# NEW: LEGACY / MOBILE AI PAYLOAD NORMALIZER
# ============================================================

def normalize_ai_payload(
    payload: Any,
) -> dict[str, Any]:

    """
    Convert legacy/mobile AI payloads
    to the current /ai/analyze contract.

    Existing fields are preserved inside
    context so no information is discarded.
    """

    if not isinstance(payload, dict):

        payload = {
            "prompt": str(
                payload or ""
            )
        }

    prompt = (
        payload.get("prompt")
        or payload.get("question")
        or payload.get("query")
        or payload.get("message")
        or payload.get("text")
        or ""
    )

    language = (
        payload.get("language")
        or payload.get("lang")
        or "fa"
    )

    context = payload.get("context")

    if not isinstance(context, dict):
        context = {}

    mapping = {

        "crop":
            "crop",

        "crop_name":
            "crop",

        "product":
            "crop",

        "plant":
            "plant",

        "tree":
            "plant",

        "species":
            "plant",

        "symptoms":
            "symptoms",

        "symptom":
            "symptoms",

        "soil":
            "soil",

        "soil_data":
            "soil",

        "water":
            "water",

        "water_data":
            "water",

        "weather":
            "weather",

        "location":
            "location",

        "lab":
            "lab",

        "image":
            "image_description",

        "image_description":
            "image_description",

        "additional_information":
            "additional_information",

        "extra_data":
            "extra_data",
    }

    for src, dst in mapping.items():

        if (
            src in payload
            and payload[src] is not None
            and dst not in context
        ):

            context[dst] = payload[src]

    control = {
        "prompt",
        "question",
        "query",
        "message",
        "text",
        "language",
        "lang",
        "context",
    }

    for key, value in payload.items():

        if (
            key not in control
            and key not in context
        ):

            context[key] = value

    return {
        "prompt": str(prompt),
        "language": str(language),
        "context": context,
    }


async def ai_analyze_compat(
    request: Request,
) -> Response:

    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:

        return JSONResponse(
            413,
            {
                "ok": False,
                "error":
                    "request_too_large",
            },
        )

    try:

        payload = (
            json.loads(
                body.decode("utf-8")
            )
            if body
            else {}
        )

    except Exception:

        payload = {
            "text":
                body.decode(
                    "utf-8",
                    errors="replace",
                )
        }

    normalized = normalize_ai_payload(
        payload
    )

    headers = {
        "Accept":
            "application/json",

        "Content-Type":
            "application/json",
    }

    auth = request.headers.get(
        "Authorization"
    )

    if auth:
        headers[
            "Authorization"
        ] = auth

    response = await call_backend(
        "POST",
        "/ai/analyze",
        body=json.dumps(
            normalized,
            ensure_ascii=False,
        ).encode("utf-8"),
        headers=headers,
        retry=False,
    )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=safe_headers(
            response.headers
        ),
        media_type=response.headers.get(
            "content-type"
        ),
    )


async def compat(
    request: Request,
    candidates: list[str],
) -> Response:

    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:

        return JSONResponse(
            413,
            {
                "ok": False,
                "error":
                    "request_too_large",
            },
        )

    try:

        payload = (
            json.loads(
                body.decode("utf-8")
            )
            if body
            else {
                k: v
                for k, v
                in request.query_params.multi_items()
            }
        )

    except Exception:

        payload = {
            "raw":
                body.decode(
                    "utf-8",
                    errors="replace",
                )
        }

    method = request.method.upper()

    target_method = (
        "POST"
        if method == "GET"
        else method
    )

    target = await choose(
        candidates,
        target_method,
    )

    if not target:

        return JSONResponse(
            404,
            {
                "ok": False,
                "error":
                    "compatible_backend_route_not_found",
                "candidates":
                    candidates,
            },
        )

    if target_method == "GET":

        data = await json_backend(
            "GET",
            target,
            query=list(
                request.query_params.multi_items()
            ),
        )

    else:

        data = await json_backend(
            target_method,
            target,
            payload,
        )

    return JSONResponse(data)


@app.get("/")
async def root():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "backend": BACKEND_URL,
    }


@app.get("/health")
async def health():

    started = time.perf_counter()

    try:

        r = await call_backend(
            "GET",
            "/health",
        )

        return {
            "ok":
                200 <= r.status_code < 300,

            "master":
                "ok",

            "backend_status":
                r.status_code,

            "latency_ms":
                round(
                    (
                        time.perf_counter()
                        - started
                    ) * 1000,
                    2,
                ),
        }

    except Exception as exc:

        return {
            "ok": False,

            "master":
                "ok",

            "backend": {
                "ok": False,
                "error": str(exc),
            },

            "latency_ms":
                round(
                    (
                        time.perf_counter()
                        - started
                    ) * 1000,
                    2,
                ),
        }


@app.get("/status")
async def status():

    spec = await load_openapi()

    return {
        "ok": True,

        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "backend":
            BACKEND_URL,

        "circuit_open":
            is_open(),

        "failures":
            circuit.failures,

        "last_error":
            last_error,

        "route_count":
            len(
                spec.get(
                    "paths",
                    {},
                )
            ),

        "requests":
            dict(stats),
    }


@app.get("/system-map")
async def system_map():

    spec = await load_openapi()

    return {
        "ok": True,

        "master":
            APP_NAME,

        "backend":
            BACKEND_URL,

        "backend_routes":
            sorted(
                spec.get(
                    "paths",
                    {},
                ).keys()
            ),
    }


@app.get("/backend-routes")
async def backend_routes():

    spec = await load_openapi()

    paths = spec.get(
        "paths",
        {},
    )

    return {
        "ok":
            bool(spec),

        "count":
            len(paths),

        "routes": {
            p:
                sorted(
                    m.upper()
                    for m in v
                    if m.lower()
                    in {
                        "get",
                        "post",
                        "put",
                        "patch",
                        "delete",
                        "options",
                        "head",
                    }
                )

            for p, v in paths.items()

            if isinstance(v, dict)
        },
    }


@app.post("/backend-routes/refresh")
async def refresh_routes():

    spec = await load_openapi(True)

    return {
        "ok":
            bool(spec),

        "count":
            len(
                spec.get(
                    "paths",
                    {},
                )
            ),
    }


@app.api_route(
    "/arya/weather",
    methods=["GET", "POST"],
)
async def arya_weather(
    request: Request,
):

    return await compat(
        request,
        ["/weather"],
    )


@app.api_route(
    "/arya/geocode",
    methods=["GET", "POST"],
)
async def arya_geocode(
    request: Request,
):

    return await compat(
        request,
        ["/location/resolve"],
    )


@app.api_route(
    "/arya/location/resolve",
    methods=["GET", "POST"],
)
async def arya_location(
    request: Request,
):

    return await compat(
        request,
        ["/location/resolve"],
    )


# ============================================================
# REAL SPECIALIST AI ROUTES
# ============================================================

@app.api_route(
    "/arya/doctor",
    methods=["POST"],
)
async def arya_doctor(
    request: Request,
):

    return await ai_analyze_compat(
        request
    )


@app.api_route(
    "/arya/diagnose",
    methods=["POST"],
)
async def arya_diagnose(
    request: Request,
):

    return await ai_analyze_compat(
        request
    )


@app.api_route(
    "/arya/analyze",
    methods=["POST"],
)
async def arya_analyze(
    request: Request,
):

    return await ai_analyze_compat(
        request
    )


@app.api_route(
    "/ai/analyze",
    methods=["POST"],
)
async def direct_ai_analyze(
    request: Request,
):

    return await ai_analyze_compat(
        request
    )


# ============================================================
# LEGACY MOBILE AI COMPATIBILITY
# ============================================================

@app.api_route(
    "/ai/ask",
    methods=["POST"],
)
async def legacy_ai_ask(
    request: Request,
):

    return await ai_analyze_compat(
        request
    )


@app.api_route(
    "/ask",
    methods=["POST"],
)
async def legacy_ask(
    request: Request,
):

    return await ai_analyze_compat(
        request
    )


@app.api_route(
    "/analyze",
    methods=["POST"],
)
async def legacy_analyze(
    request: Request,
):

    return await ai_analyze_compat(
        request
    )


@app.api_route(
    "/agri/analyze",
    methods=["POST"],
)
async def legacy_agri_analyze(
    request: Request,
):

    return await ai_analyze_compat(
        request
    )


@app.api_route(
    "/arya/recommend",
    methods=["GET", "POST"],
)
async def arya_recommend(
    request: Request,
):

    return await compat(
        request,
        [
            "/recommend",
            "/agri/recommend",
            "/ai/ask",
            "/ask",
        ],
    )


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
        f"/api/{path}"
    ] += 1

    return await passthrough(
        request,
        "/" + path,
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

    stats[
        f"/backend/{path}"
    ] += 1

    return await passthrough(
        request,
        "/" + path,
    )


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

    body = await request.body()

    if (
        REQUIRE_SIGNATURE
        and not verify_signature(
            request,
            body,
        )
    ):

        return JSONResponse(
            401,
            {
                "ok": False,
                "error":
                    "invalid_internal_signature",
            },
        )

    stats[
        f"/internal/{path}"
    ] += 1

    return await passthrough(
        request,
        "/" + path,
        body=body,
    )


async def passthrough(
    request: Request,
    path: str,
    body: Optional[bytes] = None,
) -> Response:

    if body is None:
        body = await request.body()

    response = await call_backend(
        request.method,
        path,
        body=body,
        query=list(
            request.query_params.multi_items()
        ),
        headers=safe_headers(
            request.headers
        ),
        retry=request.method
        in {
            "GET",
            "HEAD",
            "OPTIONS",
        },
    )

    headers = safe_headers(
        response.headers
    )

    media_type = response.headers.get(
        "content-type"
    )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=headers,
        media_type=media_type,
    )


@app.get("/services")
async def services():

    spec = await load_openapi()

    return {
        "ok": True,
        "backend":
            BACKEND_URL,
        "routes":
            sorted(
                spec.get(
                    "paths",
                    {},
                ).keys()
            ),
    }


@app.get("/providers")
async def providers():

    return {
        "ok": True,

        "providers": {
            "open_meteo_weather":
                "backend:/weather",

            "open_meteo_geocoding":
                "backend:/location/resolve",
        },
    }


@app.api_route(
    "/weather",
    methods=["GET"],
)
async def weather_get_compat(
    request: Request,
):

    return await compat(
        request,
        ["/weather"],
    )


@app.api_route(
    "/location/resolve",
    methods=["GET"],
)
async def location_get_compat(
    request: Request,
):

    return await compat(
        request,
        ["/location/resolve"],
    )


@app.api_route(
    "/service/{path:path}",
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
async def service_compat(
    path: str,
    request: Request,
):

    return await passthrough(
        request,
        "/" + path,
    )


@app.api_route(
    "/orchestrate",
    methods=["POST"],
)
async def orchestrate(
    request: Request,
):

    body = await request.body()

    try:

        payload = (
            json.loads(
                body.decode("utf-8")
            )
            if body
            else {}
        )

    except Exception:

        payload = {}

    action = (
        payload.get("action", "")
        if isinstance(
            payload,
            dict,
        )
        else ""
    )

    data = (
        payload.get("data", {})
        if isinstance(
            payload,
            dict,
        )
        else {}
    )

    candidates = {

        "doctor":
            ["/ai/analyze"],

        "full_diagnosis":
            ["/ai/analyze"],

        "complete_diagnosis":
            ["/ai/analyze"],

        "weather":
            ["/weather"],

        "location":
            ["/location/resolve"],

        "analyze":
            ["/ai/analyze"],

        "recommend":
            [
                "/recommend",
                "/agri/recommend",
                "/ai/ask",
                "/ask",
            ],

    }.get(action)

    if not candidates:

        return JSONResponse(
            404,
            {
                "ok": False,
                "error":
                    "unknown_action",
                "action":
                    action,
            },
        )

    target = await choose(
        candidates,
        "POST",
    )

    if not target:

        return JSONResponse(
            404,
            {
                "ok": False,
                "error":
                    "backend_route_not_found",
                "candidates":
                    candidates,
            },
        )

    return JSONResponse(
        await json_backend(
            "POST",
            target,
            data,
        )
    )


@app.on_event("startup")
async def startup():

    await load_openapi(True)


# ============================================================
# FINAL FALLBACK
# ============================================================

@app.api_route(
    "/{path:path}",
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
async def final_backend_fallback(
    path: str,
    request: Request,
):

    return await passthrough(
        request,
        "/" + path,
    )


if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "arya_master_system:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
