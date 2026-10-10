نام فایل: "arya_master_system.py"
مسیر: "backend/arya_master_system.py"

نسخهٔ کامل اصلاح‌شده برای جایگزینی فایل اصلی:

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


# ============================================================
# ARYA AgriDoctor MASTER GATEWAY
# Version: 2.1.0
# Central Gateway - Preserve Legacy and Current Routes
# ============================================================

APP_NAME = "ARYA AgriDoctor MASTER GATEWAY"
APP_VERSION = "2.1.0"

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

TIMEOUT = max(
    1.0,
    float(
        os.getenv(
            "ARYA_MASTER_TIMEOUT",
            "30",
        )
    ),
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

MAX_REQUEST_BYTES = max(
    1024,
    int(
        os.getenv(
            "ARYA_MASTER_MAX_REQUEST_BYTES",
            str(8 * 1024 * 1024),
        )
    ),
)

MAX_RESPONSE_BYTES = max(
    1024,
    int(
        os.getenv(
            "ARYA_MASTER_MAX_RESPONSE_BYTES",
            str(16 * 1024 * 1024),
        )
    ),
)

CIRCUIT_THRESHOLD = max(
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

REQUIRE_SIGNATURE = os.getenv(
    "ARYA_MASTER_REQUIRE_INTERNAL_SIGNATURE",
    "false",
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
            "15",
        )
    ),
)

# Configure explicit origins for production deployments.
# Wildcard origins cannot safely be combined with credentials.
CORS_ORIGINS = [
    item.strip()
    for item in os.getenv(
        "ARYA_MASTER_CORS_ORIGINS",
        "*",
    ).split(",")
    if item.strip()
]

ALLOW_CREDENTIALS = "*" not in CORS_ORIGINS

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Central gateway for the ARYA AgriDoctor backend, "
        "legacy clients, AI analysis, weather, location, "
        "service routing, and orchestration."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=ALLOW_CREDENTIALS,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
    allow_headers=["*"],
)


# ============================================================
# CENTRAL RUNTIME STATE
# ============================================================

class Circuit:

    def __init__(self) -> None:
        self.failures = 0
        self.opened_at = 0.0


circuit = Circuit()

stats: defaultdict[str, int] = defaultdict(int)

last_error: Optional[str] = None

_openapi: dict[str, Any] = {}
_openapi_at = 0.0

_state_lock = asyncio.Lock()
_openapi_lock = asyncio.Lock()


# ============================================================
# COMMON RESPONSE AND HEADER HELPERS
# ============================================================

def make_url(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path

    return BACKEND_URL + path


def safe_headers(
    headers: Any,
) -> dict[str, str]:

    excluded = {
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
    }

    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in excluded
    }


def error_response(
    status_code: int,
    error: str,
    **extra: Any,
) -> JSONResponse:

    return JSONResponse(
        status_code=status_code,
        content={
            "ok": False,
            "error": error,
            **extra,
        },
    )


def http_exception_response(
    exc: HTTPException,
) -> JSONResponse:

    detail = exc.detail

    if isinstance(detail, dict):
        content = detail
    else:
        content = {
            "ok": False,
            "error": str(detail),
        }

    return JSONResponse(
        status_code=exc.status_code,
        content=content,
        headers=exc.headers,
    )


def response_from_backend(
    response: httpx.Response,
) -> Response:

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=safe_headers(response.headers),
        media_type=response.headers.get("content-type"),
    )


async def read_limited_body(
    request: Request,
) -> bytes:
    """
    Enforce the configured application-level request size.

    Content-Length is checked when available, then the streamed
    body is counted so an absent or incorrect header cannot bypass
    this limit.
    """

    content_length = request.headers.get("content-length")

    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="invalid_content_length",
            )

        if length < 0:
            raise HTTPException(
                status_code=400,
                detail="invalid_content_length",
            )

        if length > MAX_REQUEST_BYTES:
            raise HTTPException(
                status_code=413,
                detail="request_too_large",
            )

    chunks: list[bytes] = []
    total = 0

    async for chunk in request.stream():
        total += len(chunk)

        if total > MAX_REQUEST_BYTES:
            raise HTTPException(
                status_code=413,
                detail="request_too_large",
            )

        chunks.append(chunk)

    return b"".join(chunks)


def parse_json_body(body: bytes) -> Any:
    if not body:
        return {}

    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(
            status_code=400,
            detail="invalid_json",
        )


def encode_json(payload: Any) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "ok": False,
                "error": "payload_not_json_serializable",
                "message": str(exc),
            },
        )


# ============================================================
# INTERNAL HMAC SIGNATURE
# ============================================================

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

    return bool(received) and hmac.compare_digest(
        received,
        expected,
    )


# ============================================================
# CIRCUIT BREAKER
# ============================================================

async def is_open() -> bool:

    async with _state_lock:

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


async def mark_success() -> None:

    async with _state_lock:
        circuit.failures = 0
        circuit.opened_at = 0.0


async def mark_failure(error: str) -> None:

    global last_error

    async with _state_lock:
        last_error = str(error)
        circuit.failures += 1

        if circuit.failures >= CIRCUIT_THRESHOLD:
            circuit.opened_at = time.time()


# ============================================================
# CENTRAL BACKEND REQUEST CLIENT
# ============================================================

async def call_backend(
    method: str,
    path: str,
    *,
    body: bytes = b"",
    query: Any = None,
    headers: Optional[dict[str, str]] = None,
    retry: bool = True,
) -> httpx.Response:

    if await is_open():
        raise HTTPException(
            status_code=503,
            detail={
                "ok": False,
                "error": "backend_circuit_open",
            },
        )

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "ok": False,
                "error": "request_too_large",
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
        if retry and method in retryable_methods
        else 1
    )

    request_headers = dict(headers or {})

    if INTERNAL_SECRET:
        request_headers["X-ARYA-Gateway"] = "ARYA-MASTER"
        request_headers["X-ARYA-Signature"] = make_signature(
            method,
            path,
            body,
        )

    last_exception: Optional[Exception] = None

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
                    headers=request_headers,
                )

            if len(response.content) > MAX_RESPONSE_BYTES:
                await mark_failure("response_too_large")

                raise HTTPException(
                    status_code=502,
                    detail={
                        "ok": False,
                        "error": "backend_response_too_large",
                    },
                )

            if response.status_code >= 500:
                await mark_failure(
                    f"backend_http_{response.status_code}"
                )

                if attempt + 1 < attempts:
                    await asyncio.sleep(
                        0.35 * (attempt + 1)
                    )
                    continue
            else:
                await mark_success()

            return response

        except HTTPException:
            raise

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
        ) as exc:

            last_exception = exc
            await mark_failure(str(exc))

            if attempt + 1 < attempts:
                await asyncio.sleep(
                    0.35 * (attempt + 1)
                )

        except httpx.HTTPError as exc:

            last_exception = exc
            await mark_failure(str(exc))

            if attempt + 1 < attempts:
                await asyncio.sleep(
                    0.35 * (attempt + 1)
                )

    raise HTTPException(
        status_code=502,
        detail={
            "ok": False,
            "error": "backend_unreachable",
            "message": str(
                last_exception or "unknown_error"
            ),
        },
    )


async def json_backend(
    method: str,
    path: str,
    payload: Any = None,
    query: Any = None,
) -> Any:

    body = b""

    headers = {
        "Accept": "application/json",
    }

    if payload is not None:
        body = encode_json(payload)
        headers["Content-Type"] = "application/json"

    response = await call_backend(
        method,
        path,
        body=body,
        query=query,
        headers=headers,
    )

    try:
        return response.json()
    except (ValueError, json.JSONDecodeError):
        return {
            "status_code": response.status_code,
            "text": response.text,
        }


# ============================================================
# BACKEND OPENAPI DISCOVERY AND ROUTE MATCHING
# ============================================================

async def load_openapi(
    force: bool = False,
) -> dict[str, Any]:

    global _openapi
    global _openapi_at

    if (
        _openapi
        and not force
        and time.time() - _openapi_at < OPENAPI_CACHE_SECONDS
    ):
        return _openapi

    async with _openapi_lock:

        if (
            _openapi
            and not force
            and time.time() - _openapi_at < OPENAPI_CACHE_SECONDS
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
            # Preserve the last known valid specification.
            pass

        return _openapi


def route_exists(
    spec: dict[str, Any],
    path: str,
    method: str,
) -> bool:

    item = spec.get("paths", {}).get(path)

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
        if route_exists(spec, path, method):
            return path

    # Only use the configured fallback when OpenAPI itself
    # is unavailable. Do not guess if a valid spec says
    # none of the candidates supports the requested method.
    if not spec:
        return candidates[0] if candidates else None

    return None


# ============================================================
# LEGACY / MOBILE AI PAYLOAD NORMALIZER
# ============================================================

def normalize_ai_payload(
    payload: Any,
) -> dict[str, Any]:

    """
    Normalize legacy/mobile AI request fields.

    Extra input fields are retained inside context so the
    gateway does not silently discard supplied farm data.
    """

    if not isinstance(payload, dict):
        payload = {
            "prompt": str(payload or ""),
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

    original_context = payload.get("context")

    context = (
        dict(original_context)
        if isinstance(original_context, dict)
        else {}
    )

    mapping = {
        "crop": "crop",
        "crop_name": "crop",
        "product": "crop",
        "plant": "plant",
        "tree": "plant",
        "species": "plant",
        "symptoms": "symptoms",
        "symptom": "symptoms",
        "soil": "soil",
        "soil_data": "soil",
        "water": "water",
        "water_data": "water",
        "weather": "weather",
        "location": "location",
        "lab": "lab",
        "image": "image_description",
        "image_description": "image_description",
        "additional_information": "additional_information",
        "extra_data": "extra_data",
    }

    for source, destination in mapping.items():
        if (
            source in payload
            and payload[source] is not None
            and destination not in context
        ):
            context[destination] = payload[source]

    control_fields = {
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
        if key not in control_fields and key not in context:
            context[key] = value

    return {
        "prompt": str(prompt),
        "language": str(language),
        "context": context,
    }


# ============================================================
# CENTRAL AI COMPATIBILITY HANDLER
# ============================================================

async def ai_analyze_compat(
    request: Request,
) -> Response:

    try:
        body = await read_limited_body(request)
        payload = parse_json_body(body)
    except HTTPException as exc:
        return http_exception_response(exc)

    normalized = normalize_ai_payload(payload)

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    authorization = request.headers.get("Authorization")

    if authorization:
        headers["Authorization"] = authorization

    try:
        response = await call_backend(
            "POST",
            "/ai/analyze",
            body=encode_json(normalized),
            headers=headers,
            retry=False,
        )

        return response_from_backend(response)

    except HTTPException as exc:
        return http_exception_response(exc)


# ============================================================
# GENERIC COMPATIBILITY HANDLER
# ============================================================

async def compat(
    request: Request,
    candidates: list[str],
) -> Response:

    method = request.method.upper()

    try:
        body = await read_limited_body(request)
    except HTTPException as exc:
        return http_exception_response(exc)

    # Preserve the incoming HTTP method. GET is not converted
    # to POST because doing so breaks weather/location routes.
    target = await choose(
        candidates,
        method,
    )

    if not target:
        return error_response(
            404,
            "compatible_backend_route_not_found",
            candidates=candidates,
            method=method,
        )

    headers = {
        "Accept": request.headers.get(
            "Accept",
            "application/json",
        ),
    }

    authorization = request.headers.get("Authorization")

    if authorization:
        headers["Authorization"] = authorization

    content_type = request.headers.get("Content-Type")

    if content_type and body:
        headers["Content-Type"] = content_type

    try:
        response = await call_backend(
            method,
            target,
            body=body,
            query=list(request.query_params.multi_items()),
            headers=headers,
            retry=method in {"GET", "HEAD", "OPTIONS"},
        )

        return response_from_backend(response)

    except HTTPException as exc:
        return http_exception_response(exc)


# ============================================================
# ROOT / HEALTH / STATUS
# ============================================================

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
        response = await call_backend(
            "GET",
            "/health",
        )

        ok = 200 <= response.status_code < 300

        return JSONResponse(
            status_code=200 if ok else 503,
            content={
                "ok": ok,
                "master": "ok",
                "backend_status": response.status_code,
                "latency_ms": round(
                    (time.perf_counter() - started) * 1000,
                    2,
                ),
            },
        )

    except Exception:
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "master": "ok",
                "backend": {
                    "ok": False,
                    "error": "backend_unavailable",
                },
                "latency_ms": round(
                    (time.perf_counter() - started) * 1000,
                    2,
                ),
            },
        )


@app.get("/status")
async def status():

    spec = await load_openapi()

    async with _state_lock:
        circuit_open = bool(circuit.opened_at)
        failures = circuit.failures
        current_error = last_error

    return {
        "ok": True,
        "service": APP_NAME,
        "version": APP_VERSION,
        "backend": BACKEND_URL,
        "circuit_open": circuit_open,
        "failures": failures,
        "last_error": current_error,
        "route_count": len(spec.get("paths", {})),
        "requests": dict(stats),
    }


@app.get("/system-map")
async def system_map():

    spec = await load_openapi()

    return {
        "ok": True,
        "master": APP_NAME,
        "backend": BACKEND_URL,
        "backend_routes": sorted(
            spec.get("paths", {}).keys()
        ),
    }


@app.get("/backend-routes")
async def backend_routes():

    spec = await load_openapi()
    paths = spec.get("paths", {})

    return {
        "ok": bool(spec),
        "count": len(paths),
        "routes": {
            path: sorted(
                method.upper()
                for method in methods
                if method.lower() in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "options",
                    "head",
                }
            )
            for path, methods in paths.items()
            if isinstance(methods, dict)
        },
    }


@app.post("/backend-routes/refresh")
async def refresh_routes():

    spec = await load_openapi(force=True)

    return {
        "ok": bool(spec),
        "count": len(spec.get("paths", {})),
    }


# ============================================================
# WEATHER / GEOCODING / LOCATION COMPATIBILITY
# ============================================================

@app.api_route(
    "/arya/weather",
    methods=["GET", "POST"],
)
async def arya_weather(request: Request):

    return await compat(
        request,
        ["/weather"],
    )


@app.api_route(
    "/arya/geocode",
    methods=["GET", "POST"],
)
async def arya_geocode(request: Request):

    return await compat(
        request,
        [
            "/location/resolve",
            "/geocode",
        ],
    )


@app.api_route(
    "/arya/location/resolve",
    methods=["GET", "POST"],
)
async def arya_location(request: Request):

    return await compat(
        request,
        ["/location/resolve"],
    )


@app.api_route(
    "/weather",
    methods=["GET"],
)
async def weather_get_compat(request: Request):

    return await compat(
        request,
        ["/weather"],
    )


@app.api_route(
    "/location/resolve",
    methods=["GET"],
)
async def location_get_compat(request: Request):

    return await compat(
        request,
        ["/location/resolve"],
    )


# ============================================================
# SPECIALIST AI ROUTES
# ============================================================

@app.post("/arya/doctor")
async def arya_doctor(request: Request):

    return await ai_analyze_compat(request)


@app.post("/arya/diagnose")
async def arya_diagnose(request: Request):

    return await ai_analyze_compat(request)


@app.post("/arya/analyze")
async def arya_analyze(request: Request):

    return await ai_analyze_compat(request)


@app.post("/ai/analyze")
async def direct_ai_analyze(request: Request):

    return await ai_analyze_compat(request)


# ============================================================
# LEGACY MOBILE AI COMPATIBILITY
# ============================================================

@app.post("/ai/ask")
async def legacy_ai_ask(request: Request):

    return await ai_analyze_compat(request)


@app.post("/ask")
async def legacy_ask(request: Request):

    return await ai_analyze_compat(request)


@app.post("/analyze")
async def legacy_analyze(request: Request):

    return await ai_analyze_compat(request)


@app.post("/agri/analyze")
async def legacy_agri_analyze(request: Request):

    return await ai_analyze_compat(request)


@app.api_route(
    "/arya/recommend",
    methods=["GET", "POST"],
)
async def arya_recommend(request: Request):

    return await compat(
        request,
        [
            "/recommend",
            "/agri/recommend",
            "/ai/ask",
            "/ask",
        ],
    )


# ============================================================
# CENTRAL API PROXY
# ============================================================

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

    stats[f"/api/{path}"] += 1

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

    stats[f"/backend/{path}"] += 1

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

    try:
        body = await read_limited_body(request)
    except HTTPException as exc:
        return http_exception_response(exc)

    if (
        REQUIRE_SIGNATURE
        and not verify_signature(request, body)
    ):
        return error_response(
            401,
            "invalid_internal_signature",
        )

    stats[f"/internal/{path}"] += 1

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
        try:
            body = await read_limited_body(request)
        except HTTPException as exc:
            return http_exception_response(exc)

    headers = safe_headers(request.headers)

    try:
        response = await call_backend(
            request.method,
            path,
            body=body,
            query=list(request.query_params.multi_items()),
            headers=headers,
            retry=request.method.upper() in {
                "GET",
                "HEAD",
                "OPTIONS",
            },
        )

        return response_from_backend(response)

    except HTTPException as exc:
        return http_exception_response(exc)


# ============================================================
# SERVICES / PROVIDERS
# ============================================================

@app.get("/services")
async def services():

    spec = await load_openapi()

    return {
        "ok": True,
        "backend": BACKEND_URL,
        "routes": sorted(
            spec.get("paths", {}).keys()
        ),
    }


@app.get("/providers")
async def providers():

    return {
        "ok": True,
        "providers": {
            "open_meteo_weather": "backend:/weather",
            "open_meteo_geocoding": "backend:/location/resolve",
        },
    }


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


# ============================================================
# ORCHESTRATION
# ============================================================

@app.post("/orchestrate")
async def orchestrate(request: Request):

    try:
        body = await read_limited_body(request)
        payload = parse_json_body(body)
    except HTTPException as exc:
        return http_exception_response(exc)

    if not isinstance(payload, dict):
        return error_response(
            400,
            "invalid_payload",
        )

    action = str(
        payload.get("action", "")
    ).strip().lower()

    data = payload.get("data", {})

    if not isinstance(data, dict):
        return error_response(
            400,
            "invalid_data",
        )

    # Weather and location are GET-based when the backend
    # OpenAPI specification confirms those methods.
    if action in {"weather", "location"}:

        candidates = (
            ["/weather"]
            if action == "weather"
            else ["/location/resolve"]
        )

        target = await choose(
            candidates,
            "GET",
        )

        if not target:
            return error_response(
                404,
                "backend_route_not_found",
                candidates=candidates,
                method="GET",
            )

        try:
            response = await call_backend(
                "GET",
                target,
                query=list(data.items()),
            )

            return response_from_backend(response)

        except HTTPException as exc:
            return http_exception_response(exc)

    candidates_by_action = {
        "doctor": ["/ai/analyze"],
        "full_diagnosis": ["/ai/analyze"],
        "complete_diagnosis": ["/ai/analyze"],
        "analyze": ["/ai/analyze"],
        "recommend": [
            "/recommend",
            "/agri/recommend",
            "/ai/ask",
            "/ask",
        ],
    }

    candidates = candidates_by_action.get(action)

    if not candidates:
        return error_response(
            404,
            "unknown_action",
            action=action,
        )

    target = await choose(
        candidates,
        "POST",
    )

    if not target:
        return error_response(
            404,
            "backend_route_not_found",
            candidates=candidates,
            method="POST",
        )

    if action in {
        "doctor",
        "full_diagnosis",
        "complete_diagnosis",
        "analyze",
    }:
        data = normalize_ai_payload(data)

    try:
        response = await call_backend(
            "POST",
            target,
            body=encode_json(data),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            retry=False,
        )

        # Preserve the actual backend status code and headers.
        return response_from_backend(response)

    except HTTPException as exc:
        return http_exception_response(exc)


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    await load_openapi(force=True)


# ============================================================
# FINAL FALLBACK
# Keep this route last so explicit routes take precedence.
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


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "arya_master_system:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
