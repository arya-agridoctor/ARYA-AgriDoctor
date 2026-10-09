
"""
ARYA Runtime Config Bridge
Version: 2.0.0

Connects:
    ARYA Central Configuration
            |
            v
    ARYA Runtime Config Bridge
            |
            v
    ARYA Service Runtime

Preserved capabilities:
- Central configuration loading
- Service/provider/feature/settings synchronization
- Configuration hashing and difference detection
- Runtime service status and system map
- Start/stop/restart individual services
- Start/stop/restart all services
- Provider filtering and service selection
- Health, status, and contract endpoints
- Background synchronization
- Existing route names and response structures where safe

Security and reliability:
- Internal shared-secret authentication
- Separate owner secret for runtime-control operations
- URL and service-ID validation
- Bounded HTTP response reads
- No automatic redirects
- Provider secret-reference redaction
- Atomic cache replacement after successful validation
- Synchronization locking and background-task cleanup
- Does not modify main.py
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Request


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Runtime Config Bridge"
APP_VERSION = "2.0.0"

HOST = os.getenv(
    "ARYA_RUNTIME_CONFIG_BRIDGE_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_RUNTIME_CONFIG_BRIDGE_PORT",
        "8029",
    )
)

CENTRAL_CONFIG_URL = os.getenv(
    "ARYA_CENTRAL_CONFIG_URL",
    "http://127.0.0.1:8025",
).rstrip("/")

SERVICE_RUNTIME_URL = os.getenv(
    "ARYA_SERVICE_RUNTIME_URL",
    "http://127.0.0.1:8024",
).rstrip("/")

BRIDGE_TIMEOUT = float(
    os.getenv(
        "ARYA_RUNTIME_CONFIG_BRIDGE_TIMEOUT",
        "20",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_RUNTIME_CONFIG_BRIDGE_MAX_RESPONSE_BYTES",
        "10485760",
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_RUNTIME_CONFIG_BRIDGE_MAX_REQUEST_BYTES",
        "1048576",
    )
)

SYNC_INTERVAL = int(
    os.getenv(
        "ARYA_RUNTIME_CONFIG_SYNC_INTERVAL",
        "30",
    )
)

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
).strip()

OWNER_OPERATION_SECRET = os.getenv(
    "ARYA_OWNER_OPERATION_SECRET",
    "",
).strip()

SERVICE_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
)

PROVIDER_TYPE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
)

PUBLIC_PATHS = {
    "/",
    "/health",
    "/contract",
}

OWNER_CONTROL_PATHS = (
    "/runtime/services/",
    "/runtime/start-all",
    "/runtime/stop-all",
    "/runtime/restart-all",
)


# ============================================================
# Configuration Validation
# ============================================================

def validate_numeric_configuration() -> None:
    if not 1 <= PORT <= 65535:
        raise RuntimeError("Invalid bridge port configuration")

    if BRIDGE_TIMEOUT <= 0 or BRIDGE_TIMEOUT > 300:
        raise RuntimeError("Invalid bridge timeout configuration")

    if MAX_RESPONSE_BYTES < 1024:
        raise RuntimeError("Invalid maximum response size")

    if MAX_REQUEST_BYTES < 1024:
        raise RuntimeError("Invalid maximum request size")

    if SYNC_INTERVAL < 5 or SYNC_INTERVAL > 86400:
        raise RuntimeError("Invalid synchronization interval")


def validate_service_url(url: str) -> str:
    if not isinstance(url, str) or not url:
        raise RuntimeError("A service URL is missing")

    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError as exc:
        raise RuntimeError("Invalid service URL configuration") from exc

    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError("Unsupported service URL scheme")

    if not parsed.hostname:
        raise RuntimeError("Invalid service URL hostname")

    if parsed.username or parsed.password:
        raise RuntimeError("Credentials must not be embedded in service URLs")

    if parsed.query or parsed.fragment:
        raise RuntimeError("Service base URLs cannot contain queries or fragments")

    if any(char.isspace() for char in url):
        raise RuntimeError("Whitespace is not allowed in service URLs")

    return url.rstrip("/")


validate_numeric_configuration()
CENTRAL_CONFIG_URL = validate_service_url(CENTRAL_CONFIG_URL)
SERVICE_RUNTIME_URL = validate_service_url(SERVICE_RUNTIME_URL)


# ============================================================
# Runtime State
# ============================================================

LAST_SYNC_AT: Optional[int] = None
LAST_SYNC_STATUS = "never"
LAST_SYNC_ERROR: Optional[str] = None
LAST_CONFIG_HASH: Optional[str] = None
SYNC_RUNNING = False

CACHED_CONFIGURATION: Dict[str, Any] = {
    "services": [],
    "providers": [],
    "features": [],
    "settings": [],
}

SYNC_LOCK = asyncio.Lock()
BACKGROUND_TASK: Optional[asyncio.Task] = None
SHUTTING_DOWN = False


# ============================================================
# Helpers
# ============================================================

def now() -> int:
    return int(time.time())


def calculate_hash(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(raw).hexdigest()


def internal_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": f"ARYA-Runtime-Config-Bridge/{APP_VERSION}",
    }

    if INTERNAL_SECRET:
        headers["X-ARYA-Internal-Secret"] = INTERNAL_SECRET

    return headers


def validate_internal_secret(
    supplied_secret: Optional[str],
) -> None:
    if not INTERNAL_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Internal authentication is not configured",
        )

    if not supplied_secret or not hmac.compare_digest(
        supplied_secret,
        INTERNAL_SECRET,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid internal credentials",
        )


def validate_owner_secret(
    supplied_secret: Optional[str],
) -> None:
    if not OWNER_OPERATION_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Owner operation authentication is not configured",
        )

    if not supplied_secret or not hmac.compare_digest(
        supplied_secret,
        OWNER_OPERATION_SECRET,
    ):
        raise HTTPException(
            status_code=403,
            detail="Owner authorization required",
        )


def validate_service_id(service_id: str) -> str:
    if not SERVICE_ID_PATTERN.fullmatch(service_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid service identifier",
        )

    return service_id


def validate_provider_type(provider_type: str) -> str:
    if not PROVIDER_TYPE_PATTERN.fullmatch(provider_type):
        raise HTTPException(
            status_code=400,
            detail="Invalid provider type",
        )

    return provider_type


def safe_error_message(exc: Exception) -> str:
    # Avoid storing response bodies, credentials, or complete URLs.
    if isinstance(exc, HTTPException):
        return f"HTTPException: status={exc.status_code}"

    return type(exc).__name__


def require_mapping(
    value: Any,
    name: str,
) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise HTTPException(
            status_code=502,
            detail=f"Invalid {name} configuration structure",
        )

    return value


def require_list(
    value: Any,
    name: str,
) -> List[Any]:
    if not isinstance(value, list):
        raise HTTPException(
            status_code=502,
            detail=f"Invalid {name} configuration collection",
        )

    if any(not isinstance(item, dict) for item in value):
        raise HTTPException(
            status_code=502,
            detail=f"Invalid item in {name} configuration",
        )

    return value


def bounded_int(
    value: Any,
    default: int,
    minimum: int,
    maximum: int,
    field_name: str,
) -> int:
    if isinstance(value, bool):
        raise HTTPException(
            status_code=502,
            detail=f"Invalid {field_name} configuration",
        )

    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Invalid {field_name} configuration",
        ) from exc

    if not minimum <= result <= maximum:
        raise HTTPException(
            status_code=502,
            detail=f"Out-of-range {field_name} configuration",
        )

    return result


def bounded_float(
    value: Any,
    default: float,
    minimum: float,
    maximum: float,
    field_name: str,
) -> float:
    if value is None:
        value = default

    if isinstance(value, bool):
        raise HTTPException(
            status_code=502,
            detail=f"Invalid {field_name} configuration",
        )

    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Invalid {field_name} configuration",
        ) from exc

    if not minimum <= result <= maximum:
        raise HTTPException(
            status_code=502,
            detail=f"Out-of-range {field_name} configuration",
        )

    return result


def safe_bool(
    value: Any,
    default: bool,
    field_name: str,
) -> bool:
    if value is None:
        return default

    if not isinstance(value, bool):
        raise HTTPException(
            status_code=502,
            detail=f"Invalid {field_name} configuration",
        )

    return value


def sanitize_metadata(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    forbidden_fragments = (
        "secret",
        "password",
        "token",
        "credential",
        "private_key",
        "apikey",
        "api_key",
        "authorization",
    )

    cleaned: Dict[str, Any] = {}

    for key, item in value.items():
        if not isinstance(key, str):
            continue

        normalized_key = key.lower().replace("-", "_")

        if any(
            fragment in normalized_key
            for fragment in forbidden_fragments
        ):
            continue

        if isinstance(item, (str, int, float, bool)) or item is None:
            cleaned[key] = item
        elif isinstance(item, list):
            cleaned[key] = [
                entry
                for entry in item
                if isinstance(entry, (str, int, float, bool))
                or entry is None
            ]
        elif isinstance(item, dict):
            cleaned[key] = sanitize_metadata(item)

    return cleaned


# ============================================================
# HTTP Client Helpers
# ============================================================

def build_timeout() -> httpx.Timeout:
    return httpx.Timeout(
        BRIDGE_TIMEOUT,
        connect=min(10.0, BRIDGE_TIMEOUT),
    )


async def read_bounded_response(
    response: httpx.Response,
) -> bytes:
    content_length = response.headers.get("content-length")

    if content_length:
        try:
            if int(content_length) > MAX_RESPONSE_BYTES:
                raise HTTPException(
                    status_code=502,
                    detail="Upstream response exceeds configured size limit",
                )
        except ValueError:
            raise HTTPException(
                status_code=502,
                detail="Invalid upstream response length",
            )

    chunks: List[bytes] = []
    total = 0

    async for chunk in response.aiter_bytes():
        total += len(chunk)

        if total > MAX_RESPONSE_BYTES:
            raise HTTPException(
                status_code=502,
                detail="Upstream response exceeds configured size limit",
            )

        chunks.append(chunk)

    return b"".join(chunks)


def parse_json_response(
    content: bytes,
    status_code: int,
) -> Any:
    if status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail="Upstream service returned an error",
        )

    try:
        return json.loads(content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Invalid JSON from upstream service",
        ) from exc


async def get_json(
    url: str,
    authorization: Optional[str] = None,
) -> Any:
    headers = internal_headers()

    if authorization:
        headers["Authorization"] = authorization

    try:
        async with httpx.AsyncClient(
            timeout=build_timeout(),
            follow_redirects=False,
        ) as client:
            async with client.stream(
                "GET",
                url,
                headers=headers,
            ) as response:
                content = await read_bounded_response(response)
                status_code = response.status_code

    except HTTPException:
        raise
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail="Upstream service timeout",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail="Upstream service unavailable",
        ) from exc

    if status_code >= 400:
        if status_code in {401, 403, 404}:
            raise HTTPException(
                status_code=502,
                detail="Upstream service rejected the request",
            )

        raise HTTPException(
            status_code=502,
            detail=f"Upstream service returned HTTP {status_code}",
        )

    return parse_json_response(content, status_code)


async def post_json(
    url: str,
    payload: Optional[Dict[str, Any]] = None,
    authorization: Optional[str] = None,
) -> Any:
    headers = internal_headers()
    headers["Content-Type"] = "application/json"

    if authorization:
        headers["Authorization"] = authorization

    body = json.dumps(
        payload or {},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request payload exceeds configured size limit",
        )

    try:
        async with httpx.AsyncClient(
            timeout=build_timeout(),
            follow_redirects=False,
        ) as client:
            async with client.stream(
                "POST",
                url,
                content=body,
                headers=headers,
            ) as response:
                content = await read_bounded_response(response)
                status_code = response.status_code

    except HTTPException:
        raise
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail="Runtime service timeout",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail="Runtime service unavailable",
        ) from exc

    if status_code >= 400:
        if status_code in {401, 403}:
            raise HTTPException(
                status_code=502,
                detail="Runtime service rejected the request",
            )

        raise HTTPException(
            status_code=502,
            detail=f"Runtime service returned HTTP {status_code}",
        )

    if not content:
        return {"status": "success"}

    try:
        return json.loads(content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {
            "raw": content[:10000].decode(
                "utf-8",
                errors="replace",
            )
        }


# ============================================================
# Application Authentication
# ============================================================

@app.middleware("http")
async def internal_authentication_middleware(
    request: Request,
    call_next,
):
    if request.url.path not in PUBLIC_PATHS:
        supplied_secret = request.headers.get(
            "X-ARYA-Internal-Secret"
        )

        try:
            validate_internal_secret(supplied_secret)
        except HTTPException as exc:
            from starlette.responses import JSONResponse

            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
            )

    content_length = request.headers.get("content-length")

    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                from starlette.responses import JSONResponse

                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request payload too large"},
                )
        except ValueError:
            from starlette.responses import JSONResponse

            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length"},
            )

    return await call_next(request)


def require_owner_operation(
    owner_secret: Optional[str],
) -> None:
    validate_owner_secret(owner_secret)


# ============================================================
# Central Configuration
# ============================================================

async def load_configuration(
    authorization: Optional[str] = None,
) -> Dict[str, Any]:
    services_response = await get_json(
        f"{CENTRAL_CONFIG_URL}/config/services",
        authorization,
    )

    providers_response = await get_json(
        f"{CENTRAL_CONFIG_URL}/config/providers",
        authorization,
    )

    features_response = await get_json(
        f"{CENTRAL_CONFIG_URL}/config/features",
        authorization,
    )

    settings_response = await get_json(
        f"{CENTRAL_CONFIG_URL}/config/settings",
        authorization,
    )

    services_response = require_mapping(
        services_response,
        "services",
    )
    providers_response = require_mapping(
        providers_response,
        "providers",
    )
    features_response = require_mapping(
        features_response,
        "features",
    )
    settings_response = require_mapping(
        settings_response,
        "settings",
    )

    return {
        "services": require_list(
            services_response.get("services", []),
            "services",
        ),
        "providers": require_list(
            providers_response.get("providers", []),
            "providers",
        ),
        "features": require_list(
            features_response.get("features", []),
            "features",
        ),
        "settings": require_list(
            settings_response.get("settings", []),
            "settings",
        ),
    }


# ============================================================
# Runtime Synchronization
# ============================================================

def normalize_service(
    service: Dict[str, Any],
) -> Dict[str, Any]:
    service = require_mapping(service, "service")

    service_id = service.get("service_id")

    if not isinstance(service_id, str):
        raise HTTPException(
            status_code=502,
            detail="Service configuration is missing a valid service_id",
        )

    validate_service_id(service_id)

    name = service.get("name", service_id)
    url = service.get("url")
    health_url = service.get("health_url")

    if not isinstance(name, str) or not name.strip():
        name = service_id

    if url is not None and not isinstance(url, str):
        raise HTTPException(
            status_code=502,
            detail="Invalid service URL configuration",
        )

    if health_url is not None and not isinstance(health_url, str):
        raise HTTPException(
            status_code=502,
            detail="Invalid service health URL configuration",
        )

    metadata = service.get("metadata", {})

    if not isinstance(metadata, dict):
        metadata = {}

    return {
        "service_id": service_id,
        "name": name[:256],
        "url": url,
        "health_url": health_url,
        "enabled": safe_bool(
            service.get("enabled"),
            True,
            "service.enabled",
        ),
        "critical": safe_bool(
            service.get("critical"),
            False,
            "service.critical",
        ),
        "priority": bounded_int(
            service.get("priority", 100),
            100,
            0,
            100000,
            "service.priority",
        ),
        "timeout": bounded_float(
            service.get("timeout", 30),
            30,
            0.1,
            300,
            "service.timeout",
        ),
        "retry_count": bounded_int(
            service.get("retry_count", 2),
            2,
            0,
            20,
            "service.retry_count",
        ),
        "metadata": sanitize_metadata(metadata),
    }


def normalize_provider(
    provider: Dict[str, Any],
) -> Dict[str, Any]:
    provider = require_mapping(provider, "provider")

    provider_id = provider.get("provider_id")
    provider_type = provider.get("provider_type")

    if not isinstance(provider_id, str) or not provider_id.strip():
        raise HTTPException(
            status_code=502,
            detail="Provider configuration is missing provider_id",
        )

    if not isinstance(provider_type, str) or not provider_type.strip():
        raise HTTPException(
            status_code=502,
            detail="Provider configuration is missing provider_type",
        )

    validate_provider_type(provider_type)

    name = provider.get("name", provider_id)
    base_url = provider.get("base_url")

    if not isinstance(name, str):
        name = provider_id

    if base_url is not None:
        if not isinstance(base_url, str):
            raise HTTPException(
                status_code=502,
                detail="Invalid provider base URL",
            )

        try:
            validate_service_url(base_url)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=502,
                detail="Invalid provider base URL configuration",
            ) from exc

    capabilities = provider.get("capabilities", [])

    if not isinstance(capabilities, list):
        capabilities = []

    capabilities = [
        item[:128]
        for item in capabilities
        if isinstance(item, str)
    ]

    metadata = provider.get("metadata", {})

    return {
        "provider_id": provider_id[:128],
        "provider_type": provider_type,
        "name": name[:256],
        "base_url": base_url,
        "enabled": safe_bool(
            provider.get("enabled"),
            True,
            "provider.enabled",
        ),
        "priority": bounded_int(
            provider.get("priority", 100),
            100,
            0,
            100000,
            "provider.priority",
        ),
        "timeout": bounded_float(
            provider.get("timeout", 30),
            30,
            0.1,
            300,
            "provider.timeout",
        ),
        # Never return secret_ref to clients.
        "capabilities": capabilities,
        "metadata": sanitize_metadata(metadata),
    }


def build_runtime_configuration(
    configuration: Dict[str, Any],
) -> Dict[str, Any]:
    configuration = require_mapping(
        configuration,
        "runtime configuration",
    )

    raw_services = require_list(
        configuration.get("services", []),
        "services",
    )

    raw_providers = require_list(
        configuration.get("providers", []),
        "providers",
    )

    raw_features = require_list(
        configuration.get("features", []),
        "features",
    )

    raw_settings = require_list(
        configuration.get("settings", []),
        "settings",
    )

    services = []
    seen_service_ids = set()

    for item in raw_services:
        if not item.get("service_id"):
            raise HTTPException(
                status_code=502,
                detail="A service configuration has no service_id",
            )

        normalized = normalize_service(item)
        service_id = normalized["service_id"]

        if service_id in seen_service_ids:
            raise HTTPException(
                status_code=502,
                detail="Duplicate service identifier in configuration",
            )

        seen_service_ids.add(service_id)
        services.append(normalized)

    providers = []
    seen_provider_ids = set()

    for item in raw_providers:
        normalized = normalize_provider(item)
        provider_id = normalized["provider_id"]

        if provider_id in seen_provider_ids:
            raise HTTPException(
                status_code=502,
                detail="Duplicate provider identifier in configuration",
            )

        seen_provider_ids.add(provider_id)
        providers.append(normalized)

    return {
        "services": services,
        "providers": providers,
        "features": raw_features,
        "settings": raw_settings,
    }


async def synchronize(
    authorization: Optional[str] = None,
) -> Dict[str, Any]:
    global LAST_SYNC_AT
    global LAST_SYNC_STATUS
    global LAST_SYNC_ERROR
    global LAST_CONFIG_HASH
    global CACHED_CONFIGURATION

    async with SYNC_LOCK:
        try:
            configuration = await load_configuration(
                authorization
            )

            runtime_configuration = build_runtime_configuration(
                configuration
            )

            config_hash = calculate_hash(
                runtime_configuration
            )

            changed = config_hash != LAST_CONFIG_HASH

            # Replace the cache only after all data validates.
            CACHED_CONFIGURATION = runtime_configuration
            LAST_CONFIG_HASH = config_hash
            LAST_SYNC_AT = now()
            LAST_SYNC_STATUS = "success"
            LAST_SYNC_ERROR = None

            return {
                "status": "synchronized",
                "changed": changed,
                "configuration_hash": config_hash,
                "services": len(runtime_configuration["services"]),
                "providers": len(runtime_configuration["providers"]),
                "features": len(runtime_configuration["features"]),
                "settings": len(runtime_configuration["settings"]),
                "timestamp": LAST_SYNC_AT,
            }

        except Exception as exc:
            LAST_SYNC_STATUS = "failed"
            LAST_SYNC_ERROR = safe_error_message(exc)
            raise


# ============================================================
# Runtime Health and Service Queries
# ============================================================

async def runtime_health() -> Dict[str, Any]:
    result = await get_json(
        f"{SERVICE_RUNTIME_URL}/health"
    )

    return require_mapping(result, "runtime health")


async def runtime_services() -> Dict[str, Any]:
    result = await get_json(
        f"{SERVICE_RUNTIME_URL}/services"
    )

    return require_mapping(result, "runtime services")


# ============================================================
# Background Synchronization
# ============================================================

async def sync_worker() -> None:
    global SYNC_RUNNING

    if SYNC_RUNNING:
        return

    SYNC_RUNNING = True

    try:
        while not SHUTTING_DOWN:
            try:
                await synchronize()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # synchronize() already records a sanitized error.
                if LAST_SYNC_STATUS != "failed":
                    globals()["LAST_SYNC_STATUS"] = "failed"
                    globals()["LAST_SYNC_ERROR"] = safe_error_message(exc)

            try:
                await asyncio.sleep(max(5, SYNC_INTERVAL))
            except asyncio.CancelledError:
                raise

    finally:
        SYNC_RUNNING = False


@asynccontextmanager
async def lifespan(_: FastAPI):
    global BACKGROUND_TASK
    global SHUTTING_DOWN

    SHUTTING_DOWN = False
    BACKGROUND_TASK = asyncio.create_task(
        sync_worker(),
        name="arya-runtime-config-sync",
    )

    try:
        yield
    finally:
        SHUTTING_DOWN = True

        if BACKGROUND_TASK is not None:
            BACKGROUND_TASK.cancel()

            try:
                await BACKGROUND_TASK
            except asyncio.CancelledError:
                pass

            BACKGROUND_TASK = None


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Runtime bridge between ARYA Central Configuration "
        "and ARYA Service Runtime."
    ),
    lifespan=lifespan,
)


# ============================================================
# Root
# ============================================================

@app.get("/")
async def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "central_config": CENTRAL_CONFIG_URL,
        "service_runtime": SERVICE_RUNTIME_URL,
        "sync_interval": SYNC_INTERVAL,
        "last_sync": LAST_SYNC_AT,
        "sync_status": LAST_SYNC_STATUS,
        "timestamp": now(),
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health():
    central_status = "unknown"
    runtime_status = "unknown"

    try:
        result = await get_json(
            f"{CENTRAL_CONFIG_URL}/health"
        )
        central_status = result.get("status", "unknown")
    except Exception:
        central_status = "unavailable"

    try:
        result = await runtime_health()
        runtime_status = result.get("status", "unknown")
    except Exception:
        runtime_status = "unavailable"

    healthy_values = {"healthy", "online"}

    status_value = (
        "healthy"
        if (
            central_status in healthy_values
            and runtime_status in healthy_values
        )
        else "degraded"
    )

    return {
        "status": status_value,
        "service": APP_NAME,
        "version": APP_VERSION,
        "central_config": central_status,
        "service_runtime": runtime_status,
        "last_sync": LAST_SYNC_AT,
        "sync_status": LAST_SYNC_STATUS,
        "timestamp": now(),
    }


# ============================================================
# Manual Synchronization
# ============================================================

@app.post("/sync")
async def manual_sync(
    authorization: Optional[str] = Header(default=None),
):
    return await synchronize(authorization)


# ============================================================
# Current Configuration
# ============================================================

@app.get("/config")
async def current_config():
    return {
        "configuration": CACHED_CONFIGURATION,
        "hash": LAST_CONFIG_HASH,
        "last_sync": LAST_SYNC_AT,
        "sync_status": LAST_SYNC_STATUS,
        "timestamp": now(),
    }


# ============================================================
# Runtime Configuration
# ============================================================

@app.get("/runtime/config")
async def runtime_config():
    return {
        "services": CACHED_CONFIGURATION.get("services", []),
        "providers": CACHED_CONFIGURATION.get("providers", []),
        "features": CACHED_CONFIGURATION.get("features", []),
        "settings": CACHED_CONFIGURATION.get("settings", []),
        "configuration_hash": LAST_CONFIG_HASH,
        "timestamp": now(),
    }


# ============================================================
# Runtime Service State
# ============================================================

@app.get("/runtime/services")
async def runtime_service_state():
    return await runtime_services()


# ============================================================
# Runtime Service Start
# ============================================================

@app.post("/runtime/services/{service_id}/start")
async def start_runtime_service(
    service_id: str,
    owner_secret: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Owner-Secret",
    ),
):
    require_owner_operation(owner_secret)
    service_id = validate_service_id(service_id)

    return await post_json(
        f"{SERVICE_RUNTIME_URL}/services/{service_id}/start"
    )


# ============================================================
# Runtime Service Stop
# ============================================================

@app.post("/runtime/services/{service_id}/stop")
async def stop_runtime_service(
    service_id: str,
    owner_secret: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Owner-Secret",
    ),
):
    require_owner_operation(owner_secret)
    service_id = validate_service_id(service_id)

    return await post_json(
        f"{SERVICE_RUNTIME_URL}/services/{service_id}/stop"
    )


# ============================================================
# Runtime Service Restart
# ============================================================

@app.post("/runtime/services/{service_id}/restart")
async def restart_runtime_service(
    service_id: str,
    owner_secret: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Owner-Secret",
    ),
):
    require_owner_operation(owner_secret)
    service_id = validate_service_id(service_id)

    return await post_json(
        f"{SERVICE_RUNTIME_URL}/services/{service_id}/restart"
    )


# ============================================================
# Runtime Start All
# ============================================================

@app.post("/runtime/start-all")
async def runtime_start_all(
    owner_secret: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Owner-Secret",
    ),
):
    require_owner_operation(owner_secret)

    return await post_json(
        f"{SERVICE_RUNTIME_URL}/runtime/start-all"
    )


# ============================================================
# Runtime Stop All
# ============================================================

@app.post("/runtime/stop-all")
async def runtime_stop_all(
    owner_secret: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Owner-Secret",
    ),
):
    require_owner_operation(owner_secret)

    return await post_json(
        f"{SERVICE_RUNTIME_URL}/runtime/stop-all"
    )


# ============================================================
# Runtime Restart All
# ============================================================

@app.post("/runtime/restart-all")
async def runtime_restart_all(
    owner_secret: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Owner-Secret",
    ),
):
    require_owner_operation(owner_secret)

    return await post_json(
        f"{SERVICE_RUNTIME_URL}/runtime/restart-all"
    )


# ============================================================
# Runtime System Map
# ============================================================

@app.get("/runtime/system-map")
async def runtime_system_map():
    result = await get_json(
        f"{SERVICE_RUNTIME_URL}/runtime/system-map"
    )

    return require_mapping(result, "runtime system map")


# ============================================================
# Configuration Difference
# ============================================================

@app.get("/config/diff")
async def configuration_diff():
    try:
        fresh = await load_configuration()
        fresh_runtime = build_runtime_configuration(fresh)
        fresh_hash = calculate_hash(fresh_runtime)

    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise

        raise HTTPException(
            status_code=502,
            detail="Unable to compare current and central configuration",
        ) from exc

    return {
        "current_hash": LAST_CONFIG_HASH,
        "fresh_hash": fresh_hash,
        "changed": fresh_hash != LAST_CONFIG_HASH,
        "current": CACHED_CONFIGURATION,
        "fresh": fresh_runtime,
        "timestamp": now(),
    }


# ============================================================
# Providers
# ============================================================

@app.get("/providers")
async def providers():
    return {
        "providers": CACHED_CONFIGURATION.get("providers", []),
        "configuration_hash": LAST_CONFIG_HASH,
        "timestamp": now(),
    }


@app.get("/providers/{provider_type}")
async def providers_by_type(provider_type: str):
    provider_type = validate_provider_type(provider_type)

    selected = [
        provider
        for provider in CACHED_CONFIGURATION.get("providers", [])
        if provider.get("provider_type") == provider_type
        and provider.get("enabled", True)
    ]

    selected.sort(
        key=lambda item: item.get("priority", 100)
    )

    return {
        "provider_type": provider_type,
        "providers": selected,
        "count": len(selected),
    }


# ============================================================
# Feature Flags
# ============================================================

@app.get("/features")
async def features():
    return {
        "features": CACHED_CONFIGURATION.get("features", []),
        "timestamp": now(),
    }


# ============================================================
# Service Selection
# ============================================================

@app.get("/services/available")
async def available_services():
    services = [
        service
        for service in CACHED_CONFIGURATION.get("services", [])
        if service.get("enabled", True)
    ]

    services.sort(
        key=lambda item: item.get("priority", 100)
    )

    return {
        "services": services,
        "count": len(services),
        "timestamp": now(),
    }


# ============================================================
# Status
# ============================================================

@app.get("/status")
async def status():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "central_config": CENTRAL_CONFIG_URL,
        "service_runtime": SERVICE_RUNTIME_URL,
        "last_sync_at": LAST_SYNC_AT,
        "last_sync_status": LAST_SYNC_STATUS,
        "last_sync_error": LAST_SYNC_ERROR,
        "configuration_hash": LAST_CONFIG_HASH,
        "sync_running": SYNC_RUNNING,
        "cached": {
            "services": len(CACHED_CONFIGURATION.get("services", [])),
            "providers": len(CACHED_CONFIGURATION.get("providers", [])),
            "features": len(CACHED_CONFIGURATION.get("features", [])),
            "settings": len(CACHED_CONFIGURATION.get("settings", [])),
        },
        "timestamp": now(),
    }


# ============================================================
# Contract
# ============================================================

@app.get("/contract")
async def contract():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "port": PORT,
        "central_configuration": {
            "url": CENTRAL_CONFIG_URL,
        },
        "runtime": {
            "url": SERVICE_RUNTIME_URL,
        },
        "endpoints": {
            "health": "GET /health",
            "sync": "POST /sync",
            "config": "GET /config",
            "runtime_config": "GET /runtime/config",
            "runtime_services": "GET /runtime/services",
            "runtime_start": "POST /runtime/services/{service_id}/start",
            "runtime_stop": "POST /runtime/services/{service_id}/stop",
            "runtime_restart": "POST /runtime/services/{service_id}/restart",
            "runtime_start_all": "POST /runtime/start-all",
            "runtime_stop_all": "POST /runtime/stop-all",
            "runtime_restart_all": "POST /runtime/restart-all",
            "runtime_system_map": "GET /runtime/system-map",
            "config_diff": "GET /config/diff",
            "providers": "GET /providers",
            "providers_by_type": "GET /providers/{provider_type}",
            "features": "GET /features",
            "available_services": "GET /services/available",
            "status": "GET /status",
        },
        "authentication": {
            "internal_header": "X-ARYA-Internal-Secret",
            "owner_control_header": "X-ARYA-Owner-Secret",
            "owner_control_secret_env": "ARYA_OWNER_OPERATION_SECRET",
        },
        "architecture": {
            "central_config": "arya_central_config",
            "runtime": "arya_service_runtime",
            "bridge": "arya_runtime_config_bridge",
            "main_api": "main.py",
        },
        "main_py_modified": False,
        "secrets_returned": False,
    }


# ============================================================
# Local Execution
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "arya_runtime_config_bridge:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
