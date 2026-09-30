"""
ARYA Runtime Config Bridge
==========================

Connects:
    ARYA Central Configuration
            ↓
    ARYA Service Runtime

Purpose:
- Read service configuration from Central Config.
- Synchronize runtime service definitions.
- Read enabled/disabled state.
- Read service URL, priority, timeout and retry settings.
- Read provider configuration.
- Detect configuration changes.
- Keep existing files untouched.
- Never modify main.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Runtime Config Bridge"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_RUNTIME_CONFIG_BRIDGE_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_RUNTIME_CONFIG_BRIDGE_PORT",
        "8026",
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

SYNC_INTERVAL = int(
    os.getenv(
        "ARYA_RUNTIME_CONFIG_SYNC_INTERVAL",
        "30",
    )
)

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)


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
)


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


# ============================================================
# Helpers
# ============================================================

def now() -> int:
    return int(time.time())


def calculate_hash(
    payload: Any,
) -> str:
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
        "User-Agent": (
            "ARYA-Runtime-Config-Bridge/1.0"
        ),
    }

    if INTERNAL_SECRET:
        headers[
            "X-ARYA-Internal-Secret"
        ] = INTERNAL_SECRET

    return headers


async def get_json(
    url: str,
    authorization: Optional[str] = None,
) -> Any:

    headers = internal_headers()

    if authorization:
        headers[
            "Authorization"
        ] = authorization

    timeout = httpx.Timeout(
        BRIDGE_TIMEOUT,
        connect=min(
            10,
            BRIDGE_TIMEOUT,
        ),
    )

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as client:

            response = await client.get(
                url,
                headers=headers,
            )

    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail="Configuration service timeout",
        ) from exc

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail="Configuration service unavailable",
        ) from exc

    if len(response.content) > MAX_RESPONSE_BYTES:
        raise HTTPException(
            status_code=502,
            detail="Configuration response too large",
        )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=(
                f"Configuration service returned "
                f"{response.status_code}"
            ),
        )

    try:
        return response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail="Invalid JSON from configuration service",
        ) from exc


async def post_json(
    url: str,
    payload: Optional[Dict[str, Any]] = None,
    authorization: Optional[str] = None,
) -> Any:

    headers = internal_headers()
    headers["Content-Type"] = (
        "application/json"
    )

    if authorization:
        headers[
            "Authorization"
        ] = authorization

    timeout = httpx.Timeout(
        BRIDGE_TIMEOUT,
        connect=min(
            10,
            BRIDGE_TIMEOUT,
        ),
    )

    body = json.dumps(
        payload or {},
        ensure_ascii=False,
    ).encode("utf-8")

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as client:

            response = await client.post(
                url,
                content=body,
                headers=headers,
            )

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

    if len(response.content) > MAX_RESPONSE_BYTES:
        raise HTTPException(
            status_code=502,
            detail="Runtime response too large",
        )

    if response.status_code >= 400:
        try:
            detail = response.json()
        except ValueError:
            detail = response.text[:5000]

        raise HTTPException(
            status_code=response.status_code,
            detail=detail,
        )

    try:
        return response.json()
    except ValueError:
        return {
            "raw": response.text[:10000]
        }


# ============================================================
# Central Configuration
# ============================================================

async def load_configuration(
    authorization: Optional[str] = None,
) -> Dict[str, Any]:

    services = await get_json(
        f"{CENTRAL_CONFIG_URL}/config/services",
        authorization,
    )

    providers = await get_json(
        f"{CENTRAL_CONFIG_URL}/config/providers",
        authorization,
    )

    features = await get_json(
        f"{CENTRAL_CONFIG_URL}/config/features",
        authorization,
    )

    settings = await get_json(
        f"{CENTRAL_CONFIG_URL}/config/settings",
        authorization,
    )

    return {
        "services": services.get(
            "services",
            [],
        ),
        "providers": providers.get(
            "providers",
            [],
        ),
        "features": features.get(
            "features",
            [],
        ),
        "settings": settings.get(
            "settings",
            [],
        ),
    }


# ============================================================
# Runtime Synchronization
# ============================================================

def normalize_service(
    service: Dict[str, Any],
) -> Dict[str, Any]:

    return {
        "service_id": service.get(
            "service_id"
        ),
        "name": service.get(
            "name"
        ),
        "url": service.get(
            "url"
        ),
        "health_url": service.get(
            "health_url"
        ),
        "enabled": bool(
            service.get(
                "enabled",
                True,
            )
        ),
        "critical": bool(
            service.get(
                "critical",
                False,
            )
        ),
        "priority": int(
            service.get(
                "priority",
                100,
            )
        ),
        "timeout": float(
            service.get(
                "timeout",
                30,
            )
        ),
        "retry_count": int(
            service.get(
                "retry_count",
                2,
            )
        ),
        "metadata": service.get(
            "metadata",
            {},
        ),
    }


def build_runtime_configuration(
    configuration: Dict[str, Any],
) -> Dict[str, Any]:

    services = [
        normalize_service(item)
        for item in configuration.get(
            "services",
            [],
        )
        if item.get("service_id")
    ]

    providers = []

    for provider in configuration.get(
        "providers",
        [],
    ):
        providers.append({
            "provider_id": provider.get(
                "provider_id"
            ),
            "provider_type": provider.get(
                "provider_type"
            ),
            "name": provider.get(
                "name"
            ),
            "base_url": provider.get(
                "base_url"
            ),
            "enabled": bool(
                provider.get(
                    "enabled",
                    True,
                )
            ),
            "priority": int(
                provider.get(
                    "priority",
                    100,
                )
            ),
            "timeout": float(
                provider.get(
                    "timeout",
                    30,
                )
            ),
            "secret_ref": provider.get(
                "secret_ref"
            ),
            "capabilities": provider.get(
                "capabilities",
                [],
            ),
            "metadata": provider.get(
                "metadata",
                {},
            ),
        })

    return {
        "services": services,
        "providers": providers,
        "features": configuration.get(
            "features",
            [],
        ),
        "settings": configuration.get(
            "settings",
            [],
        ),
    }


async def synchronize(
    authorization: Optional[str] = None,
) -> Dict[str, Any]:

    global LAST_SYNC_AT
    global LAST_SYNC_STATUS
    global LAST_SYNC_ERROR
    global LAST_CONFIG_HASH
    global CACHED_CONFIGURATION

    configuration = await load_configuration(
        authorization
    )

    runtime_configuration = (
        build_runtime_configuration(
            configuration
        )
    )

    config_hash = calculate_hash(
        runtime_configuration
    )

    changed = (
        config_hash
        != LAST_CONFIG_HASH
    )

    CACHED_CONFIGURATION = (
        runtime_configuration
    )

    LAST_CONFIG_HASH = config_hash
    LAST_SYNC_AT = now()
    LAST_SYNC_STATUS = "success"
    LAST_SYNC_ERROR = None

    return {
        "status": "synchronized",
        "changed": changed,
        "configuration_hash": config_hash,
        "services": len(
            runtime_configuration[
                "services"
            ]
        ),
        "providers": len(
            runtime_configuration[
                "providers"
            ]
        ),
        "features": len(
            runtime_configuration[
                "features"
            ]
        ),
        "settings": len(
            runtime_configuration[
                "settings"
            ]
        ),
        "timestamp": LAST_SYNC_AT,
    }


# ============================================================
# Runtime Health
# ============================================================

async def runtime_health() -> Dict[str, Any]:

    return await get_json(
        f"{SERVICE_RUNTIME_URL}/health"
    )


async def runtime_services() -> Dict[str, Any]:

    return await get_json(
        f"{SERVICE_RUNTIME_URL}/services"
    )


# ============================================================
# Sync Background Worker
# ============================================================

async def sync_worker():

    global SYNC_RUNNING
    global LAST_SYNC_STATUS
    global LAST_SYNC_ERROR

    if SYNC_RUNNING:
        return

    SYNC_RUNNING = True

    try:

        while True:

            try:
                await synchronize()

            except Exception as exc:
                LAST_SYNC_STATUS = "failed"
                LAST_SYNC_ERROR = str(exc)

            await asyncio.sleep(
                max(
                    5,
                    SYNC_INTERVAL,
                )
            )

    finally:
        SYNC_RUNNING = False


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup():

    asyncio.create_task(
        sync_worker()
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

        central_status = result.get(
            "status",
            "unknown",
        )

    except Exception:
        central_status = "unavailable"

    try:
        result = await runtime_health()

        runtime_status = result.get(
            "status",
            "unknown",
        )

    except Exception:
        runtime_status = "unavailable"

    status = (
        "healthy"
        if (
            central_status
            in {
                "healthy",
                "online",
            }
            and runtime_status
            in {
                "healthy",
                "online",
            }
        )
        else "degraded"
    )

    return {
        "status": status,
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
    authorization: Optional[str] = Header(
        default=None,
    ),
):

    return await synchronize(
        authorization
    )


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
        "services": CACHED_CONFIGURATION.get(
            "services",
            [],
        ),
        "providers": CACHED_CONFIGURATION.get(
            "providers",
            [],
        ),
        "features": CACHED_CONFIGURATION.get(
            "features",
            [],
        ),
        "settings": CACHED_CONFIGURATION.get(
            "settings",
            [],
        ),
        "configuration_hash": LAST_CONFIG_HASH,
        "timestamp": now(),
    }


# ============================================================
# Runtime Service State
# ============================================================

@app.get("/runtime/services")
async def runtime_service_state():

    try:
        return await runtime_services()

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc


# ============================================================
# Runtime Service Start
# ============================================================

@app.post(
    "/runtime/services/{service_id}/start"
)
async def start_runtime_service(
    service_id: str,
):

    return await post_json(
        f"{SERVICE_RUNTIME_URL}"
        f"/services/{service_id}/start"
    )


# ============================================================
# Runtime Service Stop
# ============================================================

@app.post(
    "/runtime/services/{service_id}/stop"
)
async def stop_runtime_service(
    service_id: str,
):

    return await post_json(
        f"{SERVICE_RUNTIME_URL}"
        f"/services/{service_id}/stop"
    )


# ============================================================
# Runtime Service Restart
# ============================================================

@app.post(
    "/runtime/services/{service_id}/restart"
)
async def restart_runtime_service(
    service_id: str,
):

    return await post_json(
        f"{SERVICE_RUNTIME_URL}"
        f"/services/{service_id}/restart"
    )


# ============================================================
# Runtime Start All
# ============================================================

@app.post("/runtime/start-all")
async def runtime_start_all():

    return await post_json(
        f"{SERVICE_RUNTIME_URL}"
        "/runtime/start-all"
    )


# ============================================================
# Runtime Stop All
# ============================================================

@app.post("/runtime/stop-all")
async def runtime_stop_all():

    return await post_json(
        f"{SERVICE_RUNTIME_URL}"
        "/runtime/stop-all"
    )


# ============================================================
# Runtime Restart All
# ============================================================

@app.post("/runtime/restart-all")
async def runtime_restart_all():

    return await post_json(
        f"{SERVICE_RUNTIME_URL}"
        "/runtime/restart-all"
    )


# ============================================================
# Runtime System Map
# ============================================================

@app.get("/runtime/system-map")
async def runtime_system_map():

    try:
        return await get_json(
            f"{SERVICE_RUNTIME_URL}"
            "/runtime/system-map"
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc


# ============================================================
# Configuration Difference
# ============================================================

@app.get("/config/diff")
async def configuration_diff():

    try:
        fresh = await load_configuration()

        fresh_runtime = (
            build_runtime_configuration(
                fresh
            )
        )

        fresh_hash = calculate_hash(
            fresh_runtime
        )

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    return {
        "current_hash": LAST_CONFIG_HASH,
        "fresh_hash": fresh_hash,
        "changed": (
            fresh_hash
            != LAST_CONFIG_HASH
        ),
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
        "providers": CACHED_CONFIGURATION.get(
            "providers",
            [],
        ),
        "configuration_hash": LAST_CONFIG_HASH,
        "timestamp": now(),
    }


@app.get(
    "/providers/{provider_type}"
)
async def providers_by_type(
    provider_type: str,
):

    providers = [
        provider
        for provider
        in CACHED_CONFIGURATION.get(
            "providers",
            [],
        )
        if provider.get(
            "provider_type"
        ) == provider_type
        and provider.get(
            "enabled",
            True,
        )
    ]

    providers.sort(
        key=lambda item: item.get(
            "priority",
            100,
        )
    )

    return {
        "provider_type": provider_type,
        "providers": providers,
        "count": len(providers),
    }


# ============================================================
# Feature Flags
# ============================================================

@app.get("/features")
async def features():

    return {
        "features": CACHED_CONFIGURATION.get(
            "features",
            [],
        ),
        "timestamp": now(),
    }


# ============================================================
# Service Selection
# ============================================================

@app.get(
    "/services/available"
)
async def available_services():

    services = [
        service
        for service
        in CACHED_CONFIGURATION.get(
            "services",
            [],
        )
        if service.get(
            "enabled",
            True,
        )
    ]

    services.sort(
        key=lambda item: item.get(
            "priority",
            100,
        )
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
            "services": len(
                CACHED_CONFIGURATION.get(
                    "services",
                    [],
                )
            ),
            "providers": len(
                CACHED_CONFIGURATION.get(
                    "providers",
                    [],
                )
            ),
            "features": len(
                CACHED_CONFIGURATION.get(
                    "features",
                    [],
                )
            ),
            "settings": len(
                CACHED_CONFIGURATION.get(
                    "settings",
                    [],
                )
            ),
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
            "runtime_config": (
                "GET /runtime/config"
            ),
            "runtime_services": (
                "GET /runtime/services"
            ),
            "runtime_start": (
                "POST /runtime/services/{service_id}/start"
            ),
            "runtime_stop": (
                "POST /runtime/services/{service_id}/stop"
            ),
            "runtime_restart": (
                "POST /runtime/services/{service_id}/restart"
            ),
            "runtime_start_all": (
                "POST /runtime/start-all"
            ),
            "runtime_stop_all": (
                "POST /runtime/stop-all"
            ),
            "runtime_restart_all": (
                "POST /runtime/restart-all"
            ),
            "runtime_system_map": (
                "GET /runtime/system-map"
            ),
            "config_diff": (
                "GET /config/diff"
            ),
            "providers": (
                "GET /providers"
            ),
            "providers_by_type": (
                "GET /providers/{provider_type}"
            ),
            "features": (
                "GET /features"
            ),
            "available_services": (
                "GET /services/available"
            ),
            "status": (
                "GET /status"
            ),
        },
        "architecture": {
            "central_config": (
                "arya_central_config"
            ),
            "runtime": (
                "arya_service_runtime"
            ),
            "bridge": (
                "arya_runtime_config_bridge"
            ),
            "main_api": (
                "main.py"
            ),
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
