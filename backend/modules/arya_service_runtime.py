"""
ARYA Service Runtime
====================

Central runtime manager for ARYA AgriDoctor.

Purpose:
- Central registry of ARYA backend services.
- Start/stop/restart services.
- Health monitoring.
- Service status.
- Automatic restart on unexpected termination.
- No modification of main.py or existing modules.
- Designed for Android/Windows client infrastructure and server deployment.

This file does NOT replace any existing ARYA service.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Service Runtime"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_RUNTIME_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_RUNTIME_PORT",
        "8024",
    )
)

PYTHON_BIN = os.getenv(
    "ARYA_RUNTIME_PYTHON",
    sys.executable,
)

HEALTH_TIMEOUT = float(
    os.getenv(
        "ARYA_RUNTIME_HEALTH_TIMEOUT",
        "8",
    )
)

START_TIMEOUT = float(
    os.getenv(
        "ARYA_RUNTIME_START_TIMEOUT",
        "30",
    )
)

RESTART_DELAY = float(
    os.getenv(
        "ARYA_RUNTIME_RESTART_DELAY",
        "5",
    )
)

MAX_RESTARTS = int(
    os.getenv(
        "ARYA_RUNTIME_MAX_RESTARTS",
        "10",
    )
)

AUTO_RESTART = (
    os.getenv(
        "ARYA_RUNTIME_AUTO_RESTART",
        "true",
    ).lower()
    in {"1", "true", "yes", "on"}
)


# ============================================================
# Service Definition
# ============================================================

@dataclass
class ServiceDefinition:
    service_id: str
    name: str
    module: str
    host: str
    port: int
    health_path: str = "/health"
    enabled: bool = True
    critical: bool = False
    environment: Dict[str, str] = field(
        default_factory=dict
    )


@dataclass
class ServiceProcess:
    definition: ServiceDefinition
    process: Optional[subprocess.Popen] = None
    started_at: Optional[float] = None
    stopped_at: Optional[float] = None
    restart_count: int = 0
    last_error: Optional[str] = None
    state: str = "stopped"


# ============================================================
# Service Registry
# ============================================================

SERVICES: List[ServiceDefinition] = [
    ServiceDefinition(
        service_id="main_api",
        name="ARYA Main API",
        module="main:app",
        host="127.0.0.1",
        port=8000,
        critical=True,
    ),

    ServiceDefinition(
        service_id="vision",
        name="ARYA Vision",
        module="vision:app",
        host="127.0.0.1",
        port=8001,
        critical=True,
    ),

    ServiceDefinition(
        service_id="voice_language",
        name="ARYA Voice Language",
        module="modules.voice_language:app",
        host="127.0.0.1",
        port=8002,
        critical=False,
    ),

    ServiceDefinition(
        service_id="agri_engine",
        name="ARYA Agricultural Engine",
        module="modules.agri_engine:app",
        host="127.0.0.1",
        port=8003,
        critical=True,
    ),

    ServiceDefinition(
        service_id="commerce_security",
        name="ARYA Commerce Security",
        module="modules.commerce_security:app",
        host="127.0.0.1",
        port=8004,
        critical=True,
    ),

    ServiceDefinition(
        service_id="orchestrator",
        name="ARYA Orchestrator",
        module="modules.orchestrator:app",
        host="127.0.0.1",
        port=8010,
        critical=True,
    ),

    ServiceDefinition(
        service_id="owner_manager",
        name="ARYA Owner Manager",
        module="modules.owner_manager:app",
        host="127.0.0.1",
        port=8014,
        critical=True,
    ),

    ServiceDefinition(
        service_id="owner_integration",
        name="ARYA Owner Integration",
        module="modules.owner_integration:app",
        host="127.0.0.1",
        port=8015,
        critical=True,
    ),

    ServiceDefinition(
        service_id="owner_runtime_gateway",
        name="ARYA Owner Runtime Gateway",
        module="modules.owner_runtime_gateway:app",
        host="127.0.0.1",
        port=8016,
        critical=True,
    ),

    ServiceDefinition(
        service_id="orchestrator_runtime_bridge",
        name="ARYA Orchestrator Runtime Bridge",
        module="modules.orchestrator_runtime_bridge:app",
        host="127.0.0.1",
        port=8017,
        critical=False,
    ),

    ServiceDefinition(
        service_id="runtime_data_provider_bridge",
        name="ARYA Runtime Data Provider Bridge",
        module="modules.runtime_data_provider_bridge:app",
        host="127.0.0.1",
        port=8018,
        critical=False,
    ),

    ServiceDefinition(
        service_id="owner_provider_control",
        name="ARYA Owner Provider Control",
        module="modules.owner_provider_control:app",
        host="127.0.0.1",
        port=8019,
        critical=True,
    ),

    ServiceDefinition(
        service_id="internal_service_security",
        name="ARYA Internal Service Security",
        module="modules.internal_service_security:app",
        host="127.0.0.1",
        port=8020,
        critical=True,
    ),

    ServiceDefinition(
        service_id="client_api_gateway",
        name="ARYA Client API Gateway",
        module="modules.client_api_gateway:app",
        host="127.0.0.1",
        port=8021,
        critical=True,
    ),

    ServiceDefinition(
        service_id="arya_main_api_bridge",
        name="ARYA Main API Bridge",
        module="modules.arya_main_api_bridge:app",
        host="127.0.0.1",
        port=8022,
        critical=True,
    ),

    ServiceDefinition(
        service_id="arya_unified_api",
        name="ARYA Unified API",
        module="modules.arya_unified_api:app",
        host="127.0.0.1",
        port=8023,
        critical=True,
    ),
]


# ============================================================
# Runtime State
# ============================================================

RUNTIME: Dict[str, ServiceProcess] = {
    service.service_id: ServiceProcess(
        definition=service
    )
    for service in SERVICES
}

RUNTIME_STARTED_AT = time.time()

SHUTDOWN_EVENT = asyncio.Event()


# ============================================================
# Helpers
# ============================================================

def timestamp() -> int:
    return int(time.time())


def service_url(
    service: ServiceDefinition,
) -> str:
    return (
        f"http://{service.host}:"
        f"{service.port}"
        f"{service.health_path}"
    )


def serialize_process(
    runtime: ServiceProcess,
) -> Dict:
    definition = runtime.definition

    pid = (
        runtime.process.pid
        if runtime.process
        else None
    )

    return {
        "id": definition.service_id,
        "name": definition.name,
        "module": definition.module,
        "host": definition.host,
        "port": definition.port,
        "health": service_url(definition),
        "enabled": definition.enabled,
        "critical": definition.critical,
        "state": runtime.state,
        "pid": pid,
        "started_at": runtime.started_at,
        "stopped_at": runtime.stopped_at,
        "restart_count": runtime.restart_count,
        "last_error": runtime.last_error,
    }


# ============================================================
# Process Manager
# ============================================================

class ServiceManager:

    def __init__(self):
        self.lock = asyncio.Lock()

    async def start(
        self,
        service_id: str,
        automatic: bool = False,
    ) -> Dict:

        async with self.lock:

            if service_id not in RUNTIME:
                raise HTTPException(
                    status_code=404,
                    detail="Service not found",
                )

            runtime = RUNTIME[service_id]
            definition = runtime.definition

            if not definition.enabled:
                raise HTTPException(
                    status_code=409,
                    detail="Service is disabled",
                )

            if (
                runtime.process is not None
                and runtime.process.poll() is None
            ):
                runtime.state = "running"
                return serialize_process(runtime)

            runtime.state = "starting"
            runtime.last_error = None

            command = [
                PYTHON_BIN,
                "-m",
                "uvicorn",
                definition.module,
                "--host",
                definition.host,
                "--port",
                str(definition.port),
            ]

            environment = os.environ.copy()

            environment.update(
                definition.environment
            )

            try:
                process = subprocess.Popen(
                    command,
                    cwd=os.getcwd(),
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            except Exception as exc:
                runtime.state = "failed"
                runtime.last_error = str(exc)

                raise HTTPException(
                    status_code=500,
                    detail=(
                        f"Could not start "
                        f"{service_id}"
                    ),
                ) from exc

            runtime.process = process
            runtime.started_at = time.time()
            runtime.stopped_at = None
            runtime.state = "running"

        healthy = await self.wait_for_health(
            service_id
        )

        if not healthy:
            runtime.state = "starting"

            if automatic:
                return serialize_process(runtime)

        return serialize_process(runtime)

    async def stop(
        self,
        service_id: str,
    ) -> Dict:

        async with self.lock:

            if service_id not in RUNTIME:
                raise HTTPException(
                    status_code=404,
                    detail="Service not found",
                )

            runtime = RUNTIME[service_id]

            if runtime.process is None:
                runtime.state = "stopped"
                return serialize_process(runtime)

            process = runtime.process

            if process.poll() is None:
                runtime.state = "stopping"

                try:
                    process.terminate()

                    await asyncio.to_thread(
                        process.wait,
                        timeout=10,
                    )

                except subprocess.TimeoutExpired:
                    process.kill()

                except Exception as exc:
                    runtime.last_error = str(exc)

            runtime.process = None
            runtime.stopped_at = time.time()
            runtime.state = "stopped"

            return serialize_process(runtime)

    async def restart(
        self,
        service_id: str,
    ) -> Dict:

        await self.stop(service_id)

        await asyncio.sleep(
            RESTART_DELAY
        )

        return await self.start(
            service_id
        )

    async def wait_for_health(
        self,
        service_id: str,
    ) -> bool:

        if service_id not in RUNTIME:
            return False

        runtime = RUNTIME[service_id]
        definition = runtime.definition

        deadline = (
            time.time()
            + START_TIMEOUT
        )

        while time.time() < deadline:

            if (
                runtime.process is not None
                and runtime.process.poll()
                is not None
            ):
                runtime.state = "failed"

                runtime.last_error = (
                    "Process exited during startup"
                )

                return False

            try:
                async with httpx.AsyncClient(
                    timeout=HEALTH_TIMEOUT,
                    follow_redirects=False,
                ) as client:

                    response = await client.get(
                        service_url(definition)
                    )

                    if response.status_code < 500:
                        runtime.state = "healthy"
                        return True

            except Exception:
                pass

            await asyncio.sleep(1)

        runtime.state = "degraded"

        return False

    async def health(
        self,
        service_id: str,
    ) -> Dict:

        if service_id not in RUNTIME:
            raise HTTPException(
                status_code=404,
                detail="Service not found",
            )

        runtime = RUNTIME[service_id]
        definition = runtime.definition

        process_alive = (
            runtime.process is not None
            and runtime.process.poll() is None
        )

        api_healthy = False

        try:
            async with httpx.AsyncClient(
                timeout=HEALTH_TIMEOUT,
                follow_redirects=False,
            ) as client:

                response = await client.get(
                    service_url(definition)
                )

                api_healthy = (
                    response.status_code < 500
                )

        except Exception:
            api_healthy = False

        if api_healthy:
            runtime.state = "healthy"
        elif process_alive:
            runtime.state = "degraded"
        else:
            runtime.state = "stopped"

        result = serialize_process(runtime)

        result["process_alive"] = process_alive
        result["api_healthy"] = api_healthy

        return result

    async def health_all(self) -> List[Dict]:
        results = []

        for service_id in RUNTIME:
            try:
                result = await self.health(
                    service_id
                )
            except Exception as exc:
                result = {
                    "id": service_id,
                    "state": "error",
                    "error": str(exc),
                }

            results.append(result)

        return results

    async def stop_all(self):
        service_ids = list(RUNTIME.keys())

        for service_id in reversed(
            service_ids
        ):
            try:
                await self.stop(
                    service_id
                )
            except Exception:
                pass

    async def start_all(self):
        """
        Start services in registry order.

        The order is intentional:
        core services first, integration layers later.
        """

        results = []

        for service_id in RUNTIME:

            runtime = RUNTIME[service_id]

            if not runtime.definition.enabled:
                continue

            try:
                result = await self.start(
                    service_id
                )
                results.append(result)

            except Exception as exc:
                results.append({
                    "id": service_id,
                    "state": "failed",
                    "error": str(exc),
                })

                if runtime.definition.critical:
                    # Continue starting other services.
                    # Critical status is reported separately.
                    continue

        return results


SERVICE_MANAGER = ServiceManager()


# ============================================================
# Background Supervisor
# ============================================================

async def supervisor_loop():
    while not SHUTDOWN_EVENT.is_set():

        if AUTO_RESTART:

            for service_id, runtime in list(
                RUNTIME.items()
            ):

                process = runtime.process

                if process is None:
                    continue

                return_code = process.poll()

                if return_code is None:
                    continue

                runtime.process = None
                runtime.state = "crashed"
                runtime.stopped_at = time.time()

                if (
                    runtime.restart_count
                    >= MAX_RESTARTS
                ):
                    runtime.state = (
                        "restart_limit_reached"
                    )
                    continue

                runtime.restart_count += 1

                await asyncio.sleep(
                    RESTART_DELAY
                )

                try:
                    await SERVICE_MANAGER.start(
                        service_id,
                        automatic=True,
                    )

                except Exception as exc:
                    runtime.state = "failed"
                    runtime.last_error = str(exc)

        try:
            await asyncio.wait_for(
                SHUTDOWN_EVENT.wait(),
                timeout=5,
            )
        except asyncio.TimeoutError:
            pass


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Central runtime manager for "
        "ARYA AgriDoctor services."
    ),
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
        "services": len(SERVICES),
        "auto_restart": AUTO_RESTART,
        "timestamp": timestamp(),
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health():
    services = await SERVICE_MANAGER.health_all()

    healthy = sum(
        1
        for item in services
        if item.get("api_healthy") is True
    )

    running = sum(
        1
        for item in services
        if item.get("process_alive") is True
    )

    critical_services = [
        item
        for item in services
        if next(
            (
                s
                for s in SERVICES
                if s.service_id
                == item.get("id")
            ),
            None,
        )
        and next(
            (
                s
                for s in SERVICES
                if s.service_id
                == item.get("id")
            )
        ).critical
    ]

    critical_unhealthy = [
        item
        for item in critical_services
        if not item.get("api_healthy")
    ]

    status = (
        "healthy"
        if not critical_unhealthy
        else "degraded"
    )

    return {
        "status": status,
        "service": APP_NAME,
        "version": APP_VERSION,
        "total_services": len(SERVICES),
        "running_services": running,
        "healthy_services": healthy,
        "critical_unhealthy": len(
            critical_unhealthy
        ),
        "timestamp": timestamp(),
    }


# ============================================================
# Service List
# ============================================================

@app.get("/services")
async def list_services():
    return {
        "services": [
            serialize_process(
                RUNTIME[
                    service.service_id
                ]
            )
            for service in SERVICES
        ],
        "timestamp": timestamp(),
    }


# ============================================================
# Single Service
# ============================================================

@app.get("/services/{service_id}")
async def service_details(
    service_id: str,
):
    if service_id not in RUNTIME:
        raise HTTPException(
            status_code=404,
            detail="Service not found",
        )

    return await SERVICE_MANAGER.health(
        service_id
    )


# ============================================================
# Start
# ============================================================

@app.post("/services/{service_id}/start")
async def start_service(
    service_id: str,
):
    return await SERVICE_MANAGER.start(
        service_id
    )


# ============================================================
# Stop
# ============================================================

@app.post("/services/{service_id}/stop")
async def stop_service(
    service_id: str,
):
    return await SERVICE_MANAGER.stop(
        service_id
    )


# ============================================================
# Restart
# ============================================================

@app.post("/services/{service_id}/restart")
async def restart_service(
    service_id: str,
):
    return await SERVICE_MANAGER.restart(
        service_id
    )


# ============================================================
# Start All
# ============================================================

@app.post("/runtime/start-all")
async def start_all():
    return {
        "status": "started",
        "results": await SERVICE_MANAGER.start_all(),
        "timestamp": timestamp(),
    }


# ============================================================
# Stop All
# ============================================================

@app.post("/runtime/stop-all")
async def stop_all():
    await SERVICE_MANAGER.stop_all()

    return {
        "status": "stopped",
        "timestamp": timestamp(),
    }


# ============================================================
# Restart All
# ============================================================

@app.post("/runtime/restart-all")
async def restart_all():
    await SERVICE_MANAGER.stop_all()

    await asyncio.sleep(
        RESTART_DELAY
    )

    results = (
        await SERVICE_MANAGER.start_all()
    )

    return {
        "status": "restarted",
        "results": results,
        "timestamp": timestamp(),
    }


# ============================================================
# Runtime Status
# ============================================================

@app.get("/runtime/status")
async def runtime_status():
    services = await SERVICE_MANAGER.health_all()

    return {
        "runtime": APP_NAME,
        "version": APP_VERSION,
        "started_at": RUNTIME_STARTED_AT,
        "uptime_seconds": int(
            time.time()
            - RUNTIME_STARTED_AT
        ),
        "auto_restart": AUTO_RESTART,
        "max_restarts": MAX_RESTARTS,
        "services": services,
        "timestamp": timestamp(),
    }


# ============================================================
# System Map
# ============================================================

@app.get("/runtime/system-map")
async def system_map():
    return {
        "runtime": APP_NAME,
        "version": APP_VERSION,
        "architecture": {
            "client_layer": [
                "Android",
                "Windows",
            ],
            "entrypoint": (
                "arya_unified_api"
            ),
            "client_gateway": (
                "client_api_gateway"
            ),
            "runtime_gateway": (
                "owner_runtime_gateway"
            ),
            "legacy_core": (
                "main_api"
            ),
            "main_bridge": (
                "arya_main_api_bridge"
            ),
            "orchestration": [
                "orchestrator",
                "orchestrator_runtime_bridge",
            ],
            "agriculture": [
                "agri_engine",
                "vision",
                "voice_language",
            ],
            "data": [
                "data_update",
                "external_providers",
                "runtime_data_provider_bridge",
            ],
            "commerce": [
                "commerce_security",
            ],
            "owner": [
                "owner_manager",
                "owner_integration",
                "owner_provider_control",
            ],
            "security": [
                "internal_service_security",
            ],
        },
        "services": [
            serialize_process(
                RUNTIME[
                    service.service_id
                ]
            )
            for service in SERVICES
        ],
        "timestamp": timestamp(),
    }


# ============================================================
# Configuration Contract
# ============================================================

@app.get("/runtime/contract")
async def runtime_contract():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "port": PORT,
        "commands": {
            "start_all": "POST /runtime/start-all",
            "stop_all": "POST /runtime/stop-all",
            "restart_all": "POST /runtime/restart-all",
            "status": "GET /runtime/status",
            "system_map": (
                "GET /runtime/system-map"
            ),
        },
        "service_routes": {
            "list": "GET /services",
            "details": (
                "GET /services/{service_id}"
            ),
            "start": (
                "POST /services/{service_id}/start"
            ),
            "stop": (
                "POST /services/{service_id}/stop"
            ),
            "restart": (
                "POST /services/{service_id}/restart"
            ),
        },
        "main_py": {
            "modified": False,
            "managed_as": "main_api",
        },
    }


# ============================================================
# Shutdown
# ============================================================

async def shutdown_runtime():
    SHUTDOWN_EVENT.set()

    try:
        await SERVICE_MANAGER.stop_all()
    except Exception:
        pass


@app.on_event("shutdown")
async def on_shutdown():
    await shutdown_runtime()


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def on_startup():
    asyncio.create_task(
        supervisor_loop()
    )


# ============================================================
# Error Handler
# ============================================================

@app.exception_handler(Exception)
async def generic_exception_handler(
    request,
    exc: Exception,
):
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "service": APP_NAME,
            "request_id": uuid.uuid4().hex,
        },
    )


# ============================================================
# Local Execution
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "arya_service_runtime:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
