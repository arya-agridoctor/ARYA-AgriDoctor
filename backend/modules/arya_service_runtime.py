"""
ARYA Service Runtime
====================

Central runtime manager for ARYA AgriDoctor.

Purpose:
- Central registry of ARYA backend services.
- Start / stop / restart services.
- Health monitoring.
- Automatic restart.
- Unified runtime map.
- Data-update service management.
- Automatic-update scheduler management.
- Provider infrastructure management.
- Android / Windows / server deployment support.
- Preserve existing service implementations.
- Do not modify backend/main.py.

This module is a runtime/orchestration layer only.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Service Runtime"
APP_VERSION = "2.1.0"

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

STOP_TIMEOUT = float(
    os.getenv(
        "ARYA_RUNTIME_STOP_TIMEOUT",
        "10",
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

# Runtime management authentication.
# Empty = compatibility mode for existing local deployments.
RUNTIME_SECRET = os.getenv(
    "ARYA_RUNTIME_SECRET",
    "",
).strip()

# backend directory.
# This avoids depending on the directory from which uvicorn was launched.
BASE_DIR = Path(
    __file__
).resolve().parents[1]


# ============================================================
# Environment helpers
# ============================================================

def env_port(
    name: str,
    default: int,
) -> int:
    try:
        value = int(
            os.getenv(
                name,
                str(default),
            )
        )

        if not 1 <= value <= 65535:
            return default

        return value

    except (TypeError, ValueError):
        return default


def env_bool(
    name: str,
    default: bool = False,
) -> bool:
    value = os.getenv(
        name,
        str(default),
    ).strip().lower()

    return value in {
        "1",
        "true",
        "yes",
        "on",
    }


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
    startup_order: int = 100


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
#
# Defaults used by the runtime service registry:
#
# 8000  main.py
# 8001  vision
# 8002  voice_language
# 8003  agri_engine
# 8010  orchestrator
# 8011  data_update
# 8013  commerce security
# 8015  owner integration
# 8016  owner runtime gateway
# 8017  orchestrator runtime bridge
# 8018  runtime data provider bridge
# 8019  owner provider control
# 8020  internal service security
# 8021  client API gateway
# 8022  main API bridge
# 8023  unified API
# 8024  this runtime
# 8025  automatic update scheduler
# 8027  final integration
# 8028  client runtime bridge
# 8029  runtime configuration bridge
# 8095  external providers
# 8096  owner manager
#
# Important:
# - Port 8029 must match arya_runtime_config_bridge.py.
# - Port 8025 remains assigned to the scheduler in this registry.
# - The central configuration module must not be started on 8025
#   without resolving its port conflict.
# - No existing service implementation is modified here.
# ============================================================

SERVICES: List[ServiceDefinition] = [

    # --------------------------------------------------------
    # Core
    # --------------------------------------------------------

    ServiceDefinition(
        service_id="main_api",
        name="ARYA Main API",
        module="main:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_MAIN_API_PORT",
            8000,
        ),
        critical=True,
        startup_order=10,
    ),

    ServiceDefinition(
        service_id="vision",
        name="ARYA Vision",
        module="vision:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_VISION_PORT",
            8001,
        ),
        critical=True,
        startup_order=20,
    ),

    ServiceDefinition(
        service_id="voice_language",
        name="ARYA Voice Language",
        module="modules.voice_language:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_VOICE_LANGUAGE_PORT",
            8002,
        ),
        critical=False,
        startup_order=20,
    ),

    ServiceDefinition(
        service_id="agri_engine",
        name="ARYA Agricultural Engine",
        module="modules.agri_engine:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_AGRI_ENGINE_PORT",
            8003,
        ),
        critical=True,
        startup_order=20,
    ),

    ServiceDefinition(
        service_id="commerce_security",
        name="ARYA Commerce Security",
        module="modules.commerce_security:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_COMMERCE_SECURITY_PORT",
            8013,
        ),
        critical=True,
        startup_order=20,
    ),

    ServiceDefinition(
        service_id="external_providers",
        name="ARYA External Providers",
        module="modules.external_providers:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_EXTERNAL_PROVIDERS_PORT",
            8095,
        ),
        critical=False,
        startup_order=30,
    ),

    # --------------------------------------------------------
    # Orchestration
    # --------------------------------------------------------

    ServiceDefinition(
        service_id="orchestrator",
        name="ARYA Orchestrator",
        module="modules.orchestrator:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_ORCHESTRATOR_PORT",
            8010,
        ),
        critical=True,
        startup_order=40,
    ),

    ServiceDefinition(
        service_id="owner_manager",
        name="ARYA Owner Manager",
        module="modules.owner_manager:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_OWNER_MANAGER_PORT",
            8096,
        ),
        critical=True,
        startup_order=40,
    ),

    ServiceDefinition(
        service_id="owner_integration",
        name="ARYA Owner Integration",
        module="modules.owner_integration:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_OWNER_INTEGRATION_PORT",
            8015,
        ),
        critical=True,
        startup_order=40,
    ),

    ServiceDefinition(
        service_id="owner_runtime_gateway",
        name="ARYA Owner Runtime Gateway",
        module="modules.owner_runtime_gateway:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_OWNER_RUNTIME_GATEWAY_PORT",
            8016,
        ),
        critical=True,
        startup_order=50,
    ),

    ServiceDefinition(
        service_id="orchestrator_runtime_bridge",
        name="ARYA Orchestrator Runtime Bridge",
        module="modules.orchestrator_runtime_bridge:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_ORCHESTRATOR_RUNTIME_BRIDGE_PORT",
            8017,
        ),
        critical=False,
        startup_order=50,
    ),

    # --------------------------------------------------------
    # Provider / Owner Bridges
    # --------------------------------------------------------

    ServiceDefinition(
        service_id="runtime_data_provider_bridge",
        name="ARYA Runtime Data Provider Bridge",
        module="modules.runtime_data_provider_bridge:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_RUNTIME_DATA_PROVIDER_BRIDGE_PORT",
            8018,
        ),
        critical=False,
        startup_order=50,
    ),

    ServiceDefinition(
        service_id="owner_provider_control",
        name="ARYA Owner Provider Control",
        module="modules.owner_provider_control:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_OWNER_PROVIDER_CONTROL_PORT",
            8019,
        ),
        critical=True,
        startup_order=50,
    ),

    ServiceDefinition(
        service_id="internal_service_security",
        name="ARYA Internal Service Security",
        module="modules.internal_service_security:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_INTERNAL_SERVICE_SECURITY_PORT",
            8020,
        ),
        critical=True,
        startup_order=50,
    ),

    # --------------------------------------------------------
    # Client / API
    # --------------------------------------------------------

    ServiceDefinition(
        service_id="client_api_gateway",
        name="ARYA Client API Gateway",
        module="modules.client_api_gateway:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_CLIENT_API_GATEWAY_PORT",
            8021,
        ),
        critical=True,
        startup_order=60,
    ),

    ServiceDefinition(
        service_id="arya_main_api_bridge",
        name="ARYA Main API Bridge",
        module="modules.arya_main_api_bridge:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_MAIN_API_BRIDGE_PORT",
            8022,
        ),
        critical=True,
        startup_order=60,
    ),

    ServiceDefinition(
        service_id="arya_unified_api",
        name="ARYA Unified API",
        module="modules.arya_unified_api:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_UNIFIED_API_PORT",
            8023,
        ),
        critical=True,
        startup_order=70,
    ),

    # --------------------------------------------------------
    # Runtime manager itself = 8024
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Configuration / Update Infrastructure
    # --------------------------------------------------------

    ServiceDefinition(
        service_id="arya_auto_update_scheduler",
        name="ARYA Automatic Update Scheduler",
        module="modules.arya_auto_update_scheduler:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_AUTO_UPDATE_PORT",
            8025,
        ),
        critical=False,
        startup_order=80,
    ),

    ServiceDefinition(
        service_id="data_update",
        name="ARYA Data Update",
        module="modules.data_update:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_DATA_UPDATE_PORT",
            8011,
        ),
        critical=False,
        startup_order=80,
    ),

    # --------------------------------------------------------
    # Runtime Configuration Bridge
    # --------------------------------------------------------
    #
    # The default port is 8029 to match the revised
    # arya_runtime_config_bridge.py.
    #
    # Override with ARYA_RUNTIME_CONFIG_BRIDGE_PORT if required.
    # --------------------------------------------------------

    ServiceDefinition(
        service_id="arya_runtime_config_bridge",
        name="ARYA Runtime Configuration Bridge",
        module="modules.arya_runtime_config_bridge:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_RUNTIME_CONFIG_BRIDGE_PORT",
            8029,
        ),
        critical=False,
        startup_order=85,
    ),

    # --------------------------------------------------------
    # New integration layer
    # --------------------------------------------------------

    ServiceDefinition(
        service_id="arya_final_integration",
        name="ARYA Final Integration",
        module="modules.arya_final_integration:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_FINAL_INTEGRATION_PORT",
            8027,
        ),
        critical=True,
        startup_order=90,
    ),

    ServiceDefinition(
        service_id="arya_client_runtime_bridge",
        name="ARYA Client Runtime Bridge",
        module="modules.arya_client_runtime_bridge:app",
        host="127.0.0.1",
        port=env_port(
            "ARYA_CLIENT_RUNTIME_BRIDGE_PORT",
            8028,
        ),
        critical=False,
        startup_order=90,
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
        "startup_order": definition.startup_order,
        "state": runtime.state,
        "pid": pid,
        "started_at": runtime.started_at,
        "stopped_at": runtime.stopped_at,
        "restart_count": runtime.restart_count,
        "last_error": runtime.last_error,
    }


def get_definition(
    service_id: str,
) -> ServiceDefinition:

    runtime = RUNTIME.get(
        service_id
    )

    if runtime is None:
        raise HTTPException(
            status_code=404,
            detail="Service not found",
        )

    return runtime.definition


def process_alive(
    runtime: ServiceProcess,
) -> bool:

    return (
        runtime.process is not None
        and runtime.process.poll() is None
    )


# ============================================================
# Runtime Authentication
# ============================================================

def verify_runtime_request(
    request: Request,
) -> None:
    """
    Protect runtime-control endpoints when a secret
    has been configured.

    Empty secret preserves local compatibility.
    """

    if not RUNTIME_SECRET:
        return

    provided = (
        request.headers.get(
            "X-ARYA-Runtime-Secret"
        )
        or request.headers.get(
            "X-ARYA-Internal-Secret"
        )
        or ""
    )

    import hmac

    if not hmac.compare_digest(
        provided,
        RUNTIME_SECRET,
    ):
        raise HTTPException(
            status_code=401,
            detail="Runtime authentication required",
        )


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

            definition = get_definition(
                service_id
            )

            runtime = RUNTIME[
                service_id
            ]

            if not definition.enabled:
                raise HTTPException(
                    status_code=409,
                    detail="Service is disabled",
                )

            if process_alive(runtime):
                runtime.state = "running"

                return serialize_process(
                    runtime
                )

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
                "--no-access-log",
            ]

            environment = os.environ.copy()
            environment.update(
                definition.environment
            )

            # Make backend imports deterministic.
            python_path = environment.get(
                "PYTHONPATH",
                "",
            )

            backend_path = str(
                BASE_DIR
            )

            if python_path:
                if backend_path not in python_path.split(
                    os.pathsep
                ):
                    environment["PYTHONPATH"] = (
                        backend_path
                        + os.pathsep
                        + python_path
                    )
            else:
                environment["PYTHONPATH"] = (
                    backend_path
                )

            try:
                process = subprocess.Popen(
                    command,
                    cwd=str(BASE_DIR),
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=(
                        os.name != "nt"
                    ),
                )

            except Exception as exc:
                runtime.state = "failed"
                runtime.last_error = str(
                    exc
                )

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
            runtime.state = "starting"

        healthy = await self.wait_for_health(
            service_id
        )

        if healthy:
            runtime.state = "healthy"

        elif process_alive(runtime):
            runtime.state = "degraded"

        else:
            runtime.state = "failed"

        return serialize_process(
            runtime
        )

    async def stop(
        self,
        service_id: str,
    ) -> Dict:

        async with self.lock:

            get_definition(
                service_id
            )

            runtime = RUNTIME[
                service_id
            ]

            if runtime.process is None:
                runtime.state = "stopped"

                return serialize_process(
                    runtime
                )

            process = runtime.process

            if process.poll() is None:
                runtime.state = "stopping"

                try:
                    process.terminate()

                    await asyncio.to_thread(
                        process.wait,
                        timeout=STOP_TIMEOUT,
                    )

                except subprocess.TimeoutExpired:

                    try:
                        process.kill()

                        await asyncio.to_thread(
                            process.wait,
                            timeout=5,
                        )

                    except Exception:
                        pass

                except Exception as exc:
                    runtime.last_error = str(
                        exc
                    )

            runtime.process = None
            runtime.stopped_at = time.time()
            runtime.state = "stopped"

            return serialize_process(
                runtime
            )

    async def restart(
        self,
        service_id: str,
    ) -> Dict:

        await self.stop(
            service_id
        )

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

        runtime = RUNTIME[
            service_id
        ]

        definition = runtime.definition

        deadline = (
            time.monotonic()
            + START_TIMEOUT
        )

        async with httpx.AsyncClient(
            timeout=HEALTH_TIMEOUT,
            follow_redirects=False,
        ) as client:

            while time.monotonic() < deadline:

                if (
                    runtime.process is not None
                    and runtime.process.poll()
                    is not None
                ):
                    runtime.state = "failed"

                    runtime.last_error = (
                        "Process exited during startup"
                    )

                    runtime.process = None

                    return False

                try:
                    response = await client.get(
                        service_url(
                            definition
                        )
                    )

                    if response.status_code < 500:
                        runtime.state = "healthy"
                        return True

                except httpx.HTTPError:
                    pass

                await asyncio.sleep(1)

        if process_alive(runtime):
            runtime.state = "degraded"
        else:
            runtime.state = "failed"

        return False

    async def health(
        self,
        service_id: str,
    ) -> Dict:

        definition = get_definition(
            service_id
        )

        runtime = RUNTIME[
            service_id
        ]

        alive = process_alive(
            runtime
        )

        api_healthy = False
        response_status = None

        try:
            async with httpx.AsyncClient(
                timeout=HEALTH_TIMEOUT,
                follow_redirects=False,
            ) as client:

                response = await client.get(
                    service_url(
                        definition
                    )
                )

                response_status = (
                    response.status_code
                )

                api_healthy = (
                    response.status_code < 500
                )

        except httpx.HTTPError as exc:
            runtime.last_error = str(exc)

        if api_healthy:
            runtime.state = "healthy"

        elif alive:
            runtime.state = "degraded"

        else:
            runtime.state = "stopped"

        result = serialize_process(
            runtime
        )

        result["process_alive"] = alive
        result["api_healthy"] = api_healthy
        result["response_status"] = response_status

        return result

    async def health_all(
        self,
    ) -> List[Dict]:

        results = []

        for service in sorted(
            SERVICES,
            key=lambda item: (
                item.startup_order,
                item.service_id,
            ),
        ):

            service_id = (
                service.service_id
            )

            try:
                result = await self.health(
                    service_id
                )

            except Exception as exc:
                result = {
                    "id": service_id,
                    "state": "error",
                    "error": str(exc),
                    "critical": service.critical,
                }

            results.append(result)

        return results

    async def stop_all(
        self,
    ):

        service_ids = [
            service.service_id
            for service in sorted(
                SERVICES,
                key=lambda item: (
                    item.startup_order,
                    item.service_id,
                ),
                reverse=True,
            )
        ]

        for service_id in service_ids:

            try:
                await self.stop(
                    service_id
                )

            except Exception:
                pass

    async def start_all(
        self,
    ):

        results = []

        ordered = sorted(
            SERVICES,
            key=lambda item: (
                item.startup_order,
                item.service_id,
            ),
        )

        for definition in ordered:

            if not definition.enabled:
                continue

            service_id = (
                definition.service_id
            )

            try:
                result = await self.start(
                    service_id
                )

                results.append(
                    result
                )

            except Exception as exc:

                result = {
                    "id": service_id,
                    "state": "failed",
                    "error": str(exc),
                    "critical": definition.critical,
                }

                results.append(
                    result
                )

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

                runtime.last_error = (
                    f"Process exited with code "
                    f"{return_code}"
                )

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

                if SHUTDOWN_EVENT.is_set():
                    break

                try:
                    await SERVICE_MANAGER.start(
                        service_id,
                        automatic=True,
                    )

                except Exception as exc:
                    runtime.state = "failed"
                    runtime.last_error = str(
                        exc
                    )

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
        "runtime_port": PORT,
        "backend_directory": str(
            BASE_DIR
        ),
        "runtime_authentication": bool(
            RUNTIME_SECRET
        ),
        "timestamp": timestamp(),
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health():

    services = (
        await SERVICE_MANAGER.health_all()
    )

    healthy = sum(
        1
        for item in services
        if item.get(
            "api_healthy"
        ) is True
    )

    running = sum(
        1
        for item in services
        if item.get(
            "process_alive"
        ) is True
    )

    critical_ids = {
        service.service_id
        for service in SERVICES
        if service.critical
    }

    critical_unhealthy = [
        item
        for item in services
        if item.get("id")
        in critical_ids
        and not item.get(
            "api_healthy"
        )
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
        "total_services": len(
            SERVICES
        ),
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

@app.get(
    "/services/{service_id}"
)
async def service_details(
    service_id: str,
):

    return await SERVICE_MANAGER.health(
        service_id
    )


# ============================================================
# Start
# ============================================================

@app.post(
    "/services/{service_id}/start"
)
async def start_service(
    service_id: str,
    request: Request,
):

    verify_runtime_request(
        request
    )

    return await SERVICE_MANAGER.start(
        service_id
    )


# ============================================================
# Stop
# ============================================================

@app.post(
    "/services/{service_id}/stop"
)
async def stop_service(
    service_id: str,
    request: Request,
):

    verify_runtime_request(
        request
    )

    return await SERVICE_MANAGER.stop(
        service_id
    )


# ============================================================
# Restart
# ============================================================

@app.post(
    "/services/{service_id}/restart"
)
async def restart_service(
    service_id: str,
    request: Request,
):

    verify_runtime_request(
        request
    )

    return await SERVICE_MANAGER.restart(
        service_id
    )


# ============================================================
# Start All
# ============================================================

@app.post(
    "/runtime/start-all"
)
async def start_all(
    request: Request,
):

    verify_runtime_request(
        request
    )

    return {
        "status": "started",
        "results": (
            await SERVICE_MANAGER.start_all()
        ),
        "timestamp": timestamp(),
    }


# ============================================================
# Stop All
# ============================================================

@app.post(
    "/runtime/stop-all"
)
async def stop_all(
    request: Request,
):

    verify_runtime_request(
        request
    )

    await SERVICE_MANAGER.stop_all()

    return {
        "status": "stopped",
        "timestamp": timestamp(),
    }


# ============================================================
# Restart All
# ============================================================

@app.post(
    "/runtime/restart-all"
)
async def restart_all(
    request: Request,
):

    verify_runtime_request(
        request
    )

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

@app.get(
    "/runtime/status"
)
async def runtime_status():

    services = (
        await SERVICE_MANAGER.health_all()
    )

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

@app.get(
    "/runtime/system-map"
)
async def system_map():

    return {
        "runtime": APP_NAME,
        "version": APP_VERSION,

        "client_layer": [
            "Android",
            "Windows",
        ],

        "entrypoint": (
            "arya_final_integration"
        ),

        "unified_api": (
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
            "arya_auto_update_scheduler",
        ],

        "commerce": [
            "commerce_security",
        ],

        "owner": [
            "owner_manager",
            "owner_integration",
            "owner_provider_control",
            "owner_runtime_gateway",
        ],

        "security": [
            "internal_service_security",
        ],

        "integration": [
            "arya_final_integration",
            "arya_client_runtime_bridge",
            "arya_main_api_bridge",
            "arya_unified_api",
            "arya_runtime_config_bridge",
        ],

        "runtime_services": [
            {
                "id": service.service_id,
                "port": service.port,
                "critical": service.critical,
                "enabled": service.enabled,
                "startup_order": service.startup_order,
            }
            for service in SERVICES
        ],

        "main_py": {
            "modified": False,
            "managed_as": "main_api",
        },

        "timestamp": timestamp(),
    }


# ============================================================
# Runtime Contract
# ============================================================

@app.get(
    "/runtime/contract"
)
async def runtime_contract():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "port": PORT,

        "runtime_services": {
            "runtime_manager": PORT,

            "main_api": env_port(
                "ARYA_MAIN_API_PORT",
                8000,
            ),

            "vision": env_port(
                "ARYA_VISION_PORT",
                8001,
            ),

            "voice_language": env_port(
                "ARYA_VOICE_LANGUAGE_PORT",
                8002,
            ),

            "agri_engine": env_port(
                "ARYA_AGRI_ENGINE_PORT",
                8003,
            ),

            "commerce_security": env_port(
                "ARYA_COMMERCE_SECURITY_PORT",
                8013,
            ),

            "external_providers": env_port(
                "ARYA_EXTERNAL_PROVIDERS_PORT",
                8095,
            ),

            "orchestrator": env_port(
                "ARYA_ORCHESTRATOR_PORT",
                8010,
            ),

            "owner_runtime_gateway": env_port(
                "ARYA_OWNER_RUNTIME_GATEWAY_PORT",
                8016,
            ),

            "client_api_gateway": env_port(
                "ARYA_CLIENT_API_GATEWAY_PORT",
                8021,
            ),

            "arya_main_api_bridge": env_port(
                "ARYA_MAIN_API_BRIDGE_PORT",
                8022,
            ),

            "arya_unified_api": env_port(
                "ARYA_UNIFIED_API_PORT",
                8023,
            ),

            "data_update": env_port(
                "ARYA_DATA_UPDATE_PORT",
                8011,
            ),

            "arya_auto_update_scheduler": env_port(
                "ARYA_AUTO_UPDATE_PORT",
                8025,
            ),

            "arya_final_integration": env_port(
                "ARYA_FINAL_INTEGRATION_PORT",
                8027,
            ),

            "arya_client_runtime_bridge": env_port(
                "ARYA_CLIENT_RUNTIME_BRIDGE_PORT",
                8028,
            ),

            "arya_runtime_config_bridge": env_port(
                "ARYA_RUNTIME_CONFIG_BRIDGE_PORT",
                8029,
            ),
        },

        "commands": {
            "start_all": (
                "POST /runtime/start-all"
            ),
            "stop_all": (
                "POST /runtime/stop-all"
            ),
            "restart_all": (
                "POST /runtime/restart-all"
            ),
            "status": (
                "GET /runtime/status"
            ),
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

        "security": {
            "runtime_secret_configured": bool(
                RUNTIME_SECRET
            ),
            "header": (
                "X-ARYA-Runtime-Secret"
            ),
        },

        "main_py": {
            "modified": False,
            "managed_as": "main_api",
        },
    }


# ============================================================
# Service Discovery
# ============================================================

@app.get(
    "/runtime/discovery"
)
async def runtime_discovery():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "services": [
            {
                "id": service.service_id,
                "name": service.name,
                "module": service.module,
                "url": (
                    f"http://{service.host}:"
                    f"{service.port}"
                ),
                "health": service_url(
                    service
                ),
                "enabled": service.enabled,
                "critical": service.critical,
            }
            for service in SERVICES
        ],
        "timestamp": timestamp(),
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


@app.on_event(
    "shutdown"
)
async def on_shutdown():

    await shutdown_runtime()


# ============================================================
# Startup
# ============================================================

@app.on_event(
    "startup"
)
async def on_startup():

    SHUTDOWN_EVENT.clear()

    asyncio.create_task(
        supervisor_loop()
    )


# ============================================================
# Error Handler
# ============================================================

@app.exception_handler(
    Exception
)
async def generic_exception_handler(
    request: Request,
    exc: Exception,
):

    return JSONResponse(
        status_code=500,
        content={
            "error": (
                "internal_server_error"
            ),
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
        "modules.arya_service_runtime:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
