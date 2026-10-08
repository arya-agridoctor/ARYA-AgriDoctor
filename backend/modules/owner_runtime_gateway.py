"""
ARYA AgriDoctor
OWNER Runtime Gateway
Version: 2.0.0

Purpose:
- Runtime connection between OWNER Integration and ARYA services.
- Read active service/provider configuration.
- Route requests without modifying main.py.
- Centralize service discovery.
- Support OWNER-controlled enable/disable state.
- Provide safe internal service calls.
- Protect external provider calls against SSRF.
- Support canonical ARYA runtime routes.
- Preserve legacy /arya/* routes.
- Support voice, payment, weather, geocode and updates.
- Propagate ARYA internal authentication and request IDs.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import socket
import time
import uuid
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


# ============================================================
# CONFIG
# ============================================================

SERVICE_NAME = "ARYA Owner Runtime Gateway"
SERVICE_VERSION = "2.0.0"

HOST = os.getenv(
    "ARYA_RUNTIME_GATEWAY_HOST",
    "0.0.0.0",
)

PORT = int(
    os.getenv(
        "ARYA_RUNTIME_GATEWAY_PORT",
        "8016",
    )
)

OWNER_INTEGRATION_URL = os.getenv(
    "ARYA_OWNER_INTEGRATION_URL",
    "http://127.0.0.1:8015",
).rstrip("/")

INTERNAL_GATEWAY_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

RUNTIME_API_SECRET = os.getenv(
    "ARYA_RUNTIME_API_SECRET",
    "",
)

DEFAULT_TIMEOUT = float(
    os.getenv(
        "ARYA_RUNTIME_TIMEOUT",
        "30",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_RUNTIME_MAX_RESPONSE_BYTES",
        str(10 * 1024 * 1024),
    )
)

MAX_REQUEST_BYTES = int(
    os.getenv(
        "ARYA_RUNTIME_MAX_REQUEST_BYTES",
        str(5 * 1024 * 1024),
    )
)

MAX_RETRIES = int(
    os.getenv(
        "ARYA_RUNTIME_MAX_RETRIES",
        "2",
    )
)

REQUEST_TTL = int(
    os.getenv(
        "ARYA_RUNTIME_REQUEST_TTL",
        "60",
    )
)

REQUIRE_INTERNAL_AUTH = (
    os.getenv(
        "ARYA_RUNTIME_REQUIRE_INTERNAL_AUTH",
        "false",
    ).strip().lower()
    in {"1", "true", "yes", "on"}
)

LOG_LEVEL = os.getenv(
    "ARYA_RUNTIME_LOG_LEVEL",
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

logger = logging.getLogger(SERVICE_NAME)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title=SERVICE_NAME,
    version=SERVICE_VERSION,
    description=(
        "OWNER-controlled runtime gateway for "
        "ARYA AgriDoctor services and providers."
    ),
)


# ============================================================
# MODELS
# ============================================================

class RuntimeCallRequest(BaseModel):
    service_id: str = Field(
        min_length=1,
        max_length=100,
    )

    path: str = Field(
        min_length=1,
        max_length=1000,
    )

    method: str = Field(
        default="POST",
        min_length=3,
        max_length=10,
    )

    payload: Optional[Dict[str, Any]] = None

    query: Optional[Dict[str, Any]] = None

    headers: Optional[Dict[str, str]] = None


class ProviderCallRequest(BaseModel):
    provider_id: str = Field(
        min_length=1,
        max_length=100,
    )

    path: str = Field(
        default="/",
        max_length=1000,
    )

    method: str = Field(
        default="GET",
        min_length=3,
        max_length=10,
    )

    payload: Optional[Dict[str, Any]] = None

    query: Optional[Dict[str, Any]] = None

    headers: Optional[Dict[str, str]] = None


# ============================================================
# HELPERS
# ============================================================

def now_ts() -> int:
    return int(time.time())


def new_request_id() -> str:
    return uuid.uuid4().hex


def constant_time_equal(
    a: str,
    b: str,
) -> bool:
    if not a or not b:
        return False

    return hmac.compare_digest(
        a.encode("utf-8"),
        b.encode("utf-8"),
    )


def sign_payload(
    timestamp: str,
    body: bytes,
    secret: str,
) -> str:
    message = (
        timestamp.encode("utf-8")
        + b"."
        + body
    )

    return hmac.new(
        secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()


def verify_signature(
    timestamp: Optional[str],
    signature: Optional[str],
    body: bytes,
    secret: str,
) -> bool:

    if not secret:
        return False

    if not timestamp or not signature:
        return False

    try:
        timestamp_int = int(timestamp)
    except (TypeError, ValueError):
        return False

    if abs(now_ts() - timestamp_int) > REQUEST_TTL:
        return False

    expected = sign_payload(
        timestamp,
        body,
        secret,
    )

    provided = signature.strip()

    if provided.lower().startswith(
        "sha256="
    ):
        provided = provided[7:]

    return constant_time_equal(
        expected,
        provided,
    )


# ============================================================
# PATH SECURITY
# ============================================================

def validate_relative_path(
    path: str,
) -> None:

    if not path:
        raise ValueError(
            "Path is required"
        )

    if path.startswith(
        ("http://", "https://")
    ):
        raise ValueError(
            "Absolute URLs are not allowed"
        )

    if "\\" in path:
        raise ValueError(
            "Backslash paths are not allowed"
        )

    if any(
        part == ".."
        for part in path.split("/")
    ):
        raise ValueError(
            "Parent traversal is not allowed"
        )


# ============================================================
# EXTERNAL URL / SSRF SECURITY
# ============================================================

def resolve_host_addresses(
    hostname: str,
    port: int,
) -> set[str]:

    try:
        addresses = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            "Target hostname cannot be resolved"
        ) from exc

    resolved: set[str] = set()

    for address in addresses:
        try:
            resolved.add(
                str(address[4][0])
            )
        except (IndexError, TypeError):
            continue

    if not resolved:
        raise ValueError(
            "Target hostname resolved to no addresses"
        )

    return resolved


def validate_external_target_url(
    url: str,
) -> None:

    parsed = urlparse(url)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Only HTTP/HTTPS URLs are allowed"
        )

    hostname = parsed.hostname

    if not hostname:
        raise ValueError(
            "Target hostname is missing"
        )

    hostname_lower = hostname.lower()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "host.docker.internal",
    }

    if hostname_lower in blocked_names:
        raise ValueError(
            "Blocked target hostname"
        )

    port = parsed.port or (
        443
        if parsed.scheme.lower() == "https"
        else 80
    )

    addresses = resolve_host_addresses(
        hostname,
        port,
    )

    for address in addresses:

        try:
            ip = ipaddress.ip_address(
                address
            )
        except ValueError as exc:
            raise ValueError(
                "Invalid resolved target address"
            ) from exc

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(
                "Target resolves to a restricted address"
            )


def validate_internal_service_url(
    url: str,
) -> None:

    parsed = urlparse(url)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Invalid internal service URL scheme"
        )

    if not parsed.hostname:
        raise ValueError(
            "Internal service hostname is missing"
        )

    validate_relative_path(
        parsed.path or "/"
    )


# ============================================================
# INTERNAL AUTH
# ============================================================

def verify_internal_request(
    authorization: Optional[str],
    timestamp: Optional[str],
    signature: Optional[str],
    internal_secret: Optional[str],
    body: bytes,
) -> None:

    if not (
        INTERNAL_GATEWAY_SECRET
        or RUNTIME_API_SECRET
    ):
        if REQUIRE_INTERNAL_AUTH:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Internal authentication "
                    "is required but no secret "
                    "is configured"
                ),
            )

        return

    if (
        INTERNAL_GATEWAY_SECRET
        and internal_secret
        and constant_time_equal(
            internal_secret,
            INTERNAL_GATEWAY_SECRET,
        )
    ):
        return

    if (
        authorization
        and INTERNAL_GATEWAY_SECRET
        and constant_time_equal(
            authorization,
            f"Bearer {INTERNAL_GATEWAY_SECRET}",
        )
    ):
        return

    if (
        authorization
        and RUNTIME_API_SECRET
        and constant_time_equal(
            authorization,
            f"Bearer {RUNTIME_API_SECRET}",
        )
    ):
        return

    if verify_signature(
        timestamp,
        signature,
        body,
        RUNTIME_API_SECRET,
    ):
        return

    if verify_signature(
        timestamp,
        signature,
        body,
        INTERNAL_GATEWAY_SECRET,
    ):
        return

    raise HTTPException(
        status_code=401,
        detail="Invalid internal authentication",
    )


async def authenticate_request(
    request: Request,
) -> str:

    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body too large",
        )

    verify_internal_request(
        authorization=request.headers.get(
            "authorization"
        ),
        timestamp=request.headers.get(
            "x-arya-timestamp"
        ),
        signature=request.headers.get(
            "x-arya-signature"
        ),
        internal_secret=request.headers.get(
            "x-arya-internal-secret"
        ),
        body=body,
    )

    return request.headers.get(
        "x-arya-request-id",
        new_request_id(),
    )


# ============================================================
# OWNER INTEGRATION CLIENT
# ============================================================

class OwnerIntegrationClient:
    """
    Reads active runtime configuration from
    owner_integration.py.

    This gateway does not maintain an independent
    service/provider registry.
    """

    def __init__(
        self,
        base_url: str,
    ):
        self.base_url = base_url.rstrip("/")

    async def _get(
        self,
        path: str,
    ) -> Dict[str, Any]:

        validate_internal_service_url(
            self.base_url
        )

        url = (
            self.base_url
            + "/"
            + path.lstrip("/")
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": (
                "ARYA-OwnerRuntimeGateway/"
                + SERVICE_VERSION
            ),
        }

        if INTERNAL_GATEWAY_SECRET:
            headers[
                "X-ARYA-Internal-Secret"
            ] = INTERNAL_GATEWAY_SECRET

        try:
            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=False,
            ) as client:

                response = await client.get(
                    url,
                    headers=headers,
                )

        except httpx.TimeoutException as exc:
            raise HTTPException(
                status_code=504,
                detail=(
                    "OWNER Integration timeout"
                ),
            ) from exc

        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail=(
                    "OWNER Integration unavailable"
                ),
            ) from exc

        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=(
                    "OWNER Integration returned "
                    f"HTTP {response.status_code}"
                ),
            )

        if len(response.content) > MAX_RESPONSE_BYTES:
            raise HTTPException(
                status_code=502,
                detail=(
                    "OWNER Integration response "
                    "exceeds configured limit"
                ),
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=502,
                detail=(
                    "OWNER Integration returned "
                    "invalid JSON"
                ),
            ) from exc

        if not isinstance(data, dict):
            raise HTTPException(
                status_code=502,
                detail=(
                    "OWNER Integration returned "
                    "invalid service configuration"
                ),
            )

        return data

    async def get_service(
        self,
        service_id: str,
    ) -> Dict[str, Any]:

        return await self._get(
            f"/internal/service/{service_id}"
        )

    async def get_provider(
        self,
        provider_id: str,
    ) -> Dict[str, Any]:

        return await self._get(
            f"/internal/provider/{provider_id}"
        )

    async def get_services(
        self,
    ) -> Dict[str, Any]:

        return await self._get(
            "/runtime/services"
        )

    async def get_providers(
        self,
    ) -> Dict[str, Any]:

        return await self._get(
            "/runtime/providers"
        )


owner_client = OwnerIntegrationClient(
    OWNER_INTEGRATION_URL
)


# ============================================================
# SERVICE CONFIGURATION
# ============================================================

def service_base_url(
    service: Dict[str, Any],
) -> str:

    enabled = service.get(
        "enabled",
        True,
    )

    active = service.get(
        "active",
        True,
    )

    if enabled is False or active is False:
        raise HTTPException(
            status_code=503,
            detail="Requested service is disabled",
        )

    base_url = service.get(
        "base_url"
    )

    if not base_url:
        raise HTTPException(
            status_code=502,
            detail="Service has no configured base_url",
        )

    return str(
        base_url
    ).rstrip("/")


def provider_base_url(
    provider: Dict[str, Any],
) -> str:

    enabled = provider.get(
        "enabled",
        True,
    )

    active = provider.get(
        "active",
        True,
    )

    if enabled is False or active is False:
        raise HTTPException(
            status_code=503,
            detail="Requested provider is disabled",
        )

    base_url = provider.get(
        "base_url"
    )

    if not base_url:
        raise HTTPException(
            status_code=502,
            detail="Provider has no configured base_url",
        )

    return str(
        base_url
    ).rstrip("/")


# ============================================================
# HTTP CALLER
# ============================================================

async def perform_http_call(
    url: str,
    method: str,
    payload: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout_seconds: float = DEFAULT_TIMEOUT,
    retries: int = MAX_RETRIES,
    internal: bool = False,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:

    method = method.upper()

    allowed_methods = {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }

    if method not in allowed_methods:
        raise HTTPException(
            status_code=400,
            detail="Unsupported HTTP method",
        )

    try:
        if internal:
            validate_internal_service_url(
                url
            )
        else:
            validate_external_target_url(
                url
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    request_headers: Dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": (
            "ARYA-AgriDoctor-"
            "OwnerRuntimeGateway/"
            f"{SERVICE_VERSION}"
        ),
        "X-ARYA-Request-ID": (
            request_id or new_request_id()
        ),
    }

    if INTERNAL_GATEWAY_SECRET:
        request_headers[
            "X-ARYA-Internal"
        ] = "true"

        request_headers[
            "X-ARYA-Internal-Secret"
        ] = INTERNAL_GATEWAY_SECRET

    if headers:
        for key, value in headers.items():

            key_lower = key.lower()

            if key_lower in {
                "host",
                "content-length",
                "transfer-encoding",
                "connection",
            }:
                continue

            request_headers[key] = value

    last_error: Optional[str] = None

    attempts = max(
        1,
        min(
            retries + 1,
            5,
        ),
    )

    retryable_statuses = {
        408,
        425,
        429,
        500,
        502,
        503,
        504,
    }

    for attempt in range(attempts):

        try:

            timeout = httpx.Timeout(
                timeout_seconds,
                connect=min(
                    15.0,
                    timeout_seconds,
                ),
            )

            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
            ) as client:

                response = await client.request(
                    method=method,
                    url=url,
                    json=(
                        payload
                        if method
                        in {
                            "POST",
                            "PUT",
                            "PATCH",
                            "DELETE",
                        }
                        else None
                    ),
                    params=query,
                    headers=request_headers,
                )

            if (
                response.status_code in
                retryable_statuses
                and attempt + 1 < attempts
                and method in {"GET", "HEAD"}
            ):
                await asyncio.sleep(
                    min(
                        2 ** attempt,
                        5,
                    )
                )
                continue

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
                                "External response "
                                "exceeds configured "
                                "size limit"
                            ),
                        )
                except ValueError:
                    pass

            content = response.content

            if len(content) > MAX_RESPONSE_BYTES:
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "External response exceeds "
                        "configured size limit"
                    ),
                )

            content_type = response.headers.get(
                "content-type",
                "",
            ).lower()

            if (
                "application/json" in content_type
                or "application/problem+json"
                in content_type
            ):
                try:
                    data: Any = response.json()
                except ValueError:
                    data = {
                        "raw": content.decode(
                            "utf-8",
                            errors="replace",
                        )
                    }
            else:
                data = {
                    "raw": content.decode(
                        "utf-8",
                        errors="replace",
                    )
                }

            return {
                "success": response.is_success,
                "status_code": response.status_code,
                "data": data,
                "attempt": attempt + 1,
                "request_id": request_headers[
                    "X-ARYA-Request-ID"
                ],
            }

        except HTTPException:
            raise

        except (
            httpx.TimeoutException,
            httpx.RequestError,
        ) as exc:

            last_error = str(exc)

            logger.warning(
                "Runtime call failed "
                "(attempt %s/%s): %s",
                attempt + 1,
                attempts,
                exc,
            )

            if attempt + 1 < attempts:
                await asyncio.sleep(
                    min(
                        2 ** attempt,
                        5,
                    )
                )

        except Exception as exc:

            last_error = str(exc)

            logger.exception(
                "Unexpected runtime call failure"
            )

            if attempt + 1 < attempts:
                await asyncio.sleep(
                    min(
                        2 ** attempt,
                        5,
                    )
                )

    raise HTTPException(
        status_code=502,
        detail=(
            "Runtime service call failed: "
            f"{last_error or 'unknown error'}"
        ),
    )


# ============================================================
# GENERIC SERVICE CALL
# ============================================================

async def call_service(
    service_id: str,
    path: str,
    method: str = "POST",
    payload: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:

    validate_relative_path(path)

    service = await owner_client.get_service(
        service_id
    )

    base_url = service_base_url(
        service
    )

    target_url = (
        base_url
        + "/"
        + path.lstrip("/")
    )

    return await perform_http_call(
        url=target_url,
        method=method,
        payload=payload,
        query=query,
        headers=headers,
        timeout_seconds=float(
            service.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            service.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=True,
        request_id=request_id,
    )


# ============================================================
# GENERIC PROVIDER CALL
# ============================================================

async def call_provider(
    provider_id: str,
    path: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:

    validate_relative_path(path)

    provider = await owner_client.get_provider(
        provider_id
    )

    base_url = provider_base_url(
        provider
    )

    target_url = (
        base_url
        + "/"
        + path.lstrip("/")
    )

    return await perform_http_call(
        url=target_url,
        method=method,
        payload=payload,
        query=query,
        headers=headers,
        timeout_seconds=float(
            provider.get(
                "timeout_seconds",
                DEFAULT_TIMEOUT,
            )
        ),
        retries=int(
            provider.get(
                "retry_count",
                MAX_RETRIES,
            )
        ),
        internal=False,
        request_id=request_id,
    )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root() -> Dict[str, Any]:

    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "running",
        "role": "owner_runtime_gateway",
        "port": PORT,
        "owner_integration": OWNER_INTEGRATION_URL,
        "main_py_untouched": True,
        "timestamp": now_ts(),
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health() -> Dict[str, Any]:

    try:

        services = await owner_client.get_services()
        providers = await owner_client.get_providers()

        return {
            "status": "healthy",
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "owner_integration": "connected",
            "active_services": services.get(
                "count",
                len(
                    services.get(
                        "services",
                        []
                    )
                    if isinstance(
                        services.get(
                            "services",
                            []
                        ),
                        list,
                    )
                    else []
                ),
            ),
            "active_providers": providers.get(
                "count",
                len(
                    providers.get(
                        "providers",
                        []
                    )
                    if isinstance(
                        providers.get(
                            "providers",
                            []
                        ),
                        list,
                    )
                    else []
                ),
            ),
            "timestamp": now_ts(),
        }

    except Exception as exc:

        logger.exception(
            "Gateway health check failed"
        )

        return {
            "status": "degraded",
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "owner_integration": "unavailable",
            "error": str(exc),
            "timestamp": now_ts(),
        }


# ============================================================
# SERVICE DISCOVERY
# ============================================================

@app.get("/runtime/services")
async def runtime_services(
    request: Request,
) -> Dict[str, Any]:

    await authenticate_request(
        request
    )

    return await owner_client.get_services()


@app.get("/runtime/providers")
async def runtime_providers(
    request: Request,
) -> Dict[str, Any]:

    await authenticate_request(
        request
    )

    return await owner_client.get_providers()


# ============================================================
# SERVICE CALL
# ============================================================

@app.post("/runtime/call")
async def runtime_call(
    request: Request,
    call: RuntimeCallRequest,
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    return {
        "gateway": SERVICE_NAME,
        "service_id": call.service_id,
        "result": await call_service(
            service_id=call.service_id,
            path=call.path,
            method=call.method,
            payload=call.payload,
            query=call.query,
            headers=call.headers,
            request_id=request_id,
        ),
        "request_id": request_id,
    }


# ============================================================
# PROVIDER CALL
# ============================================================

@app.post("/runtime/provider-call")
async def provider_call(
    request: Request,
    call: ProviderCallRequest,
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    return {
        "gateway": SERVICE_NAME,
        "provider_id": call.provider_id,
        "result": await call_provider(
            provider_id=call.provider_id,
            path=call.path,
            method=call.method,
            payload=call.payload,
            query=call.query,
            headers=call.headers,
            request_id=request_id,
        ),
        "request_id": request_id,
    }


# ============================================================
# ARYA ANALYZE
# ============================================================

@app.post("/arya/analyze")
async def arya_analyze(
    request: Request,
    payload: Dict[str, Any],
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    return await call_service(
        "agri_engine",
        "/agri/analyze",
        "POST",
        payload,
        request_id=request_id,
    )


# ============================================================
# ARYA DIAGNOSE
# ============================================================

@app.post("/arya/diagnose")
async def arya_diagnose(
    request: Request,
    payload: Dict[str, Any],
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    return await call_service(
        "agri_engine",
        "/agri/diagnose",
        "POST",
        payload,
        request_id=request_id,
    )


# ============================================================
# ARYA RECOMMEND
# ============================================================

@app.post("/arya/recommend")
async def arya_recommend(
    request: Request,
    payload: Dict[str, Any],
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    return await call_service(
        "agri_engine",
        "/agri/recommend",
        "POST",
        payload,
        request_id=request_id,
    )


# ============================================================
# ARYA VISION
# ============================================================

@app.post("/arya/vision")
async def arya_vision(
    request: Request,
    payload: Dict[str, Any],
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    return await call_service(
        "vision",
        "/vision/analyze",
        "POST",
        payload,
        request_id=request_id,
    )


# ============================================================
# ARYA VOICE
# ============================================================

@app.api_route(
    "/arya/voice",
    methods=[
        "POST",
        "GET",
    ],
)
async def arya_voice(
    request: Request,
) -> Any:

    request_id = await authenticate_request(
        request
    )

    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Voice request too large",
        )

    headers: Dict[str, str] = {}

    content_type = request.headers.get(
        "content-type"
    )

    if content_type:
        headers["Content-Type"] = content_type

    authorization = request.headers.get(
        "authorization"
    )

    if authorization:
        headers["Authorization"] = authorization

    service = await owner_client.get_service(
        "voice_language"
    )

    base_url = service_base_url(
        service
    )

    candidate_paths = [
        "/voice/process",
        "/voice/transcribe",
    ]

    last_result: Optional[Dict[str, Any]] = None

    for path in candidate_paths:

        result = await perform_http_call(
            url=base_url + path,
            method=request.method,
            payload=None,
            headers=headers,
            timeout_seconds=float(
                service.get(
                    "timeout_seconds",
                    DEFAULT_TIMEOUT,
                )
            ),
            retries=int(
                service.get(
                    "retry_count",
                    MAX_RETRIES,
                )
            ),
            internal=True,
            request_id=request_id,
        )

        last_result = result

        if result.get(
            "status_code"
        ) not in {
            404,
            405,
        }:
            return result

    return last_result or {
        "success": False,
        "status_code": 404,
        "data": {
            "detail": (
                "No compatible voice endpoint "
                "was found"
            )
        },
        "request_id": request_id,
    }


# ============================================================
# ARYA PAYMENT
# ============================================================

@app.post("/arya/payment")
async def arya_payment(
    request: Request,
    payload: Dict[str, Any],
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    service = await owner_client.get_service(
        "commerce_security"
    )

    base_url = service_base_url(
        service
    )

    candidate_paths = [
        "/commerce/payments/create",
        "/commerce/payment",
    ]

    for path in candidate_paths:

        result = await perform_http_call(
            url=base_url + path,
            method="POST",
            payload=payload,
            timeout_seconds=float(
                service.get(
                    "timeout_seconds",
                    DEFAULT_TIMEOUT,
                )
            ),
            retries=int(
                service.get(
                    "retry_count",
                    MAX_RETRIES,
                )
            ),
            internal=True,
            request_id=request_id,
        )

        if result.get(
            "status_code"
        ) not in {
            404,
            405,
        }:
            return result

    return result


# ============================================================
# ARYA UPDATES
# ============================================================

@app.get("/arya/updates")
async def arya_updates(
    request: Request,
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    service_url = os.getenv(
        "ARYA_DATA_UPDATE_URL",
        "http://127.0.0.1:8011",
    ).rstrip("/")

    return await perform_http_call(
        url=service_url + "/updates/status",
        method="GET",
        timeout_seconds=DEFAULT_TIMEOUT,
        retries=MAX_RETRIES,
        internal=True,
        request_id=request_id,
    )


@app.post("/arya/updates/run")
async def arya_updates_run(
    request: Request,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    service_url = os.getenv(
        "ARYA_DATA_UPDATE_URL",
        "http://127.0.0.1:8011",
    ).rstrip("/")

    return await perform_http_call(
        url=service_url + "/updates/run",
        method="POST",
        payload=payload or {},
        timeout_seconds=DEFAULT_TIMEOUT,
        retries=MAX_RETRIES,
        internal=True,
        request_id=request_id,
    )


# ============================================================
# ARYA WEATHER
# ============================================================

@app.get("/arya/weather")
async def arya_weather(
    request: Request,
    latitude: float,
    longitude: float,
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    return await call_provider(
        "open_meteo_weather",
        "/v1/forecast",
        "GET",
        query={
            "latitude": latitude,
            "longitude": longitude,
            "current": (
                "temperature_2m,"
                "relative_humidity_2m,"
                "precipitation,"
                "weather_code,"
                "wind_speed_10m"
            ),
            "daily": (
                "temperature_2m_max,"
                "temperature_2m_min,"
                "precipitation_sum,"
                "weather_code"
            ),
            "timezone": "auto",
        },
        request_id=request_id,
    )


# ============================================================
# ARYA GEOCODE
# ============================================================

@app.get("/arya/geocode")
async def arya_geocode(
    request: Request,
    name: str,
) -> Dict[str, Any]:

    request_id = await authenticate_request(
        request
    )

    return await call_provider(
        "open_meteo_geocoding",
        "/v1/search",
        "GET",
        query={
            "name": name,
            "count": 10,
            "language": "en",
            "format": "json",
        },
        request_id=request_id,
    )


# ============================================================
# SYSTEM MAP
# ============================================================

@app.get("/arya/system-map")
async def system_map(
    request: Request,
) -> Dict[str, Any]:

    await authenticate_request(
        request
    )

    services = await owner_client.get_services()
    providers = await owner_client.get_providers()

    return {
        "gateway": {
            "name": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "port": PORT,
        },
        "owner_integration": OWNER_INTEGRATION_URL,
        "services": services,
        "providers": providers,
        "connections": {
            "owner": True,
            "agri_engine": True,
            "vision": True,
            "voice_language": True,
            "commerce_security": True,
            "data_update": True,
            "external_providers": True,
        },
        "timestamp": now_ts(),
    }


# ============================================================
# GENERIC COMPATIBILITY ROUTE
# ============================================================

@app.api_route(
    "/runtime/{runtime_path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
async def runtime_compatibility(
    runtime_path: str,
    request: Request,
) -> Any:

    request_id = await authenticate_request(
        request
    )

    if not validate_relative_path(
        runtime_path
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid runtime path",
        )

    body = await request.body()

    payload: Optional[Dict[str, Any]] = None

    if body:
        try:
            import json

            decoded = json.loads(
                body.decode("utf-8")
            )

            if isinstance(
                decoded,
                dict,
            ):
                payload = decoded

        except (
            UnicodeDecodeError,
            ValueError,
        ):
            payload = None

    return await call_service(
        "orchestrator",
        "/" + runtime_path.lstrip("/"),
        request.method,
        payload=payload,
        request_id=request_id,
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
        "OWNER Integration URL: %s",
        OWNER_INTEGRATION_URL,
    )

    logger.info(
        "Runtime Gateway port: %s",
        PORT,
    )

    if INTERNAL_GATEWAY_SECRET:
        logger.info(
            "Internal gateway authentication configured"
        )
    else:
        logger.warning(
            "Internal gateway secret is not configured"
        )


# ============================================================
# ERROR HANDLER
# ============================================================

@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request,
    exc: Exception,
):
    logger.exception(
        "Unhandled runtime gateway error"
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "service": SERVICE_NAME,
            "request_id": request.headers.get(
                "x-arya-request-id",
                new_request_id(),
            ),
        },
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level=LOG_LEVEL.lower(),
    )
