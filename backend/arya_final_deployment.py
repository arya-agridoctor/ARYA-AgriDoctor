"""
ARYA AgriDoctor
Final Deployment & Production Configuration
Version: 1.1.0

Independent production configuration and readiness layer.

IMPORTANT:
- Does not modify backend/main.py.
- Does not modify existing service modules.
- Does not claim that configuration alone activates services.
- Secrets are never included in configuration responses.
- Administrative endpoints require authentication by default.
- Real production readiness requires deployment-specific verification.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import math
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("arya.final_deployment")


# ============================================================
# APP
# ============================================================

APP_NAME = "ARYA Final Deployment"
APP_VERSION = "1.1.0"

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Independent production configuration layer "
        "for ARYA AgriDoctor."
    ),
)


# ============================================================
# HELPERS
# ============================================================

def env(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None else value.strip()


def env_bool(name: str, default: bool = False) -> bool:
    value = env(name, "")

    if not value:
        return default

    normalized = value.lower()

    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True

    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False

    logger.warning(
        "Invalid boolean environment variable: %s; using default.",
        name,
    )
    return default


def env_int(
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = env(name, str(default))

    try:
        value = int(raw)
    except (ValueError, TypeError):
        logger.warning(
            "Invalid integer environment variable: %s; using default.",
            name,
        )
        return default

    if not minimum <= value <= maximum:
        logger.warning(
            "Out-of-range environment variable: %s; using default.",
            name,
        )
        return default

    return value


def env_float(
    name: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    raw = env(name, str(default))

    try:
        value = float(raw)
    except (ValueError, TypeError):
        logger.warning(
            "Invalid numeric environment variable: %s; using default.",
            name,
        )
        return default

    if not math.isfinite(value) or not minimum <= value <= maximum:
        logger.warning(
            "Out-of-range environment variable: %s; using default.",
            name,
        )
        return default

    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_secret_status(value: str) -> str:
    return "configured" if bool(value) else "missing"


def valid_http_url(
    value: str,
    *,
    allow_example_domain: bool = False,
) -> bool:
    if not value:
        return False

    try:
        parsed = urlsplit(value)

        if parsed.scheme not in {"http", "https"}:
            return False

        if not parsed.hostname:
            return False

        if parsed.username is not None or parsed.password is not None:
            return False

        if parsed.query or parsed.fragment:
            return False

        hostname = parsed.hostname.lower()

        if not allow_example_domain and (
            hostname == "example.com"
            or hostname.endswith(".example.com")
        ):
            return False

        if any(ord(char) < 32 for char in value):
            return False

        return True

    except (ValueError, TypeError):
        return False


def url_is_https(value: str) -> bool:
    try:
        return urlsplit(value).scheme.lower() == "https"
    except (ValueError, TypeError):
        return False


def url_is_loopback(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname

        if not hostname:
            return False

        if hostname.lower() == "localhost":
            return True

        try:
            return ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            return False

    except (ValueError, TypeError):
        return False


def local_host_available(host: str, port: int) -> bool:
    try:
        with socket.create_connection(
            (host, port),
            timeout=1.5,
        ):
            return True
    except (OSError, ValueError):
        return False


# ============================================================
# ENVIRONMENT
# ============================================================

ENVIRONMENT = env(
    "ARYA_ENVIRONMENT",
    "production",
).lower()

HOST = env(
    "ARYA_DEPLOYMENT_HOST",
    "0.0.0.0",
)

PORT = env_int(
    "ARYA_DEPLOYMENT_PORT",
    8030,
    1,
    65535,
)

PUBLIC_API_URL = env(
    "ARYA_PUBLIC_API_URL",
    "https://api.example.com",
).rstrip("/")

ANDROID_API_URL = env(
    "ARYA_ANDROID_API_URL",
    PUBLIC_API_URL,
).rstrip("/")

WINDOWS_API_URL = env(
    "ARYA_WINDOWS_API_URL",
    PUBLIC_API_URL,
).rstrip("/")

HTTPS_ENABLED = env_bool(
    "ARYA_HTTPS_ENABLED",
    True,
)


# ============================================================
# ACCESS CONTROL
# ============================================================

DEPLOYMENT_API_KEY = env(
    "ARYA_DEPLOYMENT_API_KEY",
)

ALLOW_UNAUTHENTICATED_ADMIN = env_bool(
    "ARYA_DEPLOYMENT_ALLOW_UNAUTHENTICATED_ADMIN",
    False,
)


def authenticate_admin(request: Request) -> None:
    """
    Protect operational and configuration endpoints.

    Clients must send:
        X-ARYA-Deployment-Key: <ARYA_DEPLOYMENT_API_KEY>

    If no key is configured, access is denied by default.
    Explicit unauthenticated mode should only be used behind a
    separately verified authentication layer.
    """
    if not DEPLOYMENT_API_KEY:
        if ALLOW_UNAUTHENTICATED_ADMIN:
            return

        raise HTTPException(
            status_code=503,
            detail="Deployment administration is not configured.",
        )

    supplied = request.headers.get(
        "X-ARYA-Deployment-Key",
        "",
    )

    if not supplied or not hmac.compare_digest(
        supplied,
        DEPLOYMENT_API_KEY,
    ):
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


# ============================================================
# SECURITY CONFIGURATION
# ============================================================

INTERNAL_GATEWAY_SECRET = env(
    "ARYA_INTERNAL_GATEWAY_SECRET",
)

MASTER_EMAIL = env(
    "ARYA_MASTER_EMAIL",
)

MASTER_SECRET = env(
    "ARYA_MASTER_SECRET",
)

OWNER_PASSWORD_HASH = env(
    "ARYA_OWNER_PASSWORD_HASH",
)

OWNER_TOTP_SECRET = env(
    "ARYA_OWNER_TOTP_SECRET",
)

JWT_SECRET = env(
    "ARYA_JWT_SECRET",
)

WEBHOOK_SECRET = env(
    "ARYA_WEBHOOK_SECRET",
)

SESSION_SECRET = env(
    "ARYA_SESSION_SECRET",
)

SECURITY_REQUIRE_HTTPS = env_bool(
    "ARYA_SECURITY_REQUIRE_HTTPS",
    True,
)

SECURITY_REQUIRE_MFA = env_bool(
    "ARYA_SECURITY_REQUIRE_MFA",
    True,
)

SECURITY_AUDIT_LOG = env_bool(
    "ARYA_SECURITY_AUDIT_LOG",
    True,
)

SECURITY_RATE_LIMIT = env_int(
    "ARYA_SECURITY_RATE_LIMIT",
    120,
    1,
    100000,
)


# ============================================================
# SERVICE URLS
# ============================================================

SERVICES: Dict[str, str] = {
    "main": env(
        "ARYA_MAIN_URL",
        "http://127.0.0.1:8000",
    ).rstrip("/"),

    "vision": env(
        "ARYA_VISION_URL",
        "http://127.0.0.1:8001",
    ).rstrip("/"),

    "voice_language": env(
        "ARYA_VOICE_LANGUAGE_URL",
        "http://127.0.0.1:8002",
    ).rstrip("/"),

    "agri_engine": env(
        "ARYA_AGRI_ENGINE_URL",
        "http://127.0.0.1:8003",
    ).rstrip("/"),

    "commerce_security": env(
        "ARYA_COMMERCE_SECURITY_URL",
        "http://127.0.0.1:8004",
    ).rstrip("/"),

    "orchestrator": env(
        "ARYA_ORCHESTRATOR_URL",
        "http://127.0.0.1:8010",
    ).rstrip("/"),

    "owner_integration": env(
        "ARYA_OWNER_INTEGRATION_URL",
        "http://127.0.0.1:8015",
    ).rstrip("/"),

    "runtime_gateway": env(
        "ARYA_RUNTIME_GATEWAY_URL",
        "http://127.0.0.1:8016",
    ).rstrip("/"),

    "control_center": env(
        "ARYA_CONTROL_CENTER_URL",
        "http://127.0.0.1:8020",
    ).rstrip("/"),
}

SERVICES["final_deployment"] = (
    f"http://127.0.0.1:{PORT}"
)


# ============================================================
# PROVIDERS
# ============================================================

PROVIDERS: Dict[str, Dict[str, Any]] = {
    "weather": {
        "enabled": env_bool(
            "ARYA_PROVIDER_WEATHER_ENABLED",
            True,
        ),
        "provider": env(
            "ARYA_WEATHER_PROVIDER",
            "open_meteo",
        ),
        "api_key": env(
            "ARYA_WEATHER_API_KEY",
        ),
    },

    "geocoding": {
        "enabled": env_bool(
            "ARYA_PROVIDER_GEOCODING_ENABLED",
            True,
        ),
        "provider": env(
            "ARYA_GEOCODING_PROVIDER",
            "open_meteo",
        ),
        "api_key": env(
            "ARYA_GEOCODING_API_KEY",
        ),
    },

    "satellite": {
        "enabled": env_bool(
            "ARYA_PROVIDER_SATELLITE_ENABLED",
            True,
        ),
        "provider": env(
            "ARYA_SATELLITE_PROVIDER",
            "copernicus",
        ),
        "api_key": env(
            "ARYA_SATELLITE_API_KEY",
        ),
    },

    "agriculture": {
        "enabled": env_bool(
            "ARYA_PROVIDER_AGRICULTURE_ENABLED",
            True,
        ),
        "provider": env(
            "ARYA_AGRICULTURE_PROVIDER",
            "internal",
        ),
        "api_key": env(
            "ARYA_AGRICULTURE_API_KEY",
        ),
    },

    "ai": {
        "enabled": env_bool(
            "ARYA_AI_ENABLED",
            True,
        ),
        "provider": env(
            "ARYA_AI_PROVIDER",
            "openai",
        ),
        "model": env(
            "OPENAI_MODEL",
            "gpt-5",
        ),
        "api_key": env(
            "OPENAI_API_KEY",
        ),
    },
}


# ============================================================
# AUTOMATIC DATA UPDATES
# ============================================================

UPDATE_CONFIG = {
    "enabled": env_bool(
        "ARYA_AUTO_UPDATE_ENABLED",
        True,
    ),

    "interval_minutes": env_int(
        "ARYA_AUTO_UPDATE_INTERVAL",
        360,
        1,
        43200,
    ),

    "max_source_age_hours": env_int(
        "ARYA_MAX_SOURCE_AGE_HOURS",
        72,
        1,
        87600,
    ),

    "require_source_validation": env_bool(
        "ARYA_REQUIRE_SOURCE_VALIDATION",
        True,
    ),

    "require_hash_validation": env_bool(
        "ARYA_REQUIRE_HASH_VALIDATION",
        True,
    ),

    "disable_broken_sources": env_bool(
        "ARYA_DISABLE_BROKEN_SOURCES",
        True,
    ),

    "allow_stale_data": env_bool(
        "ARYA_ALLOW_STALE_DATA",
        False,
    ),
}


# ============================================================
# PAYMENT
# ============================================================

PAYMENT_CONFIG = {
    "enabled": env_bool(
        "ARYA_PAYMENT_ENABLED",
        True,
    ),

    "iran_method": "bank_transfer",

    "international_method": "USDT",

    "device_activation_required": env_bool(
        "ARYA_DEVICE_ACTIVATION_REQUIRED",
        True,
    ),

    "retain_old_destinations": True,

    "owner_can_rotate_destinations": True,

    "prices": {
        "IR_100": {
            "amount": 500000,
            "currency": "IRR",
            "max_users": 100,
        },

        "IR_500": {
            "amount": 800000,
            "currency": "IRR",
            "max_users": 500,
        },

        "IR_STANDARD": {
            "amount": 1200000,
            "currency": "IRR",
        },

        "INT_100": {
            "amount": 10,
            "currency": "USDT",
            "max_users": 100,
        },

        "INT_500": {
            "amount": 15,
            "currency": "USDT",
            "max_users": 500,
        },

        "INT_STANDARD": {
            "amount": 20,
            "currency": "USDT",
        },
    },
}


# ============================================================
# DEVICE
# ============================================================

DEVICE_CONFIG = {
    "activation_required": PAYMENT_CONFIG[
        "device_activation_required"
    ],

    "max_devices_per_user": env_int(
        "ARYA_DEVICE_LIMIT",
        3,
        1,
        100,
    ),

    "require_reactivation_after_payment": env_bool(
        "ARYA_REQUIRE_REACTIVATION_AFTER_PAYMENT",
        True,
    ),

    "retain_device_history": True,
}


# ============================================================
# OWNER
# ============================================================

OWNER_CONFIG = {
    "enabled": True,

    "email_configured": bool(MASTER_EMAIL),

    "master_secret": safe_secret_status(
        MASTER_SECRET,
    ),

    "password_hash": safe_secret_status(
        OWNER_PASSWORD_HASH,
    ),

    "totp": safe_secret_status(
        OWNER_TOTP_SECRET,
    ),

    "mfa_required": SECURITY_REQUIRE_MFA,

    "remote_management": env_bool(
        "ARYA_OWNER_REMOTE_MANAGEMENT",
        True,
    ),

    "audit_enabled": SECURITY_AUDIT_LOG,

    "emergency_controls": True,

    "kill_switch": True,

    "provider_management": True,

    "payment_destination_management": True,

    "configuration_snapshots": True,
}


# ============================================================
# DATABASE
# ============================================================

DATABASE_CONFIG = {
    "main": env(
        "ARYA_DATABASE",
        "arya.db",
    ),

    "vision": env(
        "ARYA_VISION_DATABASE",
        "vision.db",
    ),

    "agri_engine": env(
        "ARYA_AGRI_DATABASE",
        "agri_engine.db",
    ),

    "commerce": env(
        "ARYA_COMMERCE_DATABASE",
        "commerce_security.db",
    ),

    "updates": env(
        "ARYA_UPDATE_DATABASE",
        "data_update.db",
    ),

    "owner": env(
        "ARYA_OWNER_DATABASE",
        "owner_manager.db",
    ),
}


# ============================================================
# STORAGE
# ============================================================

STORAGE_CONFIG = {
    "base_path": env(
        "ARYA_STORAGE_PATH",
        "./storage",
    ),

    "upload_path": env(
        "ARYA_UPLOAD_PATH",
        "./storage/uploads",
    ),

    "backup_path": env(
        "ARYA_BACKUP_PATH",
        "./storage/backups",
    ),

    "max_upload_mb": env_int(
        "ARYA_MAX_UPLOAD_MB",
        25,
        1,
        2048,
    ),

    "retain_backups": env_int(
        "ARYA_BACKUP_RETENTION",
        10,
        1,
        10000,
    ),
}


# ============================================================
# AI
# ============================================================

AI_CONFIG = {
    "enabled": env_bool(
        "ARYA_AI_ENABLED",
        True,
    ),

    "model": env(
        "OPENAI_MODEL",
        "gpt-5",
    ),

    "daily_limit": env_int(
        "ARYA_DAILY_AI_LIMIT",
        30,
        1,
        1000000,
    ),

    "timeout": env_int(
        "ARYA_AI_TIMEOUT",
        90,
        1,
        1800,
    ),

    "temperature": env_float(
        "ARYA_AI_TEMPERATURE",
        0.2,
        0.0,
        2.0,
    ),

    "require_source_backing": env_bool(
        "ARYA_AI_REQUIRE_SOURCES",
        True,
    ),

    "allow_unverified_diagnosis": env_bool(
        "ARYA_ALLOW_UNVERIFIED_DIAGNOSIS",
        False,
    ),
}


# ============================================================
# CLIENT CONFIGURATION
# ============================================================

CLIENT_CONFIG = {
    "android": {
        "api_url": ANDROID_API_URL,
        "enabled": True,
        "voice": True,
        "image": True,
        "location": True,
        "offline_cache": True,
    },

    "windows": {
        "api_url": WINDOWS_API_URL,
        "enabled": True,
        "voice": True,
        "image": True,
        "location": True,
        "offline_cache": True,
    },
}


# ============================================================
# SECURITY READINESS
# ============================================================

def security_readiness() -> Dict[str, Any]:
    public_urls_valid = (
        valid_http_url(PUBLIC_API_URL)
        and valid_http_url(ANDROID_API_URL)
        and valid_http_url(WINDOWS_API_URL)
    )

    external_urls_use_https = all(
        (
            url_is_loopback(url)
            or url_is_https(url)
        )
        for url in (
            PUBLIC_API_URL,
            ANDROID_API_URL,
            WINDOWS_API_URL,
        )
        if valid_http_url(url)
    )

    checks = {
        "deployment_api_key": bool(DEPLOYMENT_API_KEY),

        "public_urls_valid": public_urls_valid,

        "https_enabled": (
            HTTPS_ENABLED
            or not SECURITY_REQUIRE_HTTPS
        ),

        "external_urls_use_https": (
            external_urls_use_https
            or not SECURITY_REQUIRE_HTTPS
        ),

        "internal_secret": bool(INTERNAL_GATEWAY_SECRET),

        "master_email": bool(MASTER_EMAIL),

        "master_secret": bool(MASTER_SECRET),

        "owner_password_hash": bool(OWNER_PASSWORD_HASH),

        "owner_totp": (
            bool(OWNER_TOTP_SECRET)
            or not SECURITY_REQUIRE_MFA
        ),

        "jwt_secret": bool(JWT_SECRET),

        "webhook_secret": bool(WEBHOOK_SECRET),

        "session_secret": bool(SESSION_SECRET),

        "audit_log_enabled": SECURITY_AUDIT_LOG,
    }

    return {
        "ready": all(checks.values()),
        "checks": checks,
    }


# ============================================================
# PROVIDER READINESS
# ============================================================

def provider_readiness() -> Dict[str, Any]:
    results: Dict[str, Any] = {}

    for name, data in PROVIDERS.items():
        enabled = bool(data["enabled"])
        provider_name = str(data.get("provider", "")).strip()
        key_required = name in {
            "satellite",
            "agriculture",
            "ai",
        }

        key_configured = bool(data.get("api_key"))

        if not enabled:
            status = "disabled"
        elif not provider_name:
            status = "invalid_configuration"
        elif key_required and not key_configured:
            status = "missing_credentials"
        else:
            status = "configured_not_connectivity_verified"

        results[name] = {
            "enabled": enabled,
            "provider": provider_name,
            "api_key_configured": key_configured,
            "status": status,
        }

    return results


# ============================================================
# DEPLOYMENT READINESS
# ============================================================

def deployment_readiness() -> Dict[str, Any]:
    security = security_readiness()

    service_url_checks = {
        name: valid_http_url(url)
        for name, url in SERVICES.items()
    }

    service_urls_valid = all(
        service_url_checks.values()
    )

    clients_configured = all(
        valid_http_url(url)
        for url in (
            ANDROID_API_URL,
            WINDOWS_API_URL,
        )
    )

    provider_status = provider_readiness()

    enabled_providers_configured = all(
        item["status"] in {
            "disabled",
            "configured_not_connectivity_verified",
        }
        for item in provider_status.values()
    )

    owner_ready = (
        bool(MASTER_EMAIL)
        and bool(MASTER_SECRET)
        and bool(OWNER_PASSWORD_HASH)
        and (
            bool(OWNER_TOTP_SECRET)
            or not SECURITY_REQUIRE_MFA
        )
    )

    payment_configuration_ready = (
        PAYMENT_CONFIG["enabled"]
        and all(
            isinstance(item.get("amount"), (int, float))
            and item["amount"] > 0
            and bool(item.get("currency"))
            for item in PAYMENT_CONFIG["prices"].values()
        )
    )

    storage_paths_configured = all(
        bool(STORAGE_CONFIG[key])
        for key in (
            "base_path",
            "upload_path",
            "backup_path",
        )
    )

    https_ready = (
        HTTPS_ENABLED
        and valid_http_url(PUBLIC_API_URL)
        and url_is_https(PUBLIC_API_URL)
    )

    ready_for_production = all(
        [
            security["ready"],
            service_urls_valid,
            clients_configured,
            https_ready,
            owner_ready,
            payment_configuration_ready,
            storage_paths_configured,
            enabled_providers_configured,
        ]
    )

    return {
        "environment": ENVIRONMENT,

        "security_ready": security["ready"],

        "https_ready": https_ready,

        "owner_ready": owner_ready,

        "payment_ready": payment_configuration_ready,

        "automatic_updates_ready": UPDATE_CONFIG["enabled"],

        "service_urls_valid": service_urls_valid,

        "service_url_checks": service_url_checks,

        "clients_configured": clients_configured,

        "storage_paths_configured": storage_paths_configured,

        "provider_configuration_ready": enabled_providers_configured,

        "providers": provider_status,

        "ready_for_testing": (
            service_urls_valid
            and clients_configured
        ),

        # This is configuration readiness only.
        # It does not prove live connectivity or end-to-end correctness.
        "ready_for_production": ready_for_production,

        "production_readiness_scope": (
            "Configuration checks only; live service connectivity, "
            "TLS termination, payment verification, backups, "
            "and end-to-end tests must be verified separately."
        ),
    }


# ============================================================
# MODELS
# ============================================================

class RuntimeCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str = Field(
        min_length=1,
        max_length=100,
    )

    host: Optional[str] = Field(
        default=None,
        max_length=255,
    )

    port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
    )


class DeploymentSetting(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(
        min_length=1,
        max_length=200,
    )

    value: Any


# ============================================================
# REQUEST SIZE / REQUEST ID MIDDLEWARE
# ============================================================

@app.middleware("http")
async def deployment_request_middleware(
    request: Request,
    call_next,
):
    request_id = request.headers.get(
        "X-ARYA-Request-ID",
        "",
    )

    if (
        request_id
        and (
            len(request_id) > 128
            or not re.fullmatch(
                r"[A-Za-z0-9._:-]+",
                request_id,
            )
        )
    ):
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid request ID."},
        )

    request_id = request_id or os.urandom(16).hex()

    content_length = request.headers.get("content-length")

    if content_length:
        try:
            if int(content_length) > 2 * 1024 * 1024:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large."},
                    headers={
                        "X-ARYA-Request-ID": request_id,
                    },
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length."},
                headers={
                    "X-ARYA-Request-ID": request_id,
                },
            )

    request.state.arya_request_id = request_id

    response = await call_next(request)

    response.headers["X-ARYA-Request-ID"] = request_id

    return response


# ============================================================
# PUBLIC ROUTES
# ============================================================

@app.get("/")
def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": ENVIRONMENT,
        "time": utc_now(),
        "message": "ARYA Final Deployment configuration layer",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "time": utc_now(),
    }


# ============================================================
# CONFIGURATION
# ============================================================

@app.get("/config")
def configuration(request: Request):
    authenticate_admin(request)

    return {
        "environment": ENVIRONMENT,

        "network": {
            "host": HOST,
            "port": PORT,
            "public_api": PUBLIC_API_URL,
            "https_enabled": HTTPS_ENABLED,
        },

        "services": SERVICES,

        "clients": CLIENT_CONFIG,

        "providers": {
            key: {
                "enabled": value["enabled"],
                "provider": value["provider"],
                "api_key_configured": bool(
                    value.get("api_key")
                ),
                "model": value.get("model"),
            }
            for key, value in PROVIDERS.items()
        },

        "updates": UPDATE_CONFIG,

        "payment": PAYMENT_CONFIG,

        "devices": DEVICE_CONFIG,

        "owner": OWNER_CONFIG,

        "database": DATABASE_CONFIG,

        "storage": STORAGE_CONFIG,

        "ai": {
            key: value
            for key, value in AI_CONFIG.items()
            if key != "temperature"
        },
    }


# ============================================================
# SECURITY
# ============================================================

@app.get("/security/status")
def security_status(request: Request):
    authenticate_admin(request)
    return security_readiness()


# ============================================================
# DEPLOYMENT STATUS
# ============================================================

@app.get("/deployment/status")
def deployment_status(request: Request):
    authenticate_admin(request)
    return deployment_readiness()


# ============================================================
# RUNTIME MAP
# ============================================================

@app.get("/runtime/map")
def runtime_map(request: Request):
    authenticate_admin(request)

    return {
        "services": SERVICES,

        "flow": [
            "Android / Windows",
            "Public API",
            "ARYA Main",
            "Final Control Center",
            "Orchestrator",
            "Agri Engine / Vision / Voice / Commerce",
            "Runtime Gateway",
            "External Providers",
            "Data Update Manager",
        ],

        "management": [
            "OWNER",
            "MFA",
            "Audit",
            "Provider Management",
            "Payment Management",
            "Emergency Controls",
        ],
    }


# ============================================================
# CLIENTS
# ============================================================

@app.get("/clients")
def clients(request: Request):
    authenticate_admin(request)
    return CLIENT_CONFIG


# ============================================================
# PROVIDERS
# ============================================================

@app.get("/providers")
def providers(request: Request):
    authenticate_admin(request)
    return provider_readiness()


# ============================================================
# PAYMENT
# ============================================================

@app.get("/payment")
def payment(request: Request):
    authenticate_admin(request)
    return PAYMENT_CONFIG


# ============================================================
# UPDATES
# ============================================================

@app.get("/updates")
def updates(request: Request):
    authenticate_admin(request)
    return UPDATE_CONFIG


# ============================================================
# OWNER
# ============================================================

@app.get("/owner")
def owner(request: Request):
    authenticate_admin(request)
    return OWNER_CONFIG


# ============================================================
# DATABASE
# ============================================================

@app.get("/database")
def database(request: Request):
    authenticate_admin(request)
    return DATABASE_CONFIG


# ============================================================
# STORAGE
# ============================================================

@app.get("/storage")
def storage(request: Request):
    authenticate_admin(request)
    return STORAGE_CONFIG


# ============================================================
# AI
# ============================================================

@app.get("/ai")
def ai(request: Request):
    authenticate_admin(request)

    return {
        key: value
        for key, value in AI_CONFIG.items()
        if key != "temperature"
    }


# ============================================================
# ENVIRONMENT
# ============================================================

@app.get("/environment")
def environment(request: Request):
    authenticate_admin(request)

    return {
        "environment": ENVIRONMENT,
        "https": HTTPS_ENABLED,
        "host": HOST,
        "port": PORT,
        "public_api": PUBLIC_API_URL,
    }


# ============================================================
# SERVICE CONNECTIVITY
# ============================================================

@app.get("/check/services")
def check_services(request: Request):
    authenticate_admin(request)

    results: Dict[str, Any] = {}

    for name, url in SERVICES.items():
        if not valid_http_url(url):
            results[name] = {
                "configured": False,
                "checked": False,
                "available": False,
                "reason": "invalid_service_url",
            }
            continue

        if not url_is_loopback(url):
            results[name] = {
                "configured": True,
                "checked": False,
                "available": None,
                "reason": (
                    "Remote service connectivity is not checked "
                    "by this local TCP-only endpoint."
                ),
            }
            continue

        try:
            parsed = urlsplit(url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port

            if port is None:
                port = 443 if parsed.scheme == "https" else 80

            available = local_host_available(host, port)

            results[name] = {
                "configured": True,
                "checked": True,
                "available": available,
                "host": host,
                "port": port,
                "check_type": "tcp_connectivity_only",
            }

        except (ValueError, OSError):
            results[name] = {
                "configured": True,
                "checked": True,
                "available": False,
                "reason": "connection_check_failed",
            }

    return {
        "time": utc_now(),
        "services": results,
        "note": (
            "TCP connectivity does not prove that an application "
            "health endpoint or business function is working."
        ),
    }


# ============================================================
# PRODUCTION CHECKLIST
# ============================================================

@app.get("/production/checklist")
def production_checklist(request: Request):
    authenticate_admin(request)

    readiness = deployment_readiness()

    items = [
        {
            "name": "HTTPS",
            "status": (
                "ready"
                if readiness["https_ready"]
                else "pending"
            ),
        },

        {
            "name": "OWNER",
            "status": (
                "ready"
                if readiness["owner_ready"]
                else "pending"
            ),
        },

        {
            "name": "Security",
            "status": (
                "ready"
                if readiness["security_ready"]
                else "pending"
            ),
        },

        {
            "name": "Payments",
            "status": (
                "configured"
                if readiness["payment_ready"]
                else "pending"
            ),
        },

        {
            "name": "Automatic Updates",
            "status": (
                "enabled"
                if readiness["automatic_updates_ready"]
                else "disabled"
            ),
        },

        {
            "name": "Android",
            "status": (
                "configured"
                if valid_http_url(ANDROID_API_URL)
                else "pending"
            ),
        },

        {
            "name": "Windows",
            "status": (
                "configured"
                if valid_http_url(WINDOWS_API_URL)
                else "pending"
            ),
        },

        {
            "name": "AI",
            "status": (
                "configured"
                if (
                    PROVIDERS["ai"]["enabled"]
                    and bool(PROVIDERS["ai"]["api_key"])
                )
                else "pending"
            ),
        },
    ]

    return {
        "items": items,
        "overall": readiness,
    }


# ============================================================
# DEPLOYMENT SETTING REQUEST
# ============================================================

@app.post("/deployment/setting")
def deployment_setting(
    setting: DeploymentSetting,
    request: Request,
):
    authenticate_admin(request)

    # This endpoint intentionally does not change runtime
    # configuration or mutate secrets.
    #
    # Returning the submitted value could disclose a
