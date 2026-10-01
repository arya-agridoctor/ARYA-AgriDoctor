"""
ARYA AgriDoctor
Final Deployment & Production Configuration
Version: 1.0.0

این فایل یک لایه مستقل نهایی برای تنظیمات Production است.
هیچ فایلی را حذف یا تغییر نمی‌دهد و مخصوصاً backend/main.py دست‌نخورده می‌ماند.

مسئولیت‌ها:
- Production configuration
- Service URLs
- Android / Windows API configuration
- Security configuration
- HTTPS configuration
- OWNER configuration
- Provider configuration
- Automatic update configuration
- Payment configuration
- Device activation configuration
- Deployment readiness
- Runtime service map
- Final configuration export

نکته:
مقادیر حساس از Environment Variable خوانده می‌شوند.
هیچ Secret واقعی نباید داخل GitHub ذخیره شود.
"""

from __future__ import annotations

import os
import secrets
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field


# ============================================================
# APP
# ============================================================

APP_NAME = "ARYA Final Deployment"
APP_VERSION = "1.0.0"

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Final Production Configuration Layer for ARYA AgriDoctor",
)


# ============================================================
# HELPERS
# ============================================================

def env(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip()


def env_bool(name: str, default: bool = False) -> bool:
    value = env(name, "")
    if not value:
        return default

    return value.lower() in {
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    }


def env_int(name: str, default: int) -> int:
    try:
        return int(env(name, str(default)))
    except Exception:
        return default


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_secret_status(value: str) -> str:
    return "configured" if value else "missing"


def local_host_available(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except Exception:
        return False


# ============================================================
# ENVIRONMENT
# ============================================================

ENVIRONMENT = env("ARYA_ENVIRONMENT", "production")

HOST = env("ARYA_DEPLOYMENT_HOST", "0.0.0.0")
PORT = env_int("ARYA_DEPLOYMENT_PORT", 8030)

PUBLIC_API_URL = env(
    "ARYA_PUBLIC_API_URL",
    "https://api.example.com",
)

ANDROID_API_URL = env(
    "ARYA_ANDROID_API_URL",
    PUBLIC_API_URL,
)

WINDOWS_API_URL = env(
    "ARYA_WINDOWS_API_URL",
    PUBLIC_API_URL,
)

HTTPS_ENABLED = env_bool(
    "ARYA_HTTPS_ENABLED",
    True,
)


# ============================================================
# SECURITY
# ============================================================

INTERNAL_GATEWAY_SECRET = env(
    "ARYA_INTERNAL_GATEWAY_SECRET"
)

MASTER_EMAIL = env(
    "ARYA_MASTER_EMAIL"
)

MASTER_SECRET = env(
    "ARYA_MASTER_SECRET"
)

OWNER_PASSWORD_HASH = env(
    "ARYA_OWNER_PASSWORD_HASH"
)

OWNER_TOTP_SECRET = env(
    "ARYA_OWNER_TOTP_SECRET"
)

JWT_SECRET = env(
    "ARYA_JWT_SECRET"
)

WEBHOOK_SECRET = env(
    "ARYA_WEBHOOK_SECRET"
)

SESSION_SECRET = env(
    "ARYA_SESSION_SECRET"
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
)


# ============================================================
# SERVICE URLS
# ============================================================

SERVICES = {
    "main": env(
        "ARYA_MAIN_URL",
        "http://127.0.0.1:8000",
    ),

    "vision": env(
        "ARYA_VISION_URL",
        "http://127.0.0.1:8001",
    ),

    "voice_language": env(
        "ARYA_VOICE_LANGUAGE_URL",
        "http://127.0.0.1:8002",
    ),

    "agri_engine": env(
        "ARYA_AGRI_ENGINE_URL",
        "http://127.0.0.1:8003",
    ),

    "commerce_security": env(
        "ARYA_COMMERCE_SECURITY_URL",
        "http://127.0.0.1:8004",
    ),

    "orchestrator": env(
        "ARYA_ORCHESTRATOR_URL",
        "http://127.0.0.1:8010",
    ),

    "owner_integration": env(
        "ARYA_OWNER_INTEGRATION_URL",
        "http://127.0.0.1:8015",
    ),

    "runtime_gateway": env(
        "ARYA_RUNTIME_GATEWAY_URL",
        "http://127.0.0.1:8016",
    ),

    "control_center": env(
        "ARYA_CONTROL_CENTER_URL",
        "http://127.0.0.1:8020",
    ),

    "final_deployment": f"http://127.0.0.1:{PORT}",
}


# ============================================================
# PROVIDERS
# ============================================================

PROVIDERS = {
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
            "ARYA_WEATHER_API_KEY"
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
            "ARYA_GEOCODING_API_KEY"
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
            "ARYA_SATELLITE_API_KEY"
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
            "ARYA_AGRICULTURE_API_KEY"
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
            "OPENAI_API_KEY"
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
    ),

    "max_source_age_hours": env_int(
        "ARYA_MAX_SOURCE_AGE_HOURS",
        72,
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
    "activation_required": env_bool(
        "ARYA_DEVICE_ACTIVATION_REQUIRED",
        True,
    ),

    "max_devices_per_user": env_int(
        "ARYA_DEVICE_LIMIT",
        3,
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
        MASTER_SECRET
    ),

    "password_hash": safe_secret_status(
        OWNER_PASSWORD_HASH
    ),

    "totp": safe_secret_status(
        OWNER_TOTP_SECRET
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
# FILE / STORAGE
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
    ),

    "retain_backups": env_int(
        "ARYA_BACKUP_RETENTION",
        10,
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
    ),

    "timeout": env_int(
        "ARYA_AI_TIMEOUT",
        90,
    ),

    "temperature": float(
        env(
            "ARYA_AI_TEMPERATURE",
            "0.2",
        )
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
# SECURITY CHECKS
# ============================================================

def security_readiness() -> Dict[str, Any]:
    checks = {
        "https": HTTPS_ENABLED or not SECURITY_REQUIRE_HTTPS,
        "internal_secret": bool(INTERNAL_GATEWAY_SECRET),
        "master_email": bool(MASTER_EMAIL),
        "master_secret": bool(MASTER_SECRET),
        "owner_password_hash": bool(OWNER_PASSWORD_HASH),
        "owner_totp": bool(OWNER_TOTP_SECRET),
        "jwt_secret": bool(JWT_SECRET),
        "webhook_secret": bool(WEBHOOK_SECRET),
        "session_secret": bool(SESSION_SECRET),
    }

    return {
        "ready": all(checks.values()),
        "checks": checks,
    }


# ============================================================
# DEPLOYMENT READINESS
# ============================================================

def deployment_readiness() -> Dict[str, Any]:
    security = security_readiness()

    provider_checks = {
        name: {
            "enabled": data["enabled"],
            "api_key_configured": bool(
                data.get("api_key")
            ),
            "provider": data.get("provider"),
        }
        for name, data in PROVIDERS.items()
    }

    return {
        "environment": ENVIRONMENT,

        "security_ready": security["ready"],

        "https_ready": HTTPS_ENABLED,

        "owner_ready": OWNER_CONFIG["email_configured"]
        and OWNER_CONFIG["master_secret"] == "configured",

        "payment_ready": PAYMENT_CONFIG["enabled"],

        "automatic_updates_ready": UPDATE_CONFIG["enabled"],

        "clients_configured": (
            bool(ANDROID_API_URL)
            and bool(WINDOWS_API_URL)
        ),

        "providers": provider_checks,

        "ready_for_testing": True,

        "ready_for_production": (
            security["ready"]
            and HTTPS_ENABLED
            and OWNER_CONFIG["email_configured"]
            and PAYMENT_CONFIG["enabled"]
        ),
    }


# ============================================================
# MODELS
# ============================================================

class RuntimeCheckRequest(BaseModel):
    service: str = Field(min_length=1)
    host: Optional[str] = None
    port: Optional[int] = None


class DeploymentSetting(BaseModel):
    key: str
    value: Any


# ============================================================
# ROUTES
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


@app.get("/config")
def configuration():
    """
    Configuration safe for operational inspection.
    Secrets are never returned.
    """

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


@app.get("/security/status")
def security_status():
    return security_readiness()


@app.get("/deployment/status")
def deployment_status():
    return deployment_readiness()


@app.get("/runtime/map")
def runtime_map():
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


@app.get("/clients")
def clients():
    return CLIENT_CONFIG


@app.get("/providers")
def providers():
    return {
        name: {
            "enabled": value["enabled"],
            "provider": value["provider"],
            "api_key_configured": bool(
                value.get("api_key")
            ),
            "model": value.get("model"),
        }
        for name, value in PROVIDERS.items()
    }


@app.get("/payment")
def payment():
    return PAYMENT_CONFIG


@app.get("/updates")
def updates():
    return UPDATE_CONFIG


@app.get("/owner")
def owner():
    return OWNER_CONFIG


@app.get("/database")
def database():
    return DATABASE_CONFIG


@app.get("/storage")
def storage():
    return STORAGE_CONFIG


@app.get("/ai")
def ai():
    return {
        key: value
        for key, value in AI_CONFIG.items()
        if key != "temperature"
    }


@app.get("/environment")
def environment():
    return {
        "environment": ENVIRONMENT,
        "https": HTTPS_ENABLED,
        "host": HOST,
        "port": PORT,
        "public_api": PUBLIC_API_URL,
    }


@app.get("/check/services")
def check_services():
    """
    Lightweight local connectivity check.

    این endpoint فقط وضعیت اتصال را بررسی می‌کند.
    هیچ سرویس دیگری را تغییر نمی‌دهد.
    """

    results = {}

    for name, url in SERVICES.items():
        if not url.startswith("http://127.0.0.1"):
            results[name] = {
                "configured": True,
                "checked": False,
                "reason": "external_or_remote_service",
            }
            continue

        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)

            host = parsed.hostname or "127.0.0.1"
            port = parsed.port

            if port is None:
                port = 443 if parsed.scheme == "https" else 80

            available = local_host_available(
                host,
                port,
            )

            results[name] = {
                "configured": True,
                "checked": True,
                "available": available,
                "host": host,
                "port": port,
            }

        except Exception as exc:
            results[name] = {
                "configured": True,
                "checked": True,
                "available": False,
                "error": str(exc),
            }

    return {
        "time": utc_now(),
        "services": results,
    }


@app.get("/production/checklist")
def production_checklist():
    readiness = deployment_readiness()

    return {
        "items": [
            {
                "name": "HTTPS",
                "status": "ready"
                if HTTPS_ENABLED
                else "pending",
            },

            {
                "name": "OWNER",
                "status": "ready"
                if readiness["owner_ready"]
                else "pending",
            },

            {
                "name": "Security",
                "status": "ready"
                if readiness["security_ready"]
                else "pending",
            },

            {
                "name": "Payments",
                "status": "ready"
                if readiness["payment_ready"]
                else "pending",
            },

            {
                "name": "Automatic Updates",
                "status": "ready"
                if readiness["automatic_updates_ready"]
                else "pending",
            },

            {
                "name": "Android",
                "status": "ready"
                if CLIENT_CONFIG["android"]["api_url"]
                else "pending",
            },

            {
                "name": "Windows",
                "status": "ready"
                if CLIENT_CONFIG["windows"]["api_url"]
                else "pending",
            },

            {
                "name": "AI",
                "status": "ready"
                if PROVIDERS["ai"]["api_key"]
                else "pending",
            },
        ],

        "overall": readiness,
    }


@app.post("/deployment/setting")
def deployment_setting(setting: DeploymentSetting):
    """
    فقط وضعیت درخواست تنظیم را برمی‌گرداند.

    تغییر واقعی Environment Variable یا Secret
    از داخل API انجام نمی‌شود.
    """

    return {
        "accepted": True,
        "key": setting.key,
        "value_received": bool(setting.value),
        "message": (
            "Set this value through the deployment "
            "environment or OWNER configuration system."
        ),
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup_event():
    """
    فقط گزارش اولیه.
    هیچ فایل یا سرویس موجودی تغییر داده نمی‌شود.
    """

    Path(
        STORAGE_CONFIG["base_path"]
    ).mkdir(
        parents=True,
        exist_ok=True,
    )

    Path(
        STORAGE_CONFIG["upload_path"]
    ).mkdir(
        parents=True,
        exist_ok=True,
    )

    Path(
        STORAGE_CONFIG["backup_path"]
    ).mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 72)
    print("ARYA FINAL DEPLOYMENT")
    print(f"Version: {APP_VERSION}")
    print(f"Environment: {ENVIRONMENT}")
    print(f"Host: {HOST}")
    print(f"Port: {PORT}")
    print(f"HTTPS: {HTTPS_ENABLED}")
    print("=" * 72)

    readiness = deployment_readiness()

    print(
        "Production readiness:",
        readiness["ready_for_production"],
    )


# ============================================================
# DIRECT RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "arya_final_deployment:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
