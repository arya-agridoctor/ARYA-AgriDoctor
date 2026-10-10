"""
ARYA AgriDoctor Compatibility Gateway
Version: 1.0.0

هدف:
ایجاد یک نقطه ورود مستقل برای اتصال برنامه قدیمی
و هسته جدید، بدون حذف فایل‌های اصلی.

نکته:
نام ماژول‌های قدیمی و جدید را با متغیرهای محیطی
ARYA_LEGACY_MODULE و ARYA_CORE_MODULE مشخص کنید.
هر ماژول باید یک FastAPI app با نام app داشته باشد.
"""

import importlib
import logging
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("arya.compatibility")

APP_VERSION = "1.0.0"

app = FastAPI(
    title="ARYA AgriDoctor Compatibility Gateway",
    version=APP_VERSION,
    description=(
        "Gateway for integrating the legacy ARYA service "
        "with the new specialist core."
    ),
)


def load_fastapi_app(module_name: str, label: str):
    """Load a FastAPI application from a Python module."""
    if not module_name:
        logger.warning("Module name for %s is not configured.", label)
        return None

    try:
        module = importlib.import_module(module_name)
        service_app = getattr(module, "app", None)

        if not isinstance(service_app, FastAPI):
            logger.error(
                "%s module '%s' does not expose a FastAPI app.",
                label,
                module_name,
            )
            return None

        logger.info("Loaded %s module: %s", label, module_name)
        return service_app

    except Exception:
        logger.exception(
            "Could not load %s module '%s'.", label, module_name
        )
        return None


# Set these environment variables to the real Python module names.
LEGACY_MODULE = os.getenv("ARYA_LEGACY_MODULE", "").strip()
CORE_MODULE = os.getenv("ARYA_CORE_MODULE", "").strip()

legacy_app = load_fastapi_app(LEGACY_MODULE, "legacy service")
core_app = load_fastapi_app(CORE_MODULE, "specialist core")

# Mounting keeps each service's route namespace separate.
# Legacy routes are available under /legacy.
# New core routes are available under /core.
if legacy_app is not None:
    app.mount("/legacy", legacy_app)

if core_app is not None:
    app.mount("/core", core_app)


@app.get("/")
def root():
    return {
        "service": "ARYA AgriDoctor Compatibility Gateway",
        "version": APP_VERSION,
        "legacy_loaded": legacy_app is not None,
        "core_loaded": core_app is not None,
        "legacy_prefix": "/legacy",
        "core_prefix": "/core",
        "status": (
            "ready"
            if legacy_app is not None and core_app is not None
            else "configuration_required"
        ),
    }


@app.get("/health")
def health():
    legacy_ok = legacy_app is not None
    core_ok = core_app is not None

    if not legacy_ok or not core_ok:
        return JSONResponse(
            status_code=503,
            content={
                "status": "incomplete",
                "legacy_loaded": legacy_ok,
                "core_loaded": core_ok,
                "message": (
                    "Configure ARYA_LEGACY_MODULE and "
                    "ARYA_CORE_MODULE with the actual module names."
                ),
            },
        )

    return {
        "status": "ok",
        "legacy_loaded": True,
        "core_loaded": True,
    }
