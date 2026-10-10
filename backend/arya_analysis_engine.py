"""
ARYA AgriDoctor
Advanced Analysis Engine Adapter
Version: 2.1.0

رابط امن بین Backend و موتور تحلیل تخصصی ARYA.

ویژگی‌ها:
- سازگاری با اجرای ماژول به‌صورت package یا مستقیم
- نرمال‌سازی ورودی‌ها
- حفظ خطاهای واقعی موتور
- جلوگیری از گزارش موفقیت کاذب
- جلوگیری از افشای traceback در پاسخ عمومی
- حفظ خروجی ساختاریافته موتور
- پشتیبانی از درخواست‌های Backend
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional


logger = logging.getLogger("arya.analysis.adapter")

ENGINE_NAME = "ARYA_ANALYSIS_ENGINE"
ADAPTER_VERSION = "2.1.0"


# ============================================================
# ENGINE IMPORT
# ============================================================

try:
    from .arya_analysis_engine import analyze_agriculture
except ImportError:
    try:
        from arya_analysis_engine import analyze_agriculture
    except ImportError:
        logger.exception(
            "Failed to import ARYA agricultural analysis engine."
        )
        raise


# ============================================================
# HELPERS
# ============================================================

def _safe_text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    try:
        return str(value).strip()
    except Exception:
        return ""


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)

    if value is None:
        return {}

    if hasattr(value, "model_dump"):
        try:
            result = value.model_dump()
            if isinstance(result, dict):
                return result
        except Exception:
            logger.debug(
                "model_dump conversion failed.",
                exc_info=True,
            )

    if hasattr(value, "dict"):
        try:
            result = value.dict()
            if isinstance(result, dict):
                return result
        except Exception:
            logger.debug(
                "dict conversion failed.",
                exc_info=True,
            )

    if hasattr(value, "__dict__"):
        try:
            return dict(value.__dict__)
        except Exception:
            logger.debug(
                "Object dictionary conversion failed.",
                exc_info=True,
            )

    return {}


def _first_value(
    data: Dict[str, Any],
    *keys: str,
) -> Any:
    for key in keys:
        if key not in data:
            continue

        value = data.get(key)

        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        return value

    return None


def _error_result(
    *,
    status: str,
    message: str,
) -> Dict[str, Any]:
    return {
        "ok": False,
        "engine": ENGINE_NAME,
        "status": status,
        "message": message,
        "adapter": {
            "name": "ARYA Analysis Adapter",
            "version": ADAPTER_VERSION,
        },
    }


# ============================================================
# CONTEXT NORMALIZATION
# ============================================================

def _normalize_context(
    context: Any,
) -> Dict[str, Any]:
    data = _as_dict(context)

    normalized: Dict[str, Any] = {}

    normalized["crop"] = _first_value(
        data,
        "crop",
        "crop_name",
        "plant",
        "plant_name",
        "tree",
        "tree_name",
        "product",
        "cultivation",
    )

    normalized["plant"] = _first_value(
        data,
        "plant",
        "plant_name",
        "tree",
        "tree_name",
        "crop",
        "crop_name",
    )

    normalized["symptoms"] = _first_value(
        data,
        "symptoms",
        "symptom",
        "problem",
        "problems",
        "disease_symptoms",
        "signs",
        "observations",
    )

    normalized["soil"] = _first_value(
        data,
        "soil",
        "soil_type",
        "soil_data",
        "soil_info",
    )

    normalized["water"] = _first_value(
        data,
        "water",
        "water_source",
        "irrigation",
        "irrigation_data",
        "water_data",
    )

    normalized["weather"] = _first_value(
        data,
        "weather",
        "weather_data",
        "climate",
        "climate_data",
    )

    normalized["location"] = _first_value(
        data,
        "location",
        "location_data",
        "gps",
        "coordinates",
        "address",
        "region",
        "province",
        "city",
        "country",
    )

    normalized["lab"] = _first_value(
        data,
        "lab",
        "lab_test",
        "lab_tests",
        "soil_lab",
        "soil_lab_test",
        "soil_lab_tests",
        "laboratory",
    )

    normalized["image_description"] = _first_value(
        data,
        "image_description",
        "image_analysis",
        "image_result",
        "photo_description",
        "vision_result",
    )

    normalized["user_question"] = _first_value(
        data,
        "user_question",
        "question",
        "prompt",
        "query",
        "message",
    )

    normalized["language"] = _first_value(
        data,
        "language",
        "lang",
        "user_language",
    )

    normalized["additional_information"] = _first_value(
        data,
        "additional_information",
        "additional_info",
        "extra",
        "notes",
        "description",
    )

    normalized["raw_context"] = data

    return normalized


# ============================================================
# MAIN ANALYSIS
# ============================================================

def run_analysis(
    prompt: str = "",
    context: Optional[Dict[str, Any]] = None,
    language: str = "fa",
) -> Dict[str, Any]:
    try:
        normalized = _normalize_context(context)

        prompt_text = _safe_text(prompt)

        user_question = (
            normalized.get("user_question")
            or prompt_text
            or None
        )

        effective_language = (
            _safe_text(language)
            or _safe_text(normalized.get("language"))
            or "fa"
        )

        extra_data = {
            "language": effective_language,
            "additional_information": normalized.get(
                "additional_information"
            ),
            "raw_context": normalized.get(
                "raw_context",
                {},
            ),
        }

        result = analyze_agriculture(
            crop=normalized.get("crop"),
            plant=normalized.get("plant"),
            symptoms=normalized.get("symptoms"),
            soil=normalized.get("soil"),
            water=normalized.get("water"),
            weather=normalized.get("weather"),
            location=normalized.get("location"),
            lab=normalized.get("lab"),
            image_description=normalized.get(
                "image_description"
            ),
            user_question=user_question,
            extra_data=extra_data,
        )

        if result is None:
            logger.error(
                "Analysis engine returned None."
            )

            return _error_result(
                status="empty_result",
                message="موتور تحلیل نتیجه‌ای برنگرداند.",
            )

        if not isinstance(result, dict):
            logger.error(
                "Analysis engine returned unsupported type: %s",
                type(result).__name__,
            )

            return _error_result(
                status="invalid_engine_result",
                message="ساختار خروجی موتور تحلیل معتبر نیست.",
            )

        output = dict(result)

        # موتور ممکن است خطا را داخل دیکشنری گزارش کند.
        # در این حالت نباید پاسخ به‌عنوان موفقیت علامت‌گذاری شود.
        engine_ok = output.get("ok")

        engine_status = _safe_text(
            output.get("status")
        ).lower()

        if engine_ok is False:
            logger.error(
                "Analysis engine reported failure. Status=%s",
                engine_status or "unspecified",
            )

            output["ok"] = False

        elif engine_status in {
            "error",
            "failed",
            "failure",
            "unhealthy",
            "invalid_engine_result",
            "engine_signature_error",
        }:
            logger.error(
                "Analysis engine returned failure status: %s",
                engine_status,
            )

            output["ok"] = False

        else:
            output["ok"] = True

        output.setdefault(
            "adapter",
            {
                "name": "ARYA Analysis Adapter",
                "version": ADAPTER_VERSION,
            },
        )

        return output

    except TypeError:
        # جزئیات کامل فقط در گزارش سرور ثبت می‌شود.
        logger.exception(
            "Analysis engine signature or input type error."
        )

        return _error_result(
            status="engine_signature_error",
            message=(
                "ورودی تحلیل با ساختار مورد انتظار موتور سازگار نیست."
            ),
        )

    except Exception:
        logger.exception(
            "Unexpected error while running agricultural analysis."
        )

        return _error_result(
            status="analysis_error",
            message=(
                "هنگام تحلیل کشاورزی خطایی رخ داد. "
                "لطفاً دوباره تلاش کنید."
            ),
        )


# ============================================================
# REQUEST ADAPTER
# ============================================================

def analyze_request(
    request: Any,
) -> Dict[str, Any]:
    try:
        data = _as_dict(request)

        prompt = _first_value(
            data,
            "prompt",
            "question",
            "query",
            "message",
            "user_question",
        )

        language = _first_value(
            data,
            "language",
            "lang",
            "user_language",
        ) or "fa"

        context = _first_value(
            data,
            "context",
            "data",
            "payload",
            "analysis_context",
        )

        if not isinstance(context, dict):
            context = dict(data)

        return run_analysis(
            prompt=_safe_text(prompt),
            context=context,
            language=_safe_text(language) or "fa",
        )

    except Exception:
        logger.exception(
            "Failed to adapt incoming analysis request."
        )

        return _error_result(
            status="request_adapter_error",
            message=(
                "تبدیل درخواست برای موتور تحلیل ناموفق بود."
            ),
        )


# ============================================================
# HEALTH CHECK
# ============================================================

def health_check() -> Dict[str, Any]:
    """
    آزمون عملکرد موتور با ورودی نمونه.
    این بررسی یک تحلیل واقعی اجرا می‌کند و صرفاً بررسی import نیست.
    """

    try:
        result = analyze_agriculture(
            crop="گندم",
            symptoms=[
                "زرد شدن برگ",
                "پژمردگی",
            ],
            soil={
                "type": "رسی",
                "ph": 7.5,
            },
            water={
                "source": "آبیاری",
            },
            weather={
                "temperature": 25,
                "humidity": 50,
            },
            location={
                "region": "کرمانشاه",
            },
            lab={},
            image_description=None,
            user_question="بررسی اولیه",
            extra_data={
                "language": "fa",
            },
        )

        if not isinstance(result, dict):
            logger.error(
                "Health check returned invalid engine result."
            )

            return {
                "ok": False,
                "status": "invalid_engine_result",
                "engine": ENGINE_NAME,
                "adapter_version": ADAPTER_VERSION,
            }

        if result.get("ok") is False:
            return {
                "ok": False,
                "status": "engine_reported_failure",
                "engine": result.get(
                    "engine",
                    ENGINE_NAME,
                ),
                "adapter_version": ADAPTER_VERSION,
            }

        engine_status = _safe_text(
            result.get("status")
        ).lower()

        if engine_status in {
            "error",
            "failed",
            "failure",
            "unhealthy",
        }:
            return {
                "ok": False,
                "status": "engine_reported_failure",
                "engine": result.get(
                    "engine",
                    ENGINE_NAME,
                ),
                "adapter_version": ADAPTER_VERSION,
            }

        return {
            "ok": True,
            "status": "healthy",
            "engine": result.get(
                "engine",
                {},
            ),
            "result_status": result.get("status"),
            "adapter_version": ADAPTER_VERSION,
        }

    except Exception:
        logger.exception(
            "ARYA analysis engine health check failed."
        )

        return {
            "ok": False,
            "status": "unhealthy",
            "engine": ENGINE_NAME,
            "adapter_version": ADAPTER_VERSION,
        }


# ============================================================
# COMPATIBILITY ALIASES
# ============================================================

analyze = run_analysis

analyze_agriculture_request = analyze_request


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":
    import json

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    print(
        json.dumps(
            health_check(),
            ensure_ascii=False,
            indent=2,
        )
    )

    print(
        json.dumps(
            run_analysis(
                prompt=(
                    "برگ‌های گندم زرد شده و "
                    "گیاه پژمرده است."
                ),
                context={
                    "crop": "گندم",
                    "symptoms": [
                        "زرد شدن برگ",
                        "پژمردگی",
                    ],
                    "soil": {
                        "type": "رسی",
                        "ph": 7.8,
                    },
                    "water": {
                        "source": "چاه",
                    },
                    "weather": {
                        "temperature": 31,
                        "humidity": 25,
                    },
                    "location": {
                        "region": "کرمانشاه",
                    },
                },
                language="fa",
            ),
            ensure_ascii=False,
            indent=2,
        )
    )
