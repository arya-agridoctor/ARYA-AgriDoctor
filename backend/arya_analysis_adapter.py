"""
ARYA AgriDoctor
Analysis Engine Adapter

رابط بین Backend و موتور تحلیل تخصصی ARYA
"""

from __future__ import annotations

from typing import Any, Dict, Optional
import traceback

from .arya_analysis_engine import analyze_agriculture


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


def _first_value(
    data: Dict[str, Any],
    *keys: str,
) -> Any:
    """
    اولین مقدار معتبر را از بین کلیدهای داده‌شده برمی‌گرداند.
    """

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


def _normalize_context(
    context: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    تبدیل ورودی‌های متنوع برنامه به ساختار استاندارد موتور.
    """

    if not isinstance(context, dict):
        context = {}

    normalized: Dict[str, Any] = {}

    # --------------------------------------------------------
    # محصول / گیاه
    # --------------------------------------------------------

    normalized["crop"] = _first_value(
        context,
        "crop",
        "crop_name",
        "plant",
        "plant_name",
        "tree",
        "tree_name",
        "product",
        "cultivation",
    )

    # --------------------------------------------------------
    # علائم
    # --------------------------------------------------------

    normalized["symptoms"] = _first_value(
        context,
        "symptoms",
        "symptom",
        "problem",
        "problems",
        "disease_symptoms",
        "signs",
    )

    # --------------------------------------------------------
    # خاک
    # --------------------------------------------------------

    normalized["soil"] = _first_value(
        context,
        "soil",
        "soil_type",
        "soil_data",
        "soil_info",
    )

    # --------------------------------------------------------
    # آب
    # --------------------------------------------------------

    normalized["water"] = _first_value(
        context,
        "water",
        "water_source",
        "irrigation",
        "irrigation_data",
        "water_data",
    )

    # --------------------------------------------------------
    # آب و هوا
    # --------------------------------------------------------

    normalized["weather"] = _first_value(
        context,
        "weather",
        "weather_data",
        "climate",
        "climate_data",
    )

    # --------------------------------------------------------
    # موقعیت
    # --------------------------------------------------------

    normalized["location"] = _first_value(
        context,
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

    # --------------------------------------------------------
    # آزمایشگاه
    # --------------------------------------------------------

    normalized["lab"] = _first_value(
        context,
        "lab",
        "lab_test",
        "lab_tests",
        "soil_lab",
        "soil_lab_test",
        "soil_lab_tests",
        "laboratory",
    )

    # --------------------------------------------------------
    # تصویر
    # --------------------------------------------------------

    normalized["image_description"] = _first_value(
        context,
        "image_description",
        "image_analysis",
        "image_result",
        "photo_description",
        "vision_result",
    )

    # --------------------------------------------------------
    # زبان
    # فقط در Adapter نگهداری می‌شود.
    # موتور فعلی مستقیماً language نمی‌گیرد.
    # --------------------------------------------------------

    normalized["language"] = _first_value(
        context,
        "language",
        "lang",
        "user_language",
    )

    # --------------------------------------------------------
    # اطلاعات اضافی
    # --------------------------------------------------------

    normalized["additional_information"] = _first_value(
        context,
        "additional_information",
        "additional_info",
        "extra",
        "notes",
        "description",
    )

    # --------------------------------------------------------
    # اطلاعات خام
    # برای توسعه‌های بعدی حفظ می‌شود.
    # --------------------------------------------------------

    normalized["raw_context"] = dict(context)

    return normalized


# ============================================================
# MAIN ANALYSIS
# ============================================================

def run_analysis(
    prompt: str = "",
    context: Optional[Dict[str, Any]] = None,
    language: str = "fa",
) -> Dict[str, Any]:
    """
    اجرای موتور تحلیل تخصصی ARYA.
    """

    try:
        normalized = _normalize_context(context)

        # ----------------------------------------------------
        # زبان
        # ----------------------------------------------------

        selected_language = (
            _safe_text(language)
            or _safe_text(normalized.get("language"))
            or "fa"
        )

        # ----------------------------------------------------
        # سؤال کاربر
        # ----------------------------------------------------

        user_question = _safe_text(prompt)

        # ----------------------------------------------------
        # اطلاعات اضافی
        # ----------------------------------------------------

        extra_data: Dict[str, Any] = {}

        additional_information = normalized.get(
            "additional_information"
        )

        if additional_information:
            extra_data["additional_information"] = (
                additional_information
            )

        extra_data["language"] = selected_language
        extra_data["raw_context"] = normalized.get(
            "raw_context",
            {},
        )

        # ----------------------------------------------------
        # اجرای موتور واقعی
        #
        # نکته مهم:
        # فقط پارامترهایی ارسال می‌شوند که موتور واقعی
        # arya_analysis_engine.py قبول می‌کند.
        # ----------------------------------------------------

        result = analyze_agriculture(
            crop=normalized.get("crop"),
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

        # ----------------------------------------------------
        # نتیجه خالی
        # ----------------------------------------------------

        if result is None:
            return {
                "ok": False,
                "engine": "ARYA_ANALYSIS_ENGINE",
                "status": "error",
                "error": (
                    "موتور تحلیل نتیجه‌ای برنگرداند."
                ),
            }

        # ----------------------------------------------------
        # نتیجه استاندارد Dictionary
        # ----------------------------------------------------

        if isinstance(result, dict):

            output = dict(result)

            output.setdefault(
                "engine",
                "ARYA_ANALYSIS_ENGINE",
            )

            output.setdefault(
                "status",
                "ok",
            )

            output["ok"] = True

            return output

        # ----------------------------------------------------
        # پشتیبانی از خروجی غیر Dictionary
        # ----------------------------------------------------

        return {
            "ok": True,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "ok",
            "result": result,
        }

    except TypeError as exc:

        return {
            "ok": False,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "engine_signature_error",
            "error": str(exc),
            "message": (
                "امضای ورودی موتور تحلیل با Adapter "
                "مطابقت ندارد."
            ),
        }

    except Exception as exc:

        return {
            "ok": False,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "error",
            "error": str(exc),
            "trace": traceback.format_exc(),
        }


# ============================================================
# REQUEST ADAPTER
# ============================================================

def analyze_request(
    request: Any,
) -> Dict[str, Any]:
    """
    دریافت مستقیم Dictionary، Pydantic Model یا Object.
    """

    try:

        # ----------------------------------------------------
        # Dictionary
        # ----------------------------------------------------

        if isinstance(request, dict):
            data = dict(request)

        # ----------------------------------------------------
        # Pydantic v2
        # ----------------------------------------------------

        elif hasattr(request, "model_dump"):
            data = request.model_dump()

        # ----------------------------------------------------
        # Pydantic v1
        # ----------------------------------------------------

        elif hasattr(request, "dict"):
            data = request.dict()

        # ----------------------------------------------------
        # Object
        # ----------------------------------------------------

        elif hasattr(request, "__dict__"):
            data = dict(request.__dict__)

        else:
            data = {}

        # ----------------------------------------------------
        # سؤال
        # ----------------------------------------------------

        prompt = _first_value(
            data,
            "prompt",
            "question",
            "query",
            "message",
            "text",
            "description",
        )

        # ----------------------------------------------------
        # زبان
        # ----------------------------------------------------

        language = (
            _first_value(
                data,
                "language",
                "lang",
                "user_language",
            )
            or "fa"
        )

        # ----------------------------------------------------
        # Context
        # ----------------------------------------------------

        context = data.get("context")

        if not isinstance(context, dict):
            context = {}

        else:
            context = dict(context)

        # ----------------------------------------------------
        # انتقال سایر اطلاعات سطح درخواست به context
        # ----------------------------------------------------

        ignored_keys = {
            "context",
            "prompt",
            "question",
            "query",
            "message",
            "text",
            "language",
            "lang",
            "user_language",
        }

        for key, value in data.items():

            if key in ignored_keys:
                continue

            if key not in context:
                context[key] = value

        # ----------------------------------------------------
        # اجرای تحلیل
        # ----------------------------------------------------

        return run_analysis(
            prompt=_safe_text(prompt),
            context=context,
            language=_safe_text(language) or "fa",
        )

    except Exception as exc:

        return {
            "ok": False,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "adapter_error",
            "error": str(exc),
            "trace": traceback.format_exc(),
        }


# ============================================================
# HEALTH CHECK
# ============================================================

def health_check() -> Dict[str, Any]:
    """
    بررسی دسترسی موتور تحلیل.
    """

    try:

        if callable(analyze_agriculture):

            return {
                "ok": True,
                "engine": "ARYA_ANALYSIS_ENGINE",
                "status": "available",
            }

        return {
            "ok": False,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "unavailable",
        }

    except Exception as exc:

        return {
            "ok": False,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "error",
            "error": str(exc),
        }


# ============================================================
# PUBLIC ALIASES
# ============================================================

analyze = run_analysis
analysis = run_analysis
