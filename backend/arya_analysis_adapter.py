"""
ARYA AgriDoctor
Analysis Engine Adapter

این فایل رابط بین برنامه و موتور تحلیل علمی ARYA است.

موتور اصلی:
    backend/arya_analysis_engine.py

وظیفه این فایل:
    - دریافت درخواست تحلیل از برنامه
    - تبدیل اطلاعات ورودی به ساختار مورد نیاز موتور
    - اجرای موتور تحلیل
    - برگرداندن نتیجه به صورت JSON-serializable
    - پشتیبانی از ورودی‌های متنوع برنامه
    - جلوگیری از خراب شدن برنامه در صورت ناقص بودن بعضی اطلاعات

نکته:
    این فایل مستقل است و برای اتصال مستقیم به main.py طراحی شده است.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
import traceback

from .arya_analysis_engine import analyze_agriculture


# ============================================================
# Helpers
# ============================================================

def _safe_text(value: Any) -> str:
    """تبدیل مقدار ورودی به متن امن."""
    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    try:
        return str(value).strip()
    except Exception:
        return ""


def _first_value(data: Dict[str, Any], *keys: str) -> Any:
    """
    اولین مقدار موجود و غیرخالی را از بین کلیدهای مختلف برمی‌گرداند.
    """
    for key in keys:
        if key in data:
            value = data.get(key)

            if value is None:
                continue

            if isinstance(value, str) and not value.strip():
                continue

            return value

    return None


def _normalize_context(context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    اطلاعات خام برنامه را به ساختار استاندارد موتور تحلیل تبدیل می‌کند.
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
    # هوا / آب‌وهوا
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
    # آزمایش خاک / آزمایشگاه
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
    # همه داده‌های اصلی را نیز حفظ می‌کنیم
    # تا اطلاعاتی که موتور در آینده نیاز دارد از بین نرود.
    # --------------------------------------------------------

    normalized["raw_context"] = context

    return normalized


# ============================================================
# Main Adapter
# ============================================================

def run_analysis(
    prompt: str = "",
    context: Optional[Dict[str, Any]] = None,
    language: str = "fa",
) -> Dict[str, Any]:
    """
    اجرای موتور تحلیل کشاورزی.

    پارامترها:
        prompt:
            توضیح آزاد کاربر.

        context:
            اطلاعات ساختاریافته گیاه، علائم، خاک، آب، هوا،
            موقعیت، آزمایشگاه و غیره.

        language:
            زبان خروجی.

    خروجی:
        دیکشنری قابل تبدیل به JSON.
    """

    try:
        normalized = _normalize_context(context)

        # اگر زبان جداگانه ارسال شده باشد، اولویت با آن است.
        if language:
            normalized["language"] = language

        # متن سؤال کاربر نیز حفظ می‌شود.
        normalized["prompt"] = _safe_text(prompt)

        # ----------------------------------------------------
        # اجرای موتور واقعی
        # ----------------------------------------------------

        result = analyze_agriculture(
            crop=normalized.get("crop"),
            symptoms=normalized.get("symptoms"),
            soil=normalized.get("soil"),
            water=normalized.get("water"),
            weather=normalized.get("weather"),
            location=normalized.get("location"),
            lab=normalized.get("lab"),
            image_description=normalized.get("image_description"),
            language=normalized.get("language", "fa"),
            additional_information=normalized.get(
                "additional_information"
            ),
        )

        # ----------------------------------------------------
        # اطمینان از JSON-serializable بودن پاسخ
        # ----------------------------------------------------

        if result is None:
            return {
                "ok": False,
                "engine": "ARYA_ANALYSIS_ENGINE",
                "status": "error",
                "error": "موتور تحلیل نتیجه‌ای برنگرداند.",
            }

        if isinstance(result, dict):
            output = dict(result)

            output.setdefault(
                "engine",
                "ARYA_ANALYSIS_ENGINE",
            )

            output.setdefault(
                "status",
                "success",
            )

            output["ok"] = True

            return output

        # اگر موتور در آینده نوع دیگری برگرداند
        return {
            "ok": True,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "success",
            "result": result,
        }

    except TypeError as exc:
        """
        این بخش مخصوص ناسازگاری احتمالی امضای تابع موتور است.
        """

        return {
            "ok": False,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "engine_signature_error",
            "error": str(exc),
            "message": (
                "موتور تحلیل فراخوانی شد اما ساختار ورودی "
                "با نسخه فعلی موتور مطابقت ندارد."
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
# Request Adapter
# ============================================================

def analyze_request(request: Any) -> Dict[str, Any]:
    """
    دریافت مستقیم یک Request-like object یا dictionary.

    این تابع برای اتصال آسان به API و برنامه اصلی طراحی شده است.
    """

    try:
        # ----------------------------------------------------
        # Dictionary
        # ----------------------------------------------------

        if isinstance(request, dict):
            data = request

        # ----------------------------------------------------
        # Pydantic / object
        # ----------------------------------------------------

        elif hasattr(request, "model_dump"):
            data = request.model_dump()

        elif hasattr(request, "dict"):
            data = request.dict()

        elif hasattr(request, "__dict__"):
            data = dict(request.__dict__)

        else:
            data = {}

        # ----------------------------------------------------
        # اطلاعات پایه
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

        language = _first_value(
            data,
            "language",
            "lang",
            "user_language",
        ) or "fa"

        # ----------------------------------------------------
        # context
        # ----------------------------------------------------

        context = data.get("context")

        if not isinstance(context, dict):
            context = {}

        # اطلاعات سطح اصلی درخواست نیز وارد context می‌شوند.
        for key, value in data.items():
            if key in {
                "context",
                "prompt",
                "question",
                "query",
                "message",
                "text",
                "language",
                "lang",
                "user_language",
            }:
                continue

            if key not in context:
                context[key] = value

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
# Health Check
# ============================================================

def health_check() -> Dict[str, Any]:
    """
    بررسی ساده قابل دسترس بودن موتور تحلیل.
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
# Public aliases
# ============================================================

# برای سازگاری با بخش‌های مختلف برنامه
analyze = run_analysis
analysis = run_analysis
