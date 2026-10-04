"""
ARYA AgriDoctor
Analysis Engine Adapter

رابط امن بین Backend و موتور تحلیل تخصصی ARYA.

وظایف:
- نرمال‌سازی ورودی‌های مختلف
- اتصال امن به arya_analysis_engine
- جلوگیری از ارسال پارامترهای نامعتبر به موتور
- مدیریت خطاهای Import
- مدیریت خطاهای Runtime
- مدیریت خروجی خالی
- پشتیبانی از Dictionary و Pydantic Model
- Health Check
- Local Self Test
"""

from __future__ import annotations

from typing import Any, Dict, Optional
import traceback


# ============================================================
# ENGINE IMPORT
# ============================================================

try:
    # حالت معمول اجرای Backend به صورت package
    from .arya_analysis_engine import analyze_agriculture

except ImportError:
    try:
        # حالت اجرای مستقیم / تست محلی
        from arya_analysis_engine import analyze_agriculture

    except Exception as exc:
        analyze_agriculture = None
        _ENGINE_IMPORT_ERROR = str(exc)

else:
    _ENGINE_IMPORT_ERROR = None


ENGINE_ID = "ARYA_ANALYSIS_ENGINE"
ADAPTER_ID = "arya_analysis_adapter"


# ============================================================
# SAFE HELPERS
# ============================================================

def _safe_text(value: Any) -> str:
    """
    تبدیل امن مقدار به متن.
    """

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
    اولین مقدار معتبر را از بین کلیدهای داده‌شده پیدا می‌کند.
    """

    if not isinstance(data, dict):
        return None

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


def _model_to_dict(value: Any) -> Any:
    """
    تبدیل Pydantic v2 / v1 به Dictionary.
    """

    if value is None:
        return None

    if isinstance(value, dict):
        return dict(value)

    if hasattr(value, "model_dump"):

        try:
            return value.model_dump()

        except Exception:
            pass

    if hasattr(value, "dict"):

        try:
            return value.dict()

        except Exception:
            pass

    return value


def _as_dict(value: Any) -> Dict[str, Any]:
    """
    تبدیل مقدار به Dictionary بدون از بین بردن اطلاعات.
    """

    if value is None:
        return {}

    value = _model_to_dict(value)

    if isinstance(value, dict):
        return dict(value)

    return {
        "value": value
    }


# ============================================================
# CONTEXT NORMALIZATION
# ============================================================

def _normalize_context(
    context: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    تبدیل ورودی‌های مختلف برنامه به ساختار استاندارد.
    """

    if not isinstance(context, dict):
        context = {}

    # --------------------------------------------------------
    # CROP
    # --------------------------------------------------------

    crop = _first_value(
        context,
        "crop",
        "crop_name",
        "product",
        "cultivation",
    )

    # --------------------------------------------------------
    # PLANT / TREE
    # --------------------------------------------------------

    plant = _first_value(
        context,
        "plant",
        "plant_name",
        "tree",
        "tree_name",
    )

    # --------------------------------------------------------
    # SYMPTOMS
    # --------------------------------------------------------

    symptoms = _first_value(
        context,
        "symptoms",
        "symptom",
        "problem",
        "problems",
        "disease_symptoms",
        "signs",
    )

    # --------------------------------------------------------
    # SOIL
    # --------------------------------------------------------

    soil = _first_value(
        context,
        "soil",
        "soil_type",
        "soil_data",
        "soil_info",
    )

    # --------------------------------------------------------
    # WATER
    # --------------------------------------------------------

    water = _first_value(
        context,
        "water",
        "water_source",
        "irrigation",
        "irrigation_data",
        "water_data",
    )

    # --------------------------------------------------------
    # WEATHER
    # --------------------------------------------------------

    weather = _first_value(
        context,
        "weather",
        "weather_data",
        "climate",
        "climate_data",
    )

    # --------------------------------------------------------
    # LOCATION
    # --------------------------------------------------------

    location = _first_value(
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
    # LAB
    # --------------------------------------------------------

    lab = _first_value(
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
    # IMAGE
    # --------------------------------------------------------

    image_description = _first_value(
        context,
        "image_description",
        "image_analysis",
        "image_result",
        "photo_description",
        "vision_result",
    )

    # --------------------------------------------------------
    # LANGUAGE
    # --------------------------------------------------------

    language = _first_value(
        context,
        "language",
        "lang",
        "user_language",
    )

    # --------------------------------------------------------
    # ADDITIONAL INFORMATION
    # --------------------------------------------------------

    additional_information = _first_value(
        context,
        "additional_information",
        "additional_info",
        "extra",
        "notes",
        "description",
    )

    return {
        "crop": crop,
        "plant": plant,
        "symptoms": symptoms,

        "soil": _as_dict(soil),
        "water": _as_dict(water),
        "weather": _as_dict(weather),
        "location": _as_dict(location),
        "lab": _as_dict(lab),

        "image_description": (
            _safe_text(image_description)
            if image_description is not None
            else None
        ),

        "language": (
            _safe_text(language)
            or "fa"
        ),

        "additional_information": additional_information,

        "raw_context": dict(context),
    }


# ============================================================
# ENGINE HEALTH
# ============================================================

def health_check() -> Dict[str, Any]:
    """
    بررسی در دسترس بودن موتور تحلیل.
    """

    try:

        if analyze_agriculture is None:

            return {
                "ok": False,
                "engine": ENGINE_ID,
                "adapter": ADAPTER_ID,
                "status": "engine_import_error",
                "error": _ENGINE_IMPORT_ERROR,
            }

        if not callable(analyze_agriculture):

            return {
                "ok": False,
                "engine": ENGINE_ID,
                "adapter": ADAPTER_ID,
                "status": "engine_not_callable",
                "error": (
                    "analyze_agriculture قابل فراخوانی نیست."
                ),
            }

        return {
            "ok": True,
            "engine": ENGINE_ID,
            "adapter": ADAPTER_ID,
            "status": "available",
        }

    except Exception as exc:

        return {
            "ok": False,
            "engine": ENGINE_ID,
            "adapter": ADAPTER_ID,
            "status": "health_check_error",
            "error": str(exc),
            "trace": traceback.format_exc(),
        }


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

    نکته بسیار مهم:
    language و additional_information مستقیماً به موتور
    ارسال نمی‌شوند.

    آنها داخل extra_data قرار می‌گیرند.

    فقط پارامترهای پشتیبانی‌شده توسط موتور ارسال می‌شوند.
    """

    # --------------------------------------------------------
    # ENGINE CHECK
    # --------------------------------------------------------

    if analyze_agriculture is None:

        return {
            "ok": False,
            "engine": ENGINE_ID,
            "adapter": ADAPTER_ID,
            "status": "engine_import_error",
            "error": _ENGINE_IMPORT_ERROR,
        }

    try:

        # ----------------------------------------------------
        # NORMALIZE
        # ----------------------------------------------------

        normalized = _normalize_context(context)

        # ----------------------------------------------------
        # LANGUAGE
        # ----------------------------------------------------

        selected_language = (
            _safe_text(language)
            or _safe_text(
                normalized.get("language")
            )
            or "fa"
        )

        # ----------------------------------------------------
        # USER QUESTION
        # ----------------------------------------------------

        user_question = _safe_text(prompt)

        # ----------------------------------------------------
        # EXTRA DATA
        # ----------------------------------------------------

        extra_data: Dict[str, Any] = {
            "language": selected_language,
            "raw_context": normalized.get(
                "raw_context",
                {},
            ),
        }

        additional_information = (
            normalized.get(
                "additional_information"
            )
        )

        if additional_information is not None:

            extra_data[
                "additional_information"
            ] = additional_information

        # ----------------------------------------------------
        # ENGINE CALL
        #
        # اینجا فقط پارامترهای مجاز موتور ارسال می‌شوند.
        # ----------------------------------------------------

        result = analyze_agriculture(

            crop=normalized.get(
                "crop"
            ),

            plant=normalized.get(
                "plant"
            ),

            symptoms=normalized.get(
                "symptoms"
            ),

            soil=normalized.get(
                "soil"
            ),

            water=normalized.get(
                "water"
            ),

            weather=normalized.get(
                "weather"
            ),

            location=normalized.get(
                "location"
            ),

            lab=normalized.get(
                "lab"
            ),

            image_description=normalized.get(
                "image_description"
            ),

            user_question=(
                user_question
                if user_question
                else None
            ),

            extra_data=extra_data,
        )

        # ----------------------------------------------------
        # EMPTY RESULT
        # ----------------------------------------------------

        if result is None:

            return {
                "ok": False,
                "engine": ENGINE_ID,
                "adapter": ADAPTER_ID,
                "status": "empty_result",
                "error": (
                    "موتور تحلیل نتیجه‌ای "
                    "برنگرداند."
                ),
            }

        # ----------------------------------------------------
        # DICT RESULT
        # ----------------------------------------------------

        if isinstance(result, dict):

            output = dict(result)

            output.setdefault(
                "engine_id",
                ENGINE_ID,
            )

            output.setdefault(
                "adapter",
                ADAPTER_ID,
            )

            output.setdefault(
                "adapter_status",
                "success",
            )

            output["ok"] = True

            return output

        # ----------------------------------------------------
        # NON-DICT RESULT
        # ----------------------------------------------------

        return {
            "ok": True,
            "engine": ENGINE_ID,
            "adapter": ADAPTER_ID,
            "adapter_status": "success",
            "status": "ok",
            "result": result,
        }

    # --------------------------------------------------------
    # SIGNATURE ERROR
    # --------------------------------------------------------

    except TypeError as exc:

        return {
            "ok": False,
            "engine": ENGINE_ID,
            "adapter": ADAPTER_ID,
            "status": "engine_signature_error",
            "error": str(exc),
            "message": (
                "پارامترهای ارسال‌شده با "
                "امضای موتور تحلیل مطابقت ندارند."
            ),
        }

    # --------------------------------------------------------
    # RUNTIME ERROR
    # --------------------------------------------------------

    except Exception as exc:

        return {
            "ok": False,
            "engine": ENGINE_ID,
            "adapter": ADAPTER_ID,
            "status": "engine_runtime_error",
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
    تبدیل درخواست API به ورودی استاندارد موتور.
    """

    try:

        # ----------------------------------------------------
        # DICT
        # ----------------------------------------------------

        if isinstance(request, dict):

            data = dict(request)

        # ----------------------------------------------------
        # PYDANTIC V2
        # ----------------------------------------------------

        elif hasattr(
            request,
            "model_dump",
        ):

            data = request.model_dump()

        # ----------------------------------------------------
        # PYDANTIC V1
        # ----------------------------------------------------

        elif hasattr(
            request,
            "dict",
        ):

            data = request.dict()

        # ----------------------------------------------------
        # GENERIC OBJECT
        # ----------------------------------------------------

        elif hasattr(
            request,
            "__dict__",
        ):

            data = dict(
                request.__dict__
            )

        # ----------------------------------------------------
        # INVALID
        # ----------------------------------------------------

        else:

            return {
                "ok": False,
                "engine": ENGINE_ID,
                "adapter": ADAPTER_ID,
                "status": "invalid_request",
                "error": (
                    "ساختار درخواست "
                    "قابل شناسایی نیست."
                ),
            }

        # ----------------------------------------------------
        # PROMPT
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
        # LANGUAGE
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
        # EXISTING CONTEXT
        # ----------------------------------------------------

        existing_context = data.get(
            "context"
        )

        if isinstance(
            existing_context,
            dict,
        ):

            context = dict(
                existing_context
            )

        else:

            context = {}

        # ----------------------------------------------------
        # COPY OTHER FIELDS
        #
        # هیچ اطلاعات اضافی حذف نمی‌شود.
        # ----------------------------------------------------

        reserved = {
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

            if key in reserved:
                continue

            if key not in context:

                context[key] = value

        # ----------------------------------------------------
        # RUN
        # ----------------------------------------------------

        return run_analysis(

            prompt=_safe_text(
                prompt
            ),

            context=context,

            language=(
                _safe_text(
                    language
                )
                or "fa"
            ),
        )

    except Exception as exc:

        return {
            "ok": False,
            "engine": ENGINE_ID,
            "adapter": ADAPTER_ID,
            "status": "adapter_error",
            "error": str(exc),
            "trace": traceback.format_exc(),
        }


# ============================================================
# COMPATIBILITY ALIASES
# ============================================================

analyze = run_analysis
analysis = run_analysis


# ============================================================
# LOCAL SELF TEST
# ============================================================

if __name__ == "__main__":

    import json

    print("=" * 60)
    print("ARYA ANALYSIS ADAPTER SELF TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # TEST 1: HEALTH
    # --------------------------------------------------------

    health = health_check()

    print("\n[TEST 1] ENGINE HEALTH")

    print(
        json.dumps(
            health,
            ensure_ascii=False,
            indent=2,
            default=str,
        )
    )

    # --------------------------------------------------------
    # اگر موتور Import نشده باشد، تست را متوقف می‌کنیم.
    # --------------------------------------------------------

    if not health.get("ok"):

        print(
            "\nSELF TEST STOPPED:"
            " engine unavailable."
        )

        raise SystemExit(1)

    # --------------------------------------------------------
    # TEST 2: BASIC REQUEST
    # --------------------------------------------------------

    test_request = {

        "prompt": (
            "برگ‌های گیاه زرد شده و "
            "پژمرده است."
        ),

        "language": "fa",

        "crop": "گندم",

        "symptoms": [
            "زرد شدن برگ",
            "پژمردگی",
        ],

        "soil": {
            "type": "رسی",
            "ph": 7.8,
        },

        "weather": {
            "temperature": 31,
            "humidity": 25,
        },

        "water": {
            "irrigation": "متوسط",
        },

        "location": {
            "region": "کرمانشاه",
        },
    }

    print(
        "\n[TEST 2] ANALYSIS REQUEST"
    )

    result = analyze_request(
        test_request
    )

    print(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
            default=str,
        )
    )

    # --------------------------------------------------------
    # TEST 3: FINAL STATUS
    # --------------------------------------------------------

    print("\n" + "=" * 60)

    if result.get("ok"):

        print(
            "SELF TEST RESULT: PASS"
        )

    else:

        print(
            "SELF TEST RESULT: FAIL"
        )

    print("=" * 60)
