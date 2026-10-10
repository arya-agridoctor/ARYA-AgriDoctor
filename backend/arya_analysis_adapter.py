"""
ARYA AgriDoctor
Advanced Analysis Engine Adapter
Version: 2.1.0

رابط امن و سازگار بین Backend و موتور تحلیل تخصصی ARYA.

اصول:
- مستقل از main.py
- حفظ توابع و نام‌های سازگاری قبلی
- اعتبارسنجی ورودی‌ها
- عدم افشای traceback و جزئیات داخلی
- تشخیص صحیح نتیجه موفق و ناموفق موتور
- حفظ زبان انتخاب‌شده توسط کاربر
- سازگاری با اجرای package و اجرای مستقیم
- عدم ادعای تشخیص علمی قطعی بدون شواهد کافی
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

logger = logging.getLogger("arya.analysis.adapter")


# ------------------------------------------------------------
# Import compatibility
# ------------------------------------------------------------

try:
    from .arya_analysis_engine import analyze_agriculture
except ImportError:
    try:
        from arya_analysis_engine import analyze_agriculture
    except ImportError:
        logger.exception(
            "Unable to import ARYA agricultural analysis engine."
        )
        raise


# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

ADAPTER_NAME = "ARYA Analysis Adapter"
ADAPTER_VERSION = "2.1.0"
ENGINE_NAME = "ARYA_ANALYSIS_ENGINE"

DEFAULT_LANGUAGE = "fa"

MAX_PROMPT_LENGTH = 20_000
MAX_LANGUAGE_LENGTH = 32
MAX_TEXT_LENGTH = 20_000
MAX_CONTEXT_DEPTH = 12
MAX_CONTEXT_ITEMS = 2_000
MAX_LIST_ITEMS = 500
MAX_KEY_LENGTH = 256


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _safe_text(value: Any) -> str:
    """
    Convert supported scalar values to text safely.
    Avoid returning arbitrary object representations.
    """

    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    if isinstance(value, (int, float, bool)):
        return str(value)

    return ""


def _as_dict(value: Any) -> Dict[str, Any]:
    """
    Convert common request/model objects to a dictionary.

    Supports:
    - dict
    - Pydantic v2 model_dump()
    - Pydantic v1 dict()
    - objects exposing __dict__

    Unsupported objects produce an empty dictionary.
    """

    if isinstance(value, dict):
        return dict(value)

    if value is None:
        return {}

    model_dump = getattr(value, "model_dump", None)

    if callable(model_dump):
        try:
            result = model_dump()

            if isinstance(result, dict):
                return result

        except Exception:
            logger.debug(
                "Could not convert request using model_dump().",
                exc_info=True,
            )

    model_dict = getattr(value, "dict", None)

    if callable(model_dict):
        try:
            result = model_dict()

            if isinstance(result, dict):
                return result

        except Exception:
            logger.debug(
                "Could not convert request using dict().",
                exc_info=True,
            )

    object_dict = getattr(value, "__dict__", None)

    if isinstance(object_dict, dict):
        return dict(object_dict)

    return {}


def _first_value(
    data: Dict[str, Any],
    *keys: str,
) -> Any:
    """
    Return the first present, non-empty value.
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


def _normalize_language(
    value: Any,
    default: str = DEFAULT_LANGUAGE,
) -> str:
    """
    Normalize a language identifier without forcing Persian
    when a valid language was explicitly supplied.
    """

    language = _safe_text(value)

    if not language:
        language = default

    language = language.strip().replace("_", "-")

    if not language:
        return DEFAULT_LANGUAGE

    if len(language) > MAX_LANGUAGE_LENGTH:
        return DEFAULT_LANGUAGE

    if not all(
        character.isalnum() or character == "-"
        for character in language
    ):
        return DEFAULT_LANGUAGE

    return language


def _validate_prompt(value: Any) -> str:
    """
    Normalize and bound the prompt length.
    """

    prompt = _safe_text(value)

    if len(prompt) > MAX_PROMPT_LENGTH:
        raise ValueError(
            "طول متن درخواست بیشتر از حد مجاز است."
        )

    return prompt


def _sanitize_context_value(
    value: Any,
    *,
    depth: int = 0,
    counter: Optional[Dict[str, int]] = None,
) -> Any:
    """
    Validate supported context structures and prevent excessively
    nested or oversized input structures.

    Supported values:
    - None
    - strings
    - numbers
    - booleans
    - dictionaries
    - lists and tuples

    Unsupported arbitrary objects are rejected rather than
    being converted into potentially misleading text.
    """

    if counter is None:
        counter = {"items": 0}

    counter["items"] += 1

    if counter["items"] > MAX_CONTEXT_ITEMS:
        raise ValueError(
            "تعداد اجزای اطلاعات ورودی بیشتر از حد مجاز است."
        )

    if depth > MAX_CONTEXT_DEPTH:
        raise ValueError(
            "عمق ساختار اطلاعات ورودی بیشتر از حد مجاز است."
        )

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        # Reject NaN and infinity.
        if value != value or value in (
            float("inf"),
            float("-inf"),
        ):
            raise ValueError(
                "مقدار عددی نامعتبر در اطلاعات ورودی وجود دارد."
            )

        return value

    if isinstance(value, str):
        if len(value) > MAX_TEXT_LENGTH:
            raise ValueError(
                "یکی از فیلدهای متنی بیشتر از حد مجاز است."
            )

        return value

    if isinstance(value, dict):
        result: Dict[str, Any] = {}

        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(
                    "کلیدهای اطلاعات ورودی باید متنی باشند."
                )

            if len(key) > MAX_KEY_LENGTH:
                raise ValueError(
                    "یکی از کلیدهای اطلاعات ورودی بیش از حد طولانی است."
                )

            result[key] = _sanitize_context_value(
                item,
                depth=depth + 1,
                counter=counter,
            )

        return result

    if isinstance(value, (list, tuple)):
        if len(value) > MAX_LIST_ITEMS:
            raise ValueError(
                "تعداد اعضای یکی از فهرست‌های ورودی بیشتر از حد مجاز است."
            )

        return [
            _sanitize_context_value(
                item,
                depth=depth + 1,
                counter=counter,
            )
            for item in value
        ]

    raise ValueError(
        "نوع یکی از مقادیر اطلاعات ورودی پشتیبانی نمی‌شود."
    )


def _safe_engine_status(
    result: Dict[str, Any],
) -> str:
    """
    Return the engine status as normalized text.
    """

    status = _safe_text(
        result.get("status")
    ).lower()

    return status or "unknown"


def _engine_result_is_successful(
    result: Dict[str, Any],
) -> bool:
    """
    Do not assume every dictionary is a successful result.

    Explicit failure markers and recognized error statuses are
    treated as failures. An engine that returns a dictionary
    without an explicit status remains compatible with older
    implementations unless it explicitly reports failure.
    """

    if result.get("ok") is False:
        return False

    status = _safe_engine_status(result)

    failure_statuses = {
        "error",
        "failed",
        "failure",
        "unhealthy",
        "invalid",
        "invalid_result",
        "empty_result",
        "engine_error",
        "engine_signature_error",
        "request_adapter_error",
        "timeout",
        "unavailable",
    }

    if status in failure_statuses:
        return False

    return True


def _error_response(
    status: str,
    message: str,
) -> Dict[str, Any]:
    """
    Build a safe, stable error response without internal details.
    """

    return {
        "ok": False,
        "engine": ENGINE_NAME,
        "status": status,
        "message": message,
        "adapter": {
            "name": ADAPTER_NAME,
            "version": ADAPTER_VERSION,
        },
    }


def _attach_adapter_metadata(
    result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Preserve engine fields while adding adapter metadata.

    The adapter does not overwrite the engine's own status.
    """

    output = dict(result)

    output["ok"] = _engine_result_is_successful(output)

    output.setdefault(
        "adapter",
        {
            "name": ADAPTER_NAME,
            "version": ADAPTER_VERSION,
        },
    )

    output.setdefault(
        "engine",
        ENGINE_NAME,
    )

    return output


# ------------------------------------------------------------
# Context normalization
# ------------------------------------------------------------

def _normalize_context(
    context: Any,
) -> Dict[str, Any]:
    """
    Normalize common agricultural context field names.

    Original context is preserved under raw_context.
    """

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


# ------------------------------------------------------------
# Main analysis function
# ------------------------------------------------------------

def run_analysis(
    prompt: str = "",
    context: Optional[Dict[str, Any]] = None,
    language: str = "fa",
) -> Dict[str, Any]:
    """
    Run the agricultural analysis engine.

    Public error responses do not expose exception strings,
    filesystem paths, or traceback data.
    """

    try:
        prompt_text = _validate_prompt(prompt)

        if context is not None and not isinstance(
            context,
            dict,
        ):
            context = _as_dict(context)

        safe_context = _sanitize_context_value(
            context or {}
        )

        if not isinstance(safe_context, dict):
            return _error_response(
                "invalid_context",
                "ساختار اطلاعات تحلیل معتبر نیست.",
            )

        normalized = _normalize_context(
            safe_context
        )

        # Explicit language parameter takes precedence only when
        # it is actually provided and non-empty. Otherwise use the
        # language contained in the context.
        effective_language = _normalize_language(
            language
            if _safe_text(language)
            else normalized.get("language")
        )

        user_question = (
            normalized.get("user_question")
            or prompt_text
            or None
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

        # Only pass keyword arguments supported by the
        # ARYA analysis engine's established interface.
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
            return _error_response(
                "empty_result",
                "موتور تحلیل نتیجه‌ای برنگرداند.",
            )

        if not isinstance(result, dict):
            # Preserve compatibility with non-dictionary engine
            # results, but do not claim that the result is a
            # structured agricultural diagnosis.
            return {
                "ok": True,
                "engine": ENGINE_NAME,
                "status": "success",
                "result": result,
                "adapter": {
                    "name": ADAPTER_NAME,
                    "version": ADAPTER_VERSION,
                },
            }

        output = _attach_adapter_metadata(result)

        if not output["ok"]:
            logger.warning(
                "Agricultural analysis engine reported a failure. "
                "status=%s",
                _safe_engine_status(result),
            )

        return output

    except ValueError as exc:
        # Validation messages originate from this adapter.
        return _error_response(
            "invalid_input",
            str(exc),
        )

    except TypeError:
        logger.exception(
            "Analysis engine signature or input type mismatch."
        )

        return _error_response(
            "engine_signature_error",
            "امضای موتور تحلیل یا نوع ورودی با Adapter سازگار نیست.",
        )

    except Exception:
        logger.exception(
            "Unexpected error while running agricultural analysis."
        )

        return _error_response(
            "error",
            "در اجرای تحلیل خطایی رخ داد. لطفاً بعداً دوباره تلاش کنید.",
        )


# ------------------------------------------------------------
# Request adapter
# ------------------------------------------------------------

def analyze_request(
    request: Any,
) -> Dict[str, Any]:
    """
    Adapt an API request/model/dictionary to run_analysis().
    """

    try:
        data = _as_dict(request)

        if not data:
            return _error_response(
                "invalid_request",
                "درخواست تحلیل خالی یا نامعتبر است.",
            )

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
        )

        context = _first_value(
            data,
            "context",
            "data",
            "payload",
            "analysis_context",
        )

        if context is None:
            context = dict(data)
        elif not isinstance(context, dict):
            context = _as_dict(context)

            if not context:
                return _error_response(
                    "invalid_context",
                    "ساختار اطلاعات تحلیل معتبر نیست.",
                )

        # If the outer request supplies a language but the nested
        # context does not, preserve that language in the context.
        if (
            language
            and "language" not in context
            and "lang" not in context
            and "user_language" not in context
        ):
            context = dict(context)
            context["language"] = language

        return run_analysis(
            prompt=_safe_text(prompt),
            context=context,
            language=_safe_text(language),
        )

    except Exception:
        logger.exception(
            "Unexpected error while adapting analysis request."
        )

        return _error_response(
            "request_adapter_error",
            "پردازش درخواست تحلیل با خطا مواجه شد.",
        )


# ------------------------------------------------------------
# Health check
# ------------------------------------------------------------

def health_check() -> Dict[str, Any]:
    """
    Perform a lightweight functional check of the analysis engine.

    This checks whether the engine can execute and return a
    structured result. It does not validate scientific accuracy,
    external data freshness, or other services.
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
            user_question="بررسی اولیه سلامت موتور تحلیل",
            extra_data={
                "language": "fa",
                "health_check": True,
            },
        )

        if not isinstance(result, dict):
            return {
                "ok": False,
                "status": "invalid_engine_result",
                "engine": ENGINE_NAME,
                "adapter": {
                    "name": ADAPTER_NAME,
                    "version": ADAPTER_VERSION,
                },
            }

        if not _engine_result_is_successful(result):
            logger.warning(
                "Analysis engine health check returned a failure. "
                "status=%s",
                _safe_engine_status(result),
            )

            return {
                "ok": False,
                "status": "engine_reported_failure",
                "engine": ENGINE_NAME,
                "result_status": _safe_engine_status(result),
                "adapter": {
                    "name": ADAPTER_NAME,
                    "version": ADAPTER_VERSION,
                },
            }

        return {
            "ok": True,
            "status": "healthy",
            "engine": ENGINE_NAME,
            "result_status": _safe_engine_status(result),
            "adapter": {
                "name": ADAPTER_NAME,
                "version": ADAPTER_VERSION,
            },
            "scope": (
                "Engine execution check only; "
                "scientific accuracy and external services "
                "are not verified."
            ),
        }

    except Exception:
        logger.exception(
            "ARYA analysis engine health check failed."
        )

        return {
            "ok": False,
            "status": "unhealthy",
            "engine": ENGINE_NAME,
            "message": "بررسی سلامت موتور تحلیل ناموفق بود.",
            "adapter": {
                "name": ADAPTER_NAME,
                "version": ADAPTER_VERSION,
            },
        }


# ------------------------------------------------------------
# Compatibility aliases
# ------------------------------------------------------------

analyze = run_analysis

analyze_agriculture_request = analyze_request


# ------------------------------------------------------------
# Local test
# ------------------------------------------------------------

if __name__ == "__main__":
    import json

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
