"""
ARYA AgriDoctor
Advanced Analysis Engine Adapter
Version: 2.0.0

رابط امن بین Backend و موتور تحلیل تخصصی ARYA.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
import traceback


# ------------------------------------------------------------
# Import compatibility
# ------------------------------------------------------------
try:
    from .arya_analysis_engine import analyze_agriculture
except ImportError:
    from arya_analysis_engine import analyze_agriculture


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
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
    if value is None:
        return {}

    if isinstance(value, dict):
        return dict(value)

    if hasattr(value, "model_dump"):
        try:
            result = value.model_dump()
            if isinstance(result, dict):
                return result
        except Exception:
            pass

    if hasattr(value, "dict"):
        try:
            result = value.dict()
            if isinstance(result, dict):
                return result
        except Exception:
            pass

    if hasattr(value, "__dict__"):
        try:
            return dict(value.__dict__)
        except Exception:
            pass

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


# ------------------------------------------------------------
# Context normalization
# ------------------------------------------------------------
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


# ------------------------------------------------------------
# Main analysis function
# ------------------------------------------------------------
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
            or normalized.get("language")
            or "fa"
        )

        extra_data = {
            "language": effective_language,
            "additional_information": (
                normalized.get(
                    "additional_information"
                )
            ),
            "raw_context": normalized.get(
                "raw_context",
                {},
            ),
        }

        # IMPORTANT:
        # فقط پارامترهایی که موتور واقعی پشتیبانی می‌کند
        # مستقیماً ارسال می‌شوند.
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
            return {
                "ok": False,
                "engine": "ARYA_ANALYSIS_ENGINE",
                "status": "empty_result",
                "error": (
                    "موتور تحلیل نتیجه‌ای برنگرداند."
                ),
            }

        if not isinstance(result, dict):
            return {
                "ok": True,
                "engine": "ARYA_ANALYSIS_ENGINE",
                "status": "success",
                "result": result,
            }

        output = dict(result)

        output["ok"] = True

        output.setdefault(
            "adapter",
            {
                "name": "ARYA Analysis Adapter",
                "version": "2.0.0",
            },
        )

        return output

    except TypeError as exc:

        return {
            "ok": False,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "engine_signature_error",
            "error": str(exc),
            "message": (
                "امضای موتور تحلیل با Adapter سازگار نیست."
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


# ------------------------------------------------------------
# Request adapter
# ------------------------------------------------------------
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

    except Exception as exc:

        return {
            "ok": False,
            "engine": "ARYA_ANALYSIS_ENGINE",
            "status": "request_adapter_error",
            "error": str(exc),
            "trace": traceback.format_exc(),
        }


# ------------------------------------------------------------
# Health check
# ------------------------------------------------------------
def health_check() -> Dict[str, Any]:

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
            return {
                "ok": False,
                "status": "invalid_engine_result",
            }

        return {
            "ok": True,
            "status": "healthy",
            "engine": result.get(
                "engine",
                {},
            ),
            "result_status": result.get(
                "status"
            ),
        }

    except Exception as exc:

        return {
            "ok": False,
            "status": "unhealthy",
            "error": str(exc),
            "trace": traceback.format_exc(),
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
