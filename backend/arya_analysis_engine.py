
"""
ARYA AgriDoctor
Analysis Engine Compatibility Bridge
Version: 1.0.0

Connects the backend analysis adapter to the existing
specialized engine in modules/agri_engine.py.

This file intentionally does not duplicate the specialist
engine or its agricultural analysis logic.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
import logging


logger = logging.getLogger("arya.analysis.engine_bridge")

ENGINE_NAME = "ARYA_AGRI_ENGINE_BRIDGE"
ENGINE_VERSION = "1.0.0"


# ------------------------------------------------------------
# Import the actual specialist engine.
# Never import this file as its own engine.
# ------------------------------------------------------------

try:
    from .modules import agri_engine as _specialist_engine
except ImportError:
    try:
        from modules import agri_engine as _specialist_engine
    except ImportError:
        logger.exception(
            "Unable to import backend/modules/agri_engine.py."
        )
        raise


def _as_dict(value: Any) -> Dict[str, Any]:
    """Convert supported mappings and model objects to dictionaries."""

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
            logger.debug("model_dump conversion failed.", exc_info=True)

    old_dict = getattr(value, "dict", None)
    if callable(old_dict):
        try:
            result = old_dict()
            if isinstance(result, dict):
                return result
        except Exception:
            logger.debug("dict conversion failed.", exc_info=True)

    return {}


def _text(value: Any) -> Optional[str]:
    """Return safe, non-empty text for model fields."""

    if isinstance(value, str):
        value = value.strip()
        return value or None

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)

    return None


def _first_text(data: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        value = _text(data.get(key))
        if value:
            return value
    return None


def _number(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None

    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None

    if result != result or result in (float("inf"), float("-inf")):
        return None

    return result


def _context_value(value: Any) -> Dict[str, Any]:
    """Normalize a context field that may be text or a dictionary."""

    if isinstance(value, dict):
        return value

    text = _text(value)
    return {"description": text} if text else {}


def analyze_agriculture(
    crop: Any = None,
    plant: Any = None,
    symptoms: Any = None,
    soil: Any = None,
    water: Any = None,
    weather: Any = None,
    location: Any = None,
    lab: Any = None,
    image_description: Any = None,
    user_question: Any = None,
    extra_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Adapter-compatible entry point for specialist agricultural analysis.

    Raises real engine errors so the calling adapter can report failure
    instead of incorrectly claiming that analysis succeeded.
    """

    extra = _as_dict(extra_data)
    raw_context = _as_dict(extra.get("raw_context"))

    soil_data = _context_value(soil)
    water_data = _context_value(water)
    weather_data = _context_value(weather)
    location_data = _context_value(location)
    lab_data = _context_value(lab)

    # Preserve original context fields where available.
    merged = dict(raw_context)
    merged.update({
        key: value
        for key, value in {
            "crop": crop,
            "plant": plant,
            "soil": soil,
            "water": water,
            "weather": weather,
            "location": location,
            "lab": lab,
            "image_description": image_description,
            "symptoms": symptoms,
        }.items()
        if value is not None
    })

    crop_name = (
        _text(crop)
        or _text(plant)
        or _first_text(merged, "crop_name", "plant_name", "tree_name")
    )

    region = (
        _first_text(location_data, "region", "province", "state", "city")
        or _first_text(merged, "region", "province", "city")
        or _text(location)
    )

    country = (
        _first_text(location_data, "country")
        or _first_text(merged, "country")
    )

    latitude = _number(
        location_data.get("latitude", location_data.get("lat"))
    )
    longitude = _number(
        location_data.get("longitude", location_data.get("lon"))
    )

    soil_type = (
        _first_text(soil_data, "type", "soil_type", "description")
        or _first_text(merged, "soil_type")
    )
    soil_ph = _number(
        soil_data.get("ph", soil_data.get("soil_ph"))
    )
    if soil_ph is None:
        soil_ph = _number(merged.get("soil_ph"))

    organic_matter = _number(
        soil_data.get("organic_matter")
    )

    temperature = _number(
        weather_data.get(
            "temperature_c",
            weather_data.get(
                "temperature",
                weather_data.get("temp"),
            ),
        )
    )
    rainfall = _number(
        weather_data.get("rainfall_mm", weather_data.get("rainfall"))
    )

    water_source = (
        _first_text(water_data, "source", "water_source", "description")
        or _first_text(merged, "water_source")
    )
    irrigation_type = (
        _first_text(water_data, "irrigation", "irrigation_type", "method")
        or _first_text(merged, "irrigation_type")
    )

    crop_stage = (
        _first_text(merged, "crop_stage", "growth_stage", "stage")
    )
    season = _first_text(merged, "season")
    planting_date = _first_text(merged, "planting_date")

    # Build a useful question without inventing missing observations.
    question = (
        _text(user_question)
        or _text(merged.get("question"))
        or _text(merged.get("prompt"))
        or _text(merged.get("message"))
    )

    if not question:
        details = []
        if crop_name:
            details.append(f"محصول یا گیاه: {crop_name}")
        if symptoms is not None:
            details.append(f"علائم گزارش‌شده: {symptoms}")
        if image_description is not None:
            details.append(f"توضیح تصویر: {image_description}")
        if lab_data:
            details.append(f"اطلاعات آزمایش: {lab_data}")

        question = (
            "لطفاً اطلاعات کشاورزی زیر را بررسی کن و عدم قطعیت‌ها "
            "و داده‌های لازم را مشخص کن: "
            + ("؛ ".join(details) if details else "ارزیابی اولیه مزرعه")
        )

    # AnalyzeRequest requires a question of at least three characters.
    if len(question.strip()) < 3:
        question = "لطفاً وضعیت کشاورزی را بررسی کن."

    language = (
        _text(extra.get("language"))
        or _text(merged.get("language"))
        or "fa"
    )

    context_payload = {
        "country": country,
        "region": region,
        "province": _first_text(location_data, "province", "state")
        or _first_text(merged, "province"),
        "latitude": latitude,
        "longitude": longitude,
        "soil_type": soil_type,
        "soil_ph": soil_ph,
        "organic_matter": organic_matter,
        "irrigation_type": irrigation_type,
        "water_source": water_source,
        "season": season,
        "planting_date": planting_date,
        "temperature_c": temperature,
        "rainfall_mm": rainfall,
        "crop": crop_name,
        "crop_stage": crop_stage,
    }

    # Pydantic model fields may reject unknown values; pass only
    # the declared FarmContext fields above.
    farm_context = _specialist_engine.FarmContext(**context_payload)
    request = _specialist_engine.AnalyzeRequest(
        context=farm_context,
        question=question,
        language=language,
    )

    # Ensure SQLite tables exist before the engine queries them.
    _specialist_engine.init_db()

    result = _specialist_engine.analyze_farm(request)

    if not isinstance(result, dict):
        logger.error(
            "Specialist engine returned unsupported result type: %s",
            type(result).__name__,
        )
        raise TypeError("Specialist engine returned an invalid result.")

    status = str(result.get("status", "")).strip().lower()
    if status in {
        "error",
        "failed",
        "failure",
        "unhealthy",
        "invalid_engine_result",
    }:
        return {
            **result,
            "ok": False,
            "engine": ENGINE_NAME,
            "engine_version": ENGINE_VERSION,
        }

    return {
        **result,
        "ok": True,
        "engine": ENGINE_NAME,
        "engine_version": ENGINE_VERSION,
    }


def health_check() -> Dict[str, Any]:
    """Check that the specialist engine can be imported and initialized."""

    try:
        _specialist_engine.init_db()
        return {
            "ok": True,
            "status": "healthy",
            "engine": ENGINE_NAME,
            "engine_version": ENGINE_VERSION,
            "specialist_engine": getattr(
                _specialist_engine,
                "APP_NAME",
                "ARYA Agri Engine",
            ),
        }
    except Exception:
        logger.exception("Specialist engine health check failed.")
        return {
            "ok": False,
            "status": "unhealthy",
            "engine": ENGINE_NAME,
            "engine_version": ENGINE_VERSION,
        }
