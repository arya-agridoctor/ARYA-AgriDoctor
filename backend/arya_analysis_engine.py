"""
ARYA AgriDoctor
Advanced Agricultural Analysis Engine
Version: 1.0.0

این فایل موتور تحلیل تخصصی ARYA است.
قابلیت‌های اصلی:
- تحلیل چندعاملی وضعیت مزرعه/گیاه
- تحلیل بر اساس محصول، خاک، آب، آب‌وهوا و علائم
- تشخیص اطلاعات ناقص
- تعیین سطح اطمینان
- اولویت‌بندی احتمالات
- هشدارهای ایمنی
- پیشنهاد اقدام مرحله‌ای
- خروجی ساختاریافته برای Backend و AI
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import math
import re


ENGINE_NAME = "ARYA Advanced Agricultural Analysis Engine"
ENGINE_VERSION = "1.0.0"


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class AnalysisFactor:
    name: str
    value: Any
    weight: float
    impact: str
    explanation: str


@dataclass
class Diagnosis:
    title: str
    probability: float
    severity: str
    evidence: List[str]
    missing_evidence: List[str]
    explanation: str


@dataclass
class Recommendation:
    priority: int
    action: str
    reason: str
    urgency: str
    caution: Optional[str] = None


# ============================================================
# MAIN ENGINE
# ============================================================

class AryaAnalysisEngine:

    def __init__(self) -> None:
        self.name = ENGINE_NAME
        self.version = ENGINE_VERSION

    # --------------------------------------------------------
    # PUBLIC API
    # --------------------------------------------------------

    def analyze(
        self,
        *,
        crop: Optional[str] = None,
        plant: Optional[str] = None,
        symptoms: Optional[Any] = None,
        soil: Optional[Dict[str, Any]] = None,
        water: Optional[Dict[str, Any]] = None,
        weather: Optional[Dict[str, Any]] = None,
        location: Optional[Dict[str, Any]] = None,
        lab: Optional[Dict[str, Any]] = None,
        image_description: Optional[str] = None,
        user_question: Optional[str] = None,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        crop_name = self._clean(crop or plant)

        symptom_list = self._normalize_symptoms(symptoms)

        context = {
            "crop": crop_name,
            "symptoms": symptom_list,
            "soil": soil or {},
            "water": water or {},
            "weather": weather or {},
            "location": location or {},
            "lab": lab or {},
            "image_description": image_description,
            "user_question": user_question,
            "extra_data": extra_data or {},
        }

        missing = self.detect_missing_information(context)

        factors = self._build_factors(context)

        diagnoses = self._generate_diagnoses(context, factors)

        diagnoses = self._normalize_probabilities(diagnoses)

        recommendations = self._build_recommendations(
            context,
            diagnoses,
            missing,
        )

        warnings = self._build_warnings(context, diagnoses)

        confidence = self._calculate_confidence(
            context=context,
            diagnoses=diagnoses,
            missing=missing,
        )

        severity = self._overall_severity(diagnoses)

        analysis_summary = self._build_summary(
            context=context,
            diagnoses=diagnoses,
            confidence=confidence,
            missing=missing,
        )

        return {
            "engine": {
                "name": self.name,
                "version": self.version,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "status": "ok",
            "crop": crop_name,
            "summary": analysis_summary,
            "overall_severity": severity,
            "confidence": confidence,
            "factors": [asdict(x) for x in factors],
            "diagnoses": [asdict(x) for x in diagnoses],
            "recommendations": [asdict(x) for x in recommendations],
            "warnings": warnings,
            "missing_information": missing,
            "requires_more_data": len(missing) > 0,
        }

    # ========================================================
    # INFORMATION QUALITY
    # ========================================================

    def detect_missing_information(
        self,
        context: Dict[str, Any],
    ) -> List[str]:

        missing: List[str] = []

        if not context.get("crop"):
            missing.append("نام محصول یا گیاه")

        if not context.get("symptoms"):
            missing.append("علائم یا مشکل مشاهده‌شده")

        soil = context.get("soil") or {}

        if not soil:
            missing.append("اطلاعات خاک")

        weather = context.get("weather") or {}

        if not weather:
            missing.append("اطلاعات آب‌وهوا یا شرایط اقلیمی")

        water = context.get("water") or {}

        if not water:
            missing.append("اطلاعات آب آبیاری")

        if not context.get("location"):
            missing.append("موقعیت یا منطقه کشت")

        return missing

    # ========================================================
    # FACTOR ANALYSIS
    # ========================================================

    def _build_factors(
        self,
        context: Dict[str, Any],
    ) -> List[AnalysisFactor]:

        factors: List[AnalysisFactor] = []

        crop = context.get("crop")

        if crop:
            factors.append(
                AnalysisFactor(
                    name="crop",
                    value=crop,
                    weight=1.0,
                    impact="high",
                    explanation="نوع محصول برای تفسیر علائم و شرایط ضروری است.",
                )
            )

        symptoms = context.get("symptoms") or []

        if symptoms:
            factors.append(
                AnalysisFactor(
                    name="symptoms",
                    value=symptoms,
                    weight=1.0,
                    impact="high",
                    explanation="علائم مشاهده‌شده مهم‌ترین ورودی اولیه برای تشخیص هستند.",
                )
            )

        soil = context.get("soil") or {}

        if soil:
            factors.append(
                AnalysisFactor(
                    name="soil",
                    value=soil,
                    weight=0.85,
                    impact="high",
                    explanation="ویژگی‌های خاک می‌توانند باعث کمبود غذایی، تنش ریشه و اختلال جذب شوند.",
                )
            )

        water = context.get("water") or {}

        if water:
            factors.append(
                AnalysisFactor(
                    name="water",
                    value=water,
                    weight=0.8,
                    impact="high",
                    explanation="کیفیت و مقدار آب بر ریشه، شوری و جذب عناصر اثر دارد.",
                )
            )

        weather = context.get("weather") or {}

        if weather:
            factors.append(
                AnalysisFactor(
                    name="weather",
                    value=weather,
                    weight=0.9,
                    impact="high",
                    explanation="دما، رطوبت، بارندگی و باد می‌توانند علائم را ایجاد یا تشدید کنند.",
                )
            )

        lab = context.get("lab") or {}

        if lab:
            factors.append(
                AnalysisFactor(
                    name="laboratory",
                    value=lab,
                    weight=1.2,
                    impact="very_high",
                    explanation="نتایج آزمایشگاهی در صورت معتبر بودن می‌توانند تشخیص را بسیار دقیق‌تر کنند.",
                )
            )

        return factors

    # ========================================================
    # DIAGNOSIS
    # ========================================================

    def _generate_diagnoses(
        self,
        context: Dict[str, Any],
        factors: List[AnalysisFactor],
    ) -> List[Diagnosis]:

        symptoms = context.get("symptoms") or []
        text = " ".join(symptoms).lower()

        diagnoses: List[Diagnosis] = []

        # ----------------------------------------------------
        # WATER STRESS
        # ----------------------------------------------------

        if self._contains_any(
            text,
            [
                "خشکی",
                "پژمردگی",
                "wilting",
                "dry",
                "سوختگی",
            ],
        ):
            diagnoses.append(
                Diagnosis(
                    title="تنش آبی",
                    probability=0.68,
                    severity="medium",
                    evidence=[
                        "وجود علائم مرتبط با خشکی یا پژمردگی",
                    ],
                    missing_evidence=[
                        "رطوبت واقعی خاک",
                        "فاصله آخرین آبیاری",
                    ],
                    explanation=(
                        "علائم می‌توانند با کمبود آب مرتبط باشند، "
                        "اما قبل از افزایش آبیاری باید وضعیت ریشه و رطوبت خاک بررسی شود."
                    ),
                )
            )

        # ----------------------------------------------------
        # ROOT / EXCESS WATER
        # ----------------------------------------------------

        if self._contains_any(
            text,
            [
                "زردی",
                "yellow",
                "ریزش برگ",
                "پوسیدگی",
                "root rot",
                "خفگی ریشه",
            ],
        ):
            diagnoses.append(
                Diagnosis(
                    title="اختلال ریشه یا زهکشی",
                    probability=0.58,
                    severity="medium",
                    evidence=[
                        "زردی یا ریزش برگ می‌تواند با اختلال ریشه مرتبط باشد.",
                    ],
                    missing_evidence=[
                        "وضعیت زهکشی",
                        "رطوبت خاک",
                        "وضعیت ریشه",
                    ],
                    explanation=(
                        "زردی به‌تنهایی اثبات‌کننده کمبود غذایی نیست؛ "
                        "مشکل ریشه، آب اضافی و کمبود اکسیژن نیز باید بررسی شوند."
                    ),
                )
            )

        # ----------------------------------------------------
        # NUTRIENT DEFICIENCY
        # ----------------------------------------------------

        if self._contains_any(
            text,
            [
                "کمبود",
                "رنگ‌پریدگی",
                "کلروز",
                "chlorosis",
                "برگ زرد",
            ],
        ):
            diagnoses.append(
                Diagnosis(
                    title="احتمال اختلال تغذیه‌ای",
                    probability=0.52,
                    severity="medium",
                    evidence=[
                        "وجود تغییر رنگ یا علائم مشابه کمبود غذایی",
                    ],
                    missing_evidence=[
                        "آزمایش خاک",
                        "آزمایش برگ",
                        "pH خاک",
                        "EC",
                    ],
                    explanation=(
                        "تشخیص دقیق عنصر غذایی از روی رنگ برگ به‌تنهایی "
                        "قابل اتکا نیست و باید با خاک، آب و در صورت امکان آزمایش تأیید شود."
                    ),
                )
            )

        # ----------------------------------------------------
        # PEST / DISEASE
        # ----------------------------------------------------

        if self._contains_any(
            text,
            [
                "آفت",
                "حشره",
                "کرم",
                "لکه",
                "قارچ",
                "بیماری",
                "سوراخ",
                "شپشک",
                "شته",
            ],
        ):
            diagnoses.append(
                Diagnosis(
                    title="احتمال آفت یا بیماری",
                    probability=0.61,
                    severity="medium",
                    evidence=[
                        "وجود علائم ظاهری سازگار با آفت یا بیماری",
                    ],
                    missing_evidence=[
                        "تصویر واضح از اندام آسیب‌دیده",
                        "توزیع علائم در مزرعه",
                        "مرحله رشد محصول",
                    ],
                    explanation=(
                        "برای تشخیص قطعی عامل بیماری یا آفت، "
                        "مشاهده مستقیم یا تصویر باکیفیت و اطلاعات مزرعه لازم است."
                    ),
                )
            )

        # ----------------------------------------------------
        # GENERAL UNKNOWN
        # ----------------------------------------------------

        if not diagnoses:
            diagnoses.append(
                Diagnosis(
                    title="علت نامشخص ـ نیازمند داده بیشتر",
                    probability=0.35,
                    severity="unknown",
                    evidence=[],
                    missing_evidence=[
                        "شرح دقیق علائم",
                        "تصویر گیاه",
                        "اطلاعات خاک",
                        "اطلاعات آب",
                        "اطلاعات آب‌وهوا",
                    ],
                    explanation=(
                        "اطلاعات فعلی برای ارائه یک تشخیص تخصصی کافی نیست."
                    ),
                )
            )

        return diagnoses

    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    def _build_recommendations(
        self,
        context: Dict[str, Any],
        diagnoses: List[Diagnosis],
        missing: List[str],
    ) -> List[Recommendation]:

        recommendations: List[Recommendation] = []

        if missing:
            recommendations.append(
                Recommendation(
                    priority=1,
                    action="تکمیل اطلاعات مزرعه و گیاه",
                    reason=(
                        "بخشی از داده‌های ضروری برای کاهش خطای تشخیص موجود نیست."
                    ),
                    urgency="high",
                    caution="بدون اطلاعات کافی از مصرف خودسرانه سم یا کود خودداری شود.",
                )
            )

        for diagnosis in diagnoses:

            if diagnosis.title == "تنش آبی":
                recommendations.append(
                    Recommendation(
                        priority=2,
                        action="بررسی رطوبت خاک و وضعیت ریشه پیش از تغییر برنامه آبیاری",
                        reason="علائم می‌تواند ناشی از تنش آبی باشد.",
                        urgency="high",
                        caution="افزایش بی‌دلیل آبیاری ممکن است مشکل ریشه را تشدید کند.",
                    )
                )

            elif diagnosis.title == "اختلال ریشه یا زهکشی":
                recommendations.append(
                    Recommendation(
                        priority=2,
                        action="بررسی زهکشی، رطوبت خاک و وضعیت ریشه",
                        reason="آب اضافی و اختلال ریشه می‌تواند با زردی و ریزش برگ همراه باشد.",
                        urgency="high",
                        caution="قبل از کوددهی سنگین، وضعیت ریشه بررسی شود.",
                    )
                )

            elif diagnosis.title == "احتمال اختلال تغذیه‌ای":
                recommendations.append(
                    Recommendation(
                        priority=3,
                        action="انجام یا بررسی آزمایش خاک و آب",
                        reason="تشخیص عنصر کمبود بدون داده آزمایشگاهی ممکن است خطا داشته باشد.",
                        urgency="medium",
                        caution="از مصرف کود فقط بر اساس رنگ برگ خودداری شود.",
                    )
                )

            elif diagnosis.title == "احتمال آفت یا بیماری":
                recommendations.append(
                    Recommendation(
                        priority=2,
                        action="تهیه تصویر واضح از علائم و بررسی الگوی انتشار",
                        reason="تشخیص عامل قبل از انتخاب روش کنترل ضروری است.",
                        urgency="high",
                        caution="تا مشخص شدن عامل، از سمپاشی کورکورانه خودداری شود.",
                    )
                )

        return sorted(
            recommendations,
            key=lambda x: x.priority,
        )

    # ========================================================
    # WARNINGS
    # ========================================================

    def _build_warnings(
        self,
        context: Dict[str, Any],
        diagnoses: List[Diagnosis],
    ) -> List[str]:

        warnings: List[str] = []

        if not context.get("crop"):
            warnings.append(
                "نوع محصول مشخص نیست؛ توصیه‌های اختصاصی محصول قابل اعتماد نیستند."
            )

        if not context.get("symptoms"):
            warnings.append(
                "علائم کافی ثبت نشده‌اند؛ تشخیص قطعی امکان‌پذیر نیست."
            )

        if not context.get("weather"):
            warnings.append(
                "اطلاعات آب‌وهوا موجود نیست؛ تحلیل تنش‌های اقلیمی محدود است."
            )

        if not context.get("lab"):
            warnings.append(
                "نتیجه آزمایش خاک/آب ارائه نشده است؛ تشخیص تغذیه‌ای قطعی نیست."
            )

        warnings.append(
            "مصرف سم، کود یا ماده شیمیایی باید بر اساس محصول، عامل، دوز مجاز و مقررات منطقه‌ای انجام شود."
        )

        return warnings

    # ========================================================
    # CONFIDENCE
    # ========================================================

    def _calculate_confidence(
        self,
        *,
        context: Dict[str, Any],
        diagnoses: List[Diagnosis],
        missing: List[str],
    ) -> Dict[str, Any]:

        score = 35.0

        if context.get("crop"):
            score += 10

        if context.get("symptoms"):
            score += 15

        if context.get("soil"):
            score += 8

        if context.get("water"):
            score += 7

        if context.get("weather"):
            score += 8

        if context.get("location"):
            score += 5

        if context.get("lab"):
            score += 15

        if context.get("image_description"):
            score += 5

        score -= min(len(missing) * 3, 20)

        score = max(0.0, min(score, 95.0))

        if score >= 80:
            level = "very_high"
        elif score >= 65:
            level = "high"
        elif score >= 45:
            level = "medium"
        else:
            level = "low"

        return {
            "score": round(score, 2),
            "level": level,
            "note": (
                "این امتیاز اطمینان تحلیلی است و به معنی تشخیص قطعی بیماری نیست."
            ),
        }

    # ========================================================
    # SUMMARY
    # ========================================================

    def _build_summary(
        self,
        *,
        context: Dict[str, Any],
        diagnoses: List[Diagnosis],
        confidence: Dict[str, Any],
        missing: List[str],
    ) -> str:

        top = max(
            diagnoses,
            key=lambda x: x.probability,
        )

        crop = context.get("crop") or "محصول نامشخص"

        if missing:
            return (
                f"برای {crop}، محتمل‌ترین وضعیت فعلی «{top.title}» "
                f"است؛ اما به دلیل ناقص بودن داده‌ها، نتیجه مقدماتی است."
            )

        return (
            f"برای {crop}، محتمل‌ترین وضعیت «{top.title}» "
            f"با احتمال تحلیلی {round(top.probability * 100)}٪ است."
        )

    # ========================================================
    # SEVERITY
    # ========================================================

    def _overall_severity(
        self,
        diagnoses: List[Diagnosis],
    ) -> str:

        order = {
            "unknown": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        if not diagnoses:
            return "unknown"

        return max(
            diagnoses,
            key=lambda x: order.get(x.severity, 0),
        ).severity

    # ========================================================
    # NORMALIZATION
    # ========================================================

    def _normalize_probabilities(
        self,
        diagnoses: List[Diagnosis],
    ) -> List[Diagnosis]:

        total = sum(
            max(0.01, d.probability)
            for d in diagnoses
        )

        if total <= 0:
            return diagnoses

        for d in diagnoses:
            d.probability = round(
                max(0.01, d.probability) / total,
                4,
            )

        return diagnoses

    # ========================================================
    # HELPERS
    # ========================================================

    @staticmethod
    def _clean(value: Optional[str]) -> Optional[str]:

        if value is None:
            return None

        value = str(value).strip()

        if not value:
            return None

        return value

    @staticmethod
    def _normalize_symptoms(
        symptoms: Optional[Any],
    ) -> List[str]:

        if symptoms is None:
            return []

        if isinstance(symptoms, str):
            parts = re.split(
                r"[,،;\n]+",
                symptoms,
            )

            return [
                p.strip()
                for p in parts
                if p.strip()
            ]

        if isinstance(symptoms, list):
            return [
                str(x).strip()
                for x in symptoms
                if str(x).strip()
            ]

        return [str(symptoms).strip()]

    @staticmethod
    def _contains_any(
        text: str,
        words: List[str],
    ) -> bool:

        return any(
            word.lower() in text
            for word in words
        )


# ============================================================
# SINGLETON
# ============================================================

_engine = AryaAnalysisEngine()


def analyze_agriculture(
    *,
    crop: Optional[str] = None,
    plant: Optional[str] = None,
    symptoms: Optional[Any] = None,
    soil: Optional[Dict[str, Any]] = None,
    water: Optional[Dict[str, Any]] = None,
    weather: Optional[Dict[str, Any]] = None,
    location: Optional[Dict[str, Any]] = None,
    lab: Optional[Dict[str, Any]] = None,
    image_description: Optional[str] = None,
    user_question: Optional[str] = None,
    extra_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    return _engine.analyze(
        crop=crop,
        plant=plant,
        symptoms=symptoms,
        soil=soil,
        water=water,
        weather=weather,
        location=location,
        lab=lab,
        image_description=image_description,
        user_question=user_question,
        extra_data=extra_data,
    )


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    result = analyze_agriculture(
        crop="گندم",
        symptoms=[
            "زرد شدن برگ",
            "پژمردگی",
        ],
        soil={
            "type": "رسی",
            "ph": 7.8,
        },
        weather={
            "temperature": 31,
            "humidity": 25,
        },
        location={
            "region": "کرمانشاه",
        },
    )

    import json

    print(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        )
    )
