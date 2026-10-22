"""
ARYA AgriDoctor
Agricultural Intelligence Recovery Module
Version: 1.1.0

Preserves useful specialist results and asks targeted
follow-up questions when reliable results are unavailable.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("arya.agri_recovery")


def _clean(value: Any) -> str:
    """Extract useful text from specialist-engine results."""
    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    if isinstance(value, (int, float, bool)):
        return str(value)

    if isinstance(value, dict):
        preferred_keys = (
            "answer",
            "response",
            "summary",
            "assessment",
            "analysis",
            "recommendation",
            "recommendations",
            "recommended_actions",
            "possible_causes",
            "result",
            "message",
            "text",
        )

        parts = []
        for key in preferred_keys:
            if key not in value:
                continue

            text = _clean(value[key])
            if text and text not in parts:
                parts.append(text)

        return "\n".join(parts)

    if isinstance(value, (list, tuple)):
        parts = [_clean(item) for item in value]
        return "\n".join(part for part in parts if part)

    return ""


def _is_useful(text: str) -> bool:
    if len(text.strip()) < 20:
        return False

    normalized = re.sub(r"\s+", " ", text).strip().lower()

    generic_messages = (
        "داده معتبر کافی در دسترس نیست",
        "اطلاعات کافی در دسترس نیست",
        "در مرحله بعد تکمیل می‌شود",
        "لطفاً اطلاعات مزرعه، محصول، خاک، آب، موقعیت و شرایط فعلی را تکمیل کنید",
        "insufficient data available",
        "not enough information available",
        "please provide more information",
        "no valid data available",
    )

    return not any(
        message.lower() in normalized
        for message in generic_messages
    )


def _targeted_questions(
    prompt: str,
    context: str,
) -> list[str]:
    text = f"{prompt}\n{context}".lower()
    questions: list[str] = []

    crop_terms = (
        "درخت", "برگ", "میوه", "گندم", "جو", "گوجه",
        "سیب", "گردو", "انگور", "شلیل", "نهال",
        "crop", "tree", "leaf", "fruit", "wheat",
    )

    symptom_terms = (
        "زرد", "سیاه", "خشک", "پژمرده", "لکه",
        "پوسید", "آفت", "بیماری", "ریزش", "قهوه‌ای",
        "yellow", "black", "dry", "wilt", "spot",
        "pest", "disease",
    )

    if any(term in text for term in crop_terms):
        questions.append(
            "نام دقیق محصول یا درخت و سن آن چیست؟"
        )

    if any(term in text for term in symptom_terms):
        questions.append(
            "علائم از چه زمانی شروع شده و ابتدا در کدام قسمت گیاه دیده شده است؟"
        )
        questions.append(
            "آیا می‌توانید عکس واضحی از برگ، ساقه یا قسمت آسیب‌دیده ارسال کنید؟"
        )

    if not any(
        term in text
        for term in (
            "موقعیت", "استان", "شهر", "location", "region"
        )
    ):
        questions.append(
            "محل کشت در کدام شهر یا منطقه است؟"
        )

    if not any(
        term in text
        for term in (
            "آبیاری", "آب", "بارندگی",
            "irrigation", "watering"
        )
    ):
        questions.append(
            "آبیاری و وضعیت رطوبت خاک چگونه است؟"
        )

    if not questions:
        questions = [
            "موضوع دقیق کشاورزی یا مشکل فعلی چیست؟",
            "محل کشت و زمان شروع مشکل چه زمانی بوده است؟",
        ]

    return questions[:4]


def build_recovery_response(
    prompt: str,
    context: Any = "",
    language: str = "fa",
    specialist_result: Any = None,
) -> dict[str, Any]:
    """
    Preserve useful specialist output; otherwise request
    relevant details instead of inventing a diagnosis.
    """
    prompt_text = _clean(prompt)
    context_text = _clean(context)
    specialist_text = _clean(specialist_result)

    if _is_useful(specialist_text):
        return {
            "answer": specialist_text,
            "source": "specialist_engine",
            "needs_more_information": False,
            "follow_up_questions": [],
        }

    logger.warning(
        "Agricultural recovery activated because the specialist "
        "result was unavailable or unusable."
    )

    questions = _targeted_questions(
        prompt_text,
        context_text,
    )

    is_persian = (
        language.lower().startswith("fa")
        or bool(
            re.search(
                r"[\u0600-\u06FF]",
                f"{prompt_text} {context_text}",
            )
        )
    )

    if is_persian:
        answer = (
            "برای بررسی تخصصی، لازم نیست همه اطلاعات مزرعه را یک‌جا "
            "وارد کنید. ابتدا به پرسش‌های زیر پاسخ دهید تا علت‌های "
            "احتمالی را بررسی کنیم. بدون شواهد کافی، بیماری یا مقدار "
            "مصرف سم و کود را قطعی اعلام نمی‌کنم."
        )
    else:
        answer = (
            "Please answer the relevant questions below so I can "
            "assess the agricultural problem. I will not claim a "
            "confirmed diagnosis or invent pesticide or fertilizer "
            "dosages without sufficient evidence."
        )

    return {
        "answer": answer,
        "source": "recovery_questions",
        "needs_more_information": True,
        "follow_up_questions": questions,
    }
