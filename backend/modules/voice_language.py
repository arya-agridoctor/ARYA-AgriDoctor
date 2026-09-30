"""
ARYA AgriDoctor
VOICE & LANGUAGE SERVICE
Version: 1.0.0

این فایل مستقل است و نباید main.py یا vision.py را تغییر دهد.

قابلیت‌ها:
- Speech To Text
- Text To Speech
- Language Detection
- Translation
- مدیریت Provider
- Failover بین Providerها
- ثبت درخواست‌ها و خطاها
- محدودیت حجم فایل
- حذف خودکار فایل‌های موقت
- Cache پایه
- آماده برای Providerهای آینده
- آماده برای Realtime Voice
- آماده برای ترجمه زنده
- آماده برای OWNER
- آماده برای به‌روزرسانی Providerها
- طراحی API مستقل برای اتصال بعدی به ARYA اصلی
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
import sqlite3
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "ARYA Voice & Language"
APP_VERSION = "1.0.0"

HOST = os.getenv("ARYA_VOICE_HOST", "0.0.0.0")
PORT = int(os.getenv("ARYA_VOICE_PORT", "8001"))

DB_PATH = os.getenv(
    "ARYA_VOICE_DB",
    str(Path(__file__).resolve().parent / "voice_language.db"),
)

MEDIA_DIR = Path(
    os.getenv(
        "ARYA_VOICE_MEDIA_DIR",
        str(Path(__file__).resolve().parent / "voice_media"),
    )
)

MAX_AUDIO_MB = float(os.getenv("ARYA_VOICE_MAX_AUDIO_MB", "25"))
MAX_TEXT_LENGTH = int(os.getenv("ARYA_VOICE_MAX_TEXT_LENGTH", "20000"))

REQUEST_TIMEOUT = int(os.getenv("ARYA_VOICE_TIMEOUT", "120"))

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

OPENAI_BASE_URL = os.getenv(
    "ARYA_VOICE_OPENAI_URL",
    "https://api.openai.com/v1",
).rstrip("/")

STT_MODEL = os.getenv(
    "ARYA_VOICE_STT_MODEL",
    "gpt-transcribe",
)

TTS_MODEL = os.getenv(
    "ARYA_VOICE_TTS_MODEL",
    "gpt-4o-mini-tts",
)

TRANSLATION_MODEL = os.getenv(
    "ARYA_VOICE_TRANSLATION_MODEL",
    "gpt-5.6-luna",
)

DEFAULT_TTS_VOICE = os.getenv(
    "ARYA_VOICE_TTS_VOICE",
    "marin",
)

AUTO_FAILOVER = os.getenv(
    "ARYA_VOICE_AUTO_FAILOVER",
    "true",
).lower() in {"1", "true", "yes", "on"}

ALLOW_EXTERNAL_PROVIDERS = os.getenv(
    "ARYA_VOICE_ALLOW_EXTERNAL_PROVIDERS",
    "false",
).lower() in {"1", "true", "yes", "on"}

TEMP_FILE_TTL_SECONDS = int(
    os.getenv(
        "ARYA_VOICE_TEMP_FILE_TTL",
        "3600",
    )
)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=os.getenv("ARYA_LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("arya.voice")


# ============================================================
# DIRECTORIES
# ============================================================

MEDIA_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Independent multilingual voice, speech and translation "
        "service for ARYA AgriDoctor."
    ),
)


# ============================================================
# DATABASE
# ============================================================

def db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db_connection()

    conn.executescript(
        """
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_key TEXT UNIQUE NOT NULL,
            provider_type TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 100,
            config_json TEXT,
            last_success_at REAL,
            last_error_at REAL,
            last_error TEXT,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE NOT NULL,
            operation TEXT NOT NULL,
            provider TEXT,
            source_language TEXT,
            target_language TEXT,
            input_hash TEXT,
            status TEXT NOT NULL,
            error TEXT,
            created_at REAL NOT NULL,
            completed_at REAL
        );

        CREATE TABLE IF NOT EXISTS translations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cache_key TEXT UNIQUE NOT NULL,
            source_language TEXT,
            target_language TEXT,
            source_text TEXT NOT NULL,
            translated_text TEXT NOT NULL,
            provider TEXT,
            created_at REAL NOT NULL,
            last_used_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS generated_audio (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audio_id TEXT UNIQUE NOT NULL,
            text_hash TEXT NOT NULL,
            language TEXT,
            voice TEXT,
            provider TEXT,
            file_path TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL
        );

        CREATE TABLE IF NOT EXISTS language_catalog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            language_code TEXT UNIQUE NOT NULL,
            language_name TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            metadata_json TEXT,
            updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS provider_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_key TEXT NOT NULL,
            version TEXT,
            source TEXT,
            checksum TEXT,
            status TEXT,
            created_at REAL NOT NULL
        );
        """
    )

    now = time.time()

    default_providers = [
        (
            "openai",
            "multimodal_ai",
            1,
            10,
            "{}",
        ),
    ]

    for provider_key, provider_type, enabled, priority, config in default_providers:
        conn.execute(
            """
            INSERT OR IGNORE INTO providers
            (
                provider_key,
                provider_type,
                enabled,
                priority,
                config_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                provider_key,
                provider_type,
                enabled,
                priority,
                config,
                now,
                now,
            ),
        )

    languages = [
        ("fa", "Persian"),
        ("en", "English"),
        ("de", "German"),
        ("fr", "French"),
        ("es", "Spanish"),
        ("it", "Italian"),
        ("pt", "Portuguese"),
        ("tr", "Turkish"),
        ("ar", "Arabic"),
        ("ru", "Russian"),
        ("zh", "Chinese"),
        ("ja", "Japanese"),
        ("ko", "Korean"),
        ("hi", "Hindi"),
        ("ur", "Urdu"),
        ("az", "Azerbaijani"),
        ("ku", "Kurdish"),
        ("nl", "Dutch"),
        ("pl", "Polish"),
        ("sv", "Swedish"),
        ("no", "Norwegian"),
        ("da", "Danish"),
        ("fi", "Finnish"),
        ("el", "Greek"),
        ("he", "Hebrew"),
        ("id", "Indonesian"),
        ("ms", "Malay"),
        ("th", "Thai"),
        ("vi", "Vietnamese"),
        ("uk", "Ukrainian"),
    ]

    for code, name in languages:
        conn.execute(
            """
            INSERT OR IGNORE INTO language_catalog
            (
                language_code,
                language_name,
                enabled,
                updated_at
            )
            VALUES (?, ?, 1, ?)
            """,
            (code, name, now),
        )

    conn.commit()
    conn.close()


# ============================================================
# MODELS
# ============================================================

class TranslateRequest(BaseModel):
    text: str = Field(..., min_length=1)
    target_language: str = Field(..., min_length=2)
    source_language: Optional[str] = None
    preserve_format: bool = True


class DetectLanguageRequest(BaseModel):
    text: str = Field(..., min_length=1)


class SpeakRequest(BaseModel):
    text: str = Field(..., min_length=1)
    language: Optional[str] = None
    voice: Optional[str] = None
    response_format: str = "mp3"


class ProviderRegistration(BaseModel):
    provider_key: str
    provider_type: str
    priority: int = 100
    enabled: bool = True
    config: Dict[str, Any] = {}


# ============================================================
# HELPERS
# ============================================================

def now() -> float:
    return time.time()


def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def sha256_text(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def normalize_language(language: Optional[str]) -> Optional[str]:
    if not language:
        return None

    value = language.strip().lower()

    aliases = {
        "persian": "fa",
        "farsi": "fa",
        "فارسی": "fa",
        "english": "en",
        "انگلیسی": "en",
        "german": "de",
        "deutsch": "de",
        "آلمانی": "de",
        "french": "fr",
        "spanish": "es",
        "arabic": "ar",
        "turkish": "tr",
        "azerbaijani": "az",
        "azeri": "az",
        "kurdish": "ku",
        "chinese": "zh",
        "japanese": "ja",
        "korean": "ko",
        "russian": "ru",
    }

    return aliases.get(value, value)


def validate_text(text: str) -> str:
    text = text.strip()

    if not text:
        raise HTTPException(
            status_code=400,
            detail="Text cannot be empty.",
        )

    if len(text) > MAX_TEXT_LENGTH:
        raise HTTPException(
            status_code=413,
            detail="Text is too long.",
        )

    return text


def validate_audio_filename(filename: Optional[str]) -> str:
    if not filename:
        return "audio.bin"

    safe = Path(filename).name

    if safe in {".", ".."}:
        return "audio.bin"

    return safe


def audio_extension(filename: str, content_type: Optional[str]) -> str:
    suffix = Path(filename).suffix.lower()

    if suffix:
        return suffix

    if content_type:
        guessed = mimetypes.guess_extension(content_type)

        if guessed:
            return guessed

    return ".bin"


def provider_headers() -> Dict[str, str]:
    if not OPENAI_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="OPENAI_API_KEY is not configured.",
        )

    return {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
    }


def record_request(
    request_id: str,
    operation: str,
    provider: Optional[str],
    source_language: Optional[str],
    target_language: Optional[str],
    input_hash: Optional[str],
    status: str,
    error: Optional[str] = None,
) -> None:

    conn = db_connection()

    conn.execute(
        """
        INSERT INTO requests
        (
            request_id,
            operation,
            provider,
            source_language,
            target_language,
            input_hash,
            status,
            error,
            created_at,
            completed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            operation,
            provider,
            source_language,
            target_language,
            input_hash,
            status,
            error,
            now(),
            now() if status in {"success", "error"} else None,
        ),
    )

    conn.commit()
    conn.close()


def update_provider_success(provider: str) -> None:
    conn = db_connection()

    conn.execute(
        """
        UPDATE providers
        SET last_success_at = ?, updated_at = ?
        WHERE provider_key = ?
        """,
        (now(), now(), provider),
    )

    conn.commit()
    conn.close()


def update_provider_error(
    provider: str,
    error: str,
) -> None:

    conn = db_connection()

    conn.execute(
        """
        UPDATE providers
        SET last_error_at = ?,
            last_error = ?,
            updated_at = ?
        WHERE provider_key = ?
        """,
        (now(), error[:2000], now(), provider),
    )

    conn.commit()
    conn.close()


# ============================================================
# PROVIDER SYSTEM
# ============================================================

@dataclass
class Provider:
    key: str
    provider_type: str
    priority: int
    enabled: bool


def get_providers() -> List[Provider]:
    conn = db_connection()

    rows = conn.execute(
        """
        SELECT
            provider_key,
            provider_type,
            priority,
            enabled
        FROM providers
        WHERE enabled = 1
        ORDER BY priority ASC, id ASC
        """
    ).fetchall()

    conn.close()

    return [
        Provider(
            key=row["provider_key"],
            provider_type=row["provider_type"],
            priority=row["priority"],
            enabled=bool(row["enabled"]),
        )
        for row in rows
    ]


def get_provider(provider_key: str) -> Optional[Provider]:
    conn = db_connection()

    row = conn.execute(
        """
        SELECT
            provider_key,
            provider_type,
            priority,
            enabled
        FROM providers
        WHERE provider_key = ?
        """,
        (provider_key,),
    ).fetchone()

    conn.close()

    if not row:
        return None

    return Provider(
        key=row["provider_key"],
        provider_type=row["provider_type"],
        priority=row["priority"],
        enabled=bool(row["enabled"]),
    )


# ============================================================
# OPENAI HTTP
# ============================================================

def openai_post_json(
    endpoint: str,
    payload: Dict[str, Any],
) -> requests.Response:

    headers = {
        **provider_headers(),
        "Content-Type": "application/json",
    }

    response = requests.post(
        f"{OPENAI_BASE_URL}/{endpoint.lstrip('/')}",
        headers=headers,
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"OpenAI HTTP {response.status_code}: "
            f"{response.text[:2000]}"
        )

    return response


def openai_post_multipart(
    endpoint: str,
    files: Dict[str, Any],
    data: Dict[str, Any],
) -> requests.Response:

    response = requests.post(
        f"{OPENAI_BASE_URL}/{endpoint.lstrip('/')}",
        headers=provider_headers(),
        files=files,
        data=data,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"OpenAI HTTP {response.status_code}: "
            f"{response.text[:2000]}"
        )

    return response


# ============================================================
# SPEECH TO TEXT
# ============================================================

def openai_transcribe(
    file_path: Path,
    language: Optional[str] = None,
) -> Dict[str, Any]:

    data = {
        "model": STT_MODEL,
    }

    language = normalize_language(language)

    if language:
        data["language"] = language

    with file_path.open("rb") as audio_file:
        response = openai_post_multipart(
            "/audio/transcriptions",
            files={
                "file": (
                    file_path.name,
                    audio_file,
                    mimetypes.guess_type(
                        file_path.name
                    )[0] or "application/octet-stream",
                )
            },
            data=data,
        )

    result = response.json()

    text = result.get("text", "").strip()

    return {
        "text": text,
        "language": language,
        "provider": "openai",
        "model": STT_MODEL,
        "raw": result,
    }


# ============================================================
# TEXT TO SPEECH
# ============================================================

def openai_speak(
    text: str,
    voice: Optional[str] = None,
    response_format: str = "mp3",
) -> Path:

    text = validate_text(text)

    voice = voice or DEFAULT_TTS_VOICE

    allowed_formats = {
        "mp3",
        "wav",
        "opus",
        "aac",
        "flac",
        "pcm",
    }

    if response_format not in allowed_formats:
        raise HTTPException(
            status_code=400,
            detail="Unsupported audio format.",
        )

    payload = {
        "model": TTS_MODEL,
        "voice": voice,
        "input": text,
        "response_format": response_format,
    }

    headers = {
        **provider_headers(),
        "Content-Type": "application/json",
    }

    response = requests.post(
        f"{OPENAI_BASE_URL}/audio/speech",
        headers=headers,
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"OpenAI TTS HTTP {response.status_code}: "
            f"{response.text[:2000]}"
        )

    audio_id = make_id("aud")

    file_path = MEDIA_DIR / (
        f"{audio_id}.{response_format}"
    )

    file_path.write_bytes(response.content)

    return file_path


# ============================================================
# LANGUAGE DETECTION
# ============================================================

def detect_language_heuristic(text: str) -> Optional[str]:
    """
    تشخیص سریع اولیه.
    نتیجه قطعی نیست.
    برای تشخیص دقیق، از AI استفاده می‌شود.
    """

    text = text.strip()

    if not text:
        return None

    fa_chars = len(
        re.findall(
            r"[\u0600-\u06FF]",
            text,
        )
    )

    latin_chars = len(
        re.findall(
            r"[A-Za-z]",
            text,
        )
    )

    cyrillic_chars = len(
        re.findall(
            r"[\u0400-\u04FF]",
            text,
        )
    )

    if fa_chars > latin_chars and fa_chars > cyrillic_chars:
        return "fa"

    if cyrillic_chars > latin_chars:
        return "ru"

    if latin_chars > 0:
        return "en"

    return None


def detect_language_ai(text: str) -> Dict[str, Any]:
    prompt = f"""
Identify the language of the following text.

Return JSON only:

{{
  "language_code": "ISO-639-1 code when possible",
  "language_name": "English name",
  "confidence": 0.0
}}

Text:
{text}
"""

    response = openai_post_json(
        "/responses",
        {
            "model": TRANSLATION_MODEL,
            "input": prompt,
        },
    )

    result = response.json()

    output_text = extract_response_text(result)

    try:
        parsed = json.loads(output_text)

        return {
            "language_code": normalize_language(
                parsed.get("language_code")
            ),
            "language_name": parsed.get("language_name"),
            "confidence": parsed.get("confidence"),
            "provider": "openai",
        }

    except Exception:
        heuristic = detect_language_heuristic(text)

        return {
            "language_code": heuristic,
            "language_name": None,
            "confidence": 0.50 if heuristic else 0.0,
            "provider": "heuristic",
        }


# ============================================================
# RESPONSE TEXT EXTRACTION
# ============================================================

def extract_response_text(
    result: Dict[str, Any],
) -> str:

    if isinstance(result.get("output_text"), str):
        return result["output_text"].strip()

    output = result.get("output")

    if isinstance(output, list):
        parts = []

        for item in output:
            content = item.get("content")

            if not isinstance(content, list):
                continue

            for part in content:
                text = part.get("text")

                if isinstance(text, str):
                    parts.append(text)

        if parts:
            return "\n".join(parts).strip()

    choices = result.get("choices")

    if isinstance(choices, list):
        for choice in choices:
            message = choice.get("message", {})

            if isinstance(message, dict):
                content = message.get("content")

                if isinstance(content, str):
                    return content.strip()

    return ""


# ============================================================
# TRANSLATION
# ============================================================

def translation_cache_key(
    text: str,
    source_language: Optional[str],
    target_language: str,
) -> str:

    raw = json.dumps(
        {
            "text": text,
            "source": source_language,
            "target": target_language,
        },
        sort_keys=True,
        ensure_ascii=False,
    )

    return sha256_text(raw)


def get_translation_cache(
    cache_key: str,
) -> Optional[Dict[str, Any]]:

    conn = db_connection()

    row = conn.execute(
        """
        SELECT *
        FROM translations
        WHERE cache_key = ?
        """,
        (cache_key,),
    ).fetchone()

    if row:
        conn.execute(
            """
            UPDATE translations
            SET last_used_at = ?
            WHERE cache_key = ?
            """,
            (now(), cache_key),
        )

        conn.commit()

    conn.close()

    if not row:
        return None

    return dict(row)


def save_translation_cache(
    cache_key: str,
    source_language: Optional[str],
    target_language: str,
    source_text: str,
    translated_text: str,
    provider: str,
) -> None:

    conn = db_connection()

    conn.execute(
        """
        INSERT OR REPLACE INTO translations
        (
            cache_key,
            source_language,
            target_language,
            source_text,
            translated_text,
            provider,
            created_at,
            last_used_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cache_key,
            source_language,
            target_language,
            source_text,
            translated_text,
            provider,
            now(),
            now(),
        ),
    )

    conn.commit()
    conn.close()


def openai_translate(
    text: str,
    target_language: str,
    source_language: Optional[str] = None,
    preserve_format: bool = True,
) -> Dict[str, Any]:

    target_language = normalize_language(
        target_language
    ) or target_language

    source_language = normalize_language(
        source_language
    )

    system_instruction = """
You are ARYA AgriDoctor's professional multilingual
translation engine.

Translate accurately and naturally.

Rules:
- Never invent facts.
- Preserve numbers, units, dates and technical names.
- Preserve agricultural terminology.
- Preserve pesticide active ingredients exactly.
- Do not change dosage values.
- Do not add medical or agricultural advice.
- Preserve formatting when requested.
- Do not summarize unless explicitly requested.
- If a term is ambiguous, preserve the original technical term
  rather than inventing a meaning.
"""

    payload = {
        "model": TRANSLATION_MODEL,
        "input": [
            {
                "role": "system",
                "content": [
                    {
                        "type": "input_text",
                        "text": system_instruction,
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            f"Source language: "
                            f"{source_language or 'auto'}\n"
                            f"Target language: "
                            f"{target_language}\n"
                            f"Preserve formatting: "
                            f"{preserve_format}\n\n"
                            f"Text:\n{text}"
                        ),
                    }
                ],
            },
        ],
    }

    response = openai_post_json(
        "/responses",
        payload,
    )

    result = response.json()

    translated = extract_response_text(result)

    if not translated:
        raise RuntimeError(
            "Translation provider returned empty text."
        )

    return {
        "text": translated,
        "source_language": source_language,
        "target_language": target_language,
        "provider": "openai",
        "model": TRANSLATION_MODEL,
    }


# ============================================================
# CLEANUP
# ============================================================

def cleanup_old_audio() -> int:
    cutoff = now() - TEMP_FILE_TTL_SECONDS

    deleted = 0

    for path in MEDIA_DIR.iterdir():

        if not path.is_file():
            continue

        try:
            if path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)
                deleted += 1
        except Exception as exc:
            logger.warning(
                "Could not delete %s: %s",
                path,
                exc,
            )

    conn = db_connection()

    conn.execute(
        """
        DELETE FROM generated_audio
        WHERE expires_at IS NOT NULL
        AND expires_at < ?
        """,
        (now(),),
    )

    conn.commit()
    conn.close()

    return deleted


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "ready",
        "main_py_modified": False,
        "vision_py_modified": False,
        "features": [
            "speech_to_text",
            "text_to_speech",
            "translation",
            "language_detection",
            "provider_router",
            "cache",
            "failover_ready",
            "future_realtime_ready",
            "future_provider_ready",
        ],
    }


@app.get("/health")
def health() -> Dict[str, Any]:

    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "openai_configured": bool(
            OPENAI_API_KEY
        ),
        "stt_model": STT_MODEL,
        "tts_model": TTS_MODEL,
        "translation_model": TRANSLATION_MODEL,
        "auto_failover": AUTO_FAILOVER,
        "external_providers": ALLOW_EXTERNAL_PROVIDERS,
    }


@app.get("/voice/languages")
def languages() -> Dict[str, Any]:

    conn = db_connection()

    rows = conn.execute(
        """
        SELECT
            language_code,
            language_name,
            enabled,
            metadata_json
        FROM language_catalog
        WHERE enabled = 1
        ORDER BY language_code
        """
    ).fetchall()

    conn.close()

    return {
        "count": len(rows),
        "languages": [
            {
                "code": row["language_code"],
                "name": row["language_name"],
                "metadata": (
                    json.loads(row["metadata_json"])
                    if row["metadata_json"]
                    else {}
                ),
            }
            for row in rows
        ],
    }


@app.post("/voice/transcribe")
async def transcribe(
    file: UploadFile = File(...),
    language: Optional[str] = Form(None),
) -> Dict[str, Any]:

    request_id = make_id("req")

    original_name = validate_audio_filename(
        file.filename
    )

    suffix = audio_extension(
        original_name,
        file.content_type,
    )

    file_path = (
        MEDIA_DIR /
        f"{request_id}{suffix}"
    )

    size = 0

    try:
        with file_path.open("wb") as output:

            while True:

                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                size += len(chunk)

                if size > MAX_AUDIO_MB * 1024 * 1024:
                    raise HTTPException(
                        status_code=413,
                        detail="Audio file is too large.",
                    )

                output.write(chunk)

        record_request(
            request_id,
            "transcribe",
            "openai",
            normalize_language(language),
            None,
            sha256_text(
                str(file_path)
            ),
            "processing",
        )

        result = openai_transcribe(
            file_path,
            language,
        )

        record_request(
            request_id,
            "transcribe",
            "openai",
            result.get("language"),
            None,
            None,
            "success",
        )

        return {
            "request_id": request_id,
            "status": "success",
            "result": result,
        }

    except HTTPException:
        raise

    except Exception as exc:

        logger.exception(
            "Transcription failed."
        )

        try:
            record_request(
                request_id,
                "transcribe",
                "openai",
                normalize_language(language),
                None,
                None,
                "error",
                str(exc),
            )
        except Exception:
            pass

        raise HTTPException(
            status_code=502,
            detail="Speech transcription failed.",
        )

    finally:

        try:
            file_path.unlink(missing_ok=True)
        except Exception:
            pass


@app.post("/voice/speak")
def speak(
    request: SpeakRequest,
):

    text = validate_text(
        request.text
    )

    request_id = make_id("req")

    try:

        file_path = openai_speak(
            text=text,
            voice=request.voice,
            response_format=request.response_format,
        )

        audio_id = make_id("aud")

        expires_at = (
            now() +
            TEMP_FILE_TTL_SECONDS
        )

        conn = db_connection()

        conn.execute(
            """
            INSERT INTO generated_audio
            (
                audio_id,
                text_hash,
                language,
                voice,
                provider,
                file_path,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audio_id,
                sha256_text(text),
                normalize_language(
                    request.language
                ),
                request.voice or DEFAULT_TTS_VOICE,
                "openai",
                str(file_path),
                now(),
                expires_at,
            ),
        )

        conn.commit()
        conn.close()

        return {
            "request_id": request_id,
            "audio_id": audio_id,
            "status": "success",
            "format": request.response_format,
            "download_path": (
                f"/voice/audio/{audio_id}"
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:

        logger.exception(
            "TTS failed."
        )

        raise HTTPException(
            status_code=502,
            detail="Text to speech failed.",
        )


@app.get("/voice/audio/{audio_id}")
def audio(audio_id: str):

    conn = db_connection()

    row = conn.execute(
        """
        SELECT *
        FROM generated_audio
        WHERE audio_id = ?
        """,
        (audio_id,),
    ).fetchone()

    conn.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Audio not found.",
        )

    file_path = Path(
        row["file_path"]
    )

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Audio file no longer exists.",
        )

    media_type = (
        mimetypes.guess_type(
            str(file_path)
        )[0]
        or "application/octet-stream"
    )

    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=file_path.name,
    )


@app.post("/voice/detect-language")
def detect_language(
    request: DetectLanguageRequest,
) -> Dict[str, Any]:

    text = validate_text(
        request.text
    )

    heuristic = detect_language_heuristic(
        text
    )

    if heuristic:
        return {
            "status": "success",
            "language_code": heuristic,
            "confidence": 0.70,
            "method": "heuristic",
        }

    try:
        return {
            "status": "success",
            **detect_language_ai(text),
        }

    except Exception:

        return {
            "status": "success",
            "language_code": None,
            "confidence": 0.0,
            "method": "unknown",
        }


@app.post("/voice/translate")
def translate(
    request: TranslateRequest,
) -> Dict[str, Any]:

    text = validate_text(
        request.text
    )

    target_language = normalize_language(
        request.target_language
    )

    if not target_language:
        raise HTTPException(
            status_code=400,
            detail="Invalid target language.",
        )

    source_language = normalize_language(
        request.source_language
    )

    cache_key = translation_cache_key(
        text,
        source_language,
        target_language,
    )

    cached = get_translation_cache(
        cache_key
    )

    if cached:
        return {
            "status": "success",
            "cached": True,
            "provider": cached["provider"],
            "source_language": cached[
                "source_language"
            ],
            "target_language": cached[
                "target_language"
            ],
            "translation": cached[
                "translated_text"
            ],
        }

    request_id = make_id("req")

    try:

        result = openai_translate(
            text=text,
            target_language=target_language,
            source_language=source_language,
            preserve_format=request.preserve_format,
        )

        save_translation_cache(
            cache_key=cache_key,
            source_language=source_language,
            target_language=target_language,
            source_text=text,
            translated_text=result["text"],
            provider=result["provider"],
        )

        record_request(
            request_id,
            "translate",
            result["provider"],
            source_language,
            target_language,
            sha256_text(text),
            "success",
        )

        return {
            "request_id": request_id,
            "status": "success",
            "cached": False,
            **result,
        }

    except Exception as exc:

        record_request(
            request_id,
            "translate",
            "openai",
            source_language,
            target_language,
            sha256_text(text),
            "error",
            str(exc),
        )

        raise HTTPException(
            status_code=502,
            detail="Translation failed.",
        )


# ============================================================
# OWNER / PROVIDER MANAGEMENT
# ============================================================

@app.get("/voice/providers")
def providers() -> Dict[str, Any]:

    conn = db_connection()

    rows = conn.execute(
        """
        SELECT
            provider_key,
            provider_type,
            enabled,
            priority,
            last_success_at,
            last_error_at,
            last_error,
            created_at,
            updated_at
        FROM providers
        ORDER BY priority ASC, id ASC
        """
    ).fetchall()

    conn.close()

    return {
        "providers": [
            dict(row)
            for row in rows
        ]
    }


@app.post("/voice/providers/register")
def register_provider(
    provider: ProviderRegistration,
) -> Dict[str, Any]:

    if not ALLOW_EXTERNAL_PROVIDERS:
        raise HTTPException(
            status_code=403,
            detail=(
                "External provider registration "
                "is disabled."
            ),
        )

    if not re.match(
        r"^[a-zA-Z0-9_.-]{2,80}$",
        provider.provider_key,
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid provider key.",
        )

    conn = db_connection()

    conn.execute(
        """
        INSERT INTO providers
        (
            provider_key,
            provider_type,
            enabled,
            priority,
            config_json,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(provider_key)
        DO UPDATE SET
            provider_type = excluded.provider_type,
            enabled = excluded.enabled,
            priority = excluded.priority,
            config_json = excluded.config_json,
            updated_at = excluded.updated_at
        """,
        (
            provider.provider_key,
            provider.provider_type,
            int(provider.enabled),
            provider.priority,
            json.dumps(
                provider.config,
                ensure_ascii=False,
            ),
            now(),
            now(),
        ),
    )

    conn.commit()
    conn.close()

    return {
        "status": "success",
        "provider": provider.provider_key,
    }


# ============================================================
# MAINTENANCE
# ============================================================

@app.post("/voice/maintenance/cleanup")
def cleanup() -> Dict[str, Any]:

    deleted = cleanup_old_audio()

    return {
        "status": "success",
        "deleted_files": deleted,
    }


@app.get("/voice/status")
def service_status() -> Dict[str, Any]:

    conn = db_connection()

    request_count = conn.execute(
        "SELECT COUNT(*) AS count FROM requests"
    ).fetchone()["count"]

    translation_count = conn.execute(
        "SELECT COUNT(*) AS count FROM translations"
    ).fetchone()["count"]

    audio_count = conn.execute(
        "SELECT COUNT(*) AS count FROM generated_audio"
    ).fetchone()["count"]

    conn.close()

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "database": DB_PATH,
        "media_directory": str(MEDIA_DIR),
        "requests": request_count,
        "translation_cache": translation_count,
        "generated_audio_records": audio_count,
        "providers": [
            p.key
            for p in get_providers()
        ],
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup_event() -> None:

    init_db()

    cleanup_old_audio()

    logger.info(
        "%s v%s started.",
        APP_NAME,
        APP_VERSION,
    )

    logger.info(
        "STT model: %s",
        STT_MODEL,
    )

    logger.info(
        "TTS model: %s",
        TTS_MODEL,
    )

    logger.info(
        "Translation model: %s",
        TRANSLATION_MODEL,
    )


# ============================================================
# LOCAL RUN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "voice_language:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
