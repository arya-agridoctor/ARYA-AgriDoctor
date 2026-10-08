"""
ARYA AgriDoctor
VOICE & LANGUAGE SERVICE
Version: 2.0.0

Independent voice/language service.
Preserves legacy routes and adds compatibility for the unified/runtime
gateways. main.py and vision.py are not modified.
"""

from __future__ import annotations

import hashlib
import json
import logging
import mimetypes
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field


APP_NAME = "ARYA Voice & Language"
APP_VERSION = "2.0.0"

HOST = os.getenv("ARYA_VOICE_HOST", "0.0.0.0")
PORT = int(os.getenv("ARYA_VOICE_PORT", "8002"))

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
    os.getenv("ARYA_VOICE_TEMP_FILE_TTL", "3600")
)

logging.basicConfig(
    level=os.getenv("ARYA_LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("arya.voice")

MEDIA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Independent multilingual voice, speech and translation service.",
)


def db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def now() -> float:
    return time.time()


def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
        "hindi": "hi",
        "urdu": "ur",
        "italian": "it",
        "portuguese": "pt",
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


def safe_filename(filename: Optional[str]) -> str:
    if not filename:
        return "audio.bin"

    name = Path(filename).name

    if name in {".", "..", ""}:
        return "audio.bin"

    return name


def audio_extension(
    filename: str,
    content_type: Optional[str],
) -> str:

    suffix = Path(filename).suffix.lower()

    if suffix:
        return suffix

    return (
        mimetypes.guess_extension(
            content_type or ""
        )
        or ".bin"
    )


def provider_headers() -> Dict[str, str]:

    if not OPENAI_API_KEY:
        raise RuntimeError(
            "OPENAI_API_KEY is not configured."
        )

    return {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
    }


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

    current_time = now()

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
        VALUES (
            'openai',
            'multimodal_ai',
            1,
            10,
            '{}',
            ?,
            ?
        )
        """,
        (current_time, current_time),
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
            (code, name, current_time),
        )

    conn.commit()
    conn.close()


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


@dataclass
class Provider:
    key: str
    provider_type: str
    priority: int
    enabled: bool


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
        INSERT OR REPLACE INTO requests
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
            now()
            if status in {"success", "error"}
            else None,
        ),
    )

    conn.commit()
    conn.close()


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
        ORDER BY priority, id
        """
    ).fetchall()

    conn.close()

    return [
        Provider(
            r["provider_key"],
            r["provider_type"],
            r["priority"],
            bool(r["enabled"]),
        )
        for r in rows
    ]


def extract_response_text(
    result: Dict[str, Any],
) -> str:

    if isinstance(
        result.get("output_text"),
        str,
    ):
        return result["output_text"].strip()

    output = result.get("output")

    if isinstance(output, list):

        parts = []

        for item in output:

            content = (
                item.get("content", [])
                if isinstance(item, dict)
                else []
            )

            for part in content:

                if (
                    isinstance(part, dict)
                    and isinstance(
                        part.get("text"),
                        str,
                    )
                ):
                    parts.append(
                        part["text"]
                    )

        if parts:
            return "\n".join(parts).strip()

    choices = result.get("choices")

    if isinstance(choices, list):

        for choice in choices:

            message = choice.get(
                "message",
                {},
            )

            if (
                isinstance(message, dict)
                and isinstance(
                    message.get("content"),
                    str,
                )
            ):
                return message["content"].strip()

    return ""


def openai_post_json(
    endpoint: str,
    payload: Dict[str, Any],
) -> requests.Response:

    response = requests.post(
        f"{OPENAI_BASE_URL}/{endpoint.lstrip('/')}",
        headers={
            **provider_headers(),
            "Content-Type": "application/json",
        },
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
            {
                "file": (
                    file_path.name,
                    audio_file,
                    mimetypes.guess_type(
                        file_path.name
                    )[0]
                    or "application/octet-stream",
                )
            },
            data,
        )

    result = response.json()

    return {
        "text": str(
            result.get("text", "")
        ).strip(),
        "language": language,
        "provider": "openai",
        "model": STT_MODEL,
    }


def openai_speak(
    text: str,
    voice: Optional[str],
    response_format: str,
) -> Path:

    formats = {
        "mp3",
        "wav",
        "opus",
        "aac",
        "flac",
        "pcm",
    }

    if response_format not in formats:
        raise HTTPException(
            status_code=400,
            detail="Unsupported audio format.",
        )

    response = requests.post(
        f"{OPENAI_BASE_URL}/audio/speech",
        headers={
            **provider_headers(),
            "Content-Type": "application/json",
        },
        json={
            "model": TTS_MODEL,
            "voice": voice or DEFAULT_TTS_VOICE,
            "input": validate_text(text),
            "response_format": response_format,
        },
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code >= 400:

        raise RuntimeError(
            f"OpenAI TTS HTTP {response.status_code}: "
            f"{response.text[:2000]}"
        )

    path = (
        MEDIA_DIR
        / f"{make_id('aud')}.{response_format}"
    )

    path.write_bytes(
        response.content
    )

    return path


def detect_language_heuristic(
    text: str,
) -> Optional[str]:

    fa = len(
        re.findall(
            r"[\u0600-\u06FF]",
            text,
        )
    )

    latin = len(
        re.findall(
            r"[A-Za-z]",
            text,
        )
    )

    cyr = len(
        re.findall(
            r"[\u0400-\u04FF]",
            text,
        )
    )

    if fa > latin and fa > cyr:
        return "fa"

    if cyr > latin:
        return "ru"

    if latin:
        return "en"

    return None


def detect_language_ai(
    text: str,
) -> Dict[str, Any]:

    result = openai_post_json(
        "/responses",
        {
            "model": TRANSLATION_MODEL,
            "input": (
                "Identify the language. "
                "Return JSON only: "
                '{"language_code":"ISO-639-1",'
                '"language_name":"English name",'
                '"confidence":0.0}'
                f"\nText:\n{text}"
            ),
        },
    ).json()

    raw = extract_response_text(
        result
    )

    try:

        parsed = json.loads(raw)

        return {
            "language_code": normalize_language(
                parsed.get("language_code")
            ),
            "language_name": parsed.get(
                "language_name"
            ),
            "confidence": float(
                parsed.get(
                    "confidence",
                    0.0,
                )
            ),
            "provider": "openai",
        }

    except Exception:

        code = detect_language_heuristic(
            text
        )

        return {
            "language_code": code,
            "language_name": None,
            "confidence": 0.5
            if code
            else 0.0,
            "provider": "heuristic",
        }


def translation_cache_key(
    text: str,
    source: Optional[str],
    target: str,
) -> str:

    return sha256_text(
        json.dumps(
            {
                "text": text,
                "source": source,
                "target": target,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
    )


def get_translation_cache(
    key: str,
) -> Optional[Dict[str, Any]]:

    conn = db_connection()

    row = conn.execute(
        """
        SELECT *
        FROM translations
        WHERE cache_key = ?
        """,
        (key,),
    ).fetchone()

    if row:

        conn.execute(
            """
            UPDATE translations
            SET last_used_at = ?
            WHERE cache_key = ?
            """,
            (now(), key),
        )

        conn.commit()

    conn.close()

    return dict(row) if row else None


def save_translation_cache(
    key: str,
    source: Optional[str],
    target: str,
    source_text: str,
    translated: str,
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
            key,
            source,
            target,
            source_text,
            translated,
            provider,
            now(),
            now(),
        ),
    )

    conn.commit()
    conn.close()


def openai_translate(
    text: str,
    target: str,
    source: Optional[str],
    preserve_format: bool,
) -> Dict[str, Any]:

    system = """
You are ARYA AgriDoctor's professional multilingual
translation engine.

Translate accurately and naturally.

Never invent facts.
Preserve numbers, units, dates and technical names.
Preserve agricultural terminology.
Preserve pesticide active ingredients exactly.
Preserve dosage values.
Preserve formatting.
Do not add agricultural or medical advice.
Do not summarize.
"""

    result = openai_post_json(
        "/responses",
        {
            "model": TRANSLATION_MODEL,
            "input": [
                {
                    "role": "system",
                    "content": [
                        {
                            "type": "input_text",
                            "text": system,
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                f"Source: "
                                f"{source or 'auto'}\n"
                                f"Target: {target}\n"
                                f"Preserve formatting: "
                                f"{preserve_format}\n\n"
                                f"{text}"
                            ),
                        }
                    ],
                },
            ],
        },
    ).json()

    translated = extract_response_text(
        result
    )

    if not translated:
        raise RuntimeError(
            "Translation provider returned empty text."
        )

    return {
        "text": translated,
        "source_language": source,
        "target_language": target,
        "provider": "openai",
        "model": TRANSLATION_MODEL,
    }


def cleanup_old_audio() -> int:

    cutoff = (
        now()
        - TEMP_FILE_TTL_SECONDS
    )

    deleted = 0

    for path in MEDIA_DIR.iterdir():

        if not path.is_file():
            continue

        try:

            if path.stat().st_mtime < cutoff:

                path.unlink(
                    missing_ok=True
                )

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


@app.get("/")
def root():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "ready",
        "port": PORT,
        "features": [
            "speech_to_text",
            "text_to_speech",
            "translation",
            "language_detection",
            "provider_router",
            "cache",
            "failover_ready",
            "realtime_ready",
            "live_translation_ready",
        ],
    }


@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "openai_configured": bool(
            OPENAI_API_KEY
        ),
        "port": PORT,
        "stt_model": STT_MODEL,
        "tts_model": TTS_MODEL,
        "translation_model": TRANSLATION_MODEL,
        "auto_failover": AUTO_FAILOVER,
        "external_providers": ALLOW_EXTERNAL_PROVIDERS,
    }


@app.get("/voice/languages")
def languages():

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
                    json.loads(
                        row["metadata_json"]
                    )
                    if row["metadata_json"]
                    else {}
                ),
            }
            for row in rows
        ],
    }


async def _save_upload(
    file: UploadFile,
    request_id: str,
) -> Path:

    name = safe_filename(
        file.filename
    )

    path = (
        MEDIA_DIR
        / f"{request_id}"
        f"{audio_extension(name, file.content_type)}"
    )

    size = 0

    try:

        with path.open("wb") as output:

            while True:

                chunk = await file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                size += len(chunk)

                if (
                    size
                    > MAX_AUDIO_MB
                    * 1024
                    * 1024
                ):

                    raise HTTPException(
                        status_code=413,
                        detail="Audio file is too large.",
                    )

                output.write(chunk)

        if size == 0:

            raise HTTPException(
                status_code=400,
                detail="Audio file is empty.",
            )

        return path

    except Exception:

        path.unlink(
            missing_ok=True
        )

        raise


async def _transcribe_upload(
    file: UploadFile,
    language: Optional[str],
):

    request_id = make_id("req")

    path = await _save_upload(
        file,
        request_id,
    )

    language = normalize_language(
        language
    )

    try:

        record_request(
            request_id,
            "transcribe",
            "openai",
            language,
            None,
            None,
            "processing",
        )

        result = openai_transcribe(
            path,
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

    except Exception as exc:

        record_request(
            request_id,
            "transcribe",
            "openai",
            language,
            None,
            None,
            "error",
            str(exc),
        )

        logger.exception(
            "Transcription failed"
        )

        raise HTTPException(
            status_code=502,
            detail="Speech transcription failed.",
        )

    finally:

        path.unlink(
            missing_ok=True
        )


@app.post("/voice/transcribe")
async def transcribe(
    file: UploadFile = File(...),
    language: Optional[str] = Form(None),
):

    return await _transcribe_upload(
        file,
        language,
    )


@app.post("/voice/process")
async def voice_process(
    file: Optional[UploadFile] = File(None),
    language: Optional[str] = Form(None),
    text: Optional[str] = Form(None),
    operation: Optional[str] = Form(None),
    target_language: Optional[str] = Form(None),
):

    operation_value = (
        operation or ""
    ).strip().lower()

    if (
        file is not None
        or operation_value
        in {
            "transcribe",
            "stt",
            "speech_to_text",
        }
    ):

        if file is None:

            raise HTTPException(
                status_code=400,
                detail="Audio file is required.",
            )

        return await _transcribe_upload(
            file,
            language,
        )

    if text:

        text = validate_text(
            text
        )

        if operation_value in {
            "detect",
            "detect_language",
            "language_detection",
        }:

            return {
                "status": "success",
                **detect_language_ai(text),
            }

        if (
            operation_value
            in {
                "translate",
                "translation",
            }
            or target_language
        ):

            target = normalize_language(
                target_language
            )

            if not target:

                raise HTTPException(
                    status_code=400,
                    detail="Target language is required.",
                )

            result = openai_translate(
                text,
                target,
                normalize_language(
                    language
                ),
                True,
            )

            return {
                "status": "success",
                **result,
            }

        return {
            "status": "success",
            "text": text,
            "language": detect_language_heuristic(
                text
            ),
        }

    raise HTTPException(
        status_code=400,
        detail="Voice process requires audio or text.",
    )


@app.post("/voice/speak")
def speak(
    request: SpeakRequest,
):

    text = validate_text(
        request.text
    )

    request_id = make_id("req")

    try:

        path = openai_speak(
            text,
            request.voice,
            request.response_format,
        )

        audio_id = make_id("aud")

        expires = (
            now()
            + TEMP_FILE_TTL_SECONDS
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
                request.voice
                or DEFAULT_TTS_VOICE,
                "openai",
                str(path),
                now(),
                expires,
            ),
        )

        conn.commit()
        conn.close()

        record_request(
            request_id,
            "speak",
            "openai",
            normalize_language(
                request.language
            ),
            None,
            sha256_text(text),
            "success",
        )

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

        record_request(
            request_id,
            "speak",
            "openai",
            normalize_language(
                request.language
            ),
            None,
            sha256_text(text),
            "error",
            str(exc),
        )

        logger.exception(
            "TTS failed"
        )

        raise HTTPException(
            status_code=502,
            detail="Text to speech failed.",
        )


@app.get("/voice/audio/{audio_id}")
def audio(
    audio_id: str,
):

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

    path = Path(
        row["file_path"]
    ).resolve()

    media_root = MEDIA_DIR.resolve()

    if media_root not in path.parents:

        raise HTTPException(
            status_code=403,
            detail="Invalid audio path.",
        )

    if not path.exists():

        raise HTTPException(
            status_code=404,
            detail="Audio file no longer exists.",
        )

    return FileResponse(
        path=path,
        media_type=(
            mimetypes.guess_type(
                str(path)
            )[0]
            or "application/octet-stream"
        ),
        filename=path.name,
    )


@app.post("/voice/detect-language")
def detect_language(
    request: DetectLanguageRequest,
):

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
):

    text = validate_text(
        request.text
    )

    target = normalize_language(
        request.target_language
    )

    source = normalize_language(
        request.source_language
    )

    if not target:

        raise HTTPException(
            status_code=400,
            detail="Invalid target language.",
        )

    key = translation_cache_key(
        text,
        source,
        target,
    )

    cached = get_translation_cache(
        key
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
            text,
            target,
            source,
            request.preserve_format,
        )

        save_translation_cache(
            key,
            source,
            target,
            text,
            result["text"],
            result["provider"],
        )

        record_request(
            request_id,
            "translate",
            result["provider"],
            source,
            target,
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
            source,
            target,
            sha256_text(text),
            "error",
            str(exc),
        )

        raise HTTPException(
            status_code=502,
            detail="Translation failed.",
        )


@app.get("/voice/providers")
def providers():

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
        ORDER BY priority, id
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
):

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

    current_time = now()

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
            current_time,
            current_time,
        ),
    )

    conn.commit()
    conn.close()

    return {
        "status": "success",
        "provider": provider.provider_key,
    }


@app.post("/voice/maintenance/cleanup")
def cleanup():

    return {
        "status": "success",
        "deleted_files": cleanup_old_audio(),
    }


@app.get("/voice/status")
def service_status():

    conn = db_connection()

    requests_count = conn.execute(
        "SELECT COUNT(*) c FROM requests"
    ).fetchone()["c"]

    translations = conn.execute(
        "SELECT COUNT(*) c FROM translations"
    ).fetchone()["c"]

    audio = conn.execute(
        "SELECT COUNT(*) c FROM generated_audio"
    ).fetchone()["c"]

    conn.close()

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "port": PORT,
        "database": DB_PATH,
        "media_directory": str(MEDIA_DIR),
        "requests": requests_count,
        "translation_cache": translations,
        "generated_audio_records": audio,
        "providers": [
            provider.key
            for provider in get_providers()
        ],
    }


@app.on_event("startup")
def startup_event():

    init_db()

    cleanup_old_audio()

    logger.info(
        "%s v%s started on port %s",
        APP_NAME,
        APP_VERSION,
        PORT,
    )


if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "voice_language:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
