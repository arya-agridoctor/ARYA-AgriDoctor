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
    target_language:
