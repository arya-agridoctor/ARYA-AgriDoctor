"""
================================================================
                         ARYA VISION
                    ARYA AgriDoctor
                         v2.0.0
================================================================

ماژول مستقل بینایی کشاورزی.

اصل مهم:
- main.py نباید در این فایل قرار گیرد.
- این سرویس مستقل است.
- Providerها قابل تعویض هستند.
- منابع و سایت‌های آینده قابل اضافه شدن هستند.
- اطلاعات قابل به‌روزرسانی و نسخه‌بندی هستند.
- منبع و زمان دریافت داده ثبت می‌شود.
- AI نباید بدون شواهد کافی تشخیص قطعی بدهد.

قابلیت‌ها:
1. دریافت چند تصویر
2. کنترل فرمت و حجم
3. بررسی کیفیت تصویر
4. اصلاح جهت EXIF
5. نرمال‌سازی تصویر
6. شناسایی گیاه
7. تحلیل بیماری
8. تحلیل آفت
9. تحلیل کمبود عناصر
10. تحلیل تنش آبی/حرارتی
11. تشخیص افتراقی
12. ارزیابی شدت
13. پیشنهاد اقدامات بعدی
14. Provider قابل تعویض
15. Provider health check
16. منابع خارجی قابل ثبت
17. به‌روزرسانی خودکار منابع
18. ثبت نسخه دانش
19. ثبت زمان آخرین به‌روزرسانی
20. جلوگیری از استفاده از داده منقضی
21. معماری آماده برای API/siteهای آینده
22. بدون وابستگی به main.py

================================================================
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, ImageOps
from pydantic import BaseModel, Field


# ================================================================
# CONFIGURATION
# ================================================================

APP_NAME = "ARYA Vision"
VERSION = "2.0.0"

HOST = os.getenv(
    "ARYA_VISION_HOST",
    "0.0.0.0",
)

PORT = int(
    os.getenv(
        "ARYA_VISION_PORT",
        "8001",
    )
)

MEDIA_DIR = Path(
    os.getenv(
        "ARYA_VISION_MEDIA_DIR",
        "./vision_media",
    )
)

DB_PATH = Path(
    os.getenv(
        "ARYA_VISION_DB",
        "./vision.db",
    )
)

MAX_UPLOAD_MB = int(
    os.getenv(
        "ARYA_VISION_MAX_UPLOAD_MB",
        "12",
    )
)

MAX_IMAGES_PER_REQUEST = int(
    os.getenv(
        "ARYA_VISION_MAX_IMAGES",
        "4",
    )
)

REQUEST_TIMEOUT = int(
    os.getenv(
        "ARYA_VISION_TIMEOUT",
        "120",
    )
)

MAX_PROVIDER_TIMEOUT = int(
    os.getenv(
        "ARYA_VISION_PROVIDER_TIMEOUT",
        "60",
    )
)

# Provider پیش‌فرض قابل تعویض
VISION_PROVIDER = os.getenv(
    "ARYA_VISION_PROVIDER",
    "openai",
).strip().lower()

# مدل از Environment قابل تغییر است.
VISION_MODEL = os.getenv(
    "ARYA_VISION_MODEL",
    "gpt-5.6-luna",
).strip()

OPENAI_API_KEY = os.getenv(
    "OPENAI_API_KEY",
    "",
).strip()

OPENAI_RESPONSES_URL = os.getenv(
    "ARYA_VISION_OPENAI_URL",
    "https://api.openai.com/v1/responses",
).strip()

# فعال‌سازی به‌روزرسانی خودکار
AUTO_UPDATE_ENABLED = (
    os.getenv(
        "ARYA_VISION_AUTO_UPDATE",
        "true",
    ).lower()
    in {"1", "true", "yes", "on"}
)

UPDATE_INTERVAL_SECONDS = int(
    os.getenv(
        "ARYA_VISION_UPDATE_INTERVAL",
        str(6 * 60 * 60),
    )
)

# فقط برای منابعی که خود OWNER ثبت کرده است.
ALLOW_EXTERNAL_PROVIDERS = (
    os.getenv(
        "ARYA_VISION_ALLOW_EXTERNAL_PROVIDERS",
        "true",
    ).lower()
    in {"1", "true", "yes", "on"}
)

ALLOWED_IMAGE_TYPES = {
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
}

ALLOWED_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
}


# ================================================================
# APP
# ================================================================

app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    description=(
        "Independent agricultural computer vision "
        "and continuously updatable knowledge module."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv(
        "ARYA_VISION_CORS",
        "*",
    ).split(","),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

MEDIA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ================================================================
# TIME
# ================================================================

def utc_now() -> str:
    return (
        datetime.now(
            timezone.utc
        )
        .replace(
            microsecond=0
        )
        .isoformat()
    )


def unix_now() -> int:
    return int(
        time.time()
    )


# ================================================================
# IDENTIFIERS
# ================================================================

def new_id(prefix: str) -> str:
    return (
        prefix
        + "-"
        + uuid.uuid4().hex
    )


def request_id() -> str:
    return new_id(
        "VIS"
    ).upper()


# ================================================================
# JSON
# ================================================================

def json_dumps(
    value: Any,
) -> str:

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(
            ",",
            ":",
        ),
    )


def json_loads(
    value: Any,
    default: Any = None,
) -> Any:

    if value is None:
        return default

    if isinstance(
        value,
        (dict, list),
    ):
        return value

    try:
        return json.loads(
            value
        )
    except Exception:
        return default


# ================================================================
# DATABASE
# ================================================================

def db() -> sqlite3.Connection:

    connection = sqlite3.connect(
        str(DB_PATH),
        timeout=30,
    )

    connection.row_factory = (
        sqlite3.Row
    )

    connection.execute(
        "PRAGMA journal_mode=WAL"
    )

    connection.execute(
        "PRAGMA foreign_keys=ON"
    )

    return connection


def init_db() -> None:

    connection = db()

    try:

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                base_url TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                timeout_seconds INTEGER NOT NULL DEFAULT 60,
                config_json TEXT NOT NULL DEFAULT '{}',
                last_health TEXT,
                last_health_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                source_type TEXT NOT NULL,
                url TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                update_interval_seconds INTEGER NOT NULL DEFAULT 21600,
                last_update_at TEXT,
                last_success_at TEXT,
                last_error TEXT,
                version TEXT,
                checksum TEXT,
                item_count INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_key TEXT NOT NULL,
                item_key TEXT NOT NULL,
                title TEXT,
                category TEXT,
                content_json TEXT NOT NULL,
                version TEXT,
                checksum TEXT,
                source_url TEXT,
                observed_at TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(source
