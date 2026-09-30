"""
ARYA AgriDoctor
Global Data & Automatic Update Manager
Version: 1.0.0

این ماژول مسئول مدیریت منابع داده، دریافت اطلاعات،
نسخه‌بندی، اعتبارسنجی، ثبت خطا، تشخیص داده قدیمی
و آماده‌سازی زیرساخت به‌روزرسانی جهانی ARYA است.

این فایل مستقل است و به main.py و سایر ماژول‌های موجود
نیازی به تغییر ندارد.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import socket
import time
import uuid

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

SERVICE_NAME = "ARYA Global Data Update Manager"
SERVICE_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_DATA_UPDATE_HOST",
    "0.0.0.0",
)

PORT = int(
    os.getenv(
        "ARYA_DATA_UPDATE_PORT",
        "8011",
    )
)

DATABASE_PATH = os.getenv(
    "ARYA_DATA_UPDATE_DATABASE",
    os.path.join(
        os.path.dirname(__file__),
        "data_update.db",
    ),
)

DEFAULT_TIMEOUT = float(
    os.getenv(
        "ARYA_DATA_UPDATE_TIMEOUT",
        "30",
    )
)

MAX_RESPONSE_SIZE = int(
    os.getenv(
        "ARYA_DATA_UPDATE_MAX_RESPONSE",
        "5000000",
    )
)

DEFAULT_STALE_HOURS = int(
    os.getenv(
        "ARYA_DATA_UPDATE_STALE_HOURS",
        "168",
    )
)

USER_AGENT = os.getenv(
    "ARYA_DATA_UPDATE_USER_AGENT",
    "ARYA-AgriDoctor-DataManager/1.0",
)

LOG_LEVEL = os.getenv(
    "ARYA_DATA_UPDATE_LOG_LEVEL",
    "INFO",
).upper()


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    level=getattr(
        logging,
        LOG_LEVEL,
        logging.INFO,
    ),
    format=(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    ),
)

logger = logging.getLogger(
    "arya.data_update"
)


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title="ARYA Global Data Update Manager",
    description=(
        "Central data-source registry, update, validation "
        "and freshness management service for ARYA AgriDoctor."
    ),
    version=SERVICE_VERSION,
)


# ============================================================
# Database
# ============================================================

import sqlite3


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database() -> None:

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS data_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                url TEXT NOT NULL,
                format TEXT NOT NULL DEFAULT 'json',
                enabled INTEGER NOT NULL DEFAULT 1,
                trusted INTEGER NOT NULL DEFAULT 0,
                priority INTEGER NOT NULL DEFAULT 100,
                update_interval_hours INTEGER NOT NULL DEFAULT 168,
                stale_after_hours INTEGER NOT NULL DEFAULT 168,
                last_success_at TEXT,
                last_attempt_at TEXT,
                last_error TEXT,
                last_http_status INTEGER,
                last_hash TEXT,
                last_size INTEGER,
                record_count INTEGER NOT NULL DEFAULT 0,
                version TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS update_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL UNIQUE,
                source_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                success INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                http_status INTEGER,
                content_hash TEXT,
                content_size INTEGER,
                record_count INTEGER,
                error TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS data_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id TEXT NOT NULL UNIQUE,
                source_id TEXT NOT NULL,
                version TEXT,
                content_hash TEXT NOT NULL,
                content_size INTEGER NOT NULL DEFAULT 0,
                record_count INTEGER NOT NULL DEFAULT 0,
                received_at TEXT NOT NULL,
                valid INTEGER NOT NULL DEFAULT 1,
                active INTEGER NOT NULL DEFAULT 1,
                validation_error TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS update_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                source_id TEXT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_sources_category
            ON data_sources(category)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_sources_enabled
            ON data_sources(enabled)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_versions_source
            ON data_versions(source_id)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_runs_source
            ON update_runs(source_id)
            """
        )

        connection.commit()

    finally:
        connection.close()


initialize_database()


# ============================================================
# Models
# ============================================================

class SourceCreate(BaseModel):

    source_id: Optional[str] = None

    name: str = Field(
        ...,
        min_length=2,
        max_length=200,
    )

    category: str = Field(
        ...,
        min_length=2,
        max_length=100,
    )

    url: str = Field(
        ...,
        min_length=8,
        max_length=2000,
    )

    format: str = Field(
        default="json",
        max_length=30,
    )

    enabled: bool = True

    trusted: bool = False

    priority: int = Field(
        default=100,
        ge=1,
        le=10000,
    )

    update_interval_hours: int = Field(
        default=168,
        ge=1,
        le=8760,
    )

    stale_after_hours: int = Field(
        default=168,
        ge=1,
        le=8760,
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
    )


class SourceUpdate(BaseModel):

    name: Optional[str] = None
    category: Optional[str] = None
    url: Optional[str] = None
    format: Optional[str] = None

    enabled: Optional[bool] = None
    trusted: Optional[bool] = None

    priority: Optional[int] = Field(
        default=None,
        ge=1,
        le=10000,
    )

    update_interval_hours: Optional[int] = Field(
        default=None,
        ge=1,
        le=8760,
    )

    stale_after_hours: Optional[int] = Field(
        default=None,
        ge=1,
        le=8760,
    )

    metadata: Optional[Dict[str, Any]] = None


class FetchRequest(BaseModel):

    source_id: str

    force: bool = False


class UpdateBatchRequest(BaseModel):

    source_ids: Optional[List[str]] = None

    force: bool = False


# ============================================================
# Time Helpers
# ============================================================

def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def parse_datetime(
    value: Optional[str],
) -> Optional[datetime]:

    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00",
            )
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except Exception:
        return None


# ============================================================
# Security / URL Validation
# ============================================================

def is_private_or_reserved_host(
    hostname: str,
) -> bool:

    try:

        addresses = socket.getaddrinfo(
            hostname,
            None,
        )

        for address in addresses:

            ip_value = address[4][0]

            ip = ipaddress.ip_address(
                ip_value
            )

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return True

        return False

    except Exception:

        return True


def validate_external_url(
    url: str,
) -> None:

    parsed = urlparse(url)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Only HTTP and HTTPS URLs are allowed."
        )

    hostname = parsed.hostname

    if not hostname:
        raise ValueError(
            "URL hostname is missing."
        )

    hostname = hostname.lower()

    blocked_hosts = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
    }

    if hostname in blocked_hosts:
        raise ValueError(
            "Local or metadata hosts are not allowed."
        )

    if is_private_or_reserved_host(
        hostname
    ):
        raise ValueError(
            "Private, loopback, reserved or local network addresses are not allowed."
        )


# ============================================================
# JSON Helpers
# ============================================================

def json_dumps(
    value: Any,
) -> str:

    return json.dumps(
        value,
        ensure_ascii=False,
        default=str,
    )


def json_loads(
    value: Optional[str],
) -> Dict[str, Any]:

    if not value:
        return {}

    try:
        result = json.loads(value)

        if isinstance(result, dict):
            return result

        return {
            "value": result
        }

    except Exception:

        return {}


# ============================================================
# Logging Events
# ============================================================

def log_event(
    event_type: str,
    message: str,
    source_id: Optional[str] = None,
    severity: str = "INFO",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:

    connection = get_connection()

    try:

        connection.execute(
            """
            INSERT INTO update_events (
                event_id,
                source_id,
                event_type,
                severity,
                message,
                created_at,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                source_id,
                event_type,
                severity,
                message,
                utc_now(),
                json_dumps(
                    metadata or {}
                ),
            ),
        )

        connection.commit()

    finally:
        connection.close()


# ============================================================
# Source Helpers
# ============================================================

def get_source(
    source_id: str,
) -> Optional[sqlite3.Row]:

    connection = get_connection()

    try:

        return connection.execute(
            """
            SELECT *
            FROM data_sources
            WHERE source_id = ?
            """,
            (source_id,),
        ).fetchone()

    finally:
        connection.close()


def source_to_dict(
    row: sqlite3.Row,
) -> Dict[str, Any]:

    result = dict(row)

    result["enabled"] = bool(
        result["enabled"]
    )

    result["trusted"] = bool(
        result["trusted"]
    )

    result["metadata"] = json_loads(
        result.pop(
            "metadata_json",
            "{}",
        )
    )

    return result


# ============================================================
# Source Registration
# ============================================================

def register_source(
    data: SourceCreate,
) -> Dict[str, Any]:

    validate_external_url(
        data.url
    )

    source_id = (
        data.source_id
        or str(uuid.uuid4())
    )

    now = utc_now()

    connection = get_connection()

    try:

        existing = connection.execute(
            """
            SELECT source_id
            FROM data_sources
            WHERE source_id = ?
            """,
            (source_id,),
        ).fetchone()

        if existing:
            raise ValueError(
                "Source ID already exists."
            )

        connection.execute(
            """
            INSERT INTO data_sources (
                source_id,
                name,
                category,
                url,
                format,
                enabled,
                trusted,
                priority,
                update_interval_hours,
                stale_after_hours,
                metadata_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                data.name,
                data.category,
                data.url,
                data.format.lower(),
                int(data.enabled),
                int(data.trusted),
                data.priority,
                data.update_interval_hours,
                data.stale_after_hours,
                json_dumps(
                    data.metadata
                ),
                now,
                now,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    log_event(
        "SOURCE_REGISTERED",
        f"Data source '{data.name}' registered.",
        source_id=source_id,
        metadata={
            "category": data.category,
            "trusted": data.trusted,
        },
    )

    row = get_source(
        source_id
    )

    return source_to_dict(row)


# ============================================================
# HTTP Fetch
# ============================================================

async def fetch_url(
    url: str,
) -> Dict[str, Any]:

    validate_external_url(
        url
    )

    import httpx

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": (
            "application/json,"
            "application/xml,"
            "text/xml,"
            "text/plain,"
            "text/csv,"
            "application/rss+xml,"
            "*/*"
        ),
    }

    started = time.perf_counter()

    timeout = httpx.Timeout(
        DEFAULT_TIMEOUT
    )

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
    ) as client:

        response = await client.get(
            url,
            headers=headers,
        )

    elapsed_ms = (
        time.perf_counter()
        - started
    ) * 1000

    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            f"HTTP request failed with status "
            f"{response.status_code}."
        )

    content = response.content

    if len(content) > MAX_RESPONSE_SIZE:
        raise RuntimeError(
            "Remote response exceeds configured maximum size."
        )

    return {
        "status_code": response.status_code,
        "content": content,
        "content_type": response.headers.get(
            "content-type",
            "",
        ),
        "elapsed_ms": round(
            elapsed_ms,
            2,
        ),
    }


# ============================================================
# Data Parsing
# ============================================================

def parse_content(
    content: bytes,
    content_type: str,
    source_format: str,
) -> Dict[str, Any]:

    detected_format = (
        source_format or ""
    ).lower().strip()

    text = content.decode(
        "utf-8",
        errors="replace",
    )

    if detected_format == "json":

        try:
            parsed = json.loads(
                text
            )

            if isinstance(parsed, list):
                count = len(parsed)

            elif isinstance(parsed, dict):

                if isinstance(
                    parsed.get("data"),
                    list,
                ):
                    count = len(
                        parsed["data"]
                    )

                elif isinstance(
                    parsed.get("items"),
                    list,
                ):
                    count = len(
                        parsed["items"]
                    )

                else:
                    count = 1

            else:
                count = 1

            return {
                "format": "json",
                "data": parsed,
                "record_count": count,
            }

        except Exception as exc:
            raise ValueError(
                f"Invalid JSON data: {exc}"
            )

    if detected_format in {
        "text",
        "txt",
    }:

        return {
            "format": "text",
            "data": text,
            "record_count": 1 if text else 0,
        }

    if detected_format == "csv":

        import csv
        import io

        reader = csv.DictReader(
            io.StringIO(text)
        )

        rows = list(reader)

        return {
            "format": "csv",
            "data": rows,
            "record_count": len(rows),
        }

    if detected_format in {
        "xml",
        "rss",
        "atom",
    }:

        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(
                content
            )

            return {
                "format": detected_format,
                "data": {
                    "root_tag": root.tag,
                    "xml": text,
                },
                "record_count": 1,
            }

        except Exception as exc:

            raise ValueError(
                f"Invalid XML data: {exc}"
            )

    content_type_lower = (
        content_type.lower()
    )

    if "json" in content_type_lower:

        try:
            parsed = json.loads(
                text
            )

            return {
                "format": "json",
                "data": parsed,
                "record_count": (
                    len(parsed)
                    if isinstance(
                        parsed,
                        list,
                    )
                    else 1
                ),
            }

        except Exception:
            pass

    return {
        "format": "text",
        "data": text,
        "record_count": 1 if text else 0,
    }


# ============================================================
# Data Validation
# ============================================================

def validate_data(
    parsed: Dict[str, Any],
) -> Dict[str, Any]:

    errors: List[str] = []

    data = parsed.get(
        "data"
    )

    if data is None:
        errors.append(
            "Data payload is empty."
        )

    record_count = int(
        parsed.get(
            "record_count",
            0,
        )
    )

    if record_count < 0:
        errors.append(
            "Invalid record count."
        )

    if isinstance(
        data,
        str,
    ) and len(data.strip()) == 0:

        errors.append(
            "Text payload is empty."
        )

    valid = not errors

    return {
        "valid": valid,
        "errors": errors,
        "record_count": record_count,
    }


# ============================================================
# Hash
# ============================================================

def calculate_hash(
    content: bytes,
) -> str:

    return hashlib.sha256(
        content
    ).hexdigest()


# ============================================================
# Staleness
# ============================================================

def is_source_stale(
    row: sqlite3.Row,
) -> bool:

    last_success = parse_datetime(
        row["last_success_at"]
    )

    if not last_success:
        return True

    stale_hours = int(
        row["stale_after_hours"]
        or DEFAULT_STALE_HOURS
    )

    age = (
        datetime.now(
            timezone.utc
        )
        - last_success
    )

    return age >= timedelta(
        hours=stale_hours
    )


def next_update_due(
    row: sqlite3.Row,
