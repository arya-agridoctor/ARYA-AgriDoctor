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
) -> Optional[datetime]:
    last_attempt = parse_datetime(
        row["last_attempt_at"]
    )

    if last_attempt is None:
        return datetime.now(timezone.utc)

    interval_hours = max(
        1,
        int(row["update_interval_hours"] or 168),
    )

    due_at = last_attempt + timedelta(
        hours=interval_hours
    )

    if due_at.tzinfo is None:
        due_at = due_at.replace(
            tzinfo=timezone.utc
        )

    return due_at


# ============================================================
# Update Source
# ============================================================

async def update_source_data(
    source_id: str,
    force: bool = False,
) -> Dict[str, Any]:
    source = get_source(source_id)

    if source is None:
        raise HTTPException(
            status_code=404,
            detail="Data source not found.",
        )

    if not bool(source["enabled"]):
        raise HTTPException(
            status_code=409,
            detail="Data source is disabled.",
        )

    now = datetime.now(timezone.utc)
    due_at = next_update_due(source)

    if (
        not force
        and due_at is not None
        and now < due_at
    ):
        return {
            "success": True,
            "skipped": True,
            "reason": "Update is not due yet.",
            "source_id": source_id,
            "next_update_due": due_at.isoformat(),
        }

    run_id = str(uuid.uuid4())
    started_at = utc_now()

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO update_runs (
                run_id,
                source_id,
                started_at,
                status
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                run_id,
                source_id,
                started_at,
                "RUNNING",
            ),
        )

        connection.execute(
            """
            UPDATE data_sources
            SET last_attempt_at = ?,
                updated_at = ?
            WHERE source_id = ?
            """,
            (
                started_at,
                started_at,
                source_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    try:
        response = await fetch_url(
            source["url"]
        )

        content = response["content"]

        parsed = parse_content(
            content,
            response["content_type"],
            source["format"],
        )

        validation = validate_data(parsed)

        if not validation["valid"]:
            raise ValueError(
                "; ".join(validation["errors"])
            )

        content_hash = calculate_hash(content)
        content_size = len(content)
        record_count = validation["record_count"]
        completed_at = utc_now()

        previous_hash = source["last_hash"]
        version = (
            str(source["version"] or "0")
        )

        try:
            version_number = int(version)
        except (TypeError, ValueError):
            version_number = 0

        if previous_hash != content_hash:
            version_number += 1

        new_version = str(version_number)

        connection = get_connection()

        try:
            connection.execute(
                """
                UPDATE data_versions
                SET active = 0
                WHERE source_id = ?
                """,
                (source_id,),
            )

            connection.execute(
                """
                INSERT INTO data_versions (
                    version_id,
                    source_id,
                    version,
                    content_hash,
                    content_size,
                    record_count,
                    received_at,
                    valid,
                    active,
                    metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?)
                """,
                (
                    str(uuid.uuid4()),
                    source_id,
                    new_version,
                    content_hash,
                    content_size,
                    record_count,
                    completed_at,
                    json_dumps({
                        "content_type": response["content_type"],
                        "elapsed_ms": response["elapsed_ms"],
                        "changed": previous_hash != content_hash,
                    }),
                ),
            )

            connection.execute(
                """
                UPDATE data_sources
                SET last_success_at = ?,
                    last_error = NULL,
                    last_http_status = ?,
                    last_hash = ?,
                    last_size = ?,
                    record_count = ?,
                    version = ?,
                    updated_at = ?
                WHERE source_id = ?
                """,
                (
                    completed_at,
                    response["status_code"],
                    content_hash,
                    content_size,
                    record_count,
                    new_version,
                    completed_at,
                    source_id,
                ),
            )

            connection.execute(
                """
                UPDATE update_runs
                SET completed_at = ?,
                    success = 1,
                    status = 'SUCCESS',
                    http_status = ?,
                    content_hash = ?,
                    content_size = ?,
                    record_count = ?,
                    metadata_json = ?
                WHERE run_id = ?
                """,
                (
                    completed_at,
                    response["status_code"],
                    content_hash,
                    content_size,
                    record_count,
                    json_dumps({
                        "content_type": response["content_type"],
                        "elapsed_ms": response["elapsed_ms"],
                        "changed": previous_hash != content_hash,
                    }),
                    run_id,
                ),
            )

            connection.commit()

        finally:
            connection.close()

        log_event(
            "UPDATE_SUCCESS",
            "Data source updated successfully.",
            source_id=source_id,
            metadata={
                "run_id": run_id,
                "version": new_version,
                "content_hash": content_hash,
                "record_count": record_count,
            },
        )

        return {
            "success": True,
            "skipped": False,
            "run_id": run_id,
            "source_id": source_id,
            "version": new_version,
            "content_hash": content_hash,
            "content_size": content_size,
            "record_count": record_count,
            "http_status": response["status_code"],
            "completed_at": completed_at,
            "changed": previous_hash != content_hash,
        }

    except Exception as exc:
        completed_at = utc_now()
        error_message = str(exc)[:4000]

        connection = get_connection()

        try:
            connection.execute(
                """
                UPDATE data_sources
                SET last_error = ?,
                    updated_at = ?
                WHERE source_id = ?
                """,
                (
                    error_message,
                    completed_at,
                    source_id,
                ),
            )

            connection.execute(
                """
                UPDATE update_runs
                SET completed_at = ?,
                    success = 0,
                    status = 'FAILED',
                    error = ?
                WHERE run_id = ?
                """,
                (
                    completed_at,
                    error_message,
                    run_id,
                ),
            )

            connection.commit()

        finally:
            connection.close()

        log_event(
            "UPDATE_FAILED",
            "Data source update failed.",
            source_id=source_id,
            severity="ERROR",
            metadata={
                "run_id": run_id,
                "error": error_message,
            },
        )

        logger.exception(
            "Data update failed for source %s",
            source_id,
        )

        return {
            "success": False,
            "skipped": False,
            "run_id": run_id,
            "source_id": source_id,
            "error": error_message,
            "completed_at": completed_at,
        }


# ============================================================
# API: Health
# ============================================================

@app.get("/health")
def health() -> Dict[str, Any]:
    connection = get_connection()

    try:
        connection.execute(
            "SELECT 1"
        ).fetchone()

        return {
            "success": True,
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "database": "ok",
            "timestamp": utc_now(),
        }

    finally:
        connection.close()


# ============================================================
# API: Sources
# ============================================================

@app.post("/sources", status_code=201)
def api_register_source(
    data: SourceCreate,
) -> Dict[str, Any]:
    try:
        return {
            "success": True,
            "source": register_source(data),
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@app.get("/sources")
def api_list_sources(
    category: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    conditions = []
    parameters: List[Any] = []

    if category is not None:
        conditions.append("category = ?")
        parameters.append(category)

    if enabled is not None:
        conditions.append("enabled = ?")
        parameters.append(int(enabled))

    sql = "SELECT * FROM data_sources"

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    sql += " ORDER BY priority ASC, name ASC"

    connection = get_connection()

    try:
        rows = connection.execute(
            sql,
            parameters,
        ).fetchall()

        return {
            "success": True,
            "count": len(rows),
            "sources": [
                source_to_dict(row)
                for row in rows
            ],
        }

    finally:
        connection.close()


@app.get("/sources/{source_id}")
def api_get_source(
    source_id: str,
) -> Dict[str, Any]:
    source = get_source(source_id)

    if source is None:
        raise HTTPException(
            status_code=404,
            detail="Data source not found.",
        )

    return {
        "success": True,
        "source": source_to_dict(source),
        "stale": is_source_stale(source),
        "next_update_due": (
            next_update_due(source).isoformat()
            if next_update_due(source)
            else None
        ),
    }


@app.patch("/sources/{source_id}")
def api_update_source(
    source_id: str,
    data: SourceUpdate,
) -> Dict[str, Any]:
    current = get_source(source_id)

    if current is None:
        raise HTTPException(
            status_code=404,
            detail="Data source not found.",
        )

    updates = data.model_dump(
        exclude_unset=True,
    )

    if not updates:
        return {
            "success": True,
            "source": source_to_dict(current),
        }

    if "url" in updates and updates["url"] is not None:
        try:
            validate_external_url(updates["url"])
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

    if "format" in updates and updates["format"] is not None:
        updates["format"] = updates["format"].lower()

    if "metadata" in updates:
        updates["metadata_json"] = json_dumps(
            updates.pop("metadata") or {}
        )

    allowed = {
        "name",
        "category",
        "url",
        "format",
        "enabled",
        "trusted",
        "priority",
        "update_interval_hours",
        "stale_after_hours",
        "metadata_json",
    }

    updates = {
        key: value
        for key, value in updates.items()
        if key in allowed and value is not None
    }

    if updates:
        updates["updated_at"] = utc_now()

        assignments = ", ".join(
            f"{key} = ?"
            for key in updates
        )

        connection = get_connection()

        try:
            connection.execute(
                f"""
                UPDATE data_sources
                SET {assignments}
                WHERE source_id = ?
                """,
                [
                    *updates.values(),
                    source_id,
                ],
            )

            connection.commit()

        finally:
            connection.close()

    updated = get_source(source_id)

    return {
        "success": True,
        "source": source_to_dict(updated),
    }


@app.delete("/sources/{source_id}")
def api_delete_source(
    source_id: str,
) -> Dict[str, Any]:
    source = get_source(source_id)

    if source is None:
        raise HTTPException(
            status_code=404,
            detail="Data source not found.",
        )

    connection = get_connection()

    try:
        connection.execute(
            """
            DELETE FROM data_sources
            WHERE source_id = ?
            """,
            (source_id,),
        )

        connection.commit()

    finally:
        connection.close()

    log_event(
        "SOURCE_DELETED",
        "Data source deleted.",
        source_id=source_id,
    )

    return {
        "success": True,
        "source_id": source_id,
        "deleted": True,
    }


# ============================================================
# API: Updates
# ============================================================

@app.post("/updates/run")
async def api_run_update(
    request: FetchRequest,
) -> Dict[str, Any]:
    return await update_source_data(
        request.source_id,
        force=request.force,
    )


@app.post("/updates/batch")
async def api_run_batch(
    request: UpdateBatchRequest,
) -> Dict[str, Any]:
    connection = get_connection()

    try:
        if request.source_ids:
            placeholders = ",".join(
                "?" for _ in request.source_ids
            )

            rows = connection.execute(
                f"""
                SELECT source_id
                FROM data_sources
                WHERE enabled = 1
                  AND source_id IN ({placeholders})
                ORDER BY priority ASC
                """,
                request.source_ids,
            ).fetchall()

        else:
            rows = connection.execute(
                """
                SELECT source_id
                FROM data_sources
                WHERE enabled = 1
                ORDER BY priority ASC
                """
            ).fetchall()

        source_ids = [
            row["source_id"]
            for row in rows
        ]

    finally:
        connection.close()

    results = []

    for source_id in source_ids:
        result = await update_source_data(
            source_id,
            force=request.force,
        )
        results.append(result)

    return {
        "success": all(
            item.get("success", False)
            for item in results
        ),
        "count": len(results),
        "results": results,
    }


@app.get("/updates/history")
def api_update_history(
    source_id: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    limit = max(
        1,
        min(limit, 1000),
    )

    connection = get_connection()

    try:
        if source_id:
            rows = connection.execute(
                """
                SELECT *
                FROM update_runs
                WHERE source_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (source_id, limit),
            ).fetchall()

        else:
            rows = connection.execute(
                """
                SELECT *
                FROM update_runs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        runs = []

        for row in rows:
            item = dict(row)
            item["success"] = bool(
                item["success"]
            )
            item["metadata"] = json_loads(
                item.pop("metadata_json", "{}")
            )
            runs.append(item)

        return {
            "success": True,
            "count": len(runs),
            "runs": runs,
        }

    finally:
        connection.close()


# ============================================================
# API: Versions and Events
# ============================================================

@app.get("/sources/{source_id}/versions")
def api_source_versions(
    source_id: str,
    limit: int = 100,
) -> Dict[str, Any]:
    limit = max(
        1,
        min(limit, 1000),
    )

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM data_versions
            WHERE source_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (source_id, limit),
        ).fetchall()

        versions = []

        for row in rows:
            item = dict(row)
            item["valid"] = bool(item["valid"])
            item["active"] = bool(item["active"])
            item["metadata"] = json_loads(
                item.pop("metadata_json", "{}")
            )
            versions.append(item)

        return {
            "success": True,
            "count": len(versions),
            "versions": versions,
        }

    finally:
        connection.close()


@app.get("/events")
def api_events(
    source_id: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    limit = max(
        1,
        min(limit, 1000),
    )

    connection = get_connection()

    try:
        if source_id:
            rows = connection.execute(
                """
                SELECT *
                FROM update_events
                WHERE source_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (source_id, limit),
            ).fetchall()

        else:
            rows = connection.execute(
                """
                SELECT *
                FROM update_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        events = []

        for row in rows:
            item = dict(row)
            item["metadata"] = json_loads(
                item.pop("metadata_json", "{}")
            )
            events.append(item)

        return {
            "success": True,
            "count": len(events),
            "events": events,
        }

    finally:
        connection.close()


# ============================================================
# API: Stale Sources and Statistics
# ============================================================

@app.get("/sources/stale")
def api_stale_sources() -> Dict[str, Any]:
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM data_sources
            WHERE enabled = 1
            ORDER BY priority ASC
            """
        ).fetchall()

        stale_sources = [
            source_to_dict(row)
            for row in rows
            if is_source_stale(row)
        ]

        return {
            "success": True,
            "count": len(stale_sources),
            "sources": stale_sources,
        }

    finally:
        connection.close()


@app.get("/stats")
def api_stats() -> Dict[str, Any]:
    connection = get_connection()

    try:
        sources = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(enabled), 0) AS enabled,
                COALESCE(SUM(trusted), 0) AS trusted
            FROM data_sources
            """
        ).fetchone()

        runs = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(success), 0) AS successful
            FROM update_runs
            """
        ).fetchone()

        versions = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM data_versions
            """
        ).fetchone()

        events = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM update_events
            """
        ).fetchone()

        return {
            "success": True,
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "sources": {
                "total": sources["total"],
                "enabled": sources["enabled"],
                "trusted": sources["trusted"],
            },
            "updates": {
                "total": runs["total"],
                "successful": runs["successful"],
                "failed": (
                    runs["total"] - runs["successful"]
                ),
            },
            "versions": versions["total"],
            "events": events["total"],
            "timestamp": utc_now(),
        }

    finally:
        connection.close()


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup_event() -> None:
    initialize_database()

    logger.info(
        "%s v%s started",
        SERVICE_NAME,
        SERVICE_VERSION,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
    )
