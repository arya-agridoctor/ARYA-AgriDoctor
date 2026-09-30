"""
ARYA Central Configuration
==========================

Central configuration service for ARYA AgriDoctor.

Purpose:
- Centralize runtime/service configuration.
- Store service URLs and ports.
- Store provider configuration.
- Manage feature flags and runtime limits.
- Provide OWNER-controlled configuration.
- Keep secrets out of API responses.
- Persist configuration in SQLite.
- Allow future services/providers without modifying main.py.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Central Configuration"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_CENTRAL_CONFIG_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_CENTRAL_CONFIG_PORT",
        "8025",
    )
)

DB_PATH = os.getenv(
    "ARYA_CENTRAL_CONFIG_DB",
    "arya_central_config.db",
)

MASTER_EMAIL = os.getenv(
    "ARYA_MASTER_EMAIL",
    "",
)

MASTER_SECRET = os.getenv(
    "ARYA_MASTER_SECRET",
    "",
)

CONFIG_SESSION_TTL = int(
    os.getenv(
        "ARYA_CENTRAL_CONFIG_SESSION_TTL",
        "3600",
    )
)

AUDIT_RETENTION_DAYS = int(
    os.getenv(
        "ARYA_CENTRAL_CONFIG_AUDIT_RETENTION_DAYS",
        "365",
    )
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Central configuration and runtime settings service "
        "for ARYA AgriDoctor."
    ),
)


# ============================================================
# Database
# ============================================================

def db() -> sqlite3.Connection:
    connection = sqlite3.connect(
        DB_PATH,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    connection = db()

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            value_type TEXT NOT NULL DEFAULT 'string',
            category TEXT NOT NULL DEFAULT 'general',
            secret INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            description TEXT,
            updated_at INTEGER NOT NULL,
            updated_by TEXT
        );

        CREATE TABLE IF NOT EXISTS services (
            service_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            health_url TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            critical INTEGER NOT NULL DEFAULT 0,
            priority INTEGER NOT NULL DEFAULT 100,
            timeout REAL NOT NULL DEFAULT 30,
            retry_count INTEGER NOT NULL DEFAULT 2,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            updated_at INTEGER NOT NULL,
            updated_by TEXT
        );

        CREATE TABLE IF NOT EXISTS providers (
            provider_id TEXT PRIMARY KEY,
            provider_type TEXT NOT NULL,
            name TEXT NOT NULL,
            base_url TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 100,
            timeout REAL NOT NULL DEFAULT 30,
            secret_ref TEXT,
            capabilities_json TEXT NOT NULL DEFAULT '[]',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            updated_at INTEGER NOT NULL,
            updated_by TEXT
        );

        CREATE TABLE IF NOT EXISTS feature_flags (
            feature_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            description TEXT,
            updated_at INTEGER NOT NULL,
            updated_by TEXT
        );

        CREATE TABLE IF NOT EXISTS config_versions (
            version_id TEXT PRIMARY KEY,
            version_number INTEGER NOT NULL,
            snapshot_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            created_by TEXT,
            note TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL,
            owner_email TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            actor TEXT,
            details_json TEXT,
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_created
        ON audit_logs(created_at);

        CREATE INDEX IF NOT EXISTS idx_sessions_token
        ON sessions(token_hash);
        """
    )

    connection.commit()
    connection.close()


init_db()


# ============================================================
# Helpers
# ============================================================

def now() -> int:
    return int(time.time())


def bool_int(value: bool) -> int:
    return 1 if value else 0


def hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def audit(
    action: str,
    target: Optional[str],
    actor: Optional[str],
    details: Optional[Dict[str, Any]] = None,
) -> None:
    connection = db()

    connection.execute(
        """
        INSERT INTO audit_logs
        (
            event_id,
            action,
            target,
            actor,
            details_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            uuid.uuid4().hex,
            action,
            target,
            actor,
            json.dumps(
                details or {},
                ensure_ascii=False,
            ),
            now(),
        ),
    )

    connection.commit()
    connection.close()


def parse_value(
    value: str,
    value_type: str,
) -> Any:

    if value_type == "integer":
        return int(value)

    if value_type == "float":
        return float(value)

    if value_type == "boolean":
        return value.lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    if value_type == "json":
        return json.loads(value)

    return value


def serialize_value(
    value: Any,
    value_type: str,
) -> str:

    if value_type == "json":
        return json.dumps(
            value,
            ensure_ascii=False,
        )

    if value_type == "boolean":
        return (
            "true"
            if bool(value)
            else "false"
        )

    return str(value)


# ============================================================
# Owner Authentication
# ============================================================

def create_session(
    email: str,
) -> Dict[str, Any]:

    raw_token = secrets.token_urlsafe(48)

    created = now()
    expires = (
        created
        + CONFIG_SESSION_TTL
    )

    connection = db()

    connection.execute(
        """
        INSERT INTO sessions
        (
            session_id,
            token_hash,
            owner_email,
            created_at,
            expires_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            uuid.uuid4().hex,
            hash_token(raw_token),
            email,
            created,
            expires,
        ),
    )

    connection.commit()
    connection.close()

    return {
        "token": raw_token,
        "expires_at": expires,
    }


def owner_from_token(
    authorization: Optional[str],
) -> str:

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="OWNER authentication required",
        )

    if not authorization.lower().startswith(
        "bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization scheme",
        )

    token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing session token",
        )

    token_hash = hash_token(token)

    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM sessions
        WHERE token_hash = ?
        AND revoked = 0
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (token_hash,),
    ).fetchone()

    connection.close()

    if row is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER session",
        )

    if row["expires_at"] < now():
        raise HTTPException(
            status_code=401,
            detail="OWNER session expired",
        )

    return row["owner_email"]


# ============================================================
# Models
# ============================================================

class OwnerLogin(BaseModel):
    email: str
    secret: str


class SettingInput(BaseModel):
    key: str
    value: Any
    value_type: str = "string"
    category: str = "general"
    secret: bool = False
    enabled: bool = True
    description: Optional[str] = None


class ServiceInput(BaseModel):
    service_id: str
    name: str
    url: str
    health_url: Optional[str] = None
    enabled: bool = True
    critical: bool = False
    priority: int = 100
    timeout: float = 30
    retry_count: int = 2
    metadata: Dict[str, Any] = Field(
        default_factory=dict
    )


class ProviderInput(BaseModel):
    provider_id: str
    provider_type: str
    name: str
    base_url: Optional[str] = None
    enabled: bool = True
    priority: int = 100
    timeout: float = 30
    secret_ref: Optional[str] = None
    capabilities: list[str] = Field(
        default_factory=list
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict
    )


class FeatureInput(BaseModel):
    feature_id: str
    enabled: bool
    description: Optional[str] = None


class SnapshotInput(BaseModel):
    note: Optional[str] = None


# ============================================================
# Root / Health
# ============================================================

@app.get("/")
async def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "database": DB_PATH,
        "timestamp": now(),
    }


@app.get("/health")
async def health():
    connection = db()

    settings = connection.execute(
        "SELECT COUNT(*) AS c FROM settings"
    ).fetchone()["c"]

    services = connection.execute(
        "SELECT COUNT(*) AS c FROM services"
    ).fetchone()["c"]

    providers = connection.execute(
        "SELECT COUNT(*) AS c FROM providers"
    ).fetchone()["c"]

    connection.close()

    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "settings": settings,
        "services": services,
        "providers": providers,
        "timestamp": now(),
    }


# ============================================================
# OWNER Login
# ============================================================

@app.post("/owner/login")
async def owner_login(
    data: OwnerLogin,
):
    if not MASTER_EMAIL:
        raise HTTPException(
            status_code=503,
            detail="ARYA_MASTER_EMAIL is not configured",
        )

    if not MASTER_SECRET:
        raise HTTPException(
            status_code=503,
            detail="ARYA_MASTER_SECRET is not configured",
        )

    if data.email.strip().lower() != (
        MASTER_EMAIL.strip().lower()
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials",
        )

    if not hmac.compare_digest(
        data.secret,
        MASTER_SECRET,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials",
        )

    session = create_session(
        data.email.strip()
    )

    audit(
        "owner_login",
        "central_configuration",
        data.email.strip(),
    )

    return {
        "status": "authenticated",
        "token": session["token"],
        "expires_at": session["expires_at"],
    }


@app.post("/owner/logout")
async def owner_logout(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    token = authorization[7:].strip()

    connection = db()

    connection.execute(
        """
        UPDATE sessions
        SET revoked = 1
        WHERE token_hash = ?
        """,
        (hash_token(token),),
    )

    connection.commit()
    connection.close()

    audit(
        "owner_logout",
        "central_configuration",
        owner,
    )

    return {
        "status": "logged_out"
    }


# ============================================================
# Settings
# ============================================================

@app.get("/config/settings")
async def list_settings(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM settings
        ORDER BY category, key
        """
    ).fetchall()

    connection.close()

    result = []

    for row in rows:

        item = {
            "key": row["key"],
            "value_type": row["value_type"],
            "category": row["category"],
            "enabled": bool(
                row["enabled"]
            ),
            "description": row["description"],
            "updated_at": row["updated_at"],
        }

        if row["secret"]:
            item["secret"] = True
            item["value"] = None
        else:
            item["secret"] = False
            item["value"] = parse_value(
                row["value"],
                row["value_type"],
            )

        result.append(item)

    audit(
        "settings_list",
        "settings",
        owner,
    )

    return {
        "settings": result
    }


@app.post("/config/settings")
async def upsert_setting(
    data: SettingInput,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    allowed_types = {
        "string",
        "integer",
        "float",
        "boolean",
        "json",
    }

    if data.value_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Unsupported value_type",
        )

    serialized = serialize_value(
        data.value,
        data.value_type,
    )

    connection = db()

    connection.execute(
        """
        INSERT INTO settings
        (
            key,
            value,
            value_type,
            category,
            secret,
            enabled,
            description,
            updated_at,
            updated_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key)
        DO UPDATE SET
            value = excluded.value,
            value_type = excluded.value_type,
            category = excluded.category,
            secret = excluded.secret,
            enabled = excluded.enabled,
            description = excluded.description,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by
        """,
        (
            data.key,
            serialized,
            data.value_type,
            data.category,
            bool_int(data.secret),
            bool_int(data.enabled),
            data.description,
            now(),
            owner,
        ),
    )

    connection.commit()
    connection.close()

    audit(
        "setting_upsert",
        data.key,
        owner,
    )

    return {
        "status": "updated",
        "key": data.key,
    }


# ============================================================
# Services
# ============================================================

@app.get("/config/services")
async def list_services(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM services
        ORDER BY priority, service_id
        """
    ).fetchall()

    connection.close()

    result = []

    for row in rows:
        result.append({
            "service_id": row["service_id"],
            "name": row["name"],
            "url": row["url"],
            "health_url": row["health_url"],
            "enabled": bool(
                row["enabled"]
            ),
            "critical": bool(
                row["critical"]
            ),
            "priority": row["priority"],
            "timeout": row["timeout"],
            "retry_count": row["retry_count"],
            "metadata": json.loads(
                row["metadata_json"]
            ),
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"],
        })

    audit(
        "services_list",
        "services",
        owner,
    )

    return {
        "services": result
    }


@app.post("/config/services")
async def upsert_service(
    data: ServiceInput,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    if not (
        data.url.startswith("http://")
        or data.url.startswith("https://")
    ):
        raise HTTPException(
            status_code=400,
            detail="Service URL must use HTTP or HTTPS",
        )

    connection = db()

    connection.execute(
        """
        INSERT INTO services
        (
            service_id,
            name,
            url,
            health_url,
            enabled,
            critical,
            priority,
            timeout,
            retry_count,
            metadata_json,
            updated_at,
            updated_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(service_id)
        DO UPDATE SET
            name = excluded.name,
            url = excluded.url,
            health_url = excluded.health_url,
            enabled = excluded.enabled,
            critical = excluded.critical,
            priority = excluded.priority,
            timeout = excluded.timeout,
            retry_count = excluded.retry_count,
            metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by
        """,
        (
            data.service_id,
            data.name,
            data.url,
            data.health_url,
            bool_int(data.enabled),
            bool_int(data.critical),
            data.priority,
            data.timeout,
            data.retry_count,
            json.dumps(
                data.metadata,
                ensure_ascii=False,
            ),
            now(),
            owner,
        ),
    )

    connection.commit()
    connection.close()

    audit(
        "service_upsert",
        data.service_id,
        owner,
        {
            "url": data.url,
            "enabled": data.enabled,
        },
    )

    return {
        "status": "updated",
        "service_id": data.service_id,
    }


@app.post("/config/services/{service_id}/enable")
async def enable_service(
    service_id: str,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    return await set_service_state(
        service_id,
        True,
        authorization,
    )


@app.post("/config/services/{service_id}/disable")
async def disable_service(
    service_id: str,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    return await set_service_state(
        service_id,
        False,
        authorization,
    )


async def set_service_state(
    service_id: str,
    enabled: bool,
    authorization: Optional[str],
):
    owner = owner_from_token(
        authorization
    )

    connection = db()

    cursor = connection.execute(
        """
        UPDATE services
        SET enabled = ?,
            updated_at = ?,
            updated_by = ?
        WHERE service_id = ?
        """,
        (
            bool_int(enabled),
            now(),
            owner,
            service_id,
        ),
    )

    connection.commit()
    connection.close()

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Service not found",
        )

    audit(
        "service_state_change",
        service_id,
        owner,
        {
            "enabled": enabled
        },
    )

    return {
        "service_id": service_id,
        "enabled": enabled,
    }


# ============================================================
# Providers
# ============================================================

@app.get("/config/providers")
async def list_providers(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM providers
        ORDER BY provider_type, priority, provider_id
        """
    ).fetchall()

    connection.close()

    result = []

    for row in rows:
        result.append({
            "provider_id": row["provider_id"],
            "provider_type": row["provider_type"],
            "name": row["name"],
            "base_url": row["base_url"],
            "enabled": bool(
                row["enabled"]
            ),
            "priority": row["priority"],
            "timeout": row["timeout"],
            "secret_ref": row["secret_ref"],
            "capabilities": json.loads(
                row["capabilities_json"]
            ),
            "metadata": json.loads(
                row["metadata_json"]
            ),
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"],
        })

    audit(
        "providers_list",
        "providers",
        owner,
    )

    return {
        "providers": result
    }


@app.post("/config/providers")
async def upsert_provider(
    data: ProviderInput,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    connection = db()

    connection.execute(
        """
        INSERT INTO providers
        (
            provider_id,
            provider_type,
            name,
            base_url,
            enabled,
            priority,
            timeout,
            secret_ref,
            capabilities_json,
            metadata_json,
            updated_at,
            updated_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(provider_id)
        DO UPDATE SET
            provider_type = excluded.provider_type,
            name = excluded.name,
            base_url = excluded.base_url,
            enabled = excluded.enabled,
            priority = excluded.priority,
            timeout = excluded.timeout,
            secret_ref = excluded.secret_ref,
            capabilities_json = excluded.capabilities_json,
            metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by
        """,
        (
            data.provider_id,
            data.provider_type,
            data.name,
            data.base_url,
            bool_int(data.enabled),
            data.priority,
            data.timeout,
            data.secret_ref,
            json.dumps(
                data.capabilities,
                ensure_ascii=False,
            ),
            json.dumps(
                data.metadata,
                ensure_ascii=False,
            ),
            now(),
            owner,
        ),
    )

    connection.commit()
    connection.close()

    audit(
        "provider_upsert",
        data.provider_id,
        owner,
        {
            "provider_type": data.provider_type,
            "enabled": data.enabled,
            "priority": data.priority,
        },
    )

    return {
        "status": "updated",
        "provider_id": data.provider_id,
    }


@app.post("/config/providers/{provider_id}/enable")
async def enable_provider(
    provider_id: str,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    return await set_provider_state(
        provider_id,
        True,
        authorization,
    )


@app.post("/config/providers/{provider_id}/disable")
async def disable_provider(
    provider_id: str,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    return await set_provider_state(
        provider_id,
        False,
        authorization,
    )


async def set_provider_state(
    provider_id: str,
    enabled: bool,
    authorization: Optional[str],
):
    owner = owner_from_token(
        authorization
    )

    connection = db()

    cursor = connection.execute(
        """
        UPDATE providers
        SET enabled = ?,
            updated_at = ?,
            updated_by = ?
        WHERE provider_id = ?
        """,
        (
            bool_int(enabled),
            now(),
            owner,
            provider_id,
        ),
    )

    connection.commit()
    connection.close()

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Provider not found",
        )

    audit(
        "provider_state_change",
        provider_id,
        owner,
        {
            "enabled": enabled
        },
    )

    return {
        "provider_id": provider_id,
        "enabled": enabled,
    }


# ============================================================
# Feature Flags
# ============================================================

@app.get("/config/features")
async def list_features(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM feature_flags
        ORDER BY feature_id
        """
    ).fetchall()

    connection.close()

    return {
        "features": [
            {
                "feature_id": row["feature_id"],
                "enabled": bool(
                    row["enabled"]
                ),
                "description": row["description"],
                "updated_at": row["updated_at"],
                "updated_by": row["updated_by"],
            }
            for row in rows
        ]
    }


@app.post("/config/features")
async def upsert_feature(
    data: FeatureInput,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    connection = db()

    connection.execute(
        """
        INSERT INTO feature_flags
        (
            feature_id,
            enabled,
            description,
            updated_at,
            updated_by
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(feature_id)
        DO UPDATE SET
            enabled = excluded.enabled,
            description = excluded.description,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by
        """,
        (
            data.feature_id,
            bool_int(data.enabled),
            data.description,
            now(),
            owner,
        ),
    )

    connection.commit()
    connection.close()

    audit(
        "feature_upsert",
        data.feature_id,
        owner,
        {
            "enabled": data.enabled
        },
    )

    return {
        "status": "updated",
        "feature_id": data.feature_id,
        "enabled": data.enabled,
    }


# ============================================================
# Configuration Snapshot
# ============================================================

def build_snapshot() -> Dict[str, Any]:
    connection = db()

    settings = connection.execute(
        """
        SELECT
            key,
            value,
            value_type,
            category,
            secret,
            enabled,
            description,
            updated_at,
            updated_by
        FROM settings
        """
    ).fetchall()

    services = connection.execute(
        """
        SELECT *
        FROM services
        """
    ).fetchall()

    providers = connection.execute(
        """
        SELECT *
        FROM providers
        """
    ).fetchall()

    features = connection.execute(
        """
        SELECT *
        FROM feature_flags
        """
    ).fetchall()

    connection.close()

    snapshot_settings = {}

    for row in settings:
        if row["secret"]:
            continue

        snapshot_settings[
            row["key"]
        ] = {
            "value": parse_value(
                row["value"],
                row["value_type"],
            ),
            "value_type": row["value_type"],
            "category": row["category"],
            "enabled": bool(
                row["enabled"]
            ),
        }

    return {
        "created_at": now(),
        "settings": snapshot_settings,
        "services": [
            {
                "service_id": row["service_id"],
                "name": row["name"],
                "url": row["url"],
                "health_url": row["health_url"],
                "enabled": bool(
                    row["enabled"]
                ),
                "critical": bool(
                    row["critical"]
                ),
                "priority": row["priority"],
                "timeout": row["timeout"],
                "retry_count": row["retry_count"],
                "metadata": json.loads(
                    row["metadata_json"]
                ),
            }
            for row in services
        ],
        "providers": [
            {
                "provider_id": row["provider_id"],
                "provider_type": row["provider_type"],
                "name": row["name"],
                "base_url": row["base_url"],
                "enabled": bool(
                    row["enabled"]
                ),
                "priority": row["priority"],
                "timeout": row["timeout"],
                "secret_ref": row["secret_ref"],
                "capabilities": json.loads(
                    row["capabilities_json"]
                ),
                "metadata": json.loads(
                    row["metadata_json"]
                ),
            }
            for row in providers
        ],
        "features": [
            {
                "feature_id": row["feature_id"],
                "enabled": bool(
                    row["enabled"]
                ),
                "description": row["description"],
            }
            for row in features
        ],
    }


@app.post("/config/snapshots")
async def create_snapshot(
    data: SnapshotInput,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    snapshot = build_snapshot()

    connection = db()

    row = connection.execute(
        """
        SELECT
            COALESCE(
                MAX(version_number),
                0
            ) AS version
        FROM config_versions
        """
    ).fetchone()

    next_version = (
        int(row["version"])
        + 1
    )

    version_id = uuid.uuid4().hex

    connection.execute(
        """
        INSERT INTO config_versions
        (
            version_id,
            version_number,
            snapshot_json,
            created_at,
            created_by,
            note
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            version_id,
            next_version,
            json.dumps(
                snapshot,
                ensure_ascii=False,
            ),
            now(),
            owner,
            data.note,
        ),
    )

    connection.commit()
    connection.close()

    audit(
        "config_snapshot_created",
        version_id,
        owner,
        {
            "version": next_version
        },
    )

    return {
        "status": "created",
        "version_id": version_id,
        "version": next_version,
        "created_at": now(),
    }


@app.get("/config/snapshots")
async def list_snapshots(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT
            version_id,
            version_number,
            created_at,
            created_by,
            note
        FROM config_versions
        ORDER BY version_number DESC
        """
    ).fetchall()

    connection.close()

    return {
        "snapshots": [
            {
                "version_id": row["version_id"],
                "version": row["version_number"],
                "created_at": row["created_at"],
                "created_by": row["created_by"],
                "note": row["note"],
            }
            for row in rows
        ]
    }


# ============================================================
# Runtime Configuration
# ============================================================

@app.get("/config/runtime")
async def runtime_config(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner_from_token(
        authorization
    )

    return {
        "host": HOST,
        "port": PORT,
        "database": DB_PATH,
        "session_ttl": CONFIG_SESSION_TTL,
        "audit_retention_days": AUDIT_RETENTION_DAYS,
        "main_py_modified": False,
        "configuration_service": APP_NAME,
        "timestamp": now(),
    }


# ============================================================
# Audit
# ============================================================

@app.get("/owner/audit")
async def owner_audit(
    limit: int = 100,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner_from_token(
        authorization
    )

    limit = max(
        1,
        min(limit, 500),
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT
            event_id,
            action,
            target,
            actor,
            details_json,
            created_at
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    connection.close()

    return {
        "audit": [
            {
                "event_id": row["event_id"],
                "action": row["action"],
                "target": row["target"],
                "actor": row["actor"],
                "details": json.loads(
                    row["details_json"]
                    or "{}"
                ),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }


# ============================================================
# System Map
# ============================================================

@app.get("/config/system-map")
async def system_map(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner_from_token(
        authorization
    )

    connection = db()

    service_count = connection.execute(
        "SELECT COUNT(*) AS c FROM services"
    ).fetchone()["c"]

    provider_count = connection.execute(
        "SELECT COUNT(*) AS c FROM providers"
    ).fetchone()["c"]

    setting_count = connection.execute(
        "SELECT COUNT(*) AS c FROM settings"
    ).fetchone()["c"]

    feature_count = connection.execute(
        "SELECT COUNT(*) AS c FROM feature_flags"
    ).fetchone()["c"]

    connection.close()

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "architecture": {
            "configuration": (
                "arya_central_config"
            ),
            "runtime": (
                "arya_service_runtime"
            ),
            "unified_api": (
                "arya_unified_api"
            ),
            "client_gateway": (
                "client_api_gateway"
            ),
            "runtime_gateway": (
                "owner_runtime_gateway"
            ),
            "main_bridge": (
                "arya_main_api_bridge"
            ),
            "legacy_core": (
                "main.py"
            ),
        },
        "database": {
            "services": service_count,
            "providers": provider_count,
            "settings": setting_count,
            "features": feature_count,
        },
        "main_py_modified": False,
        "timestamp": now(),
    }


# ============================================================
# Cleanup
# ============================================================

@app.post("/owner/maintenance/cleanup")
async def cleanup(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    owner = owner_from_token(
        authorization
    )

    cutoff = (
        now()
        - (
            AUDIT_RETENTION_DAYS
            * 86400
        )
    )

    connection = db()

    audit_result = connection.execute(
        """
        DELETE FROM audit_logs
        WHERE created_at < ?
        """,
        (cutoff,),
    )

    session_result = connection.execute(
        """
        DELETE FROM sessions
        WHERE expires_at < ?
        OR revoked = 1
        """,
    )

    connection.commit()
    connection.close()

    audit(
        "maintenance_cleanup",
        "central_configuration",
        owner,
        {
            "audit_deleted": audit_result.rowcount,
            "sessions_deleted": session_result.rowcount,
        },
    )

    return {
        "status": "completed",
        "audit_deleted": audit_result.rowcount,
        "sessions_deleted": session_result.rowcount,
    }


# ============================================================
# Contract
# ============================================================

@app.get("/config/contract")
async def contract():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "port": PORT,
        "endpoints": {
            "owner_login": "POST /owner/login",
            "owner_logout": "POST /owner/logout",
            "settings": "GET/POST /config/settings",
            "services": "GET/POST /config/services",
            "service_enable": (
                "POST /config/services/{service_id}/enable"
            ),
            "service_disable": (
                "POST /config/services/{service_id}/disable"
            ),
            "providers": "GET/POST /config/providers",
            "provider_enable": (
                "POST /config/providers/{provider_id}/enable"
            ),
            "provider_disable": (
                "POST /config/providers/{provider_id}/disable"
            ),
            "features": "GET/POST /config/features",
            "snapshots": "GET/POST /config/snapshots",
            "runtime": "GET /config/runtime",
            "audit": "GET /owner/audit",
            "cleanup": "POST /owner/maintenance/cleanup",
            "system_map": "GET /config/system-map",
        },
        "security": {
            "owner_authentication": True,
            "bearer_sessions": True,
            "secret_values_hidden": True,
            "audit_logging": True,
        },
        "main_py_modified": False,
    }


# ============================================================
# Local Execution
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "arya_central_config:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
