"""
ARYA AgriDoctor
OWNER Integration Layer
Version: 1.0.0

Purpose:
- Connect OWNER Manager with service/provider configuration.
- Provide centralized runtime configuration.
- Keep provider/service settings persistent.
- Allow OWNER-controlled enable/disable state.
- Support API secret references without exposing secret values.
- Provide configuration snapshots and audit information.
- Do NOT modify backend/main.py or existing modules.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field


# ============================================================
# CONFIGURATION
# ============================================================

SERVICE_NAME = "ARYA Owner Integration"
SERVICE_VERSION = "1.0.0"

HOST = os.getenv("ARYA_OWNER_INTEGRATION_HOST", "0.0.0.0")
PORT = int(os.getenv("ARYA_OWNER_INTEGRATION_PORT", "8015"))

DATABASE_PATH = os.getenv(
    "ARYA_OWNER_INTEGRATION_DATABASE",
    "owner_integration.db",
)

MASTER_EMAIL = os.getenv("ARYA_MASTER_EMAIL", "").strip()
MASTER_SECRET = os.getenv("ARYA_MASTER_SECRET", "").strip()

SESSION_TTL_SECONDS = int(
    os.getenv("ARYA_OWNER_SESSION_TTL", str(12 * 60 * 60))
)

LOG_LEVEL = os.getenv("ARYA_OWNER_INTEGRATION_LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger(SERVICE_NAME)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title=SERVICE_NAME,
    version=SERVICE_VERSION,
    description=(
        "Central OWNER-controlled integration layer for "
        "ARYA AgriDoctor services, providers and runtime configuration."
    ),
)


# ============================================================
# DATABASE
# ============================================================

_db_lock = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _db_lock:
        conn = db()

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runtime_services (
                service_id TEXT PRIMARY KEY,
                service_name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                timeout_seconds INTEGER NOT NULL DEFAULT 30,
                retry_count INTEGER NOT NULL DEFAULT 2,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runtime_providers (
                provider_id TEXT PRIMARY KEY,
                provider_name TEXT NOT NULL,
                category TEXT NOT NULL,
                base_url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                secret_ref TEXT,
                timeout_seconds INTEGER NOT NULL DEFAULT 30,
                retry_count INTEGER NOT NULL DEFAULT 2,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runtime_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL,
                is_secret INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS integration_sessions (
                session_id TEXT PRIMARY KEY,
                owner_email TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                ip_address TEXT
            );

            CREATE TABLE IF NOT EXISTS integration_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                ip_address TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS integration_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id TEXT UNIQUE NOT NULL,
                snapshot_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            );
            """
        )

        conn.commit()
        conn.close()


init_db()


# ============================================================
# DEFAULT SERVICES
# ============================================================

DEFAULT_SERVICES = [
    {
        "service_id": "vision",
        "service_name": "ARYA Vision",
        "base_url": os.getenv(
            "ARYA_VISION_URL",
            "http://127.0.0.1:8001",
        ),
    },
    {
        "service_id": "voice_language",
        "service_name": "ARYA Voice Language",
        "base_url": os.getenv(
            "ARYA_VOICE_LANGUAGE_URL",
            "http://127.0.0.1:8002",
        ),
    },
    {
        "service_id": "agri_engine",
        "service_name": "ARYA Agricultural Engine",
        "base_url": os.getenv(
            "ARYA_AGRI_ENGINE_URL",
            "http://127.0.0.1:8003",
        ),
    },
    {
        "service_id": "commerce_security",
        "service_name": "ARYA Commerce Security",
        "base_url": os.getenv(
            "ARYA_COMMERCE_SECURITY_URL",
            "http://127.0.0.1:8004",
        ),
    },
    {
        "service_id": "orchestrator",
        "service_name": "ARYA Orchestrator",
        "base_url": os.getenv(
            "ARYA_ORCHESTRATOR_URL",
            "http://127.0.0.1:8010",
        ),
    },
]


def seed_defaults() -> None:
    now = utc_now()

    with _db_lock:
        conn = db()

        for item in DEFAULT_SERVICES:
            exists = conn.execute(
                """
                SELECT service_id
                FROM runtime_services
                WHERE service_id = ?
                """,
                (item["service_id"],),
            ).fetchone()

            if not exists:
                conn.execute(
                    """
                    INSERT INTO runtime_services (
                        service_id,
                        service_name,
                        base_url,
                        enabled,
                        timeout_seconds,
                        retry_count,
                        metadata_json,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, 1, 30, 2, '{}', ?, ?)
                    """,
                    (
                        item["service_id"],
                        item["service_name"],
                        item["base_url"],
                        now,
                        now,
                    ),
                )

        conn.commit()
        conn.close()


seed_defaults()


# ============================================================
# SECURITY
# ============================================================

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def owner_configured() -> bool:
    return bool(MASTER_EMAIL and MASTER_SECRET)


def create_session(
    owner_email: str,
    ip_address: Optional[str],
) -> str:

    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_token(raw_token)

    session_id = secrets.token_hex(16)
    now = int(time.time())
    expires_at = now + SESSION_TTL_SECONDS

    with _db_lock:
        conn = db()

        conn.execute(
            """
            INSERT INTO integration_sessions (
                session_id,
                owner_email,
                token_hash,
                created_at,
                expires_at,
                revoked,
                ip_address
            )
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (
                session_id,
                owner_email,
                token_hash,
                utc_now(),
                expires_at,
                ip_address,
            ),
        )

        conn.commit()
        conn.close()

    return raw_token


def authenticate_owner(
    email: str,
    secret: str,
) -> bool:

    if not owner_configured():
        return False

    return (
        constant_time_equal(email, MASTER_EMAIL)
        and constant_time_equal(secret, MASTER_SECRET)
    )


def require_owner(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OWNER authentication required",
        )

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme",
        )

    token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OWNER token",
        )

    token_hash = hash_token(token)

    with _db_lock:
        conn = db()

        row = conn.execute(
            """
            SELECT *
            FROM integration_sessions
            WHERE token_hash = ?
              AND revoked = 0
              AND expires_at > ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (
                token_hash,
                int(time.time()),
            ),
        ).fetchone()

        conn.close()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OWNER session expired or invalid",
        )

    return dict(row)


# ============================================================
# MODELS
# ============================================================

class OwnerLoginRequest(BaseModel):
    email: str
    secret: str


class ServiceConfig(BaseModel):
    service_id: str = Field(min_length=1, max_length=100)
    service_name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=1, max_length=1000)
    enabled: bool = True
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    retry_count: int = Field(default=2, ge=0, le=10)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProviderConfig(BaseModel):
    provider_id: str = Field(min_length=1, max_length=100)
    provider_name: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=100)
    base_url: str = Field(min_length=1, max_length=1000)
    enabled: bool = True
    secret_ref: Optional[str] = None
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    retry_count: int = Field(default=2, ge=0, le=10)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SettingRequest(BaseModel):
    key: str = Field(min_length=1, max_length=200)
    value: Any
    is_secret: bool = False


class SnapshotRequest(BaseModel):
    description: str = Field(default="", max_length=500)


# ============================================================
# AUDIT
# ============================================================

def audit(
    actor: str,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> None:

    with _db_lock:
        conn = db()

        conn.execute(
            """
            INSERT INTO integration_audit (
                actor,
                action,
                target_type,
                target_id,
                details_json,
                ip_address,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                actor,
                action,
                target_type,
                target_id,
                json.dumps(
                    details or {},
                    ensure_ascii=False,
                    default=str,
                ),
                ip_address,
                utc_now(),
            ),
        )

        conn.commit()
        conn.close()


# ============================================================
# ROOT / HEALTH
# ============================================================

@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "running",
        "owner_configured": owner_configured(),
    }


@app.get("/health")
def health() -> Dict[str, Any]:

    try:
        with _db_lock:
            conn = db()
            conn.execute("SELECT 1").fetchone()
            conn.close()

        return {
            "status": "healthy",
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "database": "ok",
            "owner_configured": owner_configured(),
            "timestamp": utc_now(),
        }

    except Exception as exc:
        logger.exception("Health check failed")

        return {
            "status": "degraded",
            "service": SERVICE_NAME,
            "database": "error",
            "error": str(exc),
            "timestamp": utc_now(),
        }


# ============================================================
# OWNER LOGIN
# ============================================================

@app.post("/owner/login")
def owner_login(
    payload: OwnerLoginRequest,
    request: Request,
) -> Dict[str, Any]:

    if not owner_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OWNER credentials are not configured",
        )

    if not authenticate_owner(
        payload.email,
        payload.secret,
    ):
        audit(
            actor=payload.email or "unknown",
            action="owner_login_failed",
            ip_address=request.client.host if request.client else None,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OWNER credentials",
        )

    token = create_session(
        owner_email=payload.email,
        ip_address=request.client.host if request.client else None,
    )

    audit(
        actor=payload.email,
        action="owner_login",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "authenticated": True,
        "token": token,
        "expires_in": SESSION_TTL_SECONDS,
        "owner_email": payload.email,
    }


@app.post("/owner/logout")
def owner_logout(
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        conn.execute(
            """
            UPDATE integration_sessions
            SET revoked = 1
            WHERE session_id = ?
            """,
            (session["session_id"],),
        )

        conn.commit()
        conn.close()

    audit(
        actor=session["owner_email"],
        action="owner_logout",
        target_type="session",
        target_id=session["session_id"],
    )

    return {
        "success": True,
        "message": "OWNER session revoked",
    }


# ============================================================
# SERVICES
# ============================================================

@app.get("/owner/services")
def list_services(
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        rows = conn.execute(
            """
            SELECT *
            FROM runtime_services
            ORDER BY service_id
            """
        ).fetchall()

        conn.close()

    services = []

    for row in rows:
        item = dict(row)

        item["enabled"] = bool(item["enabled"])
        item["metadata"] = json.loads(
            item.get("metadata_json") or "{}"
        )

        item.pop("metadata_json", None)

        services.append(item)

    return {
        "count": len(services),
        "services": services,
    }


@app.post("/owner/services")
def upsert_service(
    payload: ServiceConfig,
    request: Request,
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    now = utc_now()

    with _db_lock:
        conn = db()

        conn.execute(
            """
            INSERT INTO runtime_services (
                service_id,
                service_name,
                base_url,
                enabled,
                timeout_seconds,
                retry_count,
                metadata_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(service_id)
            DO UPDATE SET
                service_name = excluded.service_name,
                base_url = excluded.base_url,
                enabled = excluded.enabled,
                timeout_seconds = excluded.timeout_seconds,
                retry_count = excluded.retry_count,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            """,
            (
                payload.service_id,
                payload.service_name,
                payload.base_url,
                int(payload.enabled),
                payload.timeout_seconds,
                payload.retry_count,
                json.dumps(
                    payload.metadata,
                    ensure_ascii=False,
                    default=str,
                ),
                now,
                now,
            ),
        )

        conn.commit()
        conn.close()

    audit(
        actor=session["owner_email"],
        action="service_upsert",
        target_type="service",
        target_id=payload.service_id,
        details={
            "enabled": payload.enabled,
            "base_url": payload.base_url,
        },
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "service_id": payload.service_id,
    }


@app.post("/owner/services/{service_id}/enable")
def enable_service(
    service_id: str,
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    return set_service_state(
        service_id,
        True,
        session,
    )


@app.post("/owner/services/{service_id}/disable")
def disable_service(
    service_id: str,
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    return set_service_state(
        service_id,
        False,
        session,
    )


def set_service_state(
    service_id: str,
    enabled: bool,
    session: Dict[str, Any],
) -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        cursor = conn.execute(
            """
            UPDATE runtime_services
            SET enabled = ?,
                updated_at = ?
            WHERE service_id = ?
            """,
            (
                int(enabled),
                utc_now(),
                service_id,
            ),
        )

        conn.commit()
        conn.close()

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Service not found",
        )

    audit(
        actor=session["owner_email"],
        action="service_state_change",
        target_type="service",
        target_id=service_id,
        details={"enabled": enabled},
    )

    return {
        "success": True,
        "service_id": service_id,
        "enabled": enabled,
    }


# ============================================================
# PROVIDERS
# ============================================================

@app.get("/owner/providers")
def list_providers(
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        rows = conn.execute(
            """
            SELECT *
            FROM runtime_providers
            ORDER BY provider_id
            """
        ).fetchall()

        conn.close()

    providers = []

    for row in rows:
        item = dict(row)

        item["enabled"] = bool(item["enabled"])

        item["metadata"] = json.loads(
            item.get("metadata_json") or "{}"
        )

        item.pop("metadata_json", None)

        providers.append(item)

    return {
        "count": len(providers),
        "providers": providers,
    }


@app.post("/owner/providers")
def upsert_provider(
    payload: ProviderConfig,
    request: Request,
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    now = utc_now()

    with _db_lock:
        conn = db()

        conn.execute(
            """
            INSERT INTO runtime_providers (
                provider_id,
                provider_name,
                category,
                base_url,
                enabled,
                secret_ref,
                timeout_seconds,
                retry_count,
                metadata_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider_id)
            DO UPDATE SET
                provider_name = excluded.provider_name,
                category = excluded.category,
                base_url = excluded.base_url,
                enabled = excluded.enabled,
                secret_ref = excluded.secret_ref,
                timeout_seconds = excluded.timeout_seconds,
                retry_count = excluded.retry_count,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            """,
            (
                payload.provider_id,
                payload.provider_name,
                payload.category,
                payload.base_url,
                int(payload.enabled),
                payload.secret_ref,
                payload.timeout_seconds,
                payload.retry_count,
                json.dumps(
                    payload.metadata,
                    ensure_ascii=False,
                    default=str,
                ),
                now,
                now,
            ),
        )

        conn.commit()
        conn.close()

    audit(
        actor=session["owner_email"],
        action="provider_upsert",
        target_type="provider",
        target_id=payload.provider_id,
        details={
            "category": payload.category,
            "enabled": payload.enabled,
            "base_url": payload.base_url,
            "secret_ref": payload.secret_ref,
        },
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "provider_id": payload.provider_id,
    }


@app.post("/owner/providers/{provider_id}/enable")
def enable_provider(
    provider_id: str,
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    return set_provider_state(
        provider_id,
        True,
        session,
    )


@app.post("/owner/providers/{provider_id}/disable")
def disable_provider(
    provider_id: str,
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    return set_provider_state(
        provider_id,
        False,
        session,
    )


def set_provider_state(
    provider_id: str,
    enabled: bool,
    session: Dict[str, Any],
) -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        cursor = conn.execute(
            """
            UPDATE runtime_providers
            SET enabled = ?,
                updated_at = ?
            WHERE provider_id = ?
            """,
            (
                int(enabled),
                utc_now(),
                provider_id,
            ),
        )

        conn.commit()
        conn.close()

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Provider not found",
        )

    audit(
        actor=session["owner_email"],
        action="provider_state_change",
        target_type="provider",
        target_id=provider_id,
        details={"enabled": enabled},
    )

    return {
        "success": True,
        "provider_id": provider_id,
        "enabled": enabled,
    }


# ============================================================
# SETTINGS
# ============================================================

@app.get("/owner/settings")
def list_settings(
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        rows = conn.execute(
            """
            SELECT *
            FROM runtime_settings
            ORDER BY setting_key
            """
        ).fetchall()

        conn.close()

    settings = []

    for row in rows:
        item = dict(row)

        if item["is_secret"]:
            item["setting_value"] = "***REDACTED***"

        item["is_secret"] = bool(item["is_secret"])

        settings.append(item)

    return {
        "count": len(settings),
        "settings": settings,
    }


@app.post("/owner/settings")
def set_setting(
    payload: SettingRequest,
    request: Request,
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    now = utc_now()

    value = json.dumps(
        payload.value,
        ensure_ascii=False,
        default=str,
    )

    with _db_lock:
        conn = db()

        conn.execute(
            """
            INSERT INTO runtime_settings (
                setting_key,
                setting_value,
                is_secret,
                updated_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(setting_key)
            DO UPDATE SET
                setting_value = excluded.setting_value,
                is_secret = excluded.is_secret,
                updated_at = excluded.updated_at
            """,
            (
                payload.key,
                value,
                int(payload.is_secret),
                now,
            ),
        )

        conn.commit()
        conn.close()

    audit(
        actor=session["owner_email"],
        action="setting_update",
        target_type="setting",
        target_id=payload.key,
        details={
            "is_secret": payload.is_secret,
        },
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "key": payload.key,
        "stored": True,
        "secret": payload.is_secret,
    }


# ============================================================
# SNAPSHOTS
# ============================================================

def collect_snapshot() -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        services = [
            dict(row)
            for row in conn.execute(
                """
                SELECT *
                FROM runtime_services
                ORDER BY service_id
                """
            ).fetchall()
        ]

        providers = [
            dict(row)
            for row in conn.execute(
                """
                SELECT *
                FROM runtime_providers
                ORDER BY provider_id
                """
            ).fetchall()
        ]

        settings = [
            dict(row)
            for row in conn.execute(
                """
                SELECT setting_key, is_secret, updated_at
                FROM runtime_settings
                ORDER BY setting_key
                """
            ).fetchall()
        ]

        conn.close()

    return {
        "generated_at": utc_now(),
        "services": services,
        "providers": providers,
        "settings": settings,
    }


@app.post("/owner/snapshots")
def create_snapshot(
    payload: SnapshotRequest,
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    snapshot = collect_snapshot()

    snapshot["description"] = payload.description

    payload_json = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )

    snapshot_hash = hashlib.sha256(
        payload_json.encode("utf-8")
    ).hexdigest()

    snapshot_id = secrets.token_hex(16)

    with _db_lock:
        conn = db()

        conn.execute(
            """
            INSERT INTO integration_snapshots (
                snapshot_id,
                snapshot_hash,
                payload_json,
                created_at,
                created_by
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                snapshot_hash,
                payload_json,
                utc_now(),
                session["owner_email"],
            ),
        )

        conn.commit()
        conn.close()

    audit(
        actor=session["owner_email"],
        action="snapshot_created",
        target_type="snapshot",
        target_id=snapshot_id,
        details={
            "hash": snapshot_hash,
        },
    )

    return {
        "success": True,
        "snapshot_id": snapshot_id,
        "snapshot_hash": snapshot_hash,
        "created_at": utc_now(),
    }


@app.get("/owner/snapshots")
def list_snapshots(
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        rows = conn.execute(
            """
            SELECT
                snapshot_id,
                snapshot_hash,
                created_at,
                created_by
            FROM integration_snapshots
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()

        conn.close()

    return {
        "count": len(rows),
        "snapshots": [dict(row) for row in rows],
    }


# ============================================================
# AUDIT
# ============================================================

@app.get("/owner/audit")
def get_audit_logs(
    limit: int = 100,
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    limit = max(1, min(limit, 500))

    with _db_lock:
        conn = db()

        rows = conn.execute(
            """
            SELECT *
            FROM integration_audit
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        conn.close()

    logs = []

    for row in rows:
        item = dict(row)

        item["details"] = json.loads(
            item.pop("details_json") or "{}"
        )

        logs.append(item)

    return {
        "count": len(logs),
        "logs": logs,
    }


# ============================================================
# RUNTIME CONFIGURATION
# ============================================================

@app.get("/runtime/services")
def runtime_services() -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        rows = conn.execute(
            """
            SELECT
                service_id,
                service_name,
                base_url,
                enabled,
                timeout_seconds,
                retry_count,
                metadata_json,
                updated_at
            FROM runtime_services
            WHERE enabled = 1
            ORDER BY service_id
            """
        ).fetchall()

        conn.close()

    result = []

    for row in rows:
        item = dict(row)

        item["enabled"] = bool(item["enabled"])
        item["metadata"] = json.loads(
            item.pop("metadata_json") or "{}"
        )

        result.append(item)

    return {
        "services": result,
        "count": len(result),
        "timestamp": utc_now(),
    }


@app.get("/runtime/providers")
def runtime_providers() -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        rows = conn.execute(
            """
            SELECT
                provider_id,
                provider_name,
                category,
                base_url,
                enabled,
                secret_ref,
                timeout_seconds,
                retry_count,
                metadata_json,
                updated_at
            FROM runtime_providers
            WHERE enabled = 1
            ORDER BY provider_id
            """
        ).fetchall()

        conn.close()

    result = []

    for row in rows:
        item = dict(row)

        item["enabled"] = bool(item["enabled"])
        item["metadata"] = json.loads(
            item.pop("metadata_json") or "{}"
        )

        result.append(item)

    return {
        "providers": result,
        "count": len(result),
        "timestamp": utc_now(),
    }


# ============================================================
# OWNER STATUS
# ============================================================

@app.get("/owner/status")
def owner_status(
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    with _db_lock:
        conn = db()

        service_count = conn.execute(
            "SELECT COUNT(*) FROM runtime_services"
        ).fetchone()[0]

        active_services = conn.execute(
            """
            SELECT COUNT(*)
            FROM runtime_services
            WHERE enabled = 1
            """
        ).fetchone()[0]

        provider_count = conn.execute(
            "SELECT COUNT(*) FROM runtime_providers"
        ).fetchone()[0]

        active_providers = conn.execute(
            """
            SELECT COUNT(*)
            FROM runtime_providers
            WHERE enabled = 1
            """
        ).fetchone()[0]

        conn.close()

    return {
        "owner_authenticated": True,
        "owner_email": session["owner_email"],
        "service_count": service_count,
        "active_service_count": active_services,
        "provider_count": provider_count,
        "active_provider_count": active_providers,
        "timestamp": utc_now(),
    }


# ============================================================
# INTERNAL CONFIG LOOKUP
# ============================================================

def get_service_config(
    service_id: str,
) -> Optional[Dict[str, Any]]:

    with _db_lock:
        conn = db()

        row = conn.execute(
            """
            SELECT *
            FROM runtime_services
            WHERE service_id = ?
              AND enabled = 1
            """,
            (service_id,),
        ).fetchone()

        conn.close()

    if not row:
        return None

    item = dict(row)

    item["enabled"] = bool(item["enabled"])
    item["metadata"] = json.loads(
        item.pop("metadata_json") or "{}"
    )

    return item


def get_provider_config(
    provider_id: str,
) -> Optional[Dict[str, Any]]:

    with _db_lock:
        conn = db()

        row = conn.execute(
            """
            SELECT *
            FROM runtime_providers
            WHERE provider_id = ?
              AND enabled = 1
            """,
            (provider_id,),
        ).fetchone()

        conn.close()

    if not row:
        return None

    item = dict(row)

    item["enabled"] = bool(item["enabled"])
    item["metadata"] = json.loads(
        item.pop("metadata_json") or "{}"
    )

    return item


# ============================================================
# INTERNAL API
# ============================================================

@app.get("/internal/service/{service_id}")
def internal_service_config(
    service_id: str,
) -> Dict[str, Any]:

    config = get_service_config(service_id)

    if not config:
        raise HTTPException(
            status_code=404,
            detail="Enabled service not found",
        )

    return config


@app.get("/internal/provider/{provider_id}")
def internal_provider_config(
    provider_id: str,
) -> Dict[str, Any]:

    config = get_provider_config(provider_id)

    if not config:
        raise HTTPException(
            status_code=404,
            detail="Enabled provider not found",
        )

    return config


# ============================================================
# CLEANUP
# ============================================================

@app.post("/owner/maintenance/cleanup-sessions")
def cleanup_sessions(
    session: Dict[str, Any] = Depends(require_owner),
) -> Dict[str, Any]:

    now = int(time.time())

    with _db_lock:
        conn = db()

        cursor = conn.execute(
            """
            DELETE FROM integration_sessions
            WHERE expires_at <= ?
               OR revoked = 1
            """,
            (now,),
        )

        conn.commit()
        conn.close()

    audit(
        actor=session["owner_email"],
        action="session_cleanup",
        details={
            "deleted": cursor.rowcount,
        },
    )

    return {
        "success": True,
        "deleted_sessions": cursor.rowcount,
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup_event() -> None:
    init_db()
    seed_defaults()

    logger.info(
        "%s v%s started",
        SERVICE_NAME,
        SERVICE_VERSION,
    )


# ============================================================
# STANDALONE RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level=LOG_LEVEL.lower(),
    )
