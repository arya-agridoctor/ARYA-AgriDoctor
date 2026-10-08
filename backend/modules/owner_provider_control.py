"""
ARYA AgriDoctor
OWNER Provider Control
Version: 2.0.0

Purpose:
- OWNER-controlled provider management
- Enable / disable providers
- Update provider metadata
- Configure provider priority
- Maintain provider history
- Maintain audit records
- Keep provider secrets out of API responses
- Provide runtime provider selection
- Support internal runtime authentication
- Preserve existing provider-control capabilities

This module does not modify:
    main.py
    owner_manager.py
    owner_integration.py
    external_providers.py
    owner_runtime_gateway.py
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA OWNER Provider Control"
APP_VERSION = "2.0.0"

HOST = os.getenv(
    "ARYA_OWNER_PROVIDER_CONTROL_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_OWNER_PROVIDER_CONTROL_PORT",
        "8019",
    )
)

DATABASE = os.getenv(
    "ARYA_OWNER_PROVIDER_CONTROL_DB",
    "owner_provider_control.db",
)

OWNER_EMAIL = os.getenv(
    "ARYA_MASTER_EMAIL",
    "",
).strip().lower()

OWNER_SECRET = os.getenv(
    "ARYA_MASTER_SECRET",
    "",
)

INTERNAL_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
).strip()

SESSION_TTL = int(
    os.getenv(
        "ARYA_OWNER_PROVIDER_SESSION_TTL",
        "3600",
    )
)

MAX_AUDIT_LIMIT = int(
    os.getenv(
        "ARYA_OWNER_PROVIDER_MAX_AUDIT",
        "500",
    )
)

LOG_LEVEL = os.getenv(
    "ARYA_OWNER_PROVIDER_LOG_LEVEL",
    "INFO",
).upper()


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
    "arya.owner_provider_control"
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "OWNER provider control layer for "
        "ARYA AgriDoctor."
    ),
)


# ============================================================
# Database
# ============================================================

def db() -> sqlite3.Connection:
    connection = sqlite3.connect(
        DATABASE,
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def init_db() -> None:

    connection = db()

    try:

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                provider_type TEXT NOT NULL,
                base_url TEXT,
                secret_ref TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                timeout_seconds REAL NOT NULL DEFAULT 30,
                retry_count INTEGER NOT NULL DEFAULT 2,
                description TEXT,
                region TEXT,
                capabilities_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                disabled_at TEXT,
                version INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS provider_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                snapshot_json TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                changed_by TEXT,
                change_reason TEXT
            );

            CREATE TABLE IF NOT EXISTS provider_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                owner_email TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS provider_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                provider_id TEXT,
                actor TEXT,
                details_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_provider_enabled
            ON providers(enabled);

            CREATE INDEX IF NOT EXISTS idx_provider_priority
            ON providers(priority);

            CREATE INDEX IF NOT EXISTS idx_provider_type
            ON providers(provider_type);

            CREATE INDEX IF NOT EXISTS idx_provider_versions_provider
            ON provider_versions(provider_id);

            CREATE INDEX IF NOT EXISTS idx_provider_sessions_token
            ON provider_sessions(token_hash);

            CREATE INDEX IF NOT EXISTS idx_provider_audit_provider
            ON provider_audit_logs(provider_id);
            """
        )

        connection.commit()

    finally:
        connection.close()


init_db()


# ============================================================
# Utility
# ============================================================

def now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def hash_token(
    token: str,
) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def json_dumps(
    value: Any,
) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def json_loads(
    value: Optional[str],
) -> Any:

    if not value:
        return {}

    try:
        return json.loads(value)

    except Exception:
        return {}


def clean_provider(
    row: sqlite3.Row,
) -> Dict[str, Any]:

    data = dict(row)

    # Never expose provider secret references
    # through normal provider APIs.
    data.pop(
        "secret_ref",
        None,
    )

    data["enabled"] = bool(
        data.get("enabled", 0)
    )

    data["capabilities"] = json_loads(
        data.pop(
            "capabilities_json",
            None,
        )
    )

    return data


def provider_snapshot(
    row: sqlite3.Row,
) -> Dict[str, Any]:

    return {
        "provider_id": row["provider_id"],
        "name": row["name"],
        "provider_type": row["provider_type"],
        "base_url": row["base_url"],
        "secret_ref": row["secret_ref"],
        "enabled": bool(row["enabled"]),
        "priority": row["priority"],
        "timeout_seconds": row[
            "timeout_seconds"
        ],
        "retry_count": row[
            "retry_count"
        ],
        "description": row[
            "description"
        ],
        "region": row["region"],
        "capabilities": json_loads(
            row["capabilities_json"]
        ),
        "version": row["version"],
    }


def safe_provider_snapshot(
    row: sqlite3.Row,
) -> Dict[str, Any]:

    snapshot = provider_snapshot(
        row
    )

    snapshot.pop(
        "secret_ref",
        None,
    )

    return snapshot


# ============================================================
# Authentication
# ============================================================

def create_session(
    email: str,
) -> Dict[str, Any]:

    token = secrets.token_urlsafe(48)
    session_id = str(uuid.uuid4())

    created = int(time.time())
    expires = created + SESSION_TTL

    connection = db()

    try:

        connection.execute(
            """
            INSERT INTO provider_sessions (
                session_id,
                owner_email,
                token_hash,
                created_at,
                expires_at,
                revoked
            )
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (
                session_id,
                email,
                hash_token(token),
                now_iso(),
                expires,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    return {
        "session_id": session_id,
        "access_token": token,
        "expires_at": expires,
    }


def verify_session(
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
            detail="Invalid authorization format",
        )

    token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing access token",
        )

    token_hash = hash_token(token)

    connection = db()

    try:

        row = connection.execute(
            """
            SELECT *
            FROM provider_sessions
            WHERE token_hash = ?
              AND revoked = 0
            ORDER BY id DESC
            LIMIT 1
            """,
            (token_hash,),
        ).fetchone()

    finally:
        connection.close()

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked session",
        )

    if int(row["expires_at"]) <= int(
        time.time()
    ):

        raise HTTPException(
            status_code=401,
            detail="Session expired",
        )

    return str(
        row["owner_email"]
    )


def verify_owner_credentials(
    email: str,
    secret: str,
) -> bool:

    if not OWNER_EMAIL:
        return False

    if not OWNER_SECRET:
        return False

    return (
        secrets.compare_digest(
            email.strip().lower(),
            OWNER_EMAIL,
        )
        and secrets.compare_digest(
            secret,
            OWNER_SECRET,
        )
    )


def verify_internal_secret(
    value: Optional[str],
) -> None:

    if not INTERNAL_SECRET:
        raise HTTPException(
            status_code=503,
            detail=(
                "Internal authentication "
                "is not configured"
            ),
        )

    if not value:
        raise HTTPException(
            status_code=401,
            detail="Internal authentication required",
        )

    if not secrets.compare_digest(
        value,
        INTERNAL_SECRET,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid internal secret",
        )


# ============================================================
# Models
# ============================================================

class OwnerLoginRequest(BaseModel):
    email: str = Field(
        ...,
        min_length=3,
        max_length=320,
    )

    secret: str = Field(
        ...,
        min_length=1,
        max_length=1000,
    )


class ProviderCreateRequest(BaseModel):
    provider_id: str = Field(
        ...,
        min_length=1,
        max_length=150,
    )

    name: str = Field(
        ...,
        min_length=1,
        max_length=200,
    )

    provider_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    base_url: Optional[str] = Field(
        None,
        max_length=2000,
    )

    secret_ref: Optional[str] = Field(
        None,
        max_length=500,
    )

    enabled: bool = True

    priority: int = Field(
        100,
        ge=0,
        le=100000,
    )

    timeout_seconds: float = Field(
        30,
        gt=0,
        le=300,
    )

    retry_count: int = Field(
        2,
        ge=0,
        le=10,
    )

    description: Optional[str] = Field(
        None,
        max_length=2000,
    )

    region: Optional[str] = Field(
        None,
        max_length=200,
    )

    capabilities: Dict[str, Any] = Field(
        default_factory=dict
    )


class ProviderUpdateRequest(BaseModel):
    name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=200,
    )

    provider_type: Optional[str] = Field(
        None,
        min_length=1,
        max_length=100,
    )

    base_url: Optional[str] = Field(
        None,
        max_length=2000,
    )

    secret_ref: Optional[str] = Field(
        None,
        max_length=500,
    )

    enabled: Optional[bool] = None

    priority: Optional[int] = Field(
        None,
        ge=0,
        le=100000,
    )

    timeout_seconds: Optional[float] = Field(
        None,
        gt=0,
        le=300,
    )

    retry_count: Optional[int] = Field(
        None,
        ge=0,
        le=10,
    )

    description: Optional[str] = Field(
        None,
        max_length=2000,
    )

    region: Optional[str] = Field(
        None,
        max_length=200,
    )

    capabilities: Optional[
        Dict[str, Any]
    ] = None

    reason: Optional[str] = Field(
        None,
        max_length=1000,
    )


class ProviderPriorityRequest(BaseModel):
    priority: int = Field(
        ...,
        ge=0,
        le=100000,
    )

    reason: Optional[str] = Field(
        None,
        max_length=1000,
    )


# ============================================================
# Audit
# ============================================================

def audit(
    event_type: str,
    provider_id: Optional[str],
    actor: Optional[str],
    details: Dict[str, Any],
) -> None:

    # Never write raw provider secrets
    # into audit records.
    sanitized = dict(details)

    for key in (
        "secret",
        "secret_ref",
        "access_token",
        "token",
        "password",
    ):
        sanitized.pop(
            key,
            None,
        )

    connection = db()

    try:

        connection.execute(
            """
            INSERT INTO provider_audit_logs (
                event_id,
                event_type,
                provider_id,
                actor,
                details_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                event_type,
                provider_id,
                actor,
                json_dumps(sanitized),
                now_iso(),
            ),
        )

        connection.commit()

    finally:
        connection.close()


# ============================================================
# Provider lookup
# ============================================================

def get_provider(
    provider_id: str,
) -> sqlite3.Row:

    connection = db()

    try:

        row = connection.execute(
            """
            SELECT *
            FROM providers
            WHERE provider_id = ?
            """,
            (provider_id,),
        ).fetchone()

    finally:
        connection.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Provider not found",
        )

    return row


# ============================================================
# Root
# ============================================================

@app.get("/")
async def root():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "database": DATABASE,
        "port": PORT,
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health():

    connection = db()

    try:

        total = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM providers
            """
        ).fetchone()["count"]

        enabled = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM providers
            WHERE enabled = 1
            """
        ).fetchone()["count"]

    finally:
        connection.close()

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "healthy",
        "providers_total": total,
        "providers_enabled": enabled,
        "internal_auth_configured": bool(
            INTERNAL_SECRET
        ),
        "owner_auth_configured": bool(
            OWNER_EMAIL and OWNER_SECRET
        ),
    }


# ============================================================
# OWNER Login
# ============================================================

@app.post("/owner/login")
async def owner_login(
    request: OwnerLoginRequest,
):

    if not verify_owner_credentials(
        request.email,
        request.secret,
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials",
        )

    email = request.email.strip().lower()

    session = create_session(
        email
    )

    audit(
        "owner_login",
        None,
        email,
        {},
    )

    return {
        "status": "authenticated",
        **session,
    }


# ============================================================
# OWNER Logout
# ============================================================

@app.post("/owner/logout")
async def owner_logout(
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    token = authorization[7:].strip()

    connection = db()

    try:

        connection.execute(
            """
            UPDATE provider_sessions
            SET revoked = 1
            WHERE token_hash = ?
            """,
            (hash_token(token),),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        "owner_logout",
        None,
        actor,
        {},
    )

    return {
        "status": "logged_out"
    }


# ============================================================
# Create Provider
# ============================================================

@app.post("/owner/providers")
async def create_provider(
    request: ProviderCreateRequest,
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    provider_id = (
        request.provider_id.strip()
    )

    if not provider_id:
        raise HTTPException(
            status_code=400,
            detail="provider_id cannot be empty",
        )

    connection = db()

    try:

        existing = connection.execute(
            """
            SELECT id
            FROM providers
            WHERE provider_id = ?
            """,
            (provider_id,),
        ).fetchone()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="Provider already exists",
            )

        timestamp = now_iso()

        connection.execute(
            """
            INSERT INTO providers (
                provider_id,
                name,
                provider_type,
                base_url,
                secret_ref,
                enabled,
                priority,
                timeout_seconds,
                retry_count,
                description,
                region,
                capabilities_json,
                created_at,
                updated_at,
                version
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, 1
            )
            """,
            (
                provider_id,
                request.name,
                request.provider_type,
                request.base_url,
                request.secret_ref,
                1 if request.enabled else 0,
                request.priority,
                request.timeout_seconds,
                request.retry_count,
                request.description,
                request.region,
                json_dumps(
                    request.capabilities
                ),
                timestamp,
                timestamp,
            ),
        )

        row = connection.execute(
            """
            SELECT *
            FROM providers
            WHERE provider_id = ?
            """,
            (provider_id,),
        ).fetchone()

        connection.execute(
            """
            INSERT INTO provider_versions (
                provider_id,
                version,
                snapshot_json,
                changed_at,
                changed_by,
                change_reason
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                provider_id,
                1,
                json_dumps(
                    safe_provider_snapshot(
                        row
                    )
                ),
                timestamp,
                actor,
                "initial creation",
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        "provider_created",
        provider_id,
        actor,
        {
            "version": 1,
            "enabled": request.enabled,
            "priority": request.priority,
            "provider_type": request.provider_type,
        },
    )

    return {
        "status": "created",
        "provider": clean_provider(row),
    }


# ============================================================
# OWNER Provider List
# ============================================================

@app.get("/owner/providers")
async def list_providers(
    authorization: Optional[str] = Header(
        default=None
    ),
    include_disabled: bool = True,
):

    actor = verify_session(
        authorization
    )

    connection = db()

    try:

        if include_disabled:

            rows = connection.execute(
                """
                SELECT *
                FROM providers
                ORDER BY priority ASC, id ASC
                """
            ).fetchall()

        else:

            rows = connection.execute(
                """
                SELECT *
                FROM providers
                WHERE enabled = 1
                ORDER BY priority ASC, id ASC
                """
            ).fetchall()

    finally:
        connection.close()

    return {
        "actor": actor,
        "count": len(rows),
        "providers": [
            clean_provider(row)
            for row in rows
        ],
    }


# ============================================================
# Runtime Provider List
# ============================================================

@app.get("/runtime/providers")
async def runtime_providers(
    provider_type: Optional[str] = None,
):

    connection = db()

    try:

        if provider_type:

            rows = connection.execute(
                """
                SELECT *
                FROM providers
                WHERE enabled = 1
                  AND provider_type = ?
                ORDER BY priority ASC, id ASC
                """,
                (provider_type,),
            ).fetchall()

        else:

            rows = connection.execute(
                """
                SELECT *
                FROM providers
                WHERE enabled = 1
                ORDER BY priority ASC, id ASC
                """
            ).fetchall()

    finally:
        connection.close()

    return {
        "count": len(rows),
        "providers": [
            clean_provider(row)
            for row in rows
        ],
    }


# ============================================================
# Provider Details
# ============================================================

@app.get(
    "/owner/providers/{provider_id}"
)
async def provider_details(
    provider_id: str,
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    row = get_provider(
        provider_id
    )

    return {
        "actor": actor,
        "provider": clean_provider(row),
    }


# ============================================================
# Update Provider
# ============================================================

@app.patch(
    "/owner/providers/{provider_id}"
)
async def update_provider(
    provider_id: str,
    request: ProviderUpdateRequest,
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    old_row = get_provider(
        provider_id
    )

    old_version = int(
        old_row["version"]
    )

    updates: Dict[str, Any] = {}

    if request.name is not None:
        updates["name"] = request.name

    if request.provider_type is not None:
        updates["provider_type"] = (
            request.provider_type
        )

    if request.base_url is not None:
        updates["base_url"] = (
            request.base_url
        )

    if request.secret_ref is not None:
        updates["secret_ref"] = (
            request.secret_ref
        )

    if request.enabled is not None:
        updates["enabled"] = (
            1 if request.enabled else 0
        )

    if request.priority is not None:
        updates["priority"] = (
            request.priority
        )

    if request.timeout_seconds is not None:
        updates["timeout_seconds"] = (
            request.timeout_seconds
        )

    if request.retry_count is not None:
        updates["retry_count"] = (
            request.retry_count
        )

    if request.description is not None:
        updates["description"] = (
            request.description
        )

    if request.region is not None:
        updates["region"] = (
            request.region
        )

    if request.capabilities is not None:
        updates["capabilities_json"] = (
            json_dumps(
                request.capabilities
            )
        )

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No changes supplied",
        )

    new_version = old_version + 1
    timestamp = now_iso()

    updates["version"] = new_version
    updates["updated_at"] = timestamp

    if (
        "enabled" in updates
        and updates["enabled"] == 0
    ):

        updates["disabled_at"] = timestamp

    elif (
        "enabled" in updates
        and updates["enabled"] == 1
    ):

        updates["disabled_at"] = None

    connection = db()

    try:

        assignments = ", ".join(
            f"{key} = ?"
            for key in updates
        )

        values = list(
            updates.values()
        )

        values.append(
            provider_id
        )

        connection.execute(
            f"""
            UPDATE providers
            SET {assignments}
            WHERE provider_id = ?
            """,
            values,
        )

        new_row = connection.execute(
            """
            SELECT *
            FROM providers
            WHERE provider_id = ?
            """,
            (provider_id,),
        ).fetchone()

        connection.execute(
            """
            INSERT INTO provider_versions (
                provider_id,
                version,
                snapshot_json,
                changed_at,
                changed_by,
                change_reason
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                provider_id,
                new_version,
                json_dumps(
                    safe_provider_snapshot(
                        new_row
                    )
                ),
                timestamp,
                actor,
                request.reason,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        "provider_updated",
        provider_id,
        actor,
        {
            "version": new_version,
            "previous_version": old_version,
            "changed_fields": [
                key
                for key in updates
                if key
                not in {
                    "updated_at",
                    "version",
                }
            ],
            "reason": request.reason,
        },
    )

    return {
        "status": "updated",
        "provider": clean_provider(
            new_row
        ),
    }


# ============================================================
# Enable Provider
# ============================================================

@app.post(
    "/owner/providers/{provider_id}/enable"
)
async def enable_provider(
    provider_id: str,
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    row = get_provider(
        provider_id
    )

    version = int(
        row["version"]
    ) + 1

    timestamp = now_iso()

    connection = db()

    try:

        connection.execute(
            """
            UPDATE providers
            SET
                enabled = 1,
                disabled_at = NULL,
                version = ?,
                updated_at = ?
            WHERE provider_id = ?
            """,
            (
                version,
                timestamp,
                provider_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        "provider_enabled",
        provider_id,
        actor,
        {
            "version": version,
        },
    )

    return {
        "status": "enabled",
        "provider_id": provider_id,
        "version": version,
    }


# ============================================================
# Disable Provider
# ============================================================

@app.post(
    "/owner/providers/{provider_id}/disable"
)
async def disable_provider(
    provider_id: str,
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    row = get_provider(
        provider_id
    )

    version = int(
        row["version"]
    ) + 1

    timestamp = now_iso()

    connection = db()

    try:

        connection.execute(
            """
            UPDATE providers
            SET
                enabled = 0,
                disabled_at = ?,
                version = ?,
                updated_at = ?
            WHERE provider_id = ?
            """,
            (
                timestamp,
                version,
                timestamp,
                provider_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        "provider_disabled",
        provider_id,
        actor,
        {
            "version": version,
        },
    )

    return {
        "status": "disabled",
        "provider_id": provider_id,
        "version": version,
    }


# ============================================================
# Priority
# ============================================================

@app.post(
    "/owner/providers/{provider_id}/priority"
)
async def set_priority(
    provider_id: str,
    request: ProviderPriorityRequest,
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    row = get_provider(
        provider_id
    )

    version = int(
        row["version"]
    ) + 1

    timestamp = now_iso()

    connection = db()

    try:

        connection.execute(
            """
            UPDATE providers
            SET
                priority = ?,
                version = ?,
                updated_at = ?
            WHERE provider_id = ?
            """,
            (
                request.priority,
                version,
                timestamp,
                provider_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        "provider_priority_changed",
        provider_id,
        actor,
        {
            "priority": request.priority,
            "version": version,
            "reason": request.reason,
        },
    )

    return {
        "status": "updated",
        "provider_id": provider_id,
        "priority": request.priority,
        "version": version,
    }


# ============================================================
# Provider History
# ============================================================

@app.get(
    "/owner/providers/{provider_id}/history"
)
async def provider_history(
    provider_id: str,
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    get_provider(
        provider_id
    )

    connection = db()

    try:

        rows = connection.execute(
            """
            SELECT
                id,
                provider_id,
                version,
                snapshot_json,
                changed_at,
                changed_by,
                change_reason
            FROM provider_versions
            WHERE provider_id = ?
            ORDER BY version DESC
            """,
            (provider_id,),
        ).fetchall()

    finally:
        connection.close()

    history: List[
        Dict[str, Any]
    ] = []

    for row in rows:

        snapshot = json_loads(
            row["snapshot_json"]
        )

        if isinstance(
            snapshot,
            dict,
        ):
            snapshot.pop(
                "secret_ref",
                None,
            )

        history.append(
            {
                "id": row["id"],
                "provider_id": row[
                    "provider_id"
                ],
                "version": row[
                    "version"
                ],
                "snapshot": snapshot,
                "changed_at": row[
                    "changed_at"
                ],
                "changed_by": row[
                    "changed_by"
                ],
                "change_reason": row[
                    "change_reason"
                ],
            }
        )

    return {
        "actor": actor,
        "provider_id": provider_id,
        "count": len(history),
        "history": history,
    }


# ============================================================
# Provider Capabilities
# ============================================================

@app.get(
    "/runtime/providers/capabilities"
)
async def provider_capabilities():

    connection = db()

    try:

        rows = connection.execute(
            """
            SELECT
                provider_id,
                name,
                provider_type,
                priority,
                region,
                capabilities_json
            FROM providers
            WHERE enabled = 1
            ORDER BY priority ASC, id ASC
            """
        ).fetchall()

    finally:
        connection.close()

    result = []

    for row in rows:

        result.append(
            {
                "provider_id": row[
                    "provider_id"
                ],
                "name": row["name"],
                "provider_type": row[
                    "provider_type"
                ],
                "priority": row[
                    "priority"
                ],
                "region": row[
                    "region"
                ],
                "capabilities": json_loads(
                    row[
                        "capabilities_json"
                    ]
                ),
            }
        )

    return {
        "count": len(result),
        "providers": result,
    }


# ============================================================
# Select Best Provider
# ============================================================

@app.get(
    "/runtime/providers/select/{provider_type}"
)
async def select_provider(
    provider_type: str,
):

    provider_type = provider_type.strip()

    if not provider_type:
        raise HTTPException(
            status_code=400,
            detail="provider_type is required",
        )

    connection = db()

    try:

        row = connection.execute(
            """
            SELECT *
            FROM providers
            WHERE provider_type = ?
              AND enabled = 1
            ORDER BY priority ASC, id ASC
            LIMIT 1
            """,
            (provider_type,),
        ).fetchone()

    finally:
        connection.close()

    if not row:

        raise HTTPException(
            status_code=404,
            detail={
                "error": "no_enabled_provider",
                "provider_type": provider_type,
            },
        )

    return {
        "provider": clean_provider(
            row
        )
    }


# ============================================================
# Audit Logs
# ============================================================

@app.get("/owner/audit")
async def audit_logs(
    authorization: Optional[str] = Header(
        default=None
    ),
    limit: int = Query(
        100,
        ge=1,
        le=500,
    ),
):

    actor = verify_session(
        authorization
    )

    limit = min(
        limit,
        MAX_AUDIT_LIMIT,
    )

    connection = db()

    try:

        rows = connection.execute(
            """
            SELECT *
            FROM provider_audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    finally:
        connection.close()

    return {
        "actor": actor,
        "count": len(rows),
        "events": [
            {
                "event_id": row[
                    "event_id"
                ],
                "event_type": row[
                    "event_type"
                ],
                "provider_id": row[
                    "provider_id"
                ],
                "actor": row["actor"],
                "details": json_loads(
                    row["details_json"]
                ),
                "created_at": row[
                    "created_at"
                ],
            }
            for row in rows
        ],
    }


# ============================================================
# Session Cleanup
# ============================================================

@app.post("/owner/sessions/cleanup")
async def cleanup_sessions(
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    now = int(
        time.time()
    )

    connection = db()

    try:

        cursor = connection.execute(
            """
            DELETE FROM provider_sessions
            WHERE expires_at <= ?
               OR revoked = 1
            """,
            (now,),
        )

        deleted = cursor.rowcount

        connection.commit()

    finally:
        connection.close()

    audit(
        "session_cleanup",
        None,
        actor,
        {
            "deleted": deleted,
        },
    )

    return {
        "status": "completed",
        "deleted_sessions": deleted,
    }


# ============================================================
# Internal Provider Registry
# ============================================================

@app.get(
    "/internal/provider-registry"
)
async def internal_provider_registry(
    x_arya_internal_secret: Optional[str] = Header(
        default=None
    ),
    authorization: Optional[str] = Header(
        default=None
    ),
):

    supplied_secret = (
        x_arya_internal_secret
    )

    if (
        not supplied_secret
        and authorization
        and authorization.lower().startswith(
            "bearer "
        )
    ):
        supplied_secret = (
            authorization[7:].strip()
        )

    verify_internal_secret(
        supplied_secret
    )

    connection = db()

    try:

        rows = connection.execute(
            """
            SELECT *
            FROM providers
            WHERE enabled = 1
            ORDER BY priority ASC, id ASC
            """
        ).fetchall()

    finally:
        connection.close()

    return {
        "count": len(rows),
        "providers": [
            clean_provider(row)
            for row in rows
        ],
    }


# ============================================================
# Owner Status
# ============================================================

@app.get("/owner/status")
async def owner_status(
    authorization: Optional[str] = Header(
        default=None
    ),
):

    actor = verify_session(
        authorization
    )

    connection = db()

    try:

        total = connection.execute(
            """
            SELECT COUNT(*)
            FROM providers
            """
        ).fetchone()[0]

        enabled = connection.execute(
            """
            SELECT COUNT(*)
            FROM providers
            WHERE enabled = 1
            """
        ).fetchone()[0]

        disabled = connection.execute(
            """
            SELECT COUNT(*)
            FROM providers
            WHERE enabled = 0
            """
        ).fetchone()[0]

        sessions = connection.execute(
            """
            SELECT COUNT(*)
            FROM provider_sessions
            WHERE revoked = 0
              AND expires_at > ?
            """,
            (int(time.time()),),
        ).fetchone()[0]

        versions = connection.execute(
            """
            SELECT COUNT(*)
            FROM provider_versions
            """
        ).fetchone()[0]

        audits = connection.execute(
            """
            SELECT COUNT(*)
            FROM provider_audit_logs
            """
        ).fetchone()[0]

    finally:
        connection.close()

    return {
        "actor": actor,
        "service": APP_NAME,
        "version": APP_VERSION,
        "providers_total": total,
        "providers_enabled": enabled,
        "providers_disabled": disabled,
        "provider_versions": versions,
        "audit_events": audits,
        "active_owner_sessions": sessions,
        "status": "operational",
    }


# ============================================================
# System Map
# ============================================================

@app.get("/system-map")
async def system_map():

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "port": PORT,
        "database": DATABASE,
        "runtime": {
            "provider_list": (
                "/runtime/providers"
            ),
            "provider_select": (
                "/runtime/providers/select/{provider_type}"
            ),
            "capabilities": (
                "/runtime/providers/capabilities"
            ),
        },
        "owner": {
            "login": "/owner/login",
            "providers": "/owner/providers",
            "audit": "/owner/audit",
            "status": "/owner/status",
        },
        "internal": {
            "provider_registry": (
                "/internal/provider-registry"
            ),
        },
    }


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup_event():

    logger.info(
        "%s v%s started on %s:%s",
        APP_NAME,
        APP_VERSION,
        HOST,
        PORT,
    )

    logger.info(
        "OWNER authentication configured: %s",
        bool(
            OWNER_EMAIL
            and OWNER_SECRET
        ),
    )

    logger.info(
        "Internal authentication configured: %s",
        bool(INTERNAL_SECRET),
    )


# ============================================================
# Standalone execution
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        reload=False,
    )
