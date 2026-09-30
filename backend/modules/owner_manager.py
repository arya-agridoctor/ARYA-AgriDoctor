"""
ARYA AgriDoctor
OWNER Management Service
Version: 1.0.0

Independent OWNER / Super-Admin management layer.

Responsibilities:
- OWNER authentication
- TOTP MFA
- Recovery tokens
- Provider management
- System settings
- Feature flags
- Service controls
- Emergency / kill switch
- Audit logging
- API secret references
- Configuration snapshots
- Provider enable/disable
- Safe remote management foundation

IMPORTANT:
This module does not modify main.py or other ARYA modules.
Secrets are referenced through environment variables and are never
returned through API responses.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "ARYA OWNER Manager"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_OWNER_HOST",
    "0.0.0.0",
)

PORT = int(
    os.getenv(
        "ARYA_OWNER_PORT",
        "8096",
    )
)

DATABASE = os.getenv(
    "ARYA_OWNER_DATABASE",
    "owner_manager.db",
)

OWNER_EMAIL = os.getenv(
    "ARYA_MASTER_EMAIL",
    "",
).strip().lower()

OWNER_PASSWORD_HASH = os.getenv(
    "ARYA_OWNER_PASSWORD_HASH",
    "",
)

OWNER_SECRET = os.getenv(
    "ARYA_MASTER_SECRET",
    "",
)

SESSION_HOURS = int(
    os.getenv(
        "ARYA_OWNER_SESSION_HOURS",
        "12",
    )
)

MAX_LOGIN_ATTEMPTS = int(
    os.getenv(
        "ARYA_OWNER_MAX_LOGIN_ATTEMPTS",
        "5",
    )
)

LOCKOUT_MINUTES = int(
    os.getenv(
        "ARYA_OWNER_LOCKOUT_MINUTES",
        "15",
    )
)

TOTP_SECRET = os.getenv(
    "ARYA_OWNER_TOTP_SECRET",
    "",
)

LOG_LEVEL = os.getenv(
    "ARYA_OWNER_LOG_LEVEL",
    "INFO",
).upper()


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=getattr(
        logging,
        LOG_LEVEL,
        logging.INFO,
    ),
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(name)s | "
        "%(message)s"
    ),
)

logger = logging.getLogger(
    "arya.owner.manager"
)


# ============================================================
# TIME
# ============================================================

def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def utc_timestamp() -> int:
    return int(
        time.time()
    )


# ============================================================
# DATABASE
# ============================================================

def db() -> sqlite3.Connection:
    connection = sqlite3.connect(
        DATABASE,
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_db() -> None:
    connection = db()

    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS owner_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                owner_email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                ip_address TEXT,
                user_agent TEXT
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                success INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                ip_address TEXT,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                value_type TEXT NOT NULL DEFAULT 'string',
                description TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS feature_flags (
                key TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                description TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS service_controls (
                service_name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                kill_switch INTEGER NOT NULL DEFAULT 0,
                maintenance INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS provider_registry (
                provider_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                base_url TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                secret_ref TEXT,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recovery_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT
            );

            CREATE TABLE IF NOT EXISTS config_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_hash TEXT NOT NULL,
                snapshot TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                created_at TEXT NOT NULL,
                ip_address TEXT
            );
            """
        )

        connection.commit()

    finally:
        connection.close()


init_db()


# ============================================================
# SECURITY HELPERS
# ============================================================

def hash_value(value: str) -> str:
    return hashlib.sha256(
        value.encode(
            "utf-8"
        )
    ).hexdigest()


def secure_compare(
    first: str,
    second: str,
) -> bool:
    return hmac.compare_digest(
        first.encode(),
        second.encode(),
    )


def generate_token() -> str:
    return secrets.token_urlsafe(48)


def password_hash(
    password: str,
) -> str:
    if not OWNER_SECRET:
        raise RuntimeError(
            "ARYA_MASTER_SECRET is not configured"
        )

    return hmac.new(
        OWNER_SECRET.encode(),
        password.encode(),
        hashlib.sha256,
    ).hexdigest()


def verify_password(
    password: str,
) -> bool:

    if not OWNER_PASSWORD_HASH:
        return False

    calculated = password_hash(
        password
    )

    return secure_compare(
        calculated,
        OWNER_PASSWORD_HASH,
    )


# ============================================================
# TOTP
# ============================================================

def hotp(
    secret: bytes,
    counter: int,
) -> int:

    digest = hmac.new(
        secret,
        counter.to_bytes(
            8,
            "big",
        ),
        hashlib.sha1,
    ).digest()

    offset = digest[-1] & 15

    code = (
        (
            (digest[offset] & 127) << 24
        )
        | (
            digest[offset + 1] << 16
        )
        | (
            digest[offset + 2] << 8
        )
        | digest[offset + 3]
    )

    return code % 1_000_000


def verify_totp(
    code: str,
) -> bool:

    if not TOTP_SECRET:
        return False

    normalized = (
        TOTP_SECRET
        .replace(" ", "")
        .upper()
    )

    padding = (
        "="
        * (
            -len(normalized) % 8
        )
    )

    try:
        secret = base64.b32decode(
            normalized + padding
        )
    except Exception:
        return False

    try:
        supplied = int(code)
    except Exception:
        return False

    current = int(
        time.time() // 30
    )

    for offset in (-1, 0, 1):
        expected = hotp(
            secret,
            current + offset,
        )

        if expected == supplied:
            return True

    return False


# ============================================================
# AUDIT
# ============================================================

def audit(
    actor: str,
    action: str,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> None:

    connection = db()

    try:
        connection.execute(
            """
            INSERT INTO audit_logs
            (
                actor,
                action,
                target,
                details,
                created_at,
                ip_address
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                actor,
                action,
                target,
                json.dumps(
                    details or {},
                    ensure_ascii=False,
                    default=str,
                ),
                utc_now(),
                ip_address,
            ),
        )

        connection.commit()

    finally:
        connection.close()


# ============================================================
# LOGIN PROTECTION
# ============================================================

def too_many_attempts(
    email: str,
    ip_address: Optional[str],
) -> bool:

    since = (
        datetime.now(
            timezone.utc
        )
        - timedelta(
            minutes=LOCKOUT_MINUTES
        )
    ).isoformat()

    connection = db()

    try:
        row = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM login_attempts
            WHERE email = ?
              AND success = 0
              AND created_at >= ?
              AND (
                    ip_address = ?
                    OR ?
              )
            """,
            (
                email,
                since,
                ip_address,
                ip_address is None,
            ),
        ).fetchone()

        return int(
            row["count"]
        ) >= MAX_LOGIN_ATTEMPTS

    finally:
        connection.close()


def record_login(
    email: str,
    success: bool,
    ip_address: Optional[str],
    reason: str = "",
) -> None:

    connection = db()

    try:
        connection.execute(
            """
            INSERT INTO login_attempts
            (
                email,
                success,
                created_at,
                ip_address,
                reason
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                email,
                1 if success else 0,
                utc_now(),
                ip_address,
                reason,
            ),
        )

        connection.commit()

    finally:
        connection.close()


# ============================================================
# SESSION
# ============================================================

def create_session(
    email: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> str:

    token = generate_token()

    token_hash = hash_value(
        token
    )

    created = datetime.now(
        timezone.utc
    )

    expires = (
        created
        + timedelta(
            hours=SESSION_HOURS
        )
    )

    connection = db()

    try:
        connection.execute(
            """
            INSERT INTO owner_sessions
            (
                token_hash,
                owner_email,
                created_at,
                expires_at,
                ip_address,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                token_hash,
                email,
                created.isoformat(),
                expires.isoformat(),
                ip_address,
                user_agent,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    return token


def validate_session(
    token: str,
) -> sqlite3.Row:

    token_hash = hash_value(
        token
    )

    connection = db()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM owner_sessions
            WHERE token_hash = ?
              AND revoked_at IS NULL
            """,
            (
                token_hash,
            ),
        ).fetchone()

    finally:
        connection.close()

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER session",
        )

    expires = datetime.fromisoformat(
        row["expires_at"]
    )

    if expires <= datetime.now(
        timezone.utc
    ):
        raise HTTPException(
            status_code=401,
            detail="OWNER session expired",
        )

    return row


def revoke_session(
    token: str,
) -> None:

    token_hash = hash_value(
        token
    )

    connection = db()

    try:
        connection.execute(
            """
            UPDATE owner_sessions
            SET revoked_at = ?
            WHERE token_hash = ?
            """,
            (
                utc_now(),
                token_hash,
            ),
        )

        connection.commit()

    finally:
        connection.close()


# ============================================================
# AUTH DEPENDENCY
# ============================================================

def require_owner(
    authorization: Optional[str] = Header(
        default=None
    ),
) -> sqlite3.Row:

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="OWNER authorization required",
        )

    if not authorization.lower().startswith(
        "bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Bearer token required",
        )

    token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization",
        )

    return validate_session(
        token
    )


# ============================================================
# MODELS
# ============================================================

class LoginRequest(BaseModel):
    email: str
    password: str
    totp_code: Optional[str] = None


class SettingRequest(BaseModel):
    key: str = Field(
        min_length=1,
        max_length=200,
    )
    value: Any
    value_type: str = "string"
    description: Optional[str] = None


class FeatureRequest(BaseModel):
    key: str = Field(
        min_length=1,
        max_length=200,
    )
    enabled: bool
    description: Optional[str] = None


class ServiceControlRequest(BaseModel):
    service_name: str = Field(
        min_length=1,
        max_length=200,
    )
    enabled: bool = True
    kill_switch: bool = False
    maintenance: bool = False


class ProviderRequest(BaseModel):
    provider_id: str = Field(
        min_length=1,
        max_length=200,
    )
    name: str = Field(
        min_length=1,
        max_length=200,
    )
    category: str = Field(
        min_length=1,
        max_length=100,
    )
    base_url: Optional[str] = None
    enabled: bool = True
    priority: int = 100
    secret_ref: Optional[str] = None
    description: Optional[str] = None


class RecoveryRequest(BaseModel):
    hours: int = Field(
        default=24,
        ge=1,
        le=168,
    )


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Independent secure OWNER management "
        "layer for ARYA AgriDoctor"
    ),
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "time": utc_now(),
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": APP_NAME,
        "version": APP_VERSION,
        "time": utc_now(),
    }


# ============================================================
# LOGIN
# ============================================================

@app.post("/owner/login")
def owner_login(
    request: Request,
    payload: LoginRequest,
):
    email = (
        payload.email
        .strip()
        .lower()
    )

    ip_address = (
        request.client.host
        if request.client
        else None
    )

    if not OWNER_EMAIL:
        raise HTTPException(
            status_code=503,
            detail=(
                "OWNER email is not configured"
            ),
        )

    if too_many_attempts(
        email,
        ip_address,
    ):
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many failed login attempts"
            ),
        )

    if email != OWNER_EMAIL:
        record_login(
            email,
            False,
            ip_address,
            "invalid_email",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials",
        )

    if not verify_password(
        payload.password
    ):
        record_login(
            email,
            False,
            ip_address,
            "invalid_password",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials",
        )

    if not TOTP_SECRET:
        raise HTTPException(
            status_code=503,
            detail=(
                "OWNER TOTP is not configured"
            ),
        )

    if not payload.totp_code:
        raise HTTPException(
            status_code=401,
            detail="TOTP code required",
        )

    if not verify_totp(
        payload.totp_code
    ):
        record_login(
            email,
            False,
            ip_address,
            "invalid_totp",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid TOTP code",
        )

    user_agent = request.headers.get(
        "user-agent"
    )

    token = create_session(
        email,
        ip_address,
        user_agent,
    )

    record_login(
        email,
        True,
        ip_address,
        "login_success",
    )

    audit(
        email,
        "owner_login",
        ip_address=ip_address,
    )

    return {
        "ok": True,
        "access_token": token,
        "token_type": "bearer",
        "expires_in_hours": SESSION_HOURS,
        "logged_in_at": utc_now(),
    }


# ============================================================
# LOGOUT
# ============================================================

@app.post("/owner/logout")
def owner_logout(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization required",
        )

    if not authorization.lower().startswith(
        "bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Bearer token required",
        )

    token = authorization[7:].strip()

    session = validate_session(
        token
    )

    revoke_session(
        token
    )

    audit(
        session["owner_email"],
        "owner_logout",
    )

    return {
        "ok": True,
        "logged_out_at": utc_now(),
    }


# ============================================================
# OWNER PROFILE
# ============================================================

@app.get("/owner/me")
def owner_me(
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    return {
        "ok": True,
        "owner": session[
            "owner_email"
        ],
        "session_created_at": session[
            "created_at"
        ],
        "session_expires_at": session[
            "expires_at"
        ],
    }


# ============================================================
# SETTINGS
# ============================================================

@app.get("/owner/settings")
def list_settings(
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM settings
            ORDER BY key
            """
        ).fetchall()

    finally:
        connection.close()

    return {
        "ok": True,
        "settings": [
            {
                "key": row["key"],
                "value": json.loads(
                    row["value"]
                )
                if row["value_type"] == "json"
                else row["value"],
                "value_type": row[
                    "value_type"
                ],
                "description": row[
                    "description"
                ],
                "updated_at": row[
                    "updated_at"
                ],
            }
            for row in rows
        ],
    }


@app.post("/owner/settings")
def set_setting(
    payload: SettingRequest,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    if payload.value_type == "json":
        stored = json.dumps(
            payload.value,
            ensure_ascii=False,
            default=str,
        )
    else:
        stored = str(
            payload.value
        )

    connection = db()

    try:
        connection.execute(
            """
            INSERT INTO settings
            (
                key,
                value,
                value_type,
                description,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(key)
            DO UPDATE SET
                value = excluded.value,
                value_type = excluded.value_type,
                description = excluded.description,
                updated_at = excluded.updated_at
            """,
            (
                payload.key,
                stored,
                payload.value_type,
                payload.description,
                utc_now(),
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        session["owner_email"],
        "setting
