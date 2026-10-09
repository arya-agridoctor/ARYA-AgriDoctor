"""
===============================================================
ARYA AgriDoctor
OWNER Management Service
Version: 2.0.0

Independent OWNER / Super-Admin management layer.

Capabilities:
- OWNER authentication
- TOTP multi-factor authentication
- Single-use recovery tokens
- Secure session management
- System settings
- Feature flags
- Service controls
- Emergency kill switch
- Provider registry and enable/disable
- Audit logging
- Environment-variable secret references
- Configuration snapshots
- Configuration restoration
- Login rate limiting
- Security-oriented input validation

IMPORTANT:
- This module does not modify main.py or other ARYA modules.
- Secrets are never returned through API responses.
- Feature flags and service controls are stored in this service's
  database. Other ARYA services must explicitly integrate with
  this database or its API to enforce those controls.
===============================================================
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
)
from pydantic import BaseModel, Field


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "ARYA OWNER Manager"
APP_VERSION = "2.0.0"

HOST = os.getenv(
    "ARYA_OWNER_HOST",
    "0.0.0.0",
)

try:
    PORT = int(
        os.getenv(
            "ARYA_OWNER_PORT",
            "8096",
        )
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

except ValueError as exc:
    raise RuntimeError(
        "Invalid ARYA OWNER numeric configuration"
    ) from exc


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
).strip()

OWNER_SECRET = os.getenv(
    "ARYA_MASTER_SECRET",
    "",
)

TOTP_SECRET = os.getenv(
    "ARYA_OWNER_TOTP_SECRET",
    "",
).strip()

LOG_LEVEL = os.getenv(
    "ARYA_OWNER_LOG_LEVEL",
    "INFO",
).upper()

MAX_REQUEST_BODY_BYTES = 256 * 1024
MAX_SETTING_BYTES = 64 * 1024
MAX_SNAPSHOT_BYTES = 1024 * 1024
MAX_AUDIT_PAGE_SIZE = 200
MAX_RECOVERY_TOKENS = 20

if not 1 <= PORT <= 65535:
    raise RuntimeError(
        "ARYA_OWNER_PORT must be between 1 and 65535"
    )

if not 1 <= SESSION_HOURS <= 168:
    raise RuntimeError(
        "ARYA_OWNER_SESSION_HOURS must be between 1 and 168"
    )

if not 1 <= MAX_LOGIN_ATTEMPTS <= 100:
    raise RuntimeError(
        "ARYA_OWNER_MAX_LOGIN_ATTEMPTS must be between 1 and 100"
    )

if not 1 <= LOCKOUT_MINUTES <= 1440:
    raise RuntimeError(
        "ARYA_OWNER_LOCKOUT_MINUTES must be between 1 and 1440"
    )


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
# TIME HELPERS
# ============================================================

def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def utc_timestamp() -> int:
    return int(time.time())


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
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

    connection.execute(
        "PRAGMA busy_timeout = 30000"
    )

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def init_db() -> None:
    connection = db()

    try:
        connection.execute(
            "PRAGMA journal_mode = WAL"
        )

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

            CREATE INDEX IF NOT EXISTS
                idx_owner_sessions_email
            ON owner_sessions(owner_email);

            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                success INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                ip_address TEXT,
                reason TEXT
            );

            CREATE INDEX IF NOT EXISTS
                idx_login_attempts_email_time
            ON login_attempts(email, created_at);

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

            CREATE INDEX IF NOT EXISTS
                idx_audit_logs_created
            ON audit_logs(created_at);

            CREATE INDEX IF NOT EXISTS
                idx_audit_logs_actor
            ON audit_logs(actor);
            """
        )

        connection.commit()

    finally:
        connection.close()


init_db()


# ============================================================
# GENERAL SECURITY HELPERS
# ============================================================

def hash_value(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def secure_compare(
    first: str,
    second: str,
) -> bool:
    return hmac.compare_digest(
        first.encode("utf-8"),
        second.encode("utf-8"),
    )


def generate_token() -> str:
    return secrets.token_urlsafe(48)


def get_client_ip(
    request: Request,
) -> Optional[str]:
    # Do not trust X-Forwarded-For without a configured,
    # trusted reverse proxy.
    if request.client:
        return request.client.host

    return None


def validate_identifier(
    value: str,
    label: str,
    max_length: int = 200,
) -> str:
    normalized = value.strip()

    if not normalized:
        raise HTTPException(
            status_code=400,
            detail=f"{label} is required",
        )

    if len(normalized) > max_length:
        raise HTTPException(
            status_code=400,
            detail=f"{label} is too long",
        )

    if any(
        ord(character) < 32
        for character in normalized
    ):
        raise HTTPException(
            status_code=400,
            detail=f"{label} contains invalid characters",
        )

    return normalized


def validate_http_url(
    value: Optional[str],
) -> Optional[str]:
    if value is None:
        return None

    normalized = value.strip()

    if not normalized:
        return None

    if len(normalized) > 2048:
        raise HTTPException(
            status_code=400,
            detail="Provider URL is too long",
        )

    try:
        parsed = urlsplit(normalized)

        if parsed.scheme not in (
            "http",
            "https",
        ):
            raise ValueError

        if not parsed.hostname:
            raise ValueError

        if parsed.username or parsed.password:
            raise ValueError

        if parsed.fragment:
            raise ValueError

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid provider URL",
        )

    return normalized


def validate_secret_reference(
    value: Optional[str],
) -> Optional[str]:
    if value is None:
        return None

    normalized = value.strip()

    if not normalized:
        return None

    if len(normalized) > 200:
        raise HTTPException(
            status_code=400,
            detail="Secret reference is too long",
        )

    # Accept an environment-variable reference, not a secret value.
    if not re.fullmatch(
        r"[A-Z][A-Z0-9_]{0,199}",
        normalized,
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "secret_ref must be an environment "
                "variable name, not a secret value"
            ),
        )

    return normalized


def is_sensitive_key(
    key: str,
) -> bool:
    normalized = re.sub(
        r"[^a-z0-9]",
        "",
        key.lower(),
    )

    sensitive_fragments = (
        "password",
        "passwd",
        "secret",
        "apikey",
        "accesstoken",
        "refreshtoken",
        "privatekey",
        "mnemonic",
        "seedphrase",
        "authorization",
        "credential",
        "walletprivate",
    )

    return any(
        fragment in normalized
        for fragment in sensitive_fragments
    )


# ============================================================
# PASSWORD VERIFICATION
# ============================================================

def password_hash(
    password: str,
) -> str:
    if not OWNER_SECRET:
        raise RuntimeError(
            "ARYA_MASTER_SECRET is not configured"
        )

    return hmac.new(
        OWNER_SECRET.encode("utf-8"),
        password.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_password(
    password: str,
) -> bool:
    if (
        not OWNER_PASSWORD_HASH
        or not OWNER_SECRET
    ):
        return False

    try:
        calculated = password_hash(
            password
        )
    except Exception:
        return False

    return secure_compare(
        calculated,
        OWNER_PASSWORD_HASH,
    )


# ============================================================
# TOTP MULTI-FACTOR AUTHENTICATION
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

    if not re.fullmatch(
        r"[0-9]{6}",
        str(code or ""),
    ):
        return False

    normalized = (
        TOTP_SECRET
        .replace(" ", "")
        .upper()
    )

    padding = "=" * (
        -len(normalized) % 8
    )

    try:
        secret = base64.b32decode(
            normalized + padding,
            casefold=True,
        )
    except (
        ValueError,
        binascii.Error,
    ):
        return False

    if len(secret) < 10:
        return False

    current = int(
        time.time() // 30
    )

    supplied = str(code)

    for offset in (-1, 0, 1):
        expected = f"{hotp(secret, current + offset):06d}"

        if secure_compare(
            expected,
            supplied,
        ):
            return True

    return False


# ============================================================
# AUDIT LOGGING
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
        safe_details = details or {}

        serialized = json.dumps(
            safe_details,
            ensure_ascii=False,
            default=str,
        )

        if len(serialized) > 16000:
            serialized = json.dumps(
                {
                    "truncated": True,
                    "message": (
                        "Audit details exceeded "
                        "the maximum permitted length"
                    ),
                },
                ensure_ascii=False,
            )

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
                serialized,
                utc_now(),
                ip_address,
            ),
        )

        connection.commit()

    finally:
        connection.close()


# ============================================================
# LOGIN ATTEMPT PROTECTION
# ============================================================

def too_many_attempts(
    email: str,
    ip_address: Optional[str],
) -> bool:
    since = (
        datetime.now(timezone.utc)
        - timedelta(
            minutes=LOCKOUT_MINUTES
        )
    ).isoformat()

    connection = db()

    try:
        if ip_address is None:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM login_attempts
                WHERE email = ?
                  AND success = 0
                  AND created_at >= ?
                """,
                (
                    email,
                    since,
                ),
            ).fetchone()

        else:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM login_attempts
                WHERE success = 0
                  AND created_at >= ?
                  AND (
                        email = ?
                        OR ip_address = ?
                  )
                """,
                (
                    since,
                    email,
                    ip_address,
                ),
            ).fetchone()

        return (
            int(row["count"])
            >= MAX_LOGIN_ATTEMPTS
        )

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
# SESSION MANAGEMENT
# ============================================================

def create_session(
    email: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> str:
    token = generate_token()

    token_digest = hash_value(
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
                token_digest,
                email,
                created.isoformat(),
                expires.isoformat(),
                ip_address,
                (user_agent or "")[:500],
            ),
        )

        connection.commit()

    finally:
        connection.close()

    return token


def validate_session(
    token: str,
) -> sqlite3.Row:
    if (
        not token
        or len(token) > 512
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER session",
        )

    token_digest = hash_value(
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
                token_digest,
            ),
        ).fetchone()

    finally:
        connection.close()

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER session",
        )

    try:
        expires = parse_utc(
            row["expires_at"]
        )
    except (
        ValueError,
        TypeError,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER session",
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
    token_digest = hash_value(
        token
    )

    connection = db()

    try:
        connection.execute(
            """
            UPDATE owner_sessions
            SET revoked_at = ?
            WHERE token_hash = ?
              AND revoked_at IS NULL
            """,
            (
                utc_now(),
                token_digest,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def revoke_all_sessions(
    email: str,
) -> int:
    connection = db()

    try:
        cursor = connection.execute(
            """
            UPDATE owner_sessions
            SET revoked_at = ?
            WHERE owner_email = ?
              AND revoked_at IS NULL
            """,
            (
                utc_now(),
                email,
            ),
        )

        connection.commit()

        return cursor.rowcount

    finally:
        connection.close()


# ============================================================
# OWNER AUTHORIZATION
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

    scheme, separator, token = (
        authorization.partition(" ")
    )

    if (
        not separator
        or scheme.lower() != "bearer"
        or not token.strip()
    ):
        raise HTTPException(
            status_code=401,
            detail="Bearer token required",
        )

    return validate_session(
        token.strip()
    )


# ============================================================
# REQUEST MODELS
# ============================================================

class LoginRequest(BaseModel):
    email: str = Field(
        min_length=3,
        max_length=320,
    )

    password: str = Field(
        min_length=1,
        max_length=1024,
    )

    totp_code: Optional[str] = Field(
        default=None,
        max_length=20,
    )


class SettingRequest(BaseModel):
    key: str = Field(
        min_length=1,
        max_length=200,
    )

    value: Any

    value_type: str = Field(
        default="string",
        max_length=20,
    )

    description: Optional[str] = Field(
        default=None,
        max_length=2000,
    )


class FeatureRequest(BaseModel):
    key: str = Field(
        min_length=1,
        max_length=200,
    )

    enabled: bool

    description: Optional[str] = Field(
        default=None,
        max_length=2000,
    )


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

    base_url: Optional[str] = Field(
        default=None,
        max_length=2048,
    )

    enabled: bool = True

    priority: int = Field(
        default=100,
        ge=0,
        le=100000,
    )

    secret_ref: Optional[str] = Field(
        default=None,
        max_length=200,
    )

    description: Optional[str] = Field(
        default=None,
        max_length=2000,
    )


class RecoveryRequest(BaseModel):
    hours: int = Field(
        default=24,
        ge=1,
        le=168,
    )

    count: int = Field(
        default=1,
        ge=1,
        le=MAX_RECOVERY_TOKENS,
    )


class RecoveryConsumeRequest(BaseModel):
    email: str = Field(
        min_length=3,
        max_length=320,
    )

    password: str = Field(
        min_length=1,
        max_length=1024,
    )

    recovery_token: str = Field(
        min_length=16,
        max_length=256,
    )


class SnapshotRestoreRequest(BaseModel):
    snapshot_id: int = Field(
        gt=0,
    )


class EmergencyRequest(BaseModel):
    enabled: bool

    reason: str = Field(
        min_length=3,
        max_length=2000,
    )


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Independent OWNER management layer "
        "for ARYA AgriDoctor"
    ),
)


# ============================================================
# ROOT AND HEALTH
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
    connection = db()

    try:
        connection.execute(
            "SELECT 1"
        ).fetchone()

    finally:
        connection.close()

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
    email = payload.email.strip().lower()

    ip_address = get_client_ip(
        request
    )

    if not OWNER_EMAIL:
        raise HTTPException(
            status_code=503,
            detail="OWNER email is not configured",
        )

    if (
        not OWNER_PASSWORD_HASH
        or not OWNER_SECRET
    ):
        raise HTTPException(
            status_code=503,
            detail="OWNER password authentication is not configured",
        )

    if not TOTP_SECRET:
        raise HTTPException(
            status_code=503,
            detail="OWNER TOTP is not configured",
        )

    if too_many_attempts(
        email,
        ip_address,
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts",
        )

    if not secure_compare(
        email,
        OWNER_EMAIL,
    ):
        record_login(
            email,
            False,
            ip_address,
            "invalid_credentials",
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
            "invalid_credentials",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials",
        )

    if not payload.totp_code:
        record_login(
            email,
            False,
            ip_address,
            "missing_totp",
        )

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

    token = create_session(
        email,
        ip_address,
        request.headers.get("user-agent"),
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
    request: Request,
    session: sqlite3.Row = Depends(
        require_owner
    ),
    authorization: Optional[str] = Header(
        default=None
    ),
):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization required",
        )

    token = authorization.partition(" ")[2].strip()

    revoke_session(
        token
    )

    audit(
        session["owner_email"],
        "owner_logout",
        ip_address=get_client_ip(request),
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
        "owner": session["owner_email"],
        "session_created_at": session["created_at"],
        "session_expires_at": session["expires_at"],
    }


# ============================================================
# OWNER SESSION MANAGEMENT
# ============================================================

@app.get("/owner/sessions")
def list_sessions(
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                owner_email,
                created_at,
                expires_at,
                revoked_at,
                ip_address,
                user_agent
            FROM owner_sessions
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()

    finally:
        connection.close()

    return {
        "ok": True,
        "sessions": [
            dict(row)
            for row in rows
        ],
    }


@app.post("/owner/sessions/revoke-all")
def owner_revoke_all_sessions(
    request: Request,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    revoked = revoke_all_sessions(
        session["owner_email"]
    )

    audit(
        session["owner_email"],
        "owner_revoke_all_sessions",
        details={
            "revoked_count": revoked,
        },
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "revoked_count": revoked,
        "message": (
            "All OWNER sessions were revoked. "
            "Log in again to continue."
        ),
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

    result = []

    for row in rows:
        key = row["key"]

        # Never return values stored under secret-like keys.
        if is_sensitive_key(key):
            safe_value = None
            redacted = True

        else:
            redacted = False

            try:
                if row["value_type"] == "json":
                    safe_value = json.loads(
                        row["value"]
                    )
                else:
                    safe_value = row["value"]

            except (
                ValueError,
                TypeError,
            ):
                safe_value = None
                redacted = True

        result.append(
            {
                "key": key,
                "value": safe_value,
                "redacted": redacted,
                "value_type": row["value_type"],
                "description": row["description"],
                "updated_at": row["updated_at"],
            }
        )

    return {
        "ok": True,
        "settings": result,
    }


@app.post("/owner/settings")
def set_setting(
    request: Request,
    payload: SettingRequest,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    key = validate_identifier(
        payload.key,
        "Setting key",
    )

    value_type = payload.value_type.strip().lower()

    if value_type not in (
        "string",
        "number",
        "boolean",
        "json",
    ):
        raise HTTPException(
            status_code=400,
            detail="Unsupported setting value_type",
        )

    if is_sensitive_key(key):
        raise HTTPException(
            status_code=400,
            detail=(
                "Sensitive credentials must be stored "
                "in environment variables, not settings"
            ),
        )

    try:
        if value_type == "json":
            stored = json.dumps(
                payload.value,
                ensure_ascii=False,
                allow_nan=False,
            )

        elif value_type == "boolean":
            if not isinstance(
                payload.value,
                bool,
            ):
                raise ValueError(
                    "Expected boolean"
                )

            stored = (
                "true"
                if payload.value
                else "false"
            )

        elif value_type == "number":
            if isinstance(
                payload.value,
                bool,
            ) or not isinstance(
                payload.value,
                (int, float),
            ):
                raise ValueError(
                    "Expected number"
                )

            stored = json.dumps(
                payload.value,
                allow_nan=False,
            )

        else:
            if isinstance(
                payload.value,
                (dict, list),
            ):
                raise ValueError(
                    "String values must be scalar"
                )

            stored = str(
                payload.value
            )

    except (
        TypeError,
        ValueError,
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid setting value",
        )

    if len(stored.encode("utf-8")) > MAX_SETTING_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Setting value is too large",
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
                key,
                stored,
                value_type,
                payload.description,
                utc_now(),
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        session["owner_email"],
        "setting_updated",
        target=key,
        details={
            "value_type": value_type,
        },
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "key": key,
        "updated_at": utc_now(),
    }


@app.delete("/owner/settings/{key}")
def delete_setting(
    key: str,
    request: Request,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    key = validate_identifier(
        key,
        "Setting key",
    )

    connection = db()

    try:
        cursor = connection.execute(
            """
            DELETE FROM settings
            WHERE key = ?
            """,
            (key,),
        )

        connection.commit()

    finally:
        connection.close()

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Setting not found",
        )

    audit(
        session["owner_email"],
        "setting_deleted",
        target=key,
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "deleted": key,
    }


# ============================================================
# FEATURE FLAGS
# ============================================================

@app.get("/owner/feature-flags")
def list_feature_flags(
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM feature_flags
            ORDER BY key
            """
        ).fetchall()

    finally:
        connection.close()

    return {
        "ok": True,
        "feature_flags": [
            {
                "key": row["key"],
                "enabled": bool(
                    row["enabled"]
                ),
                "description": row["description"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ],
    }


@app.post("/owner/feature-flags")
def set_feature_flag(
    request: Request,
    payload: FeatureRequest,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    key = validate_identifier(
        payload.key,
        "Feature key",
    )

    connection = db()

    try:
        connection.execute(
            """
            INSERT INTO feature_flags
            (
                key,
                enabled,
                description,
                updated_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key)
            DO UPDATE SET
                enabled = excluded.enabled,
                description = excluded.description,
                updated_at = excluded.updated_at
            """,
            (
                key,
                int(payload.enabled),
                payload.description,
                utc_now(),
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        session["owner_email"],
        "feature_flag_updated",
        target=key,
        details={
            "enabled": payload.enabled,
        },
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "key": key,
        "enabled": payload.enabled,
        "updated_at": utc_now(),
    }


@app.delete("/owner/feature-flags/{key}")
def delete_feature_flag(
    key: str,
    request: Request,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    key = validate_identifier(
        key,
        "Feature key",
    )

    connection = db()

    try:
        cursor = connection.execute(
            """
            DELETE FROM feature_flags
            WHERE key = ?
            """,
            (key,),
        )

        connection.commit()

    finally:
        connection.close()

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Feature flag not found",
        )

    audit(
        session["owner_email"],
        "feature_flag_deleted",
        target=key,
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "deleted": key,
    }


# ============================================================
# SERVICE CONTROLS
# ============================================================

@app.get("/owner/services")
def list_service_controls(
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM service_controls
            ORDER BY service_name
            """
        ).fetchall()

    finally:
        connection.close()

    return {
        "ok": True,
        "services": [
            {
                "service_name": row["service_name"],
                "enabled": bool(row["enabled"]),
                "kill_switch": bool(row["kill_switch"]),
                "maintenance": bool(row["maintenance"]),
                "updated_at": row["updated_at"],
            }
            for row in rows
        ],
    }


@app.post("/owner/services")
def set_service_control(
    request: Request,
    payload: ServiceControlRequest,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    service_name = validate_identifier(
        payload.service_name,
        "Service name",
    )

    connection = db()

    try:
        connection.execute(
            """
            INSERT INTO service_controls
            (
                service_name,
                enabled,
                kill_switch,
                maintenance,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(service_name)
            DO UPDATE SET
                enabled = excluded.enabled,
                kill_switch = excluded.kill_switch,
                maintenance = excluded.maintenance,
                updated_at = excluded.updated_at
            """,
            (
                service_name,
                int(payload.enabled),
                int(payload.kill_switch),
                int(payload.maintenance),
                utc_now(),
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        session["owner_email"],
        "service_control_updated",
        target=service_name,
        details={
            "enabled": payload.enabled,
            "kill_switch": payload.kill_switch,
            "maintenance": payload.maintenance,
        },
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "service_name": service_name,
        "enabled": payload.enabled,
        "kill_switch": payload.kill_switch,
        "maintenance": payload.maintenance,
        "updated_at": utc_now(),
    }


# ============================================================
# EMERGENCY KILL SWITCH
# ============================================================

@app.post("/owner/emergency")
def emergency_control(
    request: Request,
    payload: EmergencyRequest,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    service_name = "__GLOBAL__"

    connection = db()

    try:
        connection.execute(
            """
            INSERT INTO service_controls
            (
                service_name,
                enabled,
                kill_switch,
                maintenance,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(service_name)
            DO UPDATE SET
                enabled = excluded.enabled,
                kill_switch = excluded.kill_switch,
                maintenance = excluded.maintenance,
                updated_at = excluded.updated_at
            """,
            (
                service_name,
                0 if payload.enabled else 1,
                1 if payload.enabled else 0,
                1 if payload.enabled else 0,
                utc_now(),
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        session["owner_email"],
        (
            "emergency_kill_switch_enabled"
            if payload.enabled
            else "emergency_kill_switch_disabled"
        ),
        target=service_name,
        details={
            "enabled": payload.enabled,
            "reason": payload.reason,
        },
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "emergency_kill_switch": payload.enabled,
        "updated_at": utc_now(),
        "warning": (
            "This state is recorded in the OWNER database. "
            "Other services must explicitly read and enforce "
            "the global control for it to affect runtime behavior."
        ),
    }


@app.get("/owner/emergency")
def get_emergency_state(
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM service_controls
            WHERE service_name = '__GLOBAL__'
            """
        ).fetchone()

    finally:
        connection.close()

    if not row:
        return {
            "ok": True,
            "emergency_kill_switch": False,
            "maintenance": False,
        }

    return {
        "ok": True,
        "emergency_kill_switch": bool(
            row["kill_switch"]
        ),
        "maintenance": bool(
            row["maintenance"]
        ),
        "enabled": bool(
            row["enabled"]
        ),
        "updated_at": row["updated_at"],
    }


# ============================================================
# PROVIDER REGISTRY
# ============================================================

@app.get("/owner/providers")
def list_providers(
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        rows = connection.execute(
            """
            SELECT
                provider_id,
                name,
                category,
                base_url,
                enabled,
                priority,
                secret_ref,
                description,
                created_at,
                updated_at
            FROM provider_registry
            ORDER BY priority, provider_id
            """
        ).fetchall()

    finally:
        connection.close()

    return {
        "ok": True,
        "providers": [
            {
                "provider_id": row["provider_id"],
                "name": row["name"],
                "category": row["category"],
                "base_url": row["base_url"],
                "enabled": bool(row["enabled"]),
                "priority": row["priority"],
                "secret_ref": row["secret_ref"],
                "description": row["description"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ],
    }


@app.post("/owner/providers")
def upsert_provider(
    request: Request,
    payload: ProviderRequest,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    provider_id = validate_identifier(
        payload.provider_id,
        "Provider ID",
    )

    name = validate_identifier(
        payload.name,
        "Provider name",
    )

    category = validate_identifier(
        payload.category,
        "Provider category",
        max_length=100,
    )

    base_url = validate_http_url(
        payload.base_url
    )

    secret_ref = validate_secret_reference(
        payload.secret_ref
    )

    connection = db()

    try:
        existing = connection.execute(
            """
            SELECT created_at
            FROM provider_registry
            WHERE provider_id = ?
            """,
            (provider_id,),
        ).fetchone()

        created_at = (
            existing["created_at"]
            if existing
            else utc_now()
        )

        connection.execute(
            """
            INSERT INTO provider_registry
            (
                provider_id,
                name,
                category,
                base_url,
                enabled,
                priority,
                secret_ref,
                description,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider_id)
            DO UPDATE SET
                name = excluded.name,
                category = excluded.category,
                base_url = excluded.base_url,
                enabled = excluded.enabled,
                priority = excluded.priority,
                secret_ref = excluded.secret_ref,
                description = excluded.description,
                updated_at = excluded.updated_at
            """,
            (
                provider_id,
                name,
                category,
                base_url,
                int(payload.enabled),
                payload.priority,
                secret_ref,
                payload.description,
                created_at,
                utc_now(),
            ),
        )

        connection.commit()

    finally:
        connection.close()

    audit(
        session["owner_email"],
        "provider_upserted",
        target=provider_id,
        details={
            "enabled": payload.enabled,
            "priority": payload.priority,
            "secret_ref_configured": bool(secret_ref),
        },
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "provider_id": provider_id,
        "enabled": payload.enabled,
        "updated_at": utc_now(),
    }


@app.post("/owner/providers/{provider_id}/enable")
def enable_provider(
    provider_id: str,
    request: Request,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    return _set_provider_enabled(
        provider_id,
        True,
        request,
        session,
    )


@app.post("/owner/providers/{provider_id}/disable")
def disable_provider(
    provider_id: str,
    request: Request,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    return _set_provider_enabled(
        provider_id,
        False,
        request,
        session,
    )


def _set_provider_enabled(
    provider_id: str,
    enabled: bool,
    request: Request,
    session: sqlite3.Row,
) -> Dict[str, Any]:
    provider_id = validate_identifier(
        provider_id,
        "Provider ID",
    )

    connection = db()

    try:
        cursor = connection.execute(
            """
            UPDATE provider_registry
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

        connection.commit()

    finally:
        connection.close()

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Provider not found",
        )

    audit(
        session["owner_email"],
        (
            "provider_enabled"
            if enabled
            else "provider_disabled"
        ),
        target=provider_id,
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "provider_id": provider_id,
        "enabled": enabled,
        "updated_at": utc_now(),
    }


@app.delete("/owner/providers/{provider_id}")
def delete_provider(
    provider_id: str,
    request: Request,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    provider_id = validate_identifier(
        provider_id,
        "Provider ID",
    )

    connection = db()

    try:
        cursor = connection.execute(
            """
            DELETE FROM provider_registry
            WHERE provider_id = ?
            """,
            (provider_id,),
        )

        connection.commit()

    finally:
        connection.close()

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Provider not found",
        )

    audit(
        session["owner_email"],
        "provider_deleted",
        target=provider_id,
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "deleted": provider_id,
    }


# ============================================================
# RECOVERY TOKENS
# ============================================================

@app.post("/owner/recovery-tokens")
def create_recovery_tokens(
    request: Request,
    payload: RecoveryRequest,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    generated: List[str] = []

    connection = db()

    try:
        connection.execute(
            """
            DELETE FROM recovery_tokens
            WHERE used_at IS NOT NULL
               OR expires_at < ?
            """,
            (utc_now(),),
        )

        for _ in range(payload.count):
            token = generate_token()

            connection.execute(
                """
                INSERT INTO recovery_tokens
                (
                    token_hash,
                    created_at,
                    expires_at,
                    used_at
                )
                VALUES (?, ?, ?, NULL)
                """,
                (
                    hash_value(token),
                    utc_now(),
                    (
                        datetime.now(timezone.utc)
                        + timedelta(hours=payload.hours)
                    ).isoformat(),
                ),
            )

            # The plaintext token is shown only once in this response.
            generated.append(token)

        connection.commit()

    finally:
        connection.close()

    audit(
        session["owner_email"],
        "recovery_tokens_created",
        details={
            "count": len(generated),
            "valid_hours": payload.hours,
        },
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "tokens": generated,
        "warning": (
            "Save these tokens securely. "
            "They cannot be retrieved again."
        ),
    }


@app.post("/owner/recovery/consume")
def consume_recovery_token(
    request: Request,
    payload: RecoveryConsumeRequest,
):
    email = payload.email.strip().lower()

    ip_address = get_client_ip(
        request
    )

    if not OWNER_EMAIL or not OWNER_SECRET:
        raise HTTPException(
            status_code=503,
            detail="OWNER authentication is not configured",
        )

    if too_many_attempts(
        email,
        ip_address,
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts",
        )

    if not secure_compare(
        email,
        OWNER_EMAIL,
    ) or not verify_password(
        payload.password
    ):
        record_login(
            email,
            False,
            ip_address,
            "invalid_recovery_credentials",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials",
        )

    token_digest = hash_value(
        payload.recovery_token.strip()
    )

    connection = db()

    try:
        # Atomic one-time consumption prevents two requests from
        # successfully using the same recovery token.
        cursor = connection.execute(
            """
            UPDATE recovery_tokens
            SET used_at = ?
            WHERE token_hash = ?
              AND used_at IS NULL
              AND expires_at >= ?
            """,
            (
                utc_now(),
                token_digest,
                utc_now(),
            ),
        )

        connection.commit()

        consumed = cursor.rowcount == 1

    finally:
        connection.close()

    if not consumed:
        record_login(
            email,
            False,
            ip_address,
            "invalid_recovery_token",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired recovery token",
        )

    token = create_session(
        email,
        ip_address,
        request.headers.get("user-agent"),
    )

    record_login(
        email,
        True,
        ip_address,
        "recovery_login_success",
    )

    audit(
        email,
        "owner_recovery_login",
        ip_address=ip_address,
    )

    return {
        "ok": True,
        "access_token": token,
        "token_type": "bearer",
        "expires_in_hours": SESSION_HOURS,
        "logged_in_at": utc_now(),
        "recovery_token_consumed": True,
    }


# ============================================================
# CONFIGURATION SNAPSHOTS
# ============================================================

def build_config_snapshot() -> Dict[str, Any]:
    connection = db()

    try:
        settings_rows = connection.execute(
            """
            SELECT key, value, value_type, description, updated_at
            FROM settings
            ORDER BY key
            """
        ).fetchall()

        feature_rows = connection.execute(
            """
            SELECT key, enabled, description, updated_at
            FROM feature_flags
            ORDER BY key
            """
        ).fetchall()

        service_rows = connection.execute(
            """
            SELECT
                service_name,
                enabled,
                kill_switch,
                maintenance,
                updated_at
            FROM service_controls
            ORDER BY service_name
            """
        ).fetchall()

        provider_rows = connection.execute(
            """
            SELECT
                provider_id,
                name,
                category,
                base_url,
                enabled,
                priority,
                secret_ref,
                description,
                created_at,
                updated_at
            FROM provider_registry
            ORDER BY provider_id
            """
        ).fetchall()

    finally:
        connection.close()

    settings = []

    for row in settings_rows:
        # Sensitive keys are never included in snapshots.
        if is_sensitive_key(row["key"]):
            continue

        settings.append(
            dict(row)
        )

    return {
        "schema_version": 1,
        "created_at": utc_now(),
        "settings": settings,
        "feature_flags": [
            dict(row)
            for row in feature_rows
        ],
        "service_controls": [
            dict(row)
            for row in service_rows
        ],
        "providers": [
            dict(row)
            for row in provider_rows
        ],
    }


@app.post("/owner/config-snapshots")
def create_config_snapshot(
    request: Request,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    snapshot_data = build_config_snapshot()

    serialized = json.dumps(
        snapshot_data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    if len(serialized.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Configuration snapshot is too large",
        )

    snapshot_digest = hash_value(
        serialized
    )

    connection = db()

    try:
        cursor = connection.execute(
            """
            INSERT INTO config_snapshots
            (
                snapshot_hash,
                snapshot,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (
                snapshot_digest,
                serialized,
                utc_now(),
            ),
        )

        snapshot_id = cursor.lastrowid

        connection.commit()

    finally:
        connection.close()

    audit(
        session["owner_email"],
        "config_snapshot_created",
        target=str(snapshot_id),
        details={
            "snapshot_hash": snapshot_digest,
        },
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "snapshot_id": snapshot_id,
        "snapshot_hash": snapshot_digest,
        "created_at": utc_now(),
    }


@app.get("/owner/config-snapshots")
def list_config_snapshots(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                snapshot_hash,
                created_at
            FROM config_snapshots
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    finally:
        connection.close()

    return {
        "ok": True,
        "snapshots": [
            dict(row)
            for row in rows
        ],
    }


@app.get("/owner/config-snapshots/{snapshot_id}")
def get_config_snapshot(
    snapshot_id: int,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM config_snapshots
            WHERE id = ?
            """,
            (snapshot_id,),
        ).fetchone()

    finally:
        connection.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Configuration snapshot not found",
        )

    serialized = row["snapshot"]

    if not secure_compare(
        hash_value(serialized),
        row["snapshot_hash"],
    ):
        raise HTTPException(
            status_code=500,
            detail="Configuration snapshot integrity check failed",
        )

    try:
        snapshot_data = json.loads(
            serialized
        )
    except (
        ValueError,
        TypeError,
    ):
        raise HTTPException(
            status_code=500,
            detail="Configuration snapshot is invalid",
        )

    return {
        "ok": True,
        "snapshot_id": row["id"],
        "snapshot_hash": row["snapshot_hash"],
        "created_at": row["created_at"],
        "snapshot": snapshot_data,
    }


@app.post("/owner/config-snapshots/restore")
def restore_config_snapshot(
    request: Request,
    payload: SnapshotRestoreRequest,
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM config_snapshots
            WHERE id = ?
            """,
            (payload.snapshot_id,),
        ).fetchone()

    finally:
        connection.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Configuration snapshot not found",
        )

    serialized = row["snapshot"]

    if not secure_compare(
        hash_value(serialized),
        row["snapshot_hash"],
    ):
        raise HTTPException(
            status_code=500,
            detail="Configuration snapshot integrity check failed",
        )

    try:
        snapshot = json.loads(
            serialized
        )

        if snapshot.get("schema_version") != 1:
            raise ValueError

        settings = snapshot["settings"]
        features = snapshot["feature_flags"]
        services = snapshot["service_controls"]
        providers = snapshot["providers"]

        if not all(
            isinstance(items, list)
            for items in (
                settings,
                features,
                services,
                providers,
            )
        ):
            raise ValueError

    except (
        ValueError,
        TypeError,
        KeyError,
    ):
        raise HTTPException(
            status_code=400,
            detail="Unsupported or invalid snapshot format",
        )

    connection = db()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        # Restore only the configuration domains contained in the
        # validated snapshot. Authentication, sessions, recovery
        # tokens, and audit history are deliberately not overwritten.

        connection.execute(
            "DELETE FROM settings"
        )

        for item in settings:
            key = validate_identifier(
                str(item["key"]),
                "Setting key",
            )

            if is_sensitive_key(key):
                continue

            value = item.get("value")

            if not isinstance(
                value,
                str,
            ):
                value = str(value or "")

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
                """,
                (
                    key,
                    value,
                    str(
                        item.get(
                            "value_type",
                            "string",
                        )
                    ),
                    item.get("description"),
                    utc_now(),
                ),
            )

        connection.execute(
            "DELETE FROM feature_flags"
        )

        for item in features:
            connection.execute(
                """
                INSERT INTO feature_flags
                (
                    key,
                    enabled,
                    description,
                    updated_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    validate_identifier(
                        str(item["key"]),
                        "Feature key",
                    ),
                    int(bool(item["enabled"])),
                    item.get("description"),
                    utc_now(),
                ),
            )

        connection.execute(
            "DELETE FROM service_controls"
        )

        for item in services:
            connection.execute(
                """
                INSERT INTO service_controls
                (
                    service_name,
                    enabled,
                    kill_switch,
                    maintenance,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    validate_identifier(
                        str(item["service_name"]),
                        "Service name",
                    ),
                    int(bool(item["enabled"])),
                    int(bool(item["kill_switch"])),
                    int(bool(item["maintenance"])),
                    utc_now(),
                ),
            )

        connection.execute(
            "DELETE FROM provider_registry"
        )

        for item in providers:
            base_url = validate_http_url(
                item.get("base_url")
            )

            secret_ref = validate_secret_reference(
                item.get("secret_ref")
            )

            connection.execute(
                """
                INSERT INTO provider_registry
                (
                    provider_id,
                    name,
                    category,
                    base_url,
                    enabled,
                    priority,
                    secret_ref,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    validate_identifier(
                        str(item["provider_id"]),
                        "Provider ID",
                    ),
                    validate_identifier(
                        str(item["name"]),
                        "Provider name",
                    ),
                    validate_identifier(
                        str(item["category"]),
                        "Provider category",
                        max_length=100,
                    ),
                    base_url,
                    int(bool(item["enabled"])),
                    int(item.get("priority", 100)),
                    secret_ref,
                    item.get("description"),
                    str(
                        item.get(
                            "created_at",
                            utc_now(),
                        )
                    ),
                    utc_now(),
                ),
            )

        connection.commit()

    except Exception:
        connection.rollback()
        logger.exception(
            "Configuration snapshot restore failed"
        )
        raise HTTPException(
            status_code=400,
            detail="Configuration snapshot could not be restored",
        )

    finally:
        connection.close()

    audit(
        session["owner_email"],
        "config_snapshot_restored",
        target=str(payload.snapshot_id),
        ip_address=get_client_ip(request),
    )

    return {
        "ok": True,
        "restored_snapshot_id": payload.snapshot_id,
        "restored_at": utc_now(),
        "warning": (
            "Authentication settings, active sessions, "
            "recovery tokens, and audit history were not restored."
        ),
    }


# ============================================================
# AUDIT LOG VIEWING
# ============================================================

@app.get("/owner/audit-logs")
def list_audit_logs(
    limit: int = Query(
        default=50,
        ge=1,
        le=MAX_AUDIT_PAGE_SIZE,
    ),
    offset: int = Query(
        default=0,
        ge=0,
        le=10000000,
    ),
    actor: Optional[str] = Query(
        default=None,
        max_length=320,
    ),
    action: Optional[str] = Query(
        default=None,
        max_length=200,
    ),
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    conditions = []
    parameters: List[Any] = []

    if actor:
        conditions.append(
            "actor = ?"
        )
        parameters.append(
            actor.strip()
        )

    if action:
        conditions.append(
            "action = ?"
        )
        parameters.append(
            action.strip()
        )

    where_clause = (
        "WHERE " + " AND ".join(conditions)
        if conditions
        else ""
    )

    connection = db()

    try:
        rows = connection.execute(
            f"""
            SELECT
                id,
                actor,
                action,
                target,
                details,
                created_at,
                ip_address
            FROM audit_logs
            {where_clause}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            parameters + [
                limit,
                offset,
            ],
        ).fetchall()

        count_row = connection.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM audit_logs
            {where_clause}
            """,
            parameters,
        ).fetchone()

    finally:
        connection.close()

    logs = []

    for row in rows:
        try:
            details = json.loads(
                row["details"] or "{}"
            )
        except (
            ValueError,
            TypeError,
        ):
            details = {
                "unavailable": True,
            }

        logs.append(
            {
                "id": row["id"],
                "actor": row["actor"],
                "action": row["action"],
                "target": row["target"],
                "details": details,
                "created_at": row["created_at"],
                "ip_address": row["ip_address"],
            }
        )

    return {
        "ok": True,
        "total": int(
            count_row["count"]
        ),
        "limit": limit,
        "offset": offset,
        "logs": logs,
    }


# ============================================================
# LOGIN ATTEMPT HISTORY
# ============================================================

@app.get("/owner/login-attempts")
def list_login_attempts(
    limit: int = Query(
        default=50,
        ge=1,
        le=MAX_AUDIT_PAGE_SIZE,
    ),
    offset: int = Query(
        default=0,
        ge=0,
        le=10000000,
    ),
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                email,
                success,
                created_at,
                ip_address,
                reason
            FROM login_attempts
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (
                limit,
                offset,
            ),
        ).fetchall()

        count_row = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM login_attempts
            """
        ).fetchone()

    finally:
        connection.close()

    return {
        "ok": True,
        "total": int(
            count_row["count"]
        ),
        "limit": limit,
        "offset": offset,
        "attempts": [
            {
                "id": row["id"],
                "email": row["email"],
                "success": bool(
                    row["success"]
                ),
                "created_at": row["created_at"],
                "ip_address": row["ip_address"],
                "reason": row["reason"],
            }
            for row in rows
        ],
    }


# ============================================================
# SERVICE INFORMATION
# ============================================================

@app.get("/owner/status")
def owner_status(
    session: sqlite3.Row = Depends(
        require_owner
    ),
):
    connection = db()

    try:
        counts = {}

        for table in (
            "owner_sessions",
            "settings",
            "feature_flags",
            "service_controls",
            "provider_registry",
            "recovery_tokens",
            "config_snapshots",
            "audit_logs",
        ):
            row = connection.execute(
                f"SELECT COUNT(*) AS count FROM {table}"
            ).fetchone()

            counts[table] = int(
                row["count"]
            )

        global_control = connection.execute(
            """
            SELECT kill_switch, maintenance
            FROM service_controls
            WHERE service_name = '__GLOBAL__'
            """
        ).fetchone()

    finally:
        connection.close()

    return {
        "ok": True,
        "service": APP_NAME,
        "version": APP_VERSION,
        "database": "connected",
        "owner_email_configured": bool(
            OWNER_EMAIL
        ),
        "owner_password_configured": bool(
            OWNER_PASSWORD_HASH
            and OWNER_SECRET
        ),
        "totp_configured": bool(
            TOTP_SECRET
        ),
        "global_kill_switch": bool(
            global_control["kill_switch"]
        ) if global_control else False,
        "global_maintenance": bool(
            global_control["maintenance"]
        ) if global_control else False,
        "record_counts": counts,
        "time": utc_now(),
    }


# ============================================================
# STARTUP VALIDATION
# ============================================================

@app.on_event("startup")
def startup_validation() -> None:
    if not OWNER_EMAIL:
        logger.warning(
            "ARYA_MASTER_EMAIL is not configured"
        )

    if not OWNER_PASSWORD_HASH:
        logger.warning(
            "ARYA_OWNER_PASSWORD_HASH is not configured"
        )

    if not OWNER_SECRET:
        logger.warning(
            "ARYA_MASTER_SECRET is not configured"
        )

    if not TOTP_SECRET:
        logger.warning(
            "ARYA_OWNER_TOTP_SECRET is not configured"
        )

    logger.info(
        "%s version %s initialized",
        APP_NAME,
        APP_VERSION,
    )


# ============================================================
# END OF FILE
# ============================================================
