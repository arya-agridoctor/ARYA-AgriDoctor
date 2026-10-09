"""
===============================================================
ARYA AgriDoctor
OWNER Integration Layer
Version: 1.1.0
===============================================================

Purpose:
- Connect OWNER Manager with service/provider configuration.
- Provide centralized runtime configuration.
- Persist service, provider, and setting configuration in SQLite.
- Allow OWNER-controlled enable/disable state.
- Support API secret references without exposing secret values.
- Provide configuration snapshots and audit information.
- Protect OWNER and internal endpoints.
- Avoid modifying backend/main.py or unrelated modules.

Environment variables:
- ARYA_OWNER_INTEGRATION_HOST
- ARYA_OWNER_INTEGRATION_PORT
- ARYA_OWNER_INTEGRATION_DB
- ARYA_MASTER_EMAIL
- ARYA_MASTER_SECRET
- ARYA_OWNER_INTERNAL_TOKEN
- ARYA_VISION_URL
- ARYA_VOICE_LANGUAGE_URL
- ARYA_AGRI_ENGINE_URL
- ARYA_COMMERCE_SECURITY_URL
- ARYA_ORCHESTRATOR_URL

IMPORTANT:
Set ARYA_MASTER_EMAIL and ARYA_MASTER_SECRET before using OWNER routes.
Set ARYA_OWNER_INTERNAL_TOKEN to a long, random value before allowing
other backend services to call internal/runtime endpoints.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field


# ===============================================================
# APPLICATION CONFIGURATION
# ===============================================================

APP_NAME = "ARYA OWNER Integration Layer"
APP_VERSION = "1.1.0"

HOST = os.getenv("ARYA_OWNER_INTEGRATION_HOST", "0.0.0.0").strip()

try:
    PORT = int(os.getenv("ARYA_OWNER_INTEGRATION_PORT", "8015"))
except ValueError:
    PORT = 8015

DATABASE_PATH = os.getenv(
    "ARYA_OWNER_INTEGRATION_DB",
    "owner_integration.db",
).strip() or "owner_integration.db"

MASTER_EMAIL = os.getenv("ARYA_MASTER_EMAIL", "").strip().lower()
MASTER_SECRET = os.getenv("ARYA_MASTER_SECRET", "").strip()
INTERNAL_TOKEN = os.getenv("ARYA_OWNER_INTERNAL_TOKEN", "").strip()

try:
    SESSION_TTL_SECONDS = max(
        300,
        int(os.getenv("ARYA_OWNER_SESSION_TTL_SECONDS", str(12 * 60 * 60))),
    )
except ValueError:
    SESSION_TTL_SECONDS = 12 * 60 * 60

try:
    LOGIN_MAX_ATTEMPTS = max(
        3,
        int(os.getenv("ARYA_OWNER_LOGIN_MAX_ATTEMPTS", "5")),
    )
except ValueError:
    LOGIN_MAX_ATTEMPTS = 5

try:
    LOGIN_WINDOW_SECONDS = max(
        30,
        int(os.getenv("ARYA_OWNER_LOGIN_WINDOW_SECONDS", "300")),
    )
except ValueError:
    LOGIN_WINDOW_SECONDS = 300

try:
    LOGIN_BLOCK_SECONDS = max(
        30,
        int(os.getenv("ARYA_OWNER_LOGIN_BLOCK_SECONDS", "300")),
    )
except ValueError:
    LOGIN_BLOCK_SECONDS = 300

DB_LOCK = threading.RLock()
LOGIN_LOCK = threading.RLock()

LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOGIN_BLOCKED_UNTIL: dict[str, float] = {}

logging.basicConfig(
    level=os.getenv("ARYA_OWNER_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger("arya.owner_integration")

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="ARYA AgriDoctor OWNER Integration Layer",
)


# ===============================================================
# GENERAL HELPERS
# ===============================================================

def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def constant_time_equal(left: str, right: str) -> bool:
    """Compare strings without ordinary early-exit comparison."""
    return hmac.compare_digest(
        str(left).encode("utf-8"),
        str(right).encode("utf-8"),
    )


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_json_loads(
    value: Optional[str],
    default: Any = None,
) -> Any:
    """Parse stored JSON safely."""
    if value is None:
        return default

    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def owner_configured() -> bool:
    return bool(MASTER_EMAIL and MASTER_SECRET)


def internal_token_configured() -> bool:
    return bool(INTERNAL_TOKEN)


def validate_identifier(value: str, label: str = "identifier") -> str:
    value = str(value or "").strip()

    if not value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{label} is required",
        )

    if len(value) > 120:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{label} is too long",
        )

    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{label} contains invalid characters",
        )

    return value


def validate_base_url(value: str) -> str:
    """
    Validate a service/provider base URL.

    Loopback and private addresses are permitted because the architecture
    intentionally uses local backend services. This function does not
    perform network requests.
    """
    value = str(value or "").strip()

    if not value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="base_url is required",
        )

    if len(value) > 2048:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="base_url is too long",
        )

    if any(ord(character) < 32 for character in value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="base_url contains control characters",
        )

    try:
        parsed = urlsplit(value)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base_url",
        )

    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="base_url must use HTTP or HTTPS",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="base_url must include a hostname",
        )

    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credentials must not be embedded in base_url",
        )

    if parsed.fragment:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="base_url must not contain a URL fragment",
        )

    try:
        parsed.port
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="base_url contains an invalid port",
        )

    return value.rstrip("/")


def validate_json_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{label} must be a JSON object",
        )

    try:
        json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{label} must contain JSON-compatible values",
        )

    return value


def redact_provider(provider: dict[str, Any]) -> dict[str, Any]:
    """
    Avoid returning secret references through general provider listings.
    The reference itself is not the secret value, but may disclose internal
    configuration details.
    """
    result = dict(provider)
    result.pop("secret_ref", None)
    return result


# ===============================================================
# DATABASE
# ===============================================================

@contextmanager
def db_connection():
    """
    Open and reliably close a SQLite connection.

    A process-local lock helps threads in this process. SQLite's own locking
    remains responsible for coordination between separate processes.
    """
    connection = None

    with DB_LOCK:
        try:
            connection = sqlite3.connect(
                DATABASE_PATH,
                timeout=15,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 15000")
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
        except sqlite3.Error:
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            raise
        finally:
            if connection is not None:
                connection.close()


def initialize_database() -> None:
    with db_connection() as connection:
        connection.execute("PRAGMA journal_mode = WAL")

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS runtime_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runtime_providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                provider_type TEXT NOT NULL DEFAULT 'generic',
                base_url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                secret_ref TEXT,
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at REAL NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                last_seen_at TEXT
            );

            CREATE TABLE IF NOT EXISTS integration_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS integration_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id TEXT NOT NULL UNIQUE,
                created_by TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_owner_sessions_expiry
            ON integration_sessions(expires_at);

            CREATE INDEX IF NOT EXISTS idx_owner_audit_created
            ON integration_audit(created_at);

            CREATE INDEX IF NOT EXISTS idx_owner_snapshots_created
            ON integration_snapshots(created_at);
            """
        )

        connection.commit()

    seed_default_services()


def seed_default_services() -> None:
    defaults = [
        (
            "vision",
            "ARYA Vision",
            os.getenv("ARYA_VISION_URL", "http://127.0.0.1:8001"),
        ),
        (
            "voice_language",
            "ARYA Voice Language",
            os.getenv(
                "ARYA_VOICE_LANGUAGE_URL",
                "http://127.0.0.1:8002",
            ),
        ),
        (
            "agri_engine",
            "ARYA Agriculture Engine",
            os.getenv(
                "ARYA_AGRI_ENGINE_URL",
                "http://127.0.0.1:8003",
            ),
        ),
        (
            "commerce_security",
            "ARYA Commerce Security",
            os.getenv(
                "ARYA_COMMERCE_SECURITY_URL",
                "http://127.0.0.1:8004",
            ),
        ),
        (
            "orchestrator",
            "ARYA Runtime Orchestrator",
            os.getenv(
                "ARYA_ORCHESTRATOR_URL",
                "http://127.0.0.1:8010",
            ),
        ),
    ]

    now = utc_now()

    with db_connection() as connection:
        for service_id, name, raw_url in defaults:
            try:
                base_url = validate_base_url(raw_url)
            except HTTPException:
                logger.warning(
                    "Skipping invalid default URL for service %s",
                    service_id,
                )
                continue

            connection.execute(
                """
                INSERT OR IGNORE INTO runtime_services
                (
                    service_id, name, base_url, enabled,
                    metadata_json, created_at, updated_at
                )
                VALUES (?, ?, ?, 1, '{}', ?, ?)
                """,
                (service_id, name, base_url, now, now),
            )

        connection.commit()


# ===============================================================
# AUDIT LOGGING
# ===============================================================

def write_audit(
    actor: str,
    action: str,
    target: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> None:
    details = details or {}

    try:
        details_json = json.dumps(
            details,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        details_json = "{}"

    with db_connection() as connection:
        connection.execute(
            """
            INSERT INTO integration_audit
            (actor, action, target, details_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                actor[:200],
                action[:200],
                target[:300] if target else None,
                details_json,
                utc_now(),
            ),
        )
        connection.commit()


# ===============================================================
# AUTHENTICATION AND SESSION MANAGEMENT
# ===============================================================

class OwnerLogin(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    secret: str = Field(min_length=1, max_length=4096)


class ServiceCreate(BaseModel):
    service_id: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=1, max_length=2048)
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderCreate(BaseModel):
    provider_id: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=200)
    provider_type: str = Field(default="generic", min_length=1, max_length=100)
    base_url: str = Field(min_length=1, max_length=2048)
    enabled: bool = True
    secret_ref: Optional[str] = Field(default=None, max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SettingUpdate(BaseModel):
    key: str = Field(min_length=1, max_length=200)
    value: Any
    is_secret: bool = False


def get_client_key(request: Request) -> str:
    """
    Use the direct client address for rate limiting.
    Do not trust X-Forwarded-For unless a trusted proxy is configured
    separately in the deployment.
    """
    if request.client and request.client.host:
        return request.client.host[:100]

    return "unknown"


def check_login_rate_limit(client_key: str) -> None:
    now = time.time()

    with LOGIN_LOCK:
        blocked_until = LOGIN_BLOCKED_UNTIL.get(client_key, 0)

        if blocked_until > now:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
            )

        if blocked_until:
            LOGIN_BLOCKED_UNTIL.pop(client_key, None)

        attempts = LOGIN_ATTEMPTS.get(client_key, [])
        attempts = [
            timestamp
            for timestamp in attempts
            if now - timestamp <= LOGIN_WINDOW_SECONDS
        ]
        LOGIN_ATTEMPTS[client_key] = attempts

        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            LOGIN_BLOCKED_UNTIL[client_key] = now + LOGIN_BLOCK_SECONDS
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
            )


def record_login_failure(client_key: str) -> None:
    now = time.time()

    with LOGIN_LOCK:
        attempts = LOGIN_ATTEMPTS.get(client_key, [])
        attempts = [
            timestamp
            for timestamp in attempts
            if now - timestamp <= LOGIN_WINDOW_SECONDS
        ]
        attempts.append(now)
        LOGIN_ATTEMPTS[client_key] = attempts

        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            LOGIN_BLOCKED_UNTIL[client_key] = now + LOGIN_BLOCK_SECONDS


def clear_login_failures(client_key: str) -> None:
    with LOGIN_LOCK:
        LOGIN_ATTEMPTS.pop(client_key, None)
        LOGIN_BLOCKED_UNTIL.pop(client_key, None)


def create_session(email: str) -> tuple[str, float]:
    raw_token = secrets.token_urlsafe(48)
    token_hash = sha256_hex(raw_token)
    expires_at = time.time() + SESSION_TTL_SECONDS

    with db_connection() as connection:
        connection.execute(
            """
            INSERT INTO integration_sessions
            (token_hash, email, created_at, expires_at, revoked, last_seen_at)
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            (
                token_hash,
                email,
                utc_now(),
                expires_at,
                utc_now(),
            ),
        )
        connection.commit()

    return raw_token, expires_at


def extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None

    parts = authorization.strip().split(None, 1)

    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1].strip()
    return token or None


def require_owner(
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    if not owner_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OWNER authentication is not configured",
        )

    raw_token = extract_bearer_token(authorization)

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OWNER authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_hash = sha256_hex(raw_token)
    now = time.time()

    with db_connection() as connection:
        row = connection.execute(
            """
            SELECT id, email, expires_at, revoked
            FROM integration_sessions
            WHERE token_hash = ?
            LIMIT 1
            """,
            (token_hash,),
        ).fetchone()

        if (
            row is None
            or row["revoked"]
            or float(row["expires_at"]) <= now
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired OWNER session",
                headers={"WWW-Authenticate": "Bearer"},
            )

        connection.execute(
            """
            UPDATE integration_sessions
            SET last_seen_at = ?
            WHERE id = ?
            """,
            (utc_now(), row["id"]),
        )
        connection.commit()

    return {
        "email": row["email"],
        "session_id": row["id"],
    }


def require_internal_access(
    authorization: Optional[str] = Header(default=None),
    x_arya_internal_token: Optional[str] = Header(default=None),
) -> dict[str, str]:
    """
    Internal endpoints require ARYA_OWNER_INTERNAL_TOKEN.

    An OWNER session is also accepted, so a logged-in OWNER can inspect
    runtime configuration without a second token.
    """
    raw_owner_token = extract_bearer_token(authorization)

    if raw_owner_token:
        try:
            owner = require_owner(authorization)
            return {"actor": owner["email"]}
        except HTTPException:
            pass

    if not INTERNAL_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Internal API authentication is not configured",
        )

    supplied = x_arya_internal_token or ""

    if not supplied and raw_owner_token:
        supplied = raw_owner_token

    if not supplied or not constant_time_equal(supplied, INTERNAL_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Internal API authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"actor": "internal_service"}


# ===============================================================
# SERVICE AND PROVIDER CONFIGURATION
# ===============================================================

def service_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "service_id": row["service_id"],
        "name": row["name"],
        "base_url": row["base_url"],
        "enabled": bool(row["enabled"]),
        "metadata": safe_json_loads(row["metadata_json"], {}),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def provider_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "provider_id": row["provider_id"],
        "name": row["name"],
        "provider_type": row["provider_type"],
        "base_url": row["base_url"],
        "enabled": bool(row["enabled"]),
        "secret_ref": row["secret_ref"],
        "metadata": safe_json_loads(row["metadata_json"], {}),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def get_service_config(service_id: str) -> Optional[dict[str, Any]]:
    service_id = validate_identifier(service_id, "service_id")

    with db_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM runtime_services
            WHERE service_id = ?
            LIMIT 1
            """,
            (service_id,),
        ).fetchone()

    return service_row_to_dict(row) if row else None


def get_provider_config(provider_id: str) -> Optional[dict[str, Any]]:
    provider_id = validate_identifier(provider_id, "provider_id")

    with db_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM runtime_providers
            WHERE provider_id = ?
            LIMIT 1
            """,
            (provider_id,),
        ).fetchone()

    return provider_row_to_dict(row) if row else None


def get_all_service_configs() -> list[dict[str, Any]]:
    with db_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM runtime_services
            ORDER BY service_id ASC
            """
        ).fetchall()

    return [service_row_to_dict(row) for row in rows]


def get_all_provider_configs() -> list[dict[str, Any]]:
    with db_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM runtime_providers
            ORDER BY provider_id ASC
            """
        ).fetchall()

    return [provider_row_to_dict(row) for row in rows]


# ===============================================================
# PUBLIC ROUTES
# ===============================================================

@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
    }


@app.get("/health")
def health() -> dict[str, Any]:
    try:
        with db_connection() as connection:
            connection.execute("SELECT 1").fetchone()

        return {
            "status": "ok",
            "service": APP_NAME,
            "version": APP_VERSION,
            "database": "ok",
            "owner_configured": owner_configured(),
            "internal_auth_configured": internal_token_configured(),
            "timestamp": utc_now(),
        }

    except Exception:
        logger.exception("OWNER Integration health check failed")

        return {
            "status": "degraded",
            "service": APP_NAME,
            "version": APP_VERSION,
            "database": "unavailable",
            "timestamp": utc_now(),
        }


@app.post("/owner/login")
def owner_login(
    payload: OwnerLogin,
    request: Request,
) -> dict[str, Any]:
    if not owner_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OWNER authentication is not configured",
        )

    client_key = get_client_key(request)
    check_login_rate_limit(client_key)

    supplied_email = payload.email.strip().lower()
    supplied_secret = payload.secret

    email_matches = constant_time_equal(supplied_email, MASTER_EMAIL)
    secret_matches = constant_time_equal(supplied_secret, MASTER_SECRET)

    if not (email_matches and secret_matches):
        record_login_failure(client_key)

        try:
            write_audit(
                actor="anonymous",
                action="owner_login_failed",
                target=client_key,
            )
        except Exception:
            logger.exception("Could not write failed-login audit event")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OWNER credentials",
        )

    clear_login_failures(client_key)

    token, expires_at = create_session(MASTER_EMAIL)

    try:
        write_audit(
            actor=MASTER_EMAIL,
            action="owner_login",
            target=client_key,
        )
    except Exception:
        logger.exception("Could not write successful-login audit event")

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "expires_in": SESSION_TTL_SECONDS,
    }


# ===============================================================
# OWNER SESSION ROUTES
# ===============================================================

@app.post("/owner/logout")
def owner_logout(
    request: Request,
    owner: dict[str, Any] = Depends(require_owner),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    raw_token = extract_bearer_token(authorization)

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OWNER authentication required",
        )

    token_hash = sha256_hex(raw_token)

    with db_connection() as connection:
        connection.execute(
            """
            UPDATE integration_sessions
            SET revoked = 1
            WHERE token_hash = ?
            """,
            (token_hash,),
        )
        connection.commit()

    write_audit(
        actor=owner["email"],
        action="owner_logout",
        target=get_client_key(request),
    )

    return {"status": "logged_out"}


# ===============================================================
# OWNER SERVICE MANAGEMENT
# ===============================================================

@app.get("/owner/services")
def owner_list_services(
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    return {
        "services": get_all_service_configs(),
        "count": len(get_all_service_configs()),
    }


@app.post("/owner/services")
def owner_create_or_update_service(
    payload: ServiceCreate,
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    service_id = validate_identifier(payload.service_id, "service_id")
    name = payload.name.strip()
    base_url = validate_base_url(payload.base_url)
    metadata = validate_json_object(payload.metadata, "metadata")

    if not name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="name is required",
        )

    now = utc_now()
    metadata_json = json.dumps(metadata, ensure_ascii=False)

    with db_connection() as connection:
        connection.execute(
            """
            INSERT INTO runtime_services
            (
                service_id, name, base_url, enabled,
                metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(service_id) DO UPDATE SET
                name = excluded.name,
                base_url = excluded.base_url,
                enabled = excluded.enabled,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            """,
            (
                service_id,
                name,
                base_url,
                int(payload.enabled),
                metadata_json,
                now,
                now,
            ),
        )
        connection.commit()

    write_audit(
        actor=owner["email"],
        action="service_upsert",
        target=service_id,
        details={"enabled": payload.enabled},
    )

    result = get_service_config(service_id)

    return {
        "status": "saved",
        "service": result,
    }


def set_service_enabled(
    service_id: str,
    enabled: bool,
    actor: str,
) -> dict[str, Any]:
    service_id = validate_identifier(service_id, "service_id")

    with db_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE runtime_services
            SET enabled = ?, updated_at = ?
            WHERE service_id = ?
            """,
            (int(enabled), utc_now(), service_id),
        )
        connection.commit()

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Service not found",
            )

    write_audit(
        actor=actor,
        action="service_enabled" if enabled else "service_disabled",
        target=service_id,
    )

    return {
        "status": "enabled" if enabled else "disabled",
        "service": get_service_config(service_id),
    }


@app.post("/owner/services/{service_id}/enable")
def owner_enable_service(
    service_id: str,
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    return set_service_enabled(service_id, True, owner["email"])


@app.post("/owner/services/{service_id}/disable")
def owner_disable_service(
    service_id: str,
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    return set_service_enabled(service_id, False, owner["email"])


# ===============================================================
# OWNER PROVIDER MANAGEMENT
# ===============================================================

@app.get("/owner/providers")
def owner_list_providers(
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    providers = get_all_provider_configs()

    return {
        "providers": providers,
        "count": len(providers),
    }


@app.post("/owner/providers")
def owner_create_or_update_provider(
    payload: ProviderCreate,
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    provider_id = validate_identifier(payload.provider_id, "provider_id")
    name = payload.name.strip()
    provider_type = payload.provider_type.strip()
    base_url = validate_base_url(payload.base_url)
    metadata = validate_json_object(payload.metadata, "metadata")

    secret_ref = payload.secret_ref.strip() if payload.secret_ref else None

    if not name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="name is required",
        )

    if not provider_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="provider_type is required",
        )

    now = utc_now()
    metadata_json = json.dumps(metadata, ensure_ascii=False)

    with db_connection() as connection:
        connection.execute(
            """
            INSERT INTO runtime_providers
            (
                provider_id, name, provider_type, base_url,
                enabled, secret_ref, metadata_json,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider_id) DO UPDATE SET
                name = excluded.name,
                provider_type = excluded.provider_type,
                base_url = excluded.base_url,
                enabled = excluded.enabled,
                secret_ref = excluded.secret_ref,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            """,
            (
                provider_id,
                name,
                provider_type,
                base_url,
                int(payload.enabled),
                secret_ref,
                metadata_json,
                now,
                now,
            ),
        )
        connection.commit()

    write_audit(
        actor=owner["email"],
        action="provider_upsert",
        target=provider_id,
        details={
            "enabled": payload.enabled,
            "has_secret_ref": bool(secret_ref),
        },
    )

    result = get_provider_config(provider_id)

    return {
        "status": "saved",
        "provider": result,
    }


def set_provider_enabled(
    provider_id: str,
    enabled: bool,
    actor: str,
) -> dict[str, Any]:
    provider_id = validate_identifier(provider_id, "provider_id")

    with db_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE runtime_providers
            SET enabled = ?, updated_at = ?
            WHERE provider_id = ?
            """,
            (int(enabled), utc_now(), provider_id),
        )
        connection.commit()

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Provider not found",
            )

    write_audit(
        actor=actor,
        action="provider_enabled" if enabled else "provider_disabled",
        target=provider_id,
    )

    return {
        "status": "enabled" if enabled else "disabled",
        "provider": get_provider_config(provider_id),
    }


@app.post("/owner/providers/{provider_id}/enable")
def owner_enable_provider(
    provider_id: str,
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    return set_provider_enabled(provider_id, True, owner["email"])


@app.post("/owner/providers/{provider_id}/disable")
def owner_disable_provider(
    provider_id: str,
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    return set_provider_enabled(provider_id, False, owner["email"])


# ===============================================================
# OWNER SETTINGS
# ===============================================================

@app.get("/owner/settings")
def owner_list_settings(
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    with db_connection() as connection:
        rows = connection.execute(
            """
            SELECT setting_key, setting_value, is_secret, updated_at
            FROM runtime_settings
            ORDER BY setting_key ASC
            """
        ).fetchall()

    settings = []

    for row in rows:
        is_secret = bool(row["is_secret"])

        settings.append(
            {
                "key": row["setting_key"],
                "value": (
                    None
                    if is_secret
                    else safe_json_loads(row["setting_value"], row["setting_value"])
                ),
                "is_secret": is_secret,
                "updated_at": row["updated_at"],
            }
        )

    return {
        "settings": settings,
        "count": len(settings),
    }


@app.post("/owner/settings")
def owner_update_setting(
    payload: SettingUpdate,
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    key = payload.key.strip()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Setting key is required",
        )

    if any(ord(character) < 32 for character in key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Setting key contains invalid characters",
        )

    try:
        value_json = json.dumps(
            payload.value,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Setting value must be JSON-compatible",
        )

    with db_connection() as connection:
        connection.execute(
            """
            INSERT INTO runtime_settings
            (setting_key, setting_value, is_secret, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = excluded.setting_value,
                is_secret = excluded.is_secret,
                updated_at = excluded.updated_at
            """,
            (key, value_json, int(payload.is_secret), utc_now()),
        )
        connection.commit()

    write_audit(
        actor=owner["email"],
        action="setting_updated",
        target=key,
        details={"is_secret": payload.is_secret},
    )

    return {
        "status": "saved",
        "key": key,
        "is_secret": payload.is_secret,
        "value": None if payload.is_secret else payload.value,
    }


# ===============================================================
# SNAPSHOTS
# ===============================================================

def create_snapshot_data() -> dict[str, Any]:
    with db_connection() as connection:
        services = connection.execute(
            """
            SELECT service_id, name, base_url, enabled,
                   metadata_json, created_at, updated_at
            FROM runtime_services
            ORDER BY service_id ASC
            """
        ).fetchall()

        providers = connection.execute(
            """
            SELECT provider_id, name, provider_type, base_url,
                   enabled, secret_ref, metadata_json,
                   created_at, updated_at
            FROM runtime_providers
            ORDER BY provider_id ASC
            """
        ).fetchall()

        settings = connection.execute(
            """
            SELECT setting_key, is_secret, updated_at
            FROM runtime_settings
            ORDER BY setting_key ASC
            """
        ).fetchall()

    return {
        "version": APP_VERSION,
        "created_at": utc_now(),
        "services": [dict(row) for row in services],
        "providers": [dict(row) for row in providers],
        "settings": [dict(row) for row in settings],
    }


@app.post("/owner/snapshots")
def owner_create_snapshot(
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    snapshot_id = secrets.token_urlsafe(18)
    snapshot_data = create_snapshot_data()

    snapshot_json = json.dumps(
        snapshot_data,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    with db_connection() as connection:
        connection.execute(
            """
            INSERT INTO integration_snapshots
            (snapshot_id, created_by, snapshot_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                snapshot_id,
                owner["email"],
                snapshot_json,
                utc_now(),
            ),
        )
        connection.commit()

    write_audit(
        actor=owner["email"],
        action="snapshot_created",
        target=snapshot_id,
    )

    return {
        "status": "created",
        "snapshot_id": snapshot_id,
        "created_at": snapshot_data["created_at"],
        "counts": {
            "services": len(snapshot_data["services"]),
            "providers": len(snapshot_data["providers"]),
            "settings": len(snapshot_data["settings"]),
        },
    }


@app.get("/owner/snapshots")
def owner_list_snapshots(
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    with db_connection() as connection:
        rows = connection.execute(
            """
            SELECT snapshot_id, created_by, created_at
            FROM integration_snapshots
            ORDER BY id DESC
            """
        ).fetchall()

    return {
        "snapshots": [dict(row) for row in rows],
        "count": len(rows),
    }


# ===============================================================
# OWNER AUDIT AND STATUS
# ===============================================================

@app.get("/owner/audit")
def owner_list_audit(
    limit: int = 100,
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    limit = max(1, min(int(limit), 1000))

    with db_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, actor, action, target, details_json, created_at
            FROM integration_audit
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    entries = []

    for row in rows:
        entries.append(
            {
                "id": row["id"],
                "actor": row["actor"],
                "action": row["action"],
                "target": row["target"],
                "details": safe_json_loads(row["details_json"], {}),
                "created_at": row["created_at"],
            }
        )

    return {
        "audit": entries,
        "count": len(entries),
    }


@app.get("/owner/status")
def owner_status(
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    services = get_all_service_configs()
    providers = get_all_provider_configs()

    with db_connection() as connection:
        sessions_row = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM integration_sessions
            WHERE revoked = 0 AND expires_at > ?
            """,
            (time.time(),),
        ).fetchone()

        snapshots_row = connection.execute(
            "SELECT COUNT(*) AS total FROM integration_snapshots"
        ).fetchone()

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": utc_now(),
        "owner_configured": owner_configured(),
        "internal_auth_configured": internal_token_configured(),
        "services": {
            "total": len(services),
            "enabled": sum(1 for item in services if item["enabled"]),
            "disabled": sum(1 for item in services if not item["enabled"]),
        },
        "providers": {
            "total": len(providers),
            "enabled": sum(1 for item in providers if item["enabled"]),
            "disabled": sum(1 for item in providers if not item["enabled"]),
        },
        "active_sessions": int(sessions_row["total"]),
        "snapshots": int(snapshots_row["total"]),
    }


# ===============================================================
# OWNER MAINTENANCE
# ===============================================================

@app.post("/owner/maintenance/cleanup-sessions")
def owner_cleanup_sessions(
    owner: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    now = time.time()

    with db_connection() as connection:
        cursor = connection.execute(
            """
            DELETE FROM integration_sessions
            WHERE revoked = 1 OR expires_at <= ?
            """,
            (now,),
        )
        deleted = cursor.rowcount
        connection.commit()

    write_audit(
        actor=owner["email"],
        action="expired_sessions_cleanup",
        details={"deleted": deleted},
    )

    return {
        "status": "completed",
        "deleted_sessions": deleted,
    }


# ===============================================================
# INTERNAL RUNTIME ROUTES
# ===============================================================

@app.get("/runtime/services")
def runtime_services(
    internal: dict[str, str] = Depends(require_internal_access),
) -> dict[str, Any]:
    services = get_all_service_configs()

    return {
        "services": services,
        "count": len(services),
    }


@app.get("/runtime/providers")
def runtime_providers(
    internal: dict[str, str] = Depends(require_internal_access),
) -> dict[str, Any]:
    providers = get_all_provider_configs()

    # Secret references are not included in the general provider listing.
    safe_providers = [redact_provider(item) for item in providers]

    return {
        "providers": safe_providers,
        "count": len(safe_providers),
    }


@app.get("/internal/service/{service_id}")
def internal_get_service(
    service_id: str,
    internal: dict[str, str]
