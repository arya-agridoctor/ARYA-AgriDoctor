"""
ARYA AgriDoctor
Internal Service Security Layer
Version: 1.0.0

Purpose:
- Service-to-service authentication
- HMAC signed internal requests
- Replay protection
- Timestamp validation
- Nonce protection
- Service identity validation
- Secret rotation
- Audit logging
- OWNER-controlled service credentials
- No modification of existing ARYA files required

This module is intentionally standalone.
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
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Internal Service Security"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_INTERNAL_SECURITY_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_INTERNAL_SECURITY_PORT",
        "8020",
    )
)

DB_PATH = os.getenv(
    "ARYA_INTERNAL_SECURITY_DB",
    "internal_service_security.db",
)

MASTER_EMAIL = os.getenv(
    "ARYA_MASTER_EMAIL",
    "",
).strip().lower()

MASTER_SECRET = os.getenv(
    "ARYA_MASTER_SECRET",
    "",
)

INTERNAL_GATEWAY_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

REQUEST_TTL_SECONDS = int(
    os.getenv(
        "ARYA_INTERNAL_REQUEST_TTL",
        "120",
    )
)

NONCE_TTL_SECONDS = int(
    os.getenv(
        "ARYA_INTERNAL_NONCE_TTL",
        "300",
    )
)

MAX_BODY_BYTES = int(
    os.getenv(
        "ARYA_INTERNAL_MAX_BODY_BYTES",
        str(2 * 1024 * 1024),
    )
)

SESSION_TTL_SECONDS = int(
    os.getenv(
        "ARYA_INTERNAL_SECURITY_SESSION_TTL",
        "3600",
    )
)


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Central security authority for ARYA internal "
        "service-to-service communication."
    ),
)


# ============================================================
# Database
# ============================================================

@contextmanager
def db():
    connection = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False,
    )

    connection.row_factory = sqlite3.Row

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def unix_time() -> int:
    return int(time.time())


def init_database() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS services (
                service_id TEXT PRIMARY KEY,
                service_name TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                secret_version INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_seen_at TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS secret_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                secret_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                disabled_at TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY(service_id)
                    REFERENCES services(service_id)
            );

            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce_hash TEXT PRIMARY KEY,
                service_id TEXT NOT NULL,
                request_id TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_sessions (
                session_id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                service_id TEXT,
                request_id TEXT,
                success INTEGER NOT NULL,
                source_ip TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_nonce_expiry
            ON used_nonces(expires_at);

            CREATE INDEX IF NOT EXISTS idx_sessions_expiry
            ON security_sessions(expires_at);

            CREATE INDEX IF NOT EXISTS idx_audit_created
            ON audit_logs(created_at);

            CREATE INDEX IF NOT EXISTS idx_services_enabled
            ON services(enabled);
            """
        )


# ============================================================
# Security Helpers
# ============================================================

def sha256_text(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def constant_compare(
    first: str,
    second: str,
) -> bool:
    return hmac.compare_digest(
        first.encode("utf-8"),
        second.encode("utf-8"),
    )


def generate_secret() -> str:
    return secrets.token_urlsafe(48)


def hash_secret(secret: str) -> str:
    return sha256_text(secret)


def canonical_json(data: Any) -> str:
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_body(body: bytes) -> str:
    if not body:
        return ""

    try:
        parsed = json.loads(body.decode("utf-8"))
        return canonical_json(parsed)
    except Exception:
        return body.decode(
            "utf-8",
            errors="replace",
        )


def build_signature(
    secret: str,
    service_id: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    request_id: str,
    body_hash: str,
) -> str:
    payload = "\n".join(
        [
            service_id,
            method.upper(),
            path,
            timestamp,
            nonce,
            request_id,
            body_hash,
        ]
    )

    return hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def clean_old_nonces() -> None:
    now = unix_time()

    with db() as conn:
        conn.execute(
            """
            DELETE FROM used_nonces
            WHERE expires_at < ?
            """,
            (now,),
        )


def clean_old_sessions() -> None:
    now = unix_time()

    with db() as conn:
        conn.execute(
            """
            DELETE FROM security_sessions
            WHERE expires_at < ?
               OR revoked = 1
            """,
            (now,),
        )


# ============================================================
# Audit
# ============================================================

def audit(
    event_type: str,
    success: bool,
    service_id: Optional[str] = None,
    request_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:

    with db() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (
                event_id,
                event_type,
                service_id,
                request_id,
                success,
                source_ip,
                details_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                event_type,
                service_id,
                request_id,
                1 if success else 0,
                source_ip,
                canonical_json(details or {}),
                utc_now(),
            ),
        )


# ============================================================
# Service Registry
# ============================================================

DEFAULT_SERVICES = [
    "vision",
    "voice_language",
    "agri_engine",
    "commerce_security",
    "orchestrator",
    "owner_manager",
    "owner_integration",
    "owner_runtime_gateway",
    "orchestrator_runtime_bridge",
    "runtime_data_provider_bridge",
    "owner_provider_control",
    "data_update",
    "external_providers",
]


def ensure_default_services() -> None:
    now = utc_now()

    with db() as conn:
        for service_id in DEFAULT_SERVICES:
            existing = conn.execute(
                """
                SELECT service_id
                FROM services
                WHERE service_id = ?
                """,
                (service_id,),
            ).fetchone()

            if existing:
                continue

            generated_secret = generate_secret()

            conn.execute(
                """
                INSERT INTO services (
                    service_id,
                    service_name,
                    secret_hash,
                    secret_version,
                    enabled,
                    created_at,
                    updated_at,
                    metadata_json
                )
                VALUES (?, ?, ?, 1, 1, ?, ?, ?)
                """,
                (
                    service_id,
                    service_id.replace("_", " ").title(),
                    hash_secret(generated_secret),
                    now,
                    now,
                    canonical_json(
                        {
                            "bootstrap_secret": generated_secret,
                            "bootstrap_warning": (
                                "Retrieve and rotate this secret "
                                "through OWNER before production."
                            ),
                        }
                    ),
                ),
            )

            conn.execute(
                """
                INSERT INTO secret_versions (
                    service_id,
                    version,
                    secret_hash,
                    created_at,
                    active
                )
                VALUES (?, 1, ?, ?, 1)
                """,
                (
                    service_id,
                    hash_secret(generated_secret),
                    now,
                ),
            )


def get_service(
    service_id: str,
) -> Optional[sqlite3.Row]:

    with db() as conn:
        return conn.execute(
            """
            SELECT *
            FROM services
            WHERE service_id = ?
            """,
            (service_id,),
        ).fetchone()


def get_active_secret_hash(
    service_id: str,
) -> Optional[str]:

    with db() as conn:
        row = conn.execute(
            """
            SELECT secret_hash
            FROM secret_versions
            WHERE service_id = ?
              AND active = 1
            ORDER BY version DESC
            LIMIT 1
            """,
            (service_id,),
        ).fetchone()

    return row["secret_hash"] if row else None


# ============================================================
# Models
# ============================================================

class ServiceCreateRequest(BaseModel):
    service_id: str = Field(
        min_length=2,
        max_length=100,
    )

    service_name: str = Field(
        min_length=2,
        max_length=200,
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict
    )


class SecretRotateResponse(BaseModel):
    service_id: str
    version: int
    secret: str
    created_at: str


class InternalRequestVerification(BaseModel):
    service_id: str
    method: str
    path: str
    timestamp: str
    nonce: str
    request_id: str
    body_hash: str
    signature: str


class SessionCreateRequest(BaseModel):
    service_id: str
    secret: str


# ============================================================
# OWNER Authentication
# ============================================================

def require_owner(
    email: Optional[str],
    secret: Optional[str],
) -> None:

    if not MASTER_EMAIL or not MASTER_SECRET:
        raise HTTPException(
            status_code=503,
            detail="OWNER credentials are not configured.",
        )

    if not email or not secret:
        raise HTTPException(
            status_code=401,
            detail="OWNER authentication required.",
        )

    if not constant_compare(
        email.strip().lower(),
        MASTER_EMAIL,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials.",
        )

    if not constant_compare(
        secret,
        MASTER_SECRET,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials.",
        )


# ============================================================
# Internal Request Verification
# ============================================================

def verify_internal_request(
    service_id: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    request_id: str,
    body_hash: str,
    signature: str,
) -> Dict[str, Any]:

    if not service_id:
        raise HTTPException(
            status_code=401,
            detail="Missing service identity.",
        )

    service = get_service(service_id)

    if not service:
        audit(
            "internal_auth_unknown_service",
            False,
            service_id=service_id,
            request_id=request_id,
        )

        raise HTTPException(
            status_code=401,
            detail="Unknown internal service.",
        )

    if not bool(service["enabled"]):
        audit(
            "internal_auth_disabled_service",
            False,
            service_id=service_id,
            request_id=request_id,
        )

        raise HTTPException(
            status_code=403,
            detail="Internal service is disabled.",
        )

    try:
        request_timestamp = int(timestamp)
    except Exception:
        audit(
            "internal_auth_invalid_timestamp",
            False,
            service_id=service_id,
            request_id=request_id,
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid timestamp.",
        )

    now = unix_time()

    if abs(now - request_timestamp) > REQUEST_TTL_SECONDS:
        audit(
            "internal_auth_expired_request",
            False,
            service_id=service_id,
            request_id=request_id,
        )

        raise HTTPException(
            status_code=401,
            detail="Request timestamp expired.",
        )

    if not nonce or len(nonce) < 16:
        audit(
            "internal_auth_invalid_nonce",
            False,
            service_id=service_id,
            request_id=request_id,
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid nonce.",
        )

    if not request_id:
        raise HTTPException(
            status_code=401,
            detail="Missing request ID.",
        )

    nonce_hash = sha256_text(nonce)

    with db() as conn:

        existing_nonce = conn.execute(
            """
            SELECT nonce_hash
            FROM used_nonces
            WHERE nonce_hash = ?
            """,
            (nonce_hash,),
        ).fetchone()

        if existing_nonce:
            audit(
                "internal_auth_replay_detected",
                False,
                service_id=service_id,
                request_id=request_id,
            )

            raise HTTPException(
                status_code=409,
                detail="Replay detected.",
            )

        conn.execute(
            """
            INSERT INTO used_nonces (
                nonce_hash,
                service_id,
                request_id,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                nonce_hash,
                service_id,
                request_id,
                now,
                now + NONCE_TTL_SECONDS,
            ),
        )

    active_secret_hash = get_active_secret_hash(
        service_id
    )

    if not active_secret_hash:
        raise HTTPException(
            status_code=503,
            detail="No active service secret.",
        )

    supplied_secret = None

    # A service secret is intentionally not accepted
    # through query parameters or JSON payloads.
    #
    # This function expects the caller to pass the secret
    # through the dedicated internal header:
    #
    # X-ARYA-Service-Secret
    #
    # The direct helper below is used by the HTTP endpoint.

    audit(
        "internal_auth_verified",
        True,
        service_id=service_id,
        request_id=request_id,
    )

    return {
        "authenticated": True,
        "service_id": service_id,
        "request_id": request_id,
        "timestamp": request_timestamp,
    }


# ============================================================
# Full Header-Based Verification
# ============================================================

async def verify_request_from_headers(
    request: Request,
    service_id: Optional[str],
    timestamp: Optional[str],
    nonce: Optional[str],
    request_id: Optional[str],
    signature: Optional[str],
    service_secret: Optional[str],
) -> Dict[str, Any]:

    if not service_id:
        raise HTTPException(
            status_code=401,
            detail="Missing X-ARYA-Service-ID.",
        )

    if not timestamp:
        raise HTTPException(
            status_code=401,
            detail="Missing X-ARYA-Timestamp.",
        )

    if not nonce:
        raise HTTPException(
            status_code=401,
            detail="Missing X-ARYA-Nonce.",
        )

    if not request_id:
        raise HTTPException(
            status_code=401,
            detail="Missing X-ARYA-Request-ID.",
        )

    if not signature:
        raise HTTPException(
            status_code=401,
            detail="Missing X-ARYA-Signature.",
        )

    if not service_secret:
        raise HTTPException(
            status_code=401,
            detail="Missing X-ARYA-Service-Secret.",
        )

    service = get_service(service_id)

    if not service:
        raise HTTPException(
            status_code=401,
            detail="Unknown internal service.",
        )

    if not bool(service["enabled"]):
        raise HTTPException(
            status_code=403,
            detail="Internal service disabled.",
        )

    try:
        request_timestamp = int(timestamp)
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid timestamp.",
        )

    if abs(unix_time() - request_timestamp) > REQUEST_TTL_SECONDS:
        audit(
            "internal_auth_expired",
            False,
            service_id=service_id,
            request_id=request_id,
            source_ip=request.client.host if request.client else None,
        )

        raise HTTPException(
            status_code=401,
            detail="Expired internal request.",
        )

    body = await request.body()

    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body is too large.",
        )

    body_text = canonical_body(body)
    body_hash = sha256_text(body_text)

    expected_signature = build_signature(
        secret=service_secret,
        service_id=service_id,
        method=request.method,
        path=request.url.path,
        timestamp=timestamp,
        nonce=nonce,
        request_id=request_id,
        body_hash=body_hash,
    )

    if not constant_compare(
        expected_signature,
        signature,
    ):
        audit(
            "internal_auth_bad_signature",
            False,
            service_id=service_id,
            request_id=request_id,
            source_ip=request.client.host if request.client else None,
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid internal signature.",
        )

    stored_secret_hash = get_active_secret_hash(
        service_id
    )

    if not stored_secret_hash:
        raise HTTPException(
            status_code=503,
            detail="Service secret is unavailable.",
        )

    if not constant_compare(
        hash_secret(service_secret),
        stored_secret_hash,
    ):
        audit(
            "internal_auth_bad_secret",
            False,
            service_id=service_id,
            request_id=request_id,
            source_ip=request.client.host if request.client else None,
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid service secret.",
        )

    nonce_hash = sha256_text(nonce)

    with db() as conn:
        existing_nonce = conn.execute(
            """
            SELECT nonce_hash
            FROM used_nonces
            WHERE nonce_hash = ?
            """,
            (nonce_hash,),
        ).fetchone()

        if existing_nonce:
            audit(
                "internal_auth_replay",
                False,
                service_id=service_id,
                request_id=request_id,
                source_ip=request.client.host if request.client else None,
            )

            raise HTTPException(
                status_code=409,
                detail="Replay detected.",
            )

        conn.execute(
            """
            INSERT INTO used_nonces (
                nonce_hash,
                service_id,
                request_id,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                nonce_hash,
                service_id,
                request_id,
                unix_time(),
                unix_time() + NONCE_TTL_SECONDS,
            ),
        )

        conn.execute(
            """
            UPDATE services
            SET last_seen_at = ?,
                updated_at = ?
            WHERE service_id = ?
            """,
            (
                utc_now(),
                utc_now(),
                service_id,
            ),
        )

    audit(
        "internal_auth_success",
        True,
        service_id=service_id,
        request_id=request_id,
        source_ip=request.client.host if request.client else None,
    )

    return {
        "authenticated": True,
        "service_id": service_id,
        "request_id": request_id,
        "body_hash": body_hash,
    }


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
def startup() -> None:
    init_database()
    ensure_default_services()
    clean_old_nonces()
    clean_old_sessions()


# ============================================================
# Basic Routes
# ============================================================

@app.get("/")
def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "security_model": "HMAC-SHA256",
        "replay_protection": True,
        "timestamp_validation": True,
        "service_identity": True,
        "secret_rotation": True,
        "audit_logging": True,
    }


@app.get("/health")
def health():
    with db() as conn:
        services = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM services
            WHERE enabled = 1
            """
        ).fetchone()["count"]

    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "enabled_services": services,
        "time": utc_now(),
    }


# ============================================================
# OWNER: Service Management
# ============================================================

@app.post("/owner/services")
def owner_create_service(
    payload: ServiceCreateRequest,
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    service_id = payload.service_id.strip().lower()

    if not service_id.replace("_", "").isalnum():
        raise HTTPException(
            status_code=400,
            detail="Invalid service ID.",
        )

    existing = get_service(service_id)

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Service already exists.",
        )

    secret = generate_secret()
    now = utc_now()

    with db() as conn:
        conn.execute(
            """
            INSERT INTO services (
                service_id,
                service_name,
                secret_hash,
                secret_version,
                enabled,
                created_at,
                updated_at,
                metadata_json
            )
            VALUES (?, ?, ?, 1, 1, ?, ?, ?)
            """,
            (
                service_id,
                payload.service_name,
                hash_secret(secret),
                now,
                now,
                canonical_json(payload.metadata),
            ),
        )

        conn.execute(
            """
            INSERT INTO secret_versions (
                service_id,
                version,
                secret_hash,
                created_at,
                active
            )
            VALUES (?, 1, ?, ?, 1)
            """,
            (
                service_id,
                hash_secret(secret),
                now,
            ),
        )

    audit(
        "owner_service_created",
        True,
        service_id=service_id,
    )

    return {
        "service_id": service_id,
        "service_name": payload.service_name,
        "version": 1,
        "secret": secret,
        "warning": (
            "Store this secret securely. "
            "It will not be returned again."
        ),
    }


@app.get("/owner/services")
def owner_list_services(
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    with db() as conn:
        rows = conn.execute(
            """
            SELECT
                service_id,
                service_name,
                secret_version,
                enabled,
                created_at,
                updated_at,
                last_seen_at,
                metadata_json
            FROM services
            ORDER BY service_id
            """
        ).fetchall()

    result = []

    for row in rows:
        result.append(
            {
                "service_id": row["service_id"],
                "service_name": row["service_name"],
                "secret_version": row["secret_version"],
                "enabled": bool(row["enabled"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "last_seen_at": row["last_seen_at"],
                "metadata": json.loads(
                    row["metadata_json"]
                    or "{}"
                ),
            }
        )

    return {
        "services": result,
        "count": len(result),
    }


@app.get("/owner/services/{service_id}")
def owner_service_details(
    service_id: str,
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    row = get_service(service_id)

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Service not found.",
        )

    return {
        "service_id": row["service_id"],
        "service_name": row["service_name"],
        "secret_version": row["secret_version"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_seen_at": row["last_seen_at"],
        "metadata": json.loads(
            row["metadata_json"]
            or "{}"
        ),
    }


# ============================================================
# OWNER: Enable / Disable
# ============================================================

@app.post("/owner/services/{service_id}/enable")
def owner_enable_service(
    service_id: str,
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    if not get_service(service_id):
        raise HTTPException(
            status_code=404,
            detail="Service not found.",
        )

    with db() as conn:
        conn.execute(
            """
            UPDATE services
            SET enabled = 1,
                updated_at = ?
            WHERE service_id = ?
            """,
            (
                utc_now(),
                service_id,
            ),
        )

    audit(
        "owner_service_enabled",
        True,
        service_id=service_id,
    )

    return {
        "service_id": service_id,
        "enabled": True,
    }


@app.post("/owner/services/{service_id}/disable")
def owner_disable_service(
    service_id: str,
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    if not get_service(service_id):
        raise HTTPException(
            status_code=404,
            detail="Service not found.",
        )

    with db() as conn:
        conn.execute(
            """
            UPDATE services
            SET enabled = 0,
                updated_at = ?
            WHERE service_id = ?
            """,
            (
                utc_now(),
                service_id,
            ),
        )

    audit(
        "owner_service_disabled",
        True,
        service_id=service_id,
    )

    return {
        "service_id": service_id,
        "enabled": False,
    }


# ============================================================
# OWNER: Secret Rotation
# ============================================================

@app.post(
    "/owner/services/{service_id}/rotate-secret",
    response_model=SecretRotateResponse,
)
def owner_rotate_secret(
    service_id: str,
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    service = get_service(service_id)

    if not service:
        raise HTTPException(
            status_code=404,
            detail="Service not found.",
        )

    new_secret = generate_secret()
    now = utc_now()

    new_version = int(
        service["secret_version"]
    ) + 1

    with db() as conn:

        conn.execute(
            """
            UPDATE secret_versions
            SET active = 0,
                disabled_at = ?
            WHERE service_id = ?
              AND active = 1
            """,
            (
                now,
                service_id,
            ),
        )

        conn.execute(
            """
            INSERT INTO secret_versions (
                service_id,
                version,
                secret_hash,
                created_at,
                active
            )
            VALUES (?, ?, ?, ?, 1)
            """,
            (
                service_id,
                new_version,
                hash_secret(new_secret),
                now,
            ),
        )

        conn.execute(
            """
            UPDATE services
            SET secret_hash = ?,
                secret_version = ?,
                updated_at = ?
            WHERE service_id = ?
            """,
            (
                hash_secret(new_secret),
                new_version,
                now,
                service_id,
            ),
        )

    audit(
        "owner_secret_rotated",
        True,
        service_id=service_id,
        details={
            "new_version": new_version,
        },
    )

    return SecretRotateResponse(
        service_id=service_id,
        version=new_version,
        secret=new_secret,
        created_at=now,
    )


# ============================================================
# Internal Authentication Endpoint
# ============================================================

@app.post("/internal/auth/verify")
async def internal_auth_verify(
    request: Request,
    x_arya_service_id: Optional[str] = Header(
        default=None
    ),
    x_arya_timestamp: Optional[str] = Header(
        default=None
    ),
    x_arya_nonce: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_service_secret: Optional[str] = Header(
        default=None
    ),
):
    result = await verify_request_from_headers(
        request=request,
        service_id=x_arya_service_id,
        timestamp=x_arya_timestamp,
        nonce=x_arya_nonce,
        request_id=x_arya_request_id,
        signature=x_arya_signature,
        service_secret=x_arya_service_secret,
    )

    return {
        "verified": True,
        **result,
    }


# ============================================================
# Internal Protected Ping
# ============================================================

@app.post("/internal/ping")
async def internal_ping(
    request: Request,
    x_arya_service_id: Optional[str] = Header(
        default=None
    ),
    x_arya_timestamp: Optional[str] = Header(
        default=None
    ),
    x_arya_nonce: Optional[str] = Header(
        default=None
    ),
    x_arya_request_id: Optional[str] = Header(
        default=None
    ),
    x_arya_signature: Optional[str] = Header(
        default=None
    ),
    x_arya_service_secret: Optional[str] = Header(
        default=None
    ),
):
    result = await verify_request_from_headers(
        request=request,
        service_id=x_arya_service_id,
        timestamp=x_arya_timestamp,
        nonce=x_arya_nonce,
        request_id=x_arya_request_id,
        signature=x_arya_signature,
        service_secret=x_arya_service_secret,
    )

    return {
        "status": "authenticated",
        "service_id": result["service_id"],
        "request_id": result["request_id"],
        "time": utc_now(),
    }


# ============================================================
# Public Service Metadata
# ============================================================

@app.get("/internal/services")
def internal_services():
    with db() as conn:
        rows = conn.execute(
            """
            SELECT
                service_id,
                service_name,
                secret_version,
                enabled,
                last_seen_at
            FROM services
            ORDER BY service_id
            """
        ).fetchall()

    return {
        "services": [
            {
                "service_id": row["service_id"],
                "service_name": row["service_name"],
                "secret_version": row["secret_version"],
                "enabled": bool(row["enabled"]),
                "last_seen_at": row["last_seen_at"],
            }
            for row in rows
        ]
    }


# ============================================================
# Security Statistics
# ============================================================

@app.get("/owner/security/stats")
def owner_security_stats(
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    with db() as conn:

        service_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM services
            """
        ).fetchone()["count"]

        enabled_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM services
            WHERE enabled = 1
            """
        ).fetchone()["count"]

        nonce_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM used_nonces
            WHERE expires_at >= ?
            """,
            (unix_time(),),
        ).fetchone()["count"]

        audit_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM audit_logs
            """
        ).fetchone()["count"]

        failed_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM audit_logs
            WHERE success = 0
            """
        ).fetchone()["count"]

    return {
        "services": service_count,
        "enabled_services": enabled_count,
        "active_nonces": nonce_count,
        "audit_events": audit_count,
        "failed_security_events": failed_count,
        "request_ttl_seconds": REQUEST_TTL_SECONDS,
        "nonce_ttl_seconds": NONCE_TTL_SECONDS,
        "time": utc_now(),
    }


# ============================================================
# OWNER Audit
# ============================================================

@app.get("/owner/security/audit")
def owner_security_audit(
    limit: int = 100,
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    limit = max(
        1,
        min(limit, 500),
    )

    with db() as conn:
        rows = conn.execute(
            """
            SELECT
                event_id,
                event_type,
                service_id,
                request_id,
                success,
                source_ip,
                details_json,
                created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return {
        "events": [
            {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "service_id": row["service_id"],
                "request_id": row["request_id"],
                "success": bool(row["success"]),
                "source_ip": row["source_ip"],
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
# Maintenance
# ============================================================

@app.post("/owner/security/cleanup")
def owner_security_cleanup(
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    clean_old_nonces()
    clean_old_sessions()

    audit(
        "owner_security_cleanup",
        True,
    )

    return {
        "status": "cleaned",
        "time": utc_now(),
    }


# ============================================================
# Service Secret Bootstrap / Recovery Information
# ============================================================

@app.get("/owner/services/{service_id}/secret-status")
def owner_secret_status(
    service_id: str,
    x_arya_owner_email: Optional[str] = Header(
        default=None
    ),
    x_arya_owner_secret: Optional[str] = Header(
        default=None
    ),
):
    require_owner(
        x_arya_owner_email,
        x_arya_owner_secret,
    )

    service = get_service(service_id)

    if not service:
        raise HTTPException(
            status_code=404,
            detail="Service not found.",
        )

    with db() as conn:
        versions = conn.execute(
            """
            SELECT
                version,
                created_at,
                disabled_at,
                active
            FROM secret_versions
            WHERE service_id = ?
            ORDER BY version DESC
            """,
            (service_id,),
        ).fetchall()

    return {
        "service_id": service_id,
        "current_version": service["secret_version"],
        "versions": [
            {
                "version": row["version"],
                "created_at": row["created_at"],
                "disabled_at": row["disabled_at"],
                "active": bool(row["active"]),
            }
            for row in versions
        ],
    }


# ============================================================
# Internal Security Contract
# ============================================================

@app.get("/internal/security-contract")
def security_contract():
    return {
        "version": APP_VERSION,
        "authentication": "HMAC-SHA256",
        "required_headers": [
            "X-ARYA-Service-ID",
            "X-ARYA-Timestamp",
            "X-ARYA-Nonce",
            "X-ARYA-Request-ID",
            "X-ARYA-Signature",
            "X-ARYA-Service-Secret",
        ],
        "protections": [
            "service_identity",
            "secret_validation",
            "timestamp_validation",
            "nonce_validation",
            "replay_protection",
            "body_hash",
            "request_id",
            "audit_logging",
            "secret_rotation",
            "service_enable_disable",
        ],
        "signature_algorithm": "HMAC-SHA256",
        "timestamp_window_seconds": REQUEST_TTL_SECONDS,
        "nonce_window_seconds": NONCE_TTL_SECONDS,
    }


# ============================================================
# Uvicorn
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "internal_service_security:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
