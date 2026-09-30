"""
ARYA AgriDoctor
Client API Gateway
Version: 1.0.0

Purpose:
- Unified API for Android and Windows clients
- Client authentication and sessions
- Device registration
- Runtime Gateway communication
- Rate limiting
- Request audit
- Secure client-facing API boundary
- No modification of existing ARYA files required
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
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Client API Gateway"
APP_VERSION = "1.0.0"

HOST = os.getenv(
    "ARYA_CLIENT_GATEWAY_HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "ARYA_CLIENT_GATEWAY_PORT",
        "8021",
    )
)

DB_PATH = os.getenv(
    "ARYA_CLIENT_GATEWAY_DB",
    "client_api_gateway.db",
)

RUNTIME_GATEWAY_URL = os.getenv(
    "ARYA_RUNTIME_GATEWAY_URL",
    "http://127.0.0.1:8016",
).rstrip("/")

CLIENT_MASTER_SECRET = os.getenv(
    "ARYA_CLIENT_MASTER_SECRET",
    "",
)

INTERNAL_GATEWAY_SECRET = os.getenv(
    "ARYA_INTERNAL_GATEWAY_SECRET",
    "",
)

SESSION_TTL = int(
    os.getenv(
        "ARYA_CLIENT_SESSION_TTL",
        "86400",
    )
)

REQUEST_TIMEOUT = float(
    os.getenv(
        "ARYA_CLIENT_GATEWAY_TIMEOUT",
        "60",
    )
)

MAX_RESPONSE_BYTES = int(
    os.getenv(
        "ARYA_CLIENT_GATEWAY_MAX_RESPONSE_BYTES",
        str(8 * 1024 * 1024),
    )
)

RATE_LIMIT_WINDOW = int(
    os.getenv(
        "ARYA_CLIENT_RATE_WINDOW",
        "60",
    )
)

RATE_LIMIT_MAX_REQUESTS = int(
    os.getenv(
        "ARYA_CLIENT_RATE_LIMIT",
        "60",
    )
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Unified client API gateway for ARYA "
        "Android and Windows applications."
    ),
)


# ============================================================
# Database
# ============================================================

@contextmanager
def db():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False,
    )

    conn.row_factory = sqlite3.Row

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_name TEXT NOT NULL,
                platform TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                platform TEXT NOT NULL,
                device_name TEXT,
                device_fingerprint TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_seen_at TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS rate_limits (
                rate_key TEXT PRIMARY KEY,
                window_started INTEGER NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                client_id TEXT,
                device_id TEXT,
                session_id TEXT,
                request_id TEXT,
                success INTEGER NOT NULL,
                source_ip TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_token
            ON sessions(token_hash);

            CREATE INDEX IF NOT EXISTS idx_sessions_expiry
            ON sessions(expires_at);

            CREATE INDEX IF NOT EXISTS idx_devices_client
            ON devices(client_id);

            CREATE INDEX IF NOT EXISTS idx_audit_created
            ON audit_logs(created_at);
            """
        )


# ============================================================
# Helpers
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def unix_time() -> int:
    return int(time.time())


def sha256(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def secure_equal(
    first: str,
    second: str,
) -> bool:
    return hmac.compare_digest(
        first.encode("utf-8"),
        second.encode("utf-8"),
    )


def json_string(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def generate_token() -> str:
    return secrets.token_urlsafe(48)


def generate_secret() -> str:
    return secrets.token_urlsafe(48)


# ============================================================
# Audit
# ============================================================

def audit(
    event_type: str,
    success: bool,
    client_id: Optional[str] = None,
    device_id: Optional[str] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
):
    with db() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (
                event_id,
                event_type,
                client_id,
                device_id,
                session_id,
                request_id,
                success,
                source_ip,
                details_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                event_type,
                client_id,
                device_id,
                session_id,
                request_id,
                1 if success else 0,
                source_ip,
                json_string(details or {}),
                utc_now(),
            ),
        )


# ============================================================
# Client Registry
# ============================================================

def get_client(
    client_id: str,
):
    with db() as conn:
        return conn.execute(
            """
            SELECT *
            FROM clients
            WHERE client_id = ?
            """,
            (client_id,),
        ).fetchone()


def get_device(
    device_id: str,
):
    with db() as conn:
        return conn.execute(
            """
            SELECT *
            FROM devices
            WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()


def get_session_by_token(
    token: str,
):
    token_hash = sha256(token)

    with db() as conn:
        return conn.execute(
            """
            SELECT *
            FROM sessions
            WHERE token_hash = ?
            """,
            (token_hash,),
        ).fetchone()


def cleanup_sessions():
    with db() as conn:
        conn.execute(
            """
            DELETE FROM sessions
            WHERE expires_at < ?
               OR revoked = 1
            """,
            (unix_time(),),
        )


# ============================================================
# Rate Limit
# ============================================================

def check_rate_limit(
    rate_key: str,
):
    now = unix_time()

    with db() as conn:

        row = conn.execute(
            """
            SELECT
                window_started,
                request_count
            FROM rate_limits
            WHERE rate_key = ?
            """,
            (rate_key,),
        ).fetchone()

        if not row:
            conn.execute(
                """
                INSERT INTO rate_limits (
                    rate_key,
                    window_started,
                    request_count
                )
                VALUES (?, ?, 1)
                """,
                (
                    rate_key,
                    now,
                ),
            )
            return True

        elapsed = now - int(
            row["window_started"]
        )

        if elapsed >= RATE_LIMIT_WINDOW:
            conn.execute(
                """
                UPDATE rate_limits
                SET window_started = ?,
                    request_count = 1
                WHERE rate_key = ?
                """,
                (
                    now,
                    rate_key,
                ),
            )
            return True

        if int(
            row["request_count"]
        ) >= RATE_LIMIT_MAX_REQUESTS:
            return False

        conn.execute(
            """
            UPDATE rate_limits
            SET request_count = request_count + 1
            WHERE rate_key = ?
            """,
            (rate_key,),
        )

        return True


# ============================================================
# Models
# ============================================================

class ClientCreate(BaseModel):
    client_id: str = Field(
        min_length=2,
        max_length=100,
    )

    client_name: str = Field(
        min_length=2,
        max_length=200,
    )

    platform: str = Field(
        min_length=2,
        max_length=30,
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict
    )


class ClientLogin(BaseModel):
    client_id: str
    client_secret: str
    device_id: str
    device_fingerprint: str
    device_name: Optional[str] = None
    platform: str
    metadata: Dict[str, Any] = Field(
        default_factory=dict
    )


class DeviceRegister(BaseModel):
    device_id: str = Field(
        min_length=3,
        max_length=200,
    )

    client_id: str

    platform: str

    device_fingerprint: str = Field(
        min_length=8,
        max_length=500,
    )

    device_name: Optional[str] = None

    metadata: Dict[str, Any] = Field(
        default_factory=dict
    )


class RuntimeRequest(BaseModel):
    action: str = Field(
        min_length=2,
        max_length=100,
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict
    )


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
def startup():
    init_database()
    cleanup_sessions()


# ============================================================
# Root / Health
# ============================================================

@app.get("/")
def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "platforms": [
            "android",
            "windows",
        ],
        "runtime_gateway": RUNTIME_GATEWAY_URL,
    }


@app.get("/health")
def health():
    with db() as conn:
        clients = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM clients
            WHERE enabled = 1
            """
        ).fetchone()["count"]

        devices = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM devices
            WHERE enabled = 1
            """
        ).fetchone()["count"]

        sessions = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM sessions
            WHERE revoked = 0
              AND expires_at > ?
            """,
            (unix_time(),),
        ).fetchone()["count"]

    return {
        "status": "healthy",
        "clients": clients,
        "devices": devices,
        "active_sessions": sessions,
        "time": utc_now(),
    }


# ============================================================
# OWNER Authentication
# ============================================================

def require_owner(
    email: Optional[str],
    secret: Optional[str],
):
    owner_email = os.getenv(
        "ARYA_MASTER_EMAIL",
        "",
    ).strip().lower()

    owner_secret = os.getenv(
        "ARYA_MASTER_SECRET",
        "",
    )

    if not owner_email or not owner_secret:
        raise HTTPException(
            status_code=503,
            detail="OWNER credentials are not configured.",
        )

    if not email or not secret:
        raise HTTPException(
            status_code=401,
            detail="OWNER authentication required.",
        )

    if not secure_equal(
        email.strip().lower(),
        owner_email,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials.",
        )

    if not secure_equal(
        secret,
        owner_secret,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials.",
        )


# ============================================================
# OWNER Client Creation
# ============================================================

@app.post("/owner/clients")
def owner_create_client(
    payload: ClientCreate,
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

    client_id = payload.client_id.strip().lower()

    if not client_id.replace("_", "").isalnum():
        raise HTTPException(
            status_code=400,
            detail="Invalid client ID.",
        )

    if get_client(client_id):
        raise HTTPException(
            status_code=409,
            detail="Client already exists.",
        )

    secret = generate_secret()
    now = utc_now()

    with db() as conn:
        conn.execute(
            """
            INSERT INTO clients (
                client_id,
                client_name,
                platform,
                secret_hash,
                enabled,
                created_at,
                updated_at,
                metadata_json
            )
            VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                client_id,
                payload.client_name,
                payload.platform.lower(),
                sha256(secret),
                now,
                now,
                json_string(payload.metadata),
            ),
        )

    audit(
        "owner_client_created",
        True,
        client_id=client_id,
    )

    return {
        "client_id": client_id,
        "client_name": payload.client_name,
        "platform": payload.platform,
        "client_secret": secret,
        "warning": (
            "Store this secret securely. "
            "It will not be returned again."
        ),
    }


@app.get("/owner/clients")
def owner_list_clients(
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
                client_id,
                client_name,
                platform,
                enabled,
                created_at,
                updated_at
            FROM clients
            ORDER BY client_id
            """
        ).fetchall()

    return {
        "clients": [
            {
                "client_id": row["client_id"],
                "client_name": row["client_name"],
                "platform": row["platform"],
                "enabled": bool(row["enabled"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]
    }


# ============================================================
# OWNER Client Enable / Disable
# ============================================================

@app.post("/owner/clients/{client_id}/enable")
def owner_enable_client(
    client_id: str,
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

    if not get_client(client_id):
        raise HTTPException(
            status_code=404,
            detail="Client not found.",
        )

    with db() as conn:
        conn.execute(
            """
            UPDATE clients
            SET enabled = 1,
                updated_at = ?
            WHERE client_id = ?
            """,
            (
                utc_now(),
                client_id,
            ),
        )

    audit(
        "owner_client_enabled",
        True,
        client_id=client_id,
    )

    return {
        "client_id": client_id,
        "enabled": True,
    }


@app.post("/owner/clients/{client_id}/disable")
def owner_disable_client(
    client_id: str,
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

    if not get_client(client_id):
        raise HTTPException(
            status_code=404,
            detail="Client not found.",
        )

    with db() as conn:
        conn.execute(
            """
            UPDATE clients
            SET enabled = 0,
                updated_at = ?
            WHERE client_id = ?
            """,
            (
                utc_now(),
                client_id,
            ),
        )

        conn.execute(
            """
            UPDATE sessions
            SET revoked = 1
            WHERE client_id = ?
            """,
            (client_id,),
        )

    audit(
        "owner_client_disabled",
        True,
        client_id=client_id,
    )

    return {
        "client_id": client_id,
        "enabled": False,
        "sessions_revoked": True,
    }


# ============================================================
# Device Registration
# ============================================================

@app.post("/client/devices/register")
def register_device(
    payload: DeviceRegister,
):
    client = get_client(
        payload.client_id
    )

    if not client:
        raise HTTPException(
            status_code=404,
            detail="Client not found.",
        )

    if not bool(client["enabled"]):
        raise HTTPException(
            status_code=403,
            detail="Client is disabled.",
        )

    now = utc_now()

    existing = get_device(
        payload.device_id
    )

    with db() as conn:

        if existing:

            if existing["client_id"] != payload.client_id:
                raise HTTPException(
                    status_code=409,
                    detail="Device belongs to another client.",
                )

            conn.execute(
                """
                UPDATE devices
                SET platform = ?,
                    device_name = ?,
                    device_fingerprint = ?,
                    metadata_json = ?,
                    last_seen_at = ?
                WHERE device_id = ?
                """,
                (
                    payload.platform.lower(),
                    payload.device_name,
                    payload.device_fingerprint,
                    json_string(payload.metadata),
                    now,
                    payload.device_id,
                ),
            )

        else:

            conn.execute(
                """
                INSERT INTO devices (
                    device_id,
                    client_id,
                    platform,
                    device_name,
                    device_fingerprint,
                    enabled,
                    created_at,
                    last_seen_at,
                    metadata_json
                )
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    payload.device_id,
                    payload.client_id,
                    payload.platform.lower(),
                    payload.device_name,
                    payload.device_fingerprint,
                    now,
                    now,
                    json_string(payload.metadata),
                ),
            )

    audit(
        "device_registered",
        True,
        client_id=payload.client_id,
        device_id=payload.device_id,
    )

    return {
        "device_id": payload.device_id,
        "client_id": payload.client_id,
        "enabled": True,
        "registered_at": now,
    }


# ============================================================
# Client Login
# ============================================================

@app.post("/client/login")
def client_login(
    payload: ClientLogin,
    request: Request,
):
    client = get_client(
        payload.client_id
    )

    if not client:
        audit(
            "client_login_unknown_client",
            False,
            client_id=payload.client_id,
            source_ip=(
                request.client.host
                if request.client
                else None
            ),
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid client credentials.",
        )

    if not bool(client["enabled"]):
        raise HTTPException(
            status_code=403,
            detail="Client is disabled.",
        )

    if not secure_equal(
        sha256(payload.client_secret),
        client["secret_hash"],
    ):
        audit(
            "client_login_bad_secret",
            False,
            client_id=payload.client_id,
            source_ip=(
                request.client.host
                if request.client
                else None
            ),
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid client credentials.",
        )

    device = get_device(
        payload.device_id
    )

    if not device:
        register_device(
            DeviceRegister(
                device_id=payload.device_id,
                client_id=payload.client_id,
                platform=payload.platform,
                device_fingerprint=payload.device_fingerprint,
                device_name=payload.device_name,
                metadata=payload.metadata,
            )
        )
        device = get_device(
            payload.device_id
        )

    if device["client_id"] != payload.client_id:
        raise HTTPException(
            status_code=403,
            detail="Device/client mismatch.",
        )

    if not bool(device["enabled"]):
        raise HTTPException(
            status_code=403,
            detail="Device is disabled.",
        )

    session_token = generate_token()
    now = unix_time()
    expires = now + SESSION_TTL
    session_id = str(uuid.uuid4())

    with db() as conn:
        conn.execute(
            """
            INSERT INTO sessions (
                session_id,
                client_id,
                device_id,
                token_hash,
                created_at,
                expires_at,
                revoked
            )
            VALUES (?, ?, ?, ?, ?, ?, 0)
            """,
            (
                session_id,
                payload.client_id,
                payload.device_id,
                sha256(session_token),
                now,
                expires,
            ),
        )

        conn.execute(
            """
            UPDATE devices
            SET last_seen_at = ?
            WHERE device_id = ?
            """,
            (
                utc_now(),
                payload.device_id,
            ),
        )

    audit(
        "client_login_success",
        True,
        client_id=payload.client_id,
        device_id=payload.device_id,
        session_id=session_id,
        source_ip=(
            request.client.host
            if request.client
            else None
        ),
    )

    return {
        "session_id": session_id,
        "access_token": session_token,
        "token_type": "Bearer",
        "expires_at": expires,
        "expires_in": SESSION_TTL,
        "client_id": payload.client_id,
        "device_id": payload.device_id,
        "platform": payload.platform.lower(),
    }


# ============================================================
# Session Authentication
# ============================================================

def require_session(
    authorization: Optional[str],
):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization required.",
        )

    if not authorization.lower().startswith(
        "bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Bearer token required.",
        )

    token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token.",
        )

    session = get_session_by_token(
        token
    )

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token.",
        )

    if bool(session["revoked"]):
        raise HTTPException(
            status_code=401,
            detail="Session revoked.",
        )

    if int(session["expires_at"]) <= unix_time():
        raise HTTPException(
            status_code=401,
            detail="Session expired.",
        )

    client = get_client(
        session["client_id"]
    )

    device = get_device(
        session["device_id"]
    )

    if not client or not bool(
        client["enabled"]
    ):
        raise HTTPException(
            status_code=403,
            detail="Client disabled.",
        )

    if not device or not bool(
        device["enabled"]
    ):
        raise HTTPException(
            status_code=403,
            detail="Device disabled.",
        )

    return session


# ============================================================
# Logout
# ============================================================

@app.post("/client/logout")
def client_logout(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    with db() as conn:
        conn.execute(
            """
            UPDATE sessions
            SET revoked = 1
            WHERE session_id = ?
            """,
            (session["session_id"],),
        )

    audit(
        "client_logout",
        True,
        client_id=session["client_id"],
        device_id=session["device_id"],
        session_id=session["session_id"],
    )

    return {
        "logged_out": True,
    }


# ============================================================
# Session Info
# ============================================================

@app.get("/client/me")
def client_me(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    client = get_client(
        session["client_id"]
    )

    device = get_device(
        session["device_id"]
    )

    return {
        "client": {
            "client_id": client["client_id"],
            "client_name": client["client_name"],
            "platform": client["platform"],
            "enabled": bool(client["enabled"]),
        },
        "device": {
            "device_id": device["device_id"],
            "platform": device["platform"],
            "device_name": device["device_name"],
            "enabled": bool(device["enabled"]),
        },
        "session": {
            "session_id": session["session_id"],
            "expires_at": session["expires_at"],
        },
    }


# ============================================================
# Runtime Gateway Call
# ============================================================

async def runtime_call(
    path: str,
    payload: Dict[str, Any],
):
    url = (
        RUNTIME_GATEWAY_URL
        + "/"
        + path.lstrip("/")
    )

    headers = {
        "Content-Type": "application/json",
        "X-ARYA-Client-Gateway": APP_VERSION,
    }

    if INTERNAL_GATEWAY_SECRET:
        headers[
            "X-ARYA-Internal-Secret"
        ] = INTERNAL_GATEWAY_SECRET

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        follow_redirects=False,
    ) as client:

        try:
            response = await client.post(
                url,
                json=payload,
                headers=headers,
            )

        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail="Runtime Gateway timeout.",
            )

        except httpx.HTTPError:
            raise HTTPException(
                status_code=502,
                detail="Runtime Gateway unavailable.",
            )

    if len(response.content) > MAX_RESPONSE_BYTES:
        raise HTTPException(
            status_code=502,
            detail="Runtime response too large.",
        )

    try:
        data = response.json()
    except Exception:
        data = {
            "raw": response.text
        }

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=data,
        )

    return data


# ============================================================
# Generic Client Runtime API
# ============================================================

@app.post("/api/v1/runtime")
async def api_runtime(
    payload: RuntimeRequest,
    request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    rate_key = (
        f"{session['client_id']}:"
        f"{session['device_id']}"
    )

    if not check_rate_limit(rate_key):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    request_id = str(uuid.uuid4())

    audit(
        "runtime_request",
        True,
        client_id=session["client_id"],
        device_id=session["device_id"],
        session_id=session["session_id"],
        request_id=request_id,
        source_ip=(
            request.client.host
            if request.client
            else None
        ),
        details={
            "action": payload.action,
        },
    )

    data = await runtime_call(
        "/runtime/call",
        {
            "action": payload.action,
            "payload": payload.payload,
            "request_id": request_id,
        },
    )

    return {
        "request_id": request_id,
        "data": data,
    }


# ============================================================
# Agricultural Doctor API
# ============================================================

@app.post("/api/v1/doctor")
async def doctor(
    payload: Dict[str, Any],
    request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    if not check_rate_limit(
        f"{session['client_id']}:doctor"
    ):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    request_id = str(uuid.uuid4())

    data = await runtime_call(
        "/arya/analyze",
        {
            "payload": payload,
            "request_id": request_id,
        },
    )

    audit(
        "doctor_analysis",
        True,
        client_id=session["client_id"],
        device_id=session["device_id"],
        session_id=session["session_id"],
        request_id=request_id,
        source_ip=(
            request.client.host
            if request.client
            else None
        ),
    )

    return {
        "request_id": request_id,
        "result": data,
    }


@app.post("/api/v1/analyze")
async def analyze(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    if not check_rate_limit(
        f"{session['client_id']}:analyze"
    ):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    request_id = str(uuid.uuid4())

    data = await runtime_call(
        "/arya/analyze",
        {
            "payload": payload,
            "request_id": request_id,
        },
    )

    return {
        "request_id": request_id,
        "result": data,
    }


@app.post("/api/v1/diagnose")
async def diagnose(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    if not check_rate_limit(
        f"{session['client_id']}:diagnose"
    ):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    request_id = str(uuid.uuid4())

    data = await runtime_call(
        "/arya/diagnose",
        {
            "payload": payload,
            "request_id": request_id,
        },
    )

    return {
        "request_id": request_id,
        "result": data,
    }


@app.post("/api/v1/recommend")
async def recommend(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    if not check_rate_limit(
        f"{session['client_id']}:recommend"
    ):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    request_id = str(uuid.uuid4())

    data = await runtime_call(
        "/arya/recommend",
        {
            "payload": payload,
            "request_id": request_id,
        },
    )

    return {
        "request_id": request_id,
        "result": data,
    }


# ============================================================
# Vision
# ============================================================

@app.post("/api/v1/vision")
async def vision(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    if not check_rate_limit(
        f"{session['client_id']}:vision"
    ):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    request_id = str(uuid.uuid4())

    data = await runtime_call(
        "/arya/vision",
        {
            "payload": payload,
            "request_id": request_id,
        },
    )

    return {
        "request_id": request_id,
        "result": data,
    }


# ============================================================
# Weather
# ============================================================

@app.post("/api/v1/weather")
async def weather(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    if not check_rate_limit(
        f"{session['client_id']}:weather"
    ):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    request_id = str(uuid.uuid4())

    data = await runtime_call(
        "/arya/weather",
        {
            "payload": payload,
            "request_id": request_id,
        },
    )

    return {
        "request_id": request_id,
        "result": data,
    }


# ============================================================
# Geocoding / Location
# ============================================================

@app.post("/api/v1/geocode")
async def geocode(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    if not check_rate_limit(
        f"{session['client_id']}:geocode"
    ):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    request_id = str(uuid.uuid4())

    data = await runtime_call(
        "/arya/geocode",
        {
            "payload": payload,
            "request_id": request_id,
        },
    )

    return {
        "request_id": request_id,
        "result": data,
    }


# ============================================================
# Updates
# ============================================================

@app.get("/api/v1/updates")
async def updates(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    if not check_rate_limit(
        f"{session['client_id']}:updates"
    ):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    return await runtime_call(
        "/arya/updates",
        {
            "client_id": session["client_id"],
        },
    )


@app.post("/api/v1/updates/run")
async def run_updates(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    if not check_rate_limit(
        f"{session['client_id']}:updates_run"
    ):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
        )

    return await runtime_call(
        "/arya/updates/run",
        {
            "requested_by": session["client_id"],
        },
    )


# ============================================================
# System Map
# ============================================================

@app.get("/api/v1/system-map")
async def system_map(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    return await runtime_call(
        "/arya/system-map",
        {
            "client_id": session["client_id"],
        },
    )


# ============================================================
# Device Management
# ============================================================

@app.get("/client/devices")
def client_devices(
    authorization: Optional[str] = Header(
        default=None
    ),
):
    session = require_session(
        authorization
    )

    with db() as conn:
        rows = conn.execute(
            """
            SELECT
                device_id,
                platform,
                device_name,
                enabled,
                created_at,
                last_seen_at,
                metadata_json
            FROM devices
            WHERE client_id = ?
            ORDER BY created_at DESC
            """,
            (session["client_id"],),
        ).fetchall()

    return {
        "devices": [
            {
                "device_id": row["device_id"],
                "platform": row["platform"],
                "device_name": row["device_name"],
                "enabled": bool(row["enabled"]),
                "created_at": row["created_at"],
                "last_seen_at": row["last_seen_at"],
                "metadata": json.loads(
                    row["metadata_json"]
                    or "{}"
                ),
            }
            for row in rows
        ]
    }


# ============================================================
# OWNER Device Control
# ============================================================

@app.post(
    "/owner/devices/{device_id}/disable"
)
def owner_disable_device(
    device_id: str,
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

    device = get_device(
        device_id
    )

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found.",
        )

    with db() as conn:
        conn.execute(
            """
            UPDATE devices
            SET enabled = 0
            WHERE device_id = ?
            """,
            (device_id,),
        )

        conn.execute(
            """
            UPDATE sessions
            SET revoked = 1
            WHERE device_id = ?
            """,
            (device_id,),
        )

    audit(
        "owner_device_disabled",
        True,
        client_id=device["client_id"],
        device_id=device_id,
    )

    return {
        "device_id": device_id,
        "enabled": False,
        "sessions_revoked": True,
    }


@app.post(
    "/owner/devices/{device_id}/enable"
)
def owner_enable_device(
    device_id: str,
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

    device = get_device(
        device_id
    )

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found.",
        )

    with db() as conn:
        conn.execute(
            """
            UPDATE devices
            SET enabled = 1
            WHERE device_id = ?
            """,
            (device_id,),
        )

    audit(
        "owner_device_enabled",
        True,
        client_id=device["client_id"],
        device_id=device_id,
    )

    return {
        "device_id": device_id,
        "enabled": True,
    }


# ============================================================
# OWNER Session Control
# ============================================================

@app.get("/owner/sessions")
def owner_sessions(
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
                session_id,
                client_id,
                device_id,
                created_at,
                expires_at,
                revoked
            FROM sessions
            ORDER BY created_at DESC
            LIMIT 500
            """
        ).fetchall()

    return {
        "sessions": [
            {
                "session_id": row["session_id"],
                "client_id": row["client_id"],
                "device_id": row["device_id"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "revoked": bool(row["revoked"]),
            }
            for row in rows
        ]
    }


@app.post(
    "/owner/sessions/revoke/{session_id}"
)
def owner_revoke_session(
    session_id: str,
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
        cursor = conn.execute(
            """
            UPDATE sessions
            SET revoked = 1
            WHERE session_id = ?
            """,
            (session_id,),
        )

    if cursor.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Session not found.",
        )

    audit(
        "owner_session_revoked",
        True,
        session_id=session_id,
    )

    return {
        "session_id": session_id,
        "revoked": True,
    }


# ============================================================
# OWNER Security Statistics
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
        clients = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM clients
            """
        ).fetchone()["count"]

        enabled_clients = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM clients
            WHERE enabled = 1
            """
        ).fetchone()["count"]

        devices = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM devices
            """
        ).fetchone()["count"]

        active_devices = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM devices
            WHERE enabled = 1
            """
        ).fetchone()["count"]

        active_sessions = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM sessions
            WHERE revoked = 0
              AND expires_at > ?
            """,
            (unix_time(),),
        ).fetchone()["count"]

        audit_events = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM audit_logs
            """
        ).fetchone()["count"]

    return {
        "clients": clients,
        "enabled_clients": enabled_clients,
        "devices": devices,
        "active_devices": active_devices,
        "active_sessions": active_sessions,
        "audit_events": audit_events,
        "rate_limit_window": RATE_LIMIT_WINDOW,
        "rate_limit_max_requests": RATE_LIMIT_MAX_REQUESTS,
        "runtime_gateway": RUNTIME_GATEWAY_URL,
        "time": utc_now(),
    }


# ============================================================
# OWNER Audit
# ============================================================

@app.get("/owner/audit")
def owner_audit(
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
                client_id,
                device_id,
                session_id,
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
                "client_id": row["client_id"],
                "device_id": row["device_id"],
                "session_id": row["session_id"],
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
# API Contract
# ============================================================

@app.get("/api/v1/contract")
def api_contract():
    return {
        "version": APP_VERSION,
        "platforms": [
            "android",
            "windows",
        ],
        "authentication": {
            "client": "client_id + client_secret",
            "session": "Bearer access_token",
        },
        "core_endpoints": [
            "/client/login",
            "/client/logout",
            "/client/me",
            "/client/devices",
            "/api/v1/doctor",
            "/api/v1/analyze",
            "/api/v1/diagnose",
            "/api/v1/recommend",
            "/api/v1/vision",
            "/api/v1/weather",
            "/api/v1/geocode",
            "/api/v1/updates",
            "/api/v1/updates/run",
            "/api/v1/system-map",
        ],
        "security": [
            "session_authentication",
            "device_control",
            "rate_limiting",
            "audit_logging",
            "owner_controls",
        ],
    }


# ============================================================
# Run
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "client_api_gateway:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
