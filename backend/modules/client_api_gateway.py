"""
ARYA AgriDoctor
Client API Gateway
Version: 2.0.0

Purpose:
- Unified API boundary for Android and Windows clients
- Secure client authentication and sessions
- Device registration and control
- Runtime Gateway communication
- Agricultural doctor / vision / voice / weather / geocode / payment APIs
- Rate limiting
- Request auditing
- OWNER controls
- Request ID propagation
- Internal gateway authentication
- Compatibility routes for Unified API
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Client API Gateway"
APP_VERSION = "2.0.0"

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

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
    os.path.join(
        BASE_DIR,
        "client_api_gateway.db",
    ),
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

SESSION_TTL = max(
    300,
    int(
        os.getenv(
            "ARYA_CLIENT_SESSION_TTL",
            "86400",
        )
    ),
)

REQUEST_TIMEOUT = max(
    5.0,
    float(
        os.getenv(
            "ARYA_CLIENT_GATEWAY_TIMEOUT",
            "60",
        )
    ),
)

MAX_RESPONSE_BYTES = max(
    1024,
    int(
        os.getenv(
            "ARYA_CLIENT_GATEWAY_MAX_RESPONSE_BYTES",
            str(8 * 1024 * 1024),
        )
    ),
)

MAX_REQUEST_BYTES = max(
    1024,
    int(
        os.getenv(
            "ARYA_CLIENT_GATEWAY_MAX_REQUEST_BYTES",
            str(8 * 1024 * 1024),
        )
    ),
)

RATE_LIMIT_WINDOW = max(
    1,
    int(
        os.getenv(
            "ARYA_CLIENT_RATE_WINDOW",
            "60",
        )
    ),
)

RATE_LIMIT_MAX_REQUESTS = max(
    1,
    int(
        os.getenv(
            "ARYA_CLIENT_RATE_LIMIT",
            "60",
        )
    ),
)

MAX_DEVICES_PER_CLIENT = max(
    1,
    int(
        os.getenv(
            "ARYA_MAX_DEVICES_PER_CLIENT",
            "3",
        )
    ),
)


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Secure unified client API gateway for "
        "ARYA AgriDoctor Android and Windows clients."
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
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")

        yield conn

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def init_database():
    parent = os.path.dirname(DB_PATH)

    if parent:
        os.makedirs(
            parent,
            exist_ok=True,
        )

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
                metadata_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(client_id)
                    REFERENCES clients(client_id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(client_id)
                    REFERENCES clients(client_id),
                FOREIGN KEY(device_id)
                    REFERENCES devices(device_id)
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

            CREATE INDEX IF NOT EXISTS idx_sessions_client
            ON sessions(client_id);

            CREATE INDEX IF NOT EXISTS idx_sessions_device
            ON sessions(device_id);

            CREATE INDEX IF NOT EXISTS idx_sessions_expiry
            ON sessions(expires_at);

            CREATE INDEX IF NOT EXISTS idx_devices_client
            ON devices(client_id);

            CREATE INDEX IF NOT EXISTS idx_audit_created
            ON audit_logs(created_at);

            CREATE INDEX IF NOT EXISTS idx_audit_request
            ON audit_logs(request_id);
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
        default=str,
    )


def safe_json(value: Optional[str]) -> Dict[str, Any]:
    try:
        result = json.loads(value or "{}")

        if isinstance(result, dict):
            return result

        return {}

    except Exception:
        return {}


def generate_token() -> str:
    return secrets.token_urlsafe(48)


def generate_secret() -> str:
    return secrets.token_urlsafe(48)


def request_ip(
    request: Request,
) -> Optional[str]:
    if not request.client:
        return None

    return request.client.host


def new_request_id(
    request: Optional[Request] = None,
) -> str:
    if request is not None:
        incoming = request.headers.get(
            "X-Request-ID"
        )

        if incoming:
            incoming = incoming.strip()

            if len(incoming) <= 128:
                return incoming

    return str(uuid.uuid4())


def validate_platform(
    platform: str,
) -> str:
    value = platform.strip().lower()

    if value not in {
        "android",
        "windows",
    }:
        raise HTTPException(
            status_code=400,
            detail="Unsupported client platform.",
        )

    return value


def validate_client_id(
    client_id: str,
) -> str:
    value = client_id.strip().lower()

    if not value:
        raise HTTPException(
            status_code=400,
            detail="Client ID is required.",
        )

    if len(value) > 100:
        raise HTTPException(
            status_code=400,
            detail="Client ID is too long.",
        )

    if not value.replace(
        "_",
        "",
    ).replace(
        "-",
        "",
    ).isalnum():
        raise HTTPException(
            status_code=400,
            detail="Invalid client ID.",
        )

    return value


def validate_runtime_url(
    value: str,
):
    parsed = urlparse(value)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise RuntimeError(
            "Runtime Gateway URL must use HTTP or HTTPS."
        )

    if not parsed.netloc:
        raise RuntimeError(
            "Runtime Gateway URL is invalid."
        )


def validate_request_size(
    request: Request,
):
    content_length = request.headers.get(
        "content-length"
    )

    if not content_length:
        return

    try:
        size = int(content_length)
    except ValueError:
        return

    if size > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request payload too large.",
        )


# ============================================================
# Middleware
# ============================================================

@app.middleware("http")
async def request_guard(
    request: Request,
    call_next,
):
    validate_request_size(request)

    response = await call_next(
        request
    )

    response.headers[
        "X-Request-ID"
    ] = request.headers.get(
        "X-Request-ID",
        "",
    ) or str(uuid.uuid4())

    response.headers[
        "X-ARYA-Gateway"
    ] = APP_VERSION

    return response


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
    try:
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
    except Exception:
        # Audit failure must never break authentication/runtime.
        pass


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


def count_client_devices(
    client_id: str,
) -> int:
    with db() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM devices
            WHERE client_id = ?
              AND enabled = 1
            """,
            (client_id,),
        ).fetchone()

    return int(row["count"])


# ============================================================
# Rate Limit
# ============================================================

def check_rate_limit(
    rate_key: str,
) -> bool:
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


def enforce_rate_limit(
    session,
    scope: str,
):
    key = (
        f"{session['client_id']}:"
        f"{session['device_id']}:"
        f"{scope}"
    )

    if not check_rate_limit(key):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
            headers={
                "Retry-After": str(
                    RATE_LIMIT_WINDOW
                )
            },
        )


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

    try:
        validate_runtime_url(
            RUNTIME_GATEWAY_URL
        )
    except Exception:
        # Runtime failures are reported when called.
        pass


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
        "authentication": "client_session",
    }


@app.get("/health")
def health():
    runtime_configured = bool(
        RUNTIME_GATEWAY_URL
    )

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
        "service": APP_NAME,
        "version": APP_VERSION,
        "clients": clients,
        "devices": devices,
        "active_sessions": sessions,
        "runtime_gateway_configured": runtime_configured,
        "internal_secret_configured": bool(
            INTERNAL_GATEWAY_SECRET
        ),
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

    client_id = validate_client_id(
        payload.client_id
    )

    platform = validate_platform(
        payload.platform
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
                payload.client_name.strip(),
                platform,
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
        "client_name": payload.client_name.strip(),
        "platform": platform,
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

    client_id = validate_client_id(
        client_id
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

    client_id = validate_client_id(
        client_id
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
    request: Request,
):
    client_id = validate_client_id(
        payload.client_id
    )

    platform = validate_platform(
        payload.platform
    )

    client = get_client(client_id)

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

    existing = get_device(
        payload.device_id
    )

    if existing:
        if existing["client_id"] != client_id:
            audit(
                "device_registration_conflict",
                False,
                client_id=client_id,
                device_id=payload.device_id,
                source_ip=request_ip(request),
            )

            raise HTTPException(
                status_code=409,
                detail="Device belongs to another client.",
            )

        if not secure_equal(
            str(existing["device_fingerprint"]),
            str(payload.device_fingerprint),
        ):
            audit(
                "device_fingerprint_mismatch",
                False,
                client_id=client_id,
                device_id=payload.device_id,
                source_ip=request_ip(request),
            )

            raise HTTPException(
                status_code=403,
                detail="Device fingerprint mismatch.",
            )

    else:
        if (
            count_client_devices(client_id)
            >= MAX_DEVICES_PER_CLIENT
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "Maximum device limit reached "
                    f"({MAX_DEVICES_PER_CLIENT})."
                ),
            )

    now = utc_now()

    with db() as conn:
        if existing:
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
                    platform,
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
                    client_id,
                    platform,
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
        client_id=client_id,
        device_id=payload.device_id,
        source_ip=request_ip(request),
    )

    return {
        "device_id": payload.device_id,
        "client_id": client_id,
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
    client_id = validate_client_id(
        payload.client_id
    )

    platform = validate_platform(
        payload.platform
    )

    client = get_client(
        client_id
    )

    source_ip = request_ip(request)

    if not client:
        audit(
            "client_login_unknown_client",
            False,
            client_id=client_id,
            source_ip=source_ip,
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
            client_id=client_id,
            source_ip=source_ip,
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
                client_id=client_id,
                platform=platform,
                device_fingerprint=payload.device_fingerprint,
                device_name=payload.device_name,
                metadata=payload.metadata,
            ),
            request,
        )

        device = get_device(
            payload.device_id
        )

    if device["client_id"] != client_id:
        raise HTTPException(
            status_code=403,
            detail="Device/client mismatch.",
        )

    if not secure_equal(
        str(device["device_fingerprint"]),
        str(payload.device_fingerprint),
    ):
        audit(
            "client_login_fingerprint_mismatch",
            False,
            client_id=client_id,
            device_id=payload.device_id,
            source_ip=source_ip,
        )

        raise HTTPException(
            status_code=403,
            detail="Device fingerprint mismatch.",
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
                client_id,
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
        client_id=client_id,
        device_id=payload.device_id,
        session_id=session_id,
        source_ip=source_ip,
    )

    return {
        "session_id": session_id,
        "access_token": session_token,
        "token_type": "Bearer",
        "expires_at": expires,
        "expires_in": SESSION_TTL,
        "client_id": client_id,
        "device_id": payload.device_id,
        "platform": platform,
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
# Runtime Gateway Security
# ============================================================

def require_internal_runtime_secret():
    if not INTERNAL_GATEWAY_SECRET:
        raise HTTPException(
            status_code=503,
            detail=(
                "Internal gateway secret is not configured."
            ),
        )


# ============================================================
# Runtime Gateway Call
# ============================================================

async def runtime_call(
    path: str,
    payload: Dict[str, Any],
    request_id: Optional[str] = None,
):
    require_internal_runtime_secret()

    try:
        validate_runtime_url(
            RUNTIME_GATEWAY_URL
        )
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Runtime Gateway URL is invalid.",
        )

    normalized_path = path.lstrip("/")

    allowed_paths = {
        "runtime/call",
        "arya/analyze",
        "arya/diagnose",
        "arya/recommend",
        "arya/vision",
        "arya/voice",
        "arya/weather",
        "arya/geocode",
        "arya/payment",
        "arya/updates",
        "arya/updates/run",
        "arya/system-map",
    }

    if normalized_path not in allowed_paths:
        raise HTTPException(
            status_code=400,
            detail="Unsupported runtime route.",
        )

    url = (
        RUNTIME_GATEWAY_URL
        + "/"
        + normalized_path
    )

    rid = request_id or str(
        uuid.uuid4()
    )

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-ARYA-Client-Gateway": APP_VERSION,
        "X-Request-ID": rid,
        "X-ARYA-Internal-Secret":
            INTERNAL_GATEWAY_SECRET,
    }

    body = dict(payload)
    body["request_id"] = rid

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        follow_redirects=False,
    ) as client:
        try:
            response = await client.post(
                url,
                json=body,
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

    enforce_rate_limit(
        session,
        "runtime",
    )

    request_id = new_request_id(
        request
    )

    audit(
        "runtime_request",
        True,
        client_id=session["client_id"],
        device_id=session["device_id"],
        session_id=session["session_id"],
        request_id=request_id,
        source_ip=request_ip(request),
        details={
            "action": payload.action,
        },
    )

    try:
        data = await runtime_call(
            "runtime/call",
            {
                "action": payload.action,
                "payload": payload.payload,
            },
            request_id,
        )

    except HTTPException as exc:
        audit(
            "runtime_request_failed",
            False,
            client_id=session["client_id"],
            device_id=session["device_id"],
            session_id=session["session_id"],
            request_id=request_id,
            source_ip=request_ip(request),
            details={
                "action": payload.action,
                "status_code": exc.status_code,
            },
        )
        raise

    return {
        "request_id": request_id,
        "data": data,
    }


# ============================================================
# Agricultural Doctor Internal Helper
# ============================================================

async def authenticated_arya_call(
    runtime_path: str,
    scope: str,
    payload: Dict[str, Any],
    request: Request,
    authorization: Optional[str],
):
    session = require_session(
        authorization
    )

    enforce_rate_limit(
        session,
        scope,
    )

    request_id = new_request_id(
        request
    )

    try:
        data = await runtime_call(
            runtime_path,
            {
                "payload": payload,
            },
            request_id,
        )

    except HTTPException as exc:
        audit(
            f"{scope}_failed",
            False,
            client_id=session["client_id"],
            device_id=session["device_id"],
            session_id=session["session_id"],
            request_id=request_id,
            source_ip=request_ip(request),
            details={
                "status_code": exc.status_code,
            },
        )
        raise

    audit(
        scope,
        True,
        client_id=session["client_id"],
        device_id=session["device_id"],
        session_id=session["session_id"],
        request_id=request_id,
        source_ip=request_ip(request),
    )

    return {
        "request_id": request_id,
        "result": data,
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
    return await authenticated_arya_call(
        "arya/analyze",
        "doctor_analysis",
        payload,
        request,
        authorization,
    )


@app.post("/api/v1/doctor/analyze")
async def doctor_analyze(
    payload: Dict[str, Any],
    request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    return await authenticated_arya_call(
        "arya/analyze",
        "doctor_analyze",
        payload,
        request,
        authorization,
    )


@app.post("/api/v1/doctor/diagnose")
async def doctor_diagnose(
    payload: Dict[str, Any],
    request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    return await authenticated_arya_call(
        "arya/diagnose",
        "doctor_diagnose",
        payload,
        request,
        authorization,
    )


@app.post("/api/v1/doctor/recommend")
async def doctor_recommend(
    payload: Dict[str, Any],
    request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    return await authenticated_arya_call(
        "arya/recommend",
        "doctor_recommend",
        payload,
        request,
        authorization,
    )


@app.post("/api/v1/analyze")
async def analyze(
    payload: Dict[str, Any],
    request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    return await authenticated_arya_call(
        "arya/analyze",
        "analyze",
        payload,
        request,
        authorization,
    )


@app.post("/api/v1/diagnose")
async def diagnose(
    payload: Dict[str, Any],
    request: Request,
    authorization: Optional[str] = Header(
        default=None
    ),
):
    return await authenticated_arya_call(
        "arya/diagnose",
       
