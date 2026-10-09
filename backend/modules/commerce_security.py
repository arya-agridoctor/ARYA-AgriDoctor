"""
===============================================================
 ARYA Commerce & Security
 Version: 2.1.0
 Independent Commerce / Payment / OWNER Security Service
===============================================================

Preserves the independent commerce-service architecture.
Does not modify main.py, vision.py, voice_language.py,
or agri_engine.py.

Security improvements:
- OWNER session validation
- User identity authorization
- Atomic payment and subscription operations
- Atomic device-limit enforcement
- MFA encryption at rest
- Audited administrative operations
- Payment idempotency protection
- Historical destination snapshots
===============================================================
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import struct
import time

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
)
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from pydantic import BaseModel, Field


# ===============================================================
# APPLICATION CONFIGURATION
# ===============================================================

APP_NAME = "ARYA Commerce & Security"
APP_VERSION = "2.1.0"

DATABASE_PATH = os.getenv(
    "ARYA_COMMERCE_DATABASE",
    "commerce_security.db",
)

OWNER_EMAIL = os.getenv(
    "ARYA_OWNER_EMAIL",
    "",
).strip()

OWNER_SECRET_HASH = os.getenv(
    "ARYA_OWNER_SECRET_HASH",
    "",
).strip()

COMMERCE_JWT_SECRET = os.getenv(
    "ARYA_COMMERCE_JWT_SECRET",
    "",
).strip()

PAYMENT_WEBHOOK_SECRET = os.getenv(
    "ARYA_PAYMENT_WEBHOOK_SECRET",
    "",
).strip()

# Required for encrypting MFA secrets at rest.
# Configure a strong, persistent key before enabling MFA.
MFA_ENCRYPTION_KEY = os.getenv(
    "ARYA_MFA_ENCRYPTION_KEY",
    "",
).strip()

DEFAULT_DEVICE_LIMIT = max(
    1,
    int(os.getenv("ARYA_DEFAULT_DEVICE_LIMIT", "3")),
)

PAYMENT_EXPIRY_HOURS = max(
    1,
    int(os.getenv("ARYA_PAYMENT_EXPIRY_HOURS", "72")),
)

SUBSCRIPTION_DAYS = max(
    1,
    int(os.getenv("ARYA_SUBSCRIPTION_DAYS", "30")),
)

SESSION_HOURS = max(
    1,
    int(os.getenv("ARYA_OWNER_SESSION_HOURS", "12")),
)

RECOVERY_HOURS = max(
    1,
    int(os.getenv("ARYA_RECOVERY_HOURS", "24")),
)

TOTP_STEP_SECONDS = max(
    15,
    int(os.getenv("ARYA_TOTP_STEP_SECONDS", "30")),
)

TOTP_DIGITS = 6
MAX_AUDIT_LIMIT = 1000


# ===============================================================
# FASTAPI
# ===============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Independent ARYA payment, subscription, "
        "destination-management and OWNER security service."
    ),
)

security = HTTPBearer(auto_error=False)


# ===============================================================
# TIME
# ===============================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso() -> str:
    return utc_now().isoformat()


def future_iso(hours: int) -> str:
    return (
        utc_now() + timedelta(hours=hours)
    ).isoformat()


def future_days(days: int) -> str:
    return (
        utc_now() + timedelta(days=days)
    ).isoformat()


def parse_utc(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (TypeError, ValueError):
        return None


def is_future(value: Optional[str]) -> bool:
    parsed = parse_utc(value)
    return parsed is not None and parsed > utc_now()


# ===============================================================
# DATABASE
# ===============================================================

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
        check_same_thread=False,
        isolation_level="DEFERRED",
    )

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")

    return conn


def init_database() -> None:
    conn = get_db()

    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS system_controls (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payment_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                market TEXT NOT NULL,
                currency TEXT NOT NULL,
                amount REAL NOT NULL,
                max_users INTEGER,
                active INTEGER NOT NULL DEFAULT 1,
                metadata_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bank_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bank_name TEXT NOT NULL,
                account_holder TEXT NOT NULL,
                iban TEXT NOT NULL,
                account_number TEXT,
                card_number TEXT,
                currency TEXT NOT NULL DEFAULT 'IRR',
                label TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                effective_from TEXT NOT NULL,
                disabled_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS wallet_destinations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT NOT NULL,
                currency TEXT NOT NULL,
                address TEXT NOT NULL,
                label TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                effective_from TEXT NOT NULL,
                disabled_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payment_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                plan_code TEXT NOT NULL,
                market TEXT NOT NULL,
                method TEXT NOT NULL,
                currency TEXT NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL,
                destination_type TEXT,
                destination_id INTEGER,
                destination_snapshot TEXT,
                provider TEXT,
                provider_reference TEXT,
                idempotency_key TEXT UNIQUE NOT NULL,
                metadata_json TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                verified_at TEXT,
                FOREIGN KEY(destination_id)
                    REFERENCES wallet_destinations(id)
            );

            CREATE TABLE IF NOT EXISTS payment_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_id TEXT UNIQUE,
                payload_hash TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(transaction_id)
                    REFERENCES payment_transactions(transaction_id)
            );

            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subscription_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                plan_code TEXT NOT NULL,
                status TEXT NOT NULL,
                starts_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                source_transaction_id TEXT UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                device_name TEXT,
                platform TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                UNIQUE(user_id, device_id)
            );

            CREATE TABLE IF NOT EXISTS security_users (
                user_id TEXT PRIMARY KEY,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                mfa_secret_encrypted TEXT,
                recovery_hash TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_code TEXT UNIQUE NOT NULL,
                provider_type TEXT NOT NULL,
                name TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                config_json TEXT,
                secret_ref TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id TEXT,
                actor_role TEXT,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                ip_address TEXT,
                details_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recovery_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_payments_user
                ON payment_transactions(user_id, id);

            CREATE INDEX IF NOT EXISTS idx_subscriptions_user
                ON subscriptions(user_id, status, expires_at);

            CREATE INDEX IF NOT EXISTS idx_devices_user_active
                ON devices(user_id, active);

            CREATE INDEX IF NOT EXISTS idx_audit_created
                ON audit_logs(created_at);
            """
        )

        default_controls = {
            "commerce_enabled": "true",
            "payments_enabled": "true",
            "crypto_payments_enabled": "true",
            "bank_transfer_enabled": "true",
            "new_device_activation_enabled": "true",
            "maintenance_mode": "false",
        }

        for key, value in default_controls.items():
            conn.execute(
                """
                INSERT OR IGNORE INTO system_controls
                    (key, value, updated_at)
                VALUES (?, ?, ?)
                """,
                (key, value, utc_iso()),
            )

        conn.commit()

    finally:
        conn.close()


# ===============================================================
# DATABASE HELPERS
# ===============================================================

def fetch_one(
    sql: str,
    params: tuple = (),
) -> Optional[sqlite3.Row]:
    conn = get_db()

    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def fetch_all(
    sql: str,
    params: tuple = (),
) -> List[sqlite3.Row]:
    conn = get_db()

    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def execute(
    sql: str,
    params: tuple = (),
) -> int:
    conn = get_db()

    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


# ===============================================================
# CRYPTOGRAPHIC HELPERS
# ===============================================================

def sha256_text(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def random_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(16)}"


def constant_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(
        str(a).encode("utf-8"),
        str(b).encode("utf-8"),
    )


def safe_json_object(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {}

    try:
        result = json.loads(value)
        return result if isinstance(result, dict) else {}
    except (TypeError, ValueError):
        return {}


# ===============================================================
# PASSWORD HASH SUPPORT
# ===============================================================

def pbkdf2_hash(
    password: str,
    iterations: int = 310000,
) -> str:
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return (
        "pbkdf2_sha256$"
        f"{iterations}$"
        f"{base64.urlsafe_b64encode(salt).decode()}$"
        f"{base64.urlsafe_b64encode(digest).decode()}"
    )


def verify_secret(
    supplied: str,
    stored: str,
) -> bool:
    if not stored:
        return False

    if stored.startswith("pbkdf2_sha256$"):
        try:
            parts = stored.split("$")

            if len(parts) != 4:
                return False

            iterations = int(parts[1])

            if iterations < 100000 or iterations > 2000000:
                return False

            salt = base64.urlsafe_b64decode(
                parts[2].encode()
            )

            expected = base64.urlsafe_b64decode(
                parts[3].encode()
            )

            actual = hashlib.pbkdf2_hmac(
                "sha256",
                supplied.encode("utf-8"),
                salt,
                iterations,
            )

            return hmac.compare_digest(actual, expected)

        except (ValueError, TypeError, IndexError):
            return False

    # Backward compatibility with a SHA-256 environment hash.
    return constant_compare(
        sha256_text(supplied),
        stored,
    )


# ===============================================================
# TOTP MFA
# ===============================================================

def normalize_base32_secret(secret: str) -> bytes:
    clean = (
        secret.replace(" ", "")
        .replace("-", "")
        .upper()
    )

    padding = "=" * ((8 - len(clean) % 8) % 8)

    return base64.b32decode(
        clean + padding,
        casefold=True,
    )


def totp_code(
    secret: str,
    timestamp: Optional[int] = None,
) -> str:
    if timestamp is None:
        timestamp = int(time.time())

    counter = timestamp // TOTP_STEP_SECONDS
    key = normalize_base32_secret(secret)

    message = struct.pack(">Q", counter)

    digest = hmac.new(
        key,
        message,
        hashlib.sha1,
    ).digest()

    offset = digest[-1] & 0x0F

    binary = (
        ((digest[offset] & 0x7F) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )

    return str(
        binary % (10 ** TOTP_DIGITS)
    ).zfill(TOTP_DIGITS)


def verify_totp(
    secret: str,
    supplied_code: str,
) -> bool:
    code = supplied_code.strip()

    if not re.fullmatch(r"\d{6}", code):
        return False

    now = int(time.time())

    for offset in (-1, 0, 1):
        expected = totp_code(
            secret,
            now + offset * TOTP_STEP_SECONDS,
        )

        if hmac.compare_digest(expected, code):
            return True

    return False


# ===============================================================
# MFA SECRET ENCRYPTION
# ===============================================================

def _mfa_fernet():
    """
    Returns an authenticated encryption provider.

    MFA must not be enabled without a configured persistent key.
    Install cryptography and set ARYA_MFA_ENCRYPTION_KEY to a
    Fernet-compatible key generated by Fernet.generate_key().
    """
    if not MFA_ENCRYPTION_KEY:
        raise HTTPException(
            status_code=503,
            detail="MFA encryption key is not configured",
        )

    try:
        from cryptography.fernet import Fernet
        return Fernet(MFA_ENCRYPTION_KEY.encode("utf-8"))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="MFA encryption is unavailable",
        ) from exc


def encrypt_mfa_secret(secret: str) -> str:
    return _mfa_fernet().encrypt(
        secret.encode("utf-8")
    ).decode("ascii")


def decrypt_mfa_secret(encrypted: str) -> str:
    try:
        return _mfa_fernet().decrypt(
            encrypted.encode("ascii")
        ).decode("utf-8")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Stored MFA secret cannot be decrypted",
        ) from exc


# ===============================================================
# SYSTEM CONTROLS
# ===============================================================

def get_control(key: str) -> bool:
    row = fetch_one(
        "SELECT value FROM system_controls WHERE key = ?",
        (key,),
    )

    if not row:
        return False

    return str(row["value"]).strip().lower() == "true"


def set_control(key: str, enabled: bool) -> None:
    execute(
        """
        INSERT INTO system_controls (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        """,
        (
            key,
            "true" if enabled else "false",
            utc_iso(),
        ),
    )


def require_commerce() -> None:
    if not get_control("commerce_enabled"):
        raise HTTPException(
            status_code=503,
            detail="ARYA Commerce is disabled",
        )

    if get_control("maintenance_mode"):
        raise HTTPException(
            status_code=503,
            detail="ARYA Commerce is under maintenance",
        )


def require_payments() -> None:
    require_commerce()

    if not get_control("payments_enabled"):
        raise HTTPException(
            status_code=503,
            detail="Payments are disabled",
        )


# ===============================================================
# AUDIT LOG
# ===============================================================

def audit(
    action: str,
    actor_id: Optional[str] = None,
    actor_role: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    execute(
        """
        INSERT INTO audit_logs
        (
            actor_id, actor_role, action,
            target_type, target_id, ip_address,
            details_json, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            actor_id,
            actor_role,
            action,
            target_type,
            target_id,
            ip_address,
            json.dumps(
                details or {},
                ensure_ascii=False,
                default=str,
            ),
            utc_iso(),
        ),
    )


# ===============================================================
# AUTHENTICATION
# ===============================================================

def create_session(
    user_id: str,
    role: str,
) -> str:
    raw_token = secrets.token_urlsafe(48)
    token_hash = sha256_text(raw_token)

    execute(
        """
        INSERT INTO sessions
        (
            token_hash, user_id, role,
            expires_at, created_at, revoked
        )
        VALUES (?, ?, ?, ?, ?, 0)
        """,
        (
            token_hash,
            user_id,
            role,
            future_iso(SESSION_HOURS),
            utc_iso(),
        ),
    )

    return raw_token


def authenticate(
    credentials: Optional[HTTPAuthorizationCredentials],
) -> Dict[str, str]:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    token_hash = sha256_text(credentials.credentials)

    row = fetch_one(
        """
        SELECT user_id, role, expires_at, revoked
        FROM sessions
        WHERE token_hash = ?
        """,
        (token_hash,),
    )

    if not row or row["revoked"]:
        raise HTTPException(
            status_code=401,
            detail="Invalid session",
        )

    if not is_future(row["expires_at"]):
        raise HTTPException(
            status_code=401,
            detail="Session expired",
        )

    return {
        "user_id": str(row["user_id"]),
        "role": str(row["role"]),
    }


def owner_required(
    credentials: Optional[HTTPAuthorizationCredentials] =
        Depends(security),
) -> Dict[str, str]:
    identity = authenticate(credentials)

    if identity["role"] != "OWNER":
        raise HTTPException(
            status_code=403,
            detail="OWNER access required",
        )

    return identity


def user_required(
    credentials: Optional[HTTPAuthorizationCredentials] =
        Depends(security),
) -> Dict[str, str]:
    """
    Validates a session issued by this commerce service.

    Important: tokens issued by backend/main.py are not assumed
    to be valid commerce sessions. Integration with that service's
    actual token validator must be explicitly implemented before
    main.py-issued customer tokens can use these endpoints.
    """
    identity = authenticate(credentials)

    if identity["role"] == "OWNER":
        raise HTTPException(
            status_code=403,
            detail="A customer account is required",
        )

    return identity


def require_same_user(
    requested_user_id: str,
    identity: Dict[str, str],
) -> None:
    if not constant_compare(
        identity.get("user_id", ""),
        requested_user_id,
    ):
        raise HTTPException(
            status_code=403,
            detail="Access denied",
        )


# ===============================================================
# REQUEST MODELS
# ===============================================================

class OwnerLoginRequest(BaseModel):
    email: str
    secret: str
    mfa_code: Optional[str] = None


class BankAccountCreate(BaseModel):
    bank_name: str = Field(min_length=1, max_length=120)
    account_holder: str = Field(min_length=1, max_length=160)
    iban: str = Field(min_length=1, max_length=40)
    account_number: Optional[str] = None
    card_number: Optional[str] = None
    currency: str = "IRR"
    label: Optional[str] = None


class WalletCreate(BaseModel):
    network: str = Field(min_length=1, max_length=40)
    currency: str = "USDT"
    address: str = Field(min_length=20, max_length=200)
    label: Optional[str] = None


class PlanCreate(BaseModel):
    code: str = Field(min_length=2, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    market: str
    currency: str
    amount: float = Field(gt=0)
    max_users: Optional[int] = Field(default=None, gt=0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PaymentCreate(BaseModel):
    user_id: str = Field(min_length=1, max_length=200)
    plan_code: str
    method: str
    idempotency_key: str = Field(min_length=8, max_length=200)
    provider: Optional[str] = None
    network: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PaymentVerify(BaseModel):
    provider: str = Field(min_length=1, max_length=100)
    provider_reference: str = Field(min_length=1, max_length=250)
    observed_destination: Optional[str] = None
    verification_note: Optional[str] = None


class DeviceActivate(BaseModel):
    user_id: str = Field(min_length=1, max_length=200)
    device_id: str = Field(min_length=1, max_length=250)
    device_name: Optional[str] = None
    platform: Optional[str] = None


class ProviderCreate(BaseModel):
    provider_code: str = Field(min_length=1, max_length=100)
    provider_type: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=160)
    priority: int = 100
    config: Dict[str, Any] = Field(default_factory=dict)
    secret_ref: Optional[str] = None


class ControlUpdate(BaseModel):
    key: str
    enabled: bool


class MFASetupRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=200)
    secret: str = Field(min_length=16, max_length=128)
    verification_code: str = Field(min_length=6, max_length=6)


class MFAVerifyRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=200)
    code: str = Field(min_length=6, max_length=6)


class RecoveryCreate(BaseModel):
    user_id: str = Field(min_length=1, max_length=200)


# ===============================================================
# NORMALIZATION
# ===============================================================

def normalize_iban(iban: str) -> str:
    return (
        iban.replace(" ", "")
        .replace("-", "")
        .upper()
    )


def validate_iban(iban: str) -> bool:
    normalized = normalize_iban(iban)

    return (
        normalized.startswith("IR")
        and len(normalized) == 26
        and normalized[2:].isdigit()
    )


def validate_wallet_address(address: str) -> bool:
    clean = address.strip()
    return 20 <= len(clean) <= 200


# ===============================================================
# DEFAULT PLANS
# ===============================================================

def seed_default_plans() -> None:
    existing = fetch_one(
        "SELECT id FROM payment_plans LIMIT 1"
    )

    if existing:
        return

    plans = [
        ("IR_100", "Iran First 100", "IR", "IRR", 500000, 100),
        ("IR_500", "Iran Next 500", "IR", "IRR", 800000, 500),
        ("IR_STANDARD", "Iran Standard", "IR", "IRR", 1200000, None),
        ("INT_100", "International First 100", "INT", "USDT", 10, 100),
        ("INT_500", "International Next 500", "INT", "USDT", 15, 500),
        ("INT_STANDARD", "International Standard", "INT", "USDT", 20, None),
    ]

    conn = get_db()

    try:
        now = utc_iso()

        for plan in plans:
            conn.execute(
                """
                INSERT OR IGNORE INTO payment_plans
                (
                    code, name, market, currency,
                    amount, max_users, active,
                    metadata_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (*plan, "{}", now, now),
            )

        conn.commit()

    finally:
        conn.close()


# ===============================================================
# ACTIVE DESTINATION LOOKUPS
# ===============================================================

def get_active_bank_account(
    currency: str = "IRR",
) -> Optional[sqlite3.Row]:
    return fetch_one(
        """
        SELECT *
        FROM bank_accounts
        WHERE currency = ? AND active = 1
        ORDER BY id DESC
        LIMIT 1
        """,
        (currency,),
    )


def get_active_wallet(
    network: str,
    currency: str = "USDT",
) -> Optional[sqlite3.Row]:
    return fetch_one(
        """
        SELECT *
        FROM wallet_destinations
        WHERE network = ?
          AND currency = ?
          AND active = 1
        ORDER BY id DESC
        LIMIT 1
        """,
        (network, currency),
    )
 # ===============================================================
# OWNER LOGIN / LOGOUT
# ===============================================================

def get_security_user(user_id: str) -> Optional[sqlite3.Row]:
    return fetch_one(
        "SELECT * FROM security_users WHERE user_id = ?",
        (user_id,),
    )


def ensure_security_user(user_id: str) -> None:
    now = utc_iso()

    execute(
        """
        INSERT OR IGNORE INTO security_users
        (user_id, created_at, updated_at)
        VALUES (?, ?, ?)
        """,
        (user_id, now, now),
    )


def check_owner_lockout() -> None:
    row = get_security_user("OWNER")

    if row and is_future(row["locked_until"]):
        raise HTTPException(
            status_code=429,
            detail="OWNER login temporarily locked",
        )


def record_owner_login_failure() -> None:
    ensure_security_user("OWNER")

    row = get_security_user("OWNER")
    attempts = int(row["failed_attempts"] or 0) + 1

    locked_until = None

    if attempts >= 5:
        locked_until = (
            utc_now() + timedelta(minutes=15)
        ).isoformat()

    execute(
        """
        UPDATE security_users
        SET failed_attempts = ?,
            locked_until = ?,
            updated_at = ?
        WHERE user_id = 'OWNER'
        """,
        (attempts, locked_until, utc_iso()),
    )


def reset_owner_login_failures() -> None:
    ensure_security_user("OWNER")

    execute(
        """
        UPDATE security_users
        SET failed_attempts = 0,
            locked_until = NULL,
            updated_at = ?
        WHERE user_id = 'OWNER'
        """,
        (utc_iso(),),
    )


@app.post("/owner/login")
def owner_login(
    payload: OwnerLoginRequest,
    request: Request,
):
    if not OWNER_EMAIL or not OWNER_SECRET_HASH:
        raise HTTPException(
            status_code=503,
            detail="OWNER credentials are not configured",
        )

    check_owner_lockout()

    valid_email = constant_compare(
        payload.email.strip().lower(),
        OWNER_EMAIL.lower(),
    )

    valid_secret = verify_secret(
        payload.secret,
        OWNER_SECRET_HASH,
    )

    if not valid_email or not valid_secret:
        record_owner_login_failure()

        audit(
            "owner_login_failed",
            actor_id="OWNER",
            actor_role="OWNER",
            ip_address=request.client.host if request.client else None,
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    security_row = get_security_user("OWNER")

    if security_row and int(security_row["mfa_enabled"] or 0):
        if not payload.mfa_code:
            raise HTTPException(
                status_code=401,
                detail="MFA code required",
            )

        encrypted_secret = security_row["mfa_secret_encrypted"]

        if not encrypted_secret:
            raise HTTPException(
                status_code=503,
                detail="OWNER MFA configuration is incomplete",
            )

        secret = decrypt_mfa_secret(encrypted_secret)

        if not verify_totp(secret, payload.mfa_code):
            record_owner_login_failure()

            audit(
                "owner_mfa_failed",
                actor_id="OWNER",
                actor_role="OWNER",
                ip_address=request.client.host if request.client else None,
            )

            raise HTTPException(
                status_code=401,
                detail="Invalid MFA code",
            )

    reset_owner_login_failures()

    token = create_session("OWNER", "OWNER")

    audit(
        "owner_login_success",
        actor_id="OWNER",
        actor_role="OWNER",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_hours": SESSION_HOURS,
    }


@app.post("/owner/logout")
def owner_logout(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    identity: Dict[str, str] = Depends(owner_required),
):
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    execute(
        """
        UPDATE sessions
        SET revoked = 1
        WHERE token_hash = ?
        """,
        (sha256_text(credentials.credentials),),
    )

    audit(
        "owner_logout",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        ip_address=request.client.host if request.client else None,
    )

    return {"success": True}


# ===============================================================
# PUBLIC STATUS / HEALTH
# ===============================================================

@app.get("/")
def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
    }


@app.get("/health")
def health():
    try:
        fetch_one("SELECT 1")
        database_status = "ok"
    except Exception:
        database_status = "error"

    return {
        "status": "ok" if database_status == "ok" else "degraded",
        "database": database_status,
        "version": APP_VERSION,
    }


@app.get("/commerce/status")
def commerce_status():
    return {
        "commerce_enabled": get_control("commerce_enabled"),
        "payments_enabled": get_control("payments_enabled"),
        "bank_transfer_enabled": get_control("bank_transfer_enabled"),
        "crypto_payments_enabled": get_control("crypto_payments_enabled"),
        "maintenance_mode": get_control("maintenance_mode"),
    }


# ===============================================================
# BANK ACCOUNT MANAGEMENT
# ===============================================================

@app.post("/owner/bank-accounts")
def create_bank_account(
    payload: BankAccountCreate,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    if not validate_iban(payload.iban):
        raise HTTPException(
            status_code=400,
            detail="Invalid Iranian IBAN format",
        )

    currency = payload.currency.strip().upper()

    if currency != "IRR":
        raise HTTPException(
            status_code=400,
            detail="Bank transfer currency must be IRR",
        )

    conn = get_db()

    try:
        conn.execute("BEGIN IMMEDIATE")

        conn.execute(
            """
            UPDATE bank_accounts
            SET active = 0, disabled_at = ?
            WHERE active = 1 AND currency = ?
            """,
            (utc_iso(), currency),
        )

        cur = conn.execute(
            """
            INSERT INTO bank_accounts
            (
                bank_name, account_holder, iban,
                account_number, card_number, currency,
                label, active, effective_from, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                payload.bank_name.strip(),
                payload.account_holder.strip(),
                normalize_iban(payload.iban),
                payload.account_number,
                payload.card_number,
                currency,
                payload.label,
                utc_iso(),
                utc_iso(),
            ),
        )

        account_id = int(cur.lastrowid)
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    audit(
        "bank_account_created",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="bank_account",
        target_id=str(account_id),
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "account_id": account_id,
    }


@app.get("/owner/bank-accounts")
def list_bank_accounts(
    identity: Dict[str, str] = Depends(owner_required),
):
    rows = fetch_all(
        """
        SELECT *
        FROM bank_accounts
        ORDER BY id DESC
        """
    )

    return [dict(row) for row in rows]


@app.post("/owner/bank-accounts/{account_id}/disable")
def disable_bank_account(
    account_id: int,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    row = fetch_one(
        "SELECT id FROM bank_accounts WHERE id = ?",
        (account_id,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Bank account not found",
        )

    execute(
        """
        UPDATE bank_accounts
        SET active = 0, disabled_at = ?
        WHERE id = ?
        """,
        (utc_iso(), account_id),
    )

    audit(
        "bank_account_disabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="bank_account",
        target_id=str(account_id),
        ip_address=request.client.host if request.client else None,
    )

    return {"success": True}


@app.get("/commerce/payment-destinations/bank")
def public_bank_destinations():
    if not get_control("bank_transfer_enabled"):
        raise HTTPException(
            status_code=503,
            detail="Bank transfer payments are disabled",
        )

    rows = fetch_all(
        """
        SELECT id, bank_name, account_holder, iban,
               account_number, card_number, currency, label
        FROM bank_accounts
        WHERE active = 1
        ORDER BY id DESC
        """
    )

    return [dict(row) for row in rows]


# ===============================================================
# CRYPTO WALLET DESTINATION MANAGEMENT
# ===============================================================

@app.post("/owner/wallet-destinations")
def create_wallet_destination(
    payload: WalletCreate,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    if not validate_wallet_address(payload.address):
        raise HTTPException(
            status_code=400,
            detail="Invalid wallet address length",
        )

    currency = payload.currency.strip().upper()
    network = payload.network.strip().upper()

    if currency != "USDT":
        raise HTTPException(
            status_code=400,
            detail="Only USDT destinations are supported",
        )

    conn = get_db()

    try:
        conn.execute("BEGIN IMMEDIATE")

        conn.execute(
            """
            UPDATE wallet_destinations
            SET active = 0, disabled_at = ?
            WHERE active = 1
              AND currency = ?
              AND network = ?
            """,
            (utc_iso(), currency, network),
        )

        cur = conn.execute(
            """
            INSERT INTO wallet_destinations
            (
                network, currency, address, label,
                active, effective_from, created_at
            )
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (
                network,
                currency,
                payload.address.strip(),
                payload.label,
                utc_iso(),
                utc_iso(),
            ),
        )

        destination_id = int(cur.lastrowid)
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    audit(
        "wallet_destination_created",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="wallet_destination",
        target_id=str(destination_id),
        ip_address=request.client.host if request.client else None,
        details={"network": network, "currency": currency},
    )

    return {
        "success": True,
        "destination_id": destination_id,
    }


@app.get("/owner/wallet-destinations")
def list_wallet_destinations(
    identity: Dict[str, str] = Depends(owner_required),
):
    rows = fetch_all(
        """
        SELECT *
        FROM wallet_destinations
        ORDER BY id DESC
        """
    )

    return [dict(row) for row in rows]


@app.post("/owner/wallet-destinations/{destination_id}/disable")
def disable_wallet_destination(
    destination_id: int,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    row = fetch_one(
        "SELECT id FROM wallet_destinations WHERE id = ?",
        (destination_id,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Wallet destination not found",
        )

    execute(
        """
        UPDATE wallet_destinations
        SET active = 0, disabled_at = ?
        WHERE id = ?
        """,
        (utc_iso(), destination_id),
    )

    audit(
        "wallet_destination_disabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="wallet_destination",
        target_id=str(destination_id),
        ip_address=request.client.host if request.client else None,
    )

    return {"success": True}


@app.get("/commerce/payment-destinations/crypto")
def public_crypto_destinations():
    if not get_control("crypto_payments_enabled"):
        raise HTTPException(
            status_code=503,
            detail="Crypto payments are disabled",
        )

    rows = fetch_all(
        """
        SELECT id, network, currency, address, label
        FROM wallet_destinations
        WHERE active = 1
        ORDER BY id DESC
        """
    )

    return [dict(row) for row in rows]


# ===============================================================
# PAYMENT PLAN MANAGEMENT
# ===============================================================

@app.post("/owner/payment-plans")
def create_payment_plan(
    payload: PlanCreate,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    market = payload.market.strip().upper()
    currency = payload.currency.strip().upper()

    if market not in {"IR", "INT"}:
        raise HTTPException(
            status_code=400,
            detail="market must be IR or INT",
        )

    expected_currency = "IRR" if market == "IR" else "USDT"

    if currency != expected_currency:
        raise HTTPException(
            status_code=400,
            detail="Currency does not match market",
        )

    try:
        plan_id = execute(
            """
            INSERT INTO payment_plans
            (
                code, name, market, currency,
                amount, max_users, active,
                metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                payload.code.strip(),
                payload.name.strip(),
                market,
                currency,
                payload.amount,
                payload.max_users,
                json.dumps(payload.metadata, ensure_ascii=False),
                utc_iso(),
                utc_iso(),
            ),
        )

    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="Plan code already exists",
        ) from exc

    audit(
        "payment_plan_created",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="payment_plan",
        target_id=str(plan_id),
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "plan_id": plan_id,
    }


@app.get("/commerce/payment-plans")
def list_public_payment_plans(
    market: Optional[str] = None,
):
    if market:
        market = market.strip().upper()

        if market not in {"IR", "INT"}:
            raise HTTPException(
                status_code=400,
                detail="Invalid market",
            )

        rows = fetch_all(
            """
            SELECT code, name, market, currency,
                   amount, max_users, metadata_json
            FROM payment_plans
            WHERE active = 1 AND market = ?
            ORDER BY amount ASC
            """,
            (market,),
        )
    else:
        rows = fetch_all(
            """
            SELECT code, name, market, currency,
                   amount, max_users, metadata_json
            FROM payment_plans
            WHERE active = 1
            ORDER BY market, amount ASC
            """
        )

    result = []

    for row in rows:
        item = dict(row)
        item["metadata"] = safe_json_object(
            item.pop("metadata_json", None)
        )
        result.append(item)

    return result


@app.get("/owner/payment-plans")
def list_owner_payment_plans(
    identity: Dict[str, str] = Depends(owner_required),
):
    rows = fetch_all(
        """
        SELECT *
        FROM payment_plans
        ORDER BY id DESC
        """
    )

    result = []

    for row in rows:
        item = dict(row)
        item["metadata"] = safe_json_object(
            item.pop("metadata_json", None)
        )
        result.append(item)

    return result


@app.post("/owner/payment-plans/{plan_code}/disable")
def disable_payment_plan(
    plan_code: str,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    row = fetch_one(
        "SELECT code FROM payment_plans WHERE code = ?",
        (plan_code,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Payment plan not found",
        )

    execute(
        """
        UPDATE payment_plans
        SET active = 0, updated_at = ?
        WHERE code = ?
        """,
        (utc_iso(), plan_code),
    )

    audit(
        "payment_plan_disabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="payment_plan",
        target_id=plan_code,
        ip_address=request.client.host if request.client else None,
    )

    return {"success": True}


# ===============================================================
# PAYMENT CREATION HELPERS
# ===============================================================

def get_existing_idempotent_payment(
    user_id: str,
    idempotency_key: str,
) -> Optional[sqlite3.Row]:
    return fetch_one(
        """
        SELECT *
        FROM payment_transactions
        WHERE user_id = ? AND idempotency_key = ?
        """,
        (user_id, idempotency_key),
    )


def serialize_payment(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["metadata"] = safe_json_object(
        item.pop("metadata_json", None)
    )
    item["destination"] = safe_json_object(
        item.pop("destination_snapshot", None)
    )
    return item


def get_active_plan_in_transaction(
    conn: sqlite3.Connection,
    plan_code: str,
) -> sqlite3.Row:
    row = conn.execute(
        """
        SELECT *
        FROM payment_plans
        WHERE code = ? AND active = 1
        """,
        (plan_code,),
    ).fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Active payment plan not found",
        )

    return row


def get_destination_snapshot(
    conn: sqlite3.Connection,
    method: str,
    network: Optional[str],
    currency: str,
) -> tuple:
    if method == "BANK_TRANSFER":
        row = conn.execute(
            """
            SELECT *
            FROM bank_accounts
            WHERE active = 1 AND currency = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (currency,),
        ).fetchone()

        if not row:
            raise HTTPException(
                status_code=503,
                detail="No active bank destination",
            )

        snapshot = {
            "id": row["id"],
            "bank_name": row["bank_name"],
            "account_holder": row["account_holder"],
            "iban": row["iban"],
            "account_number": row["account_number"],
            "card_number": row["card_number"],
            "currency": row["currency"],
            "label": row["label"],
        }

        return "BANK_ACCOUNT", int(row["id"]), snapshot

    if method == "CRYPTO":
        if not network:
            raise HTTPException(
                status_code=400,
                detail="Crypto network is required",
            )

        row = conn.execute(
            """
            SELECT *
            FROM wallet_destinations
            WHERE active = 1
              AND currency = ?
              AND network = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (currency, network.strip().upper()),
        ).fetchone()

        if not row:
            raise HTTPException(
                status_code=503,
                detail="No active wallet destination for this network",
            )

        snapshot = {
            "id": row["id"],
            "network": row["network"],
            "currency": row["currency"],
            "address": row["address"],
            "label": row["label"],
        }

        return "WALLET", int(row["id"]), snapshot

    raise HTTPException(
        status_code=400,
        detail="Unsupported payment method",
    )


# ===============================================================
# CUSTOMER PAYMENT CREATION
# ===============================================================

@app.post("/commerce/payments/create")
def create_payment(
    payload: PaymentCreate,
    request: Request,
    identity: Dict[str, str] = Depends(user_required),
):
    require_payments()

    require_same_user(
        payload.user_id,
        identity,
    )

    method = payload.method.strip().upper()

    if method == "BANK_TRANSFER" and not get_control(
        "bank_transfer_enabled"
    ):
        raise HTTPException(
            status_code=503,
            detail="Bank transfer payments are disabled",
        )

    if method == "CRYPTO" and not get_control(
        "crypto_payments_enabled"
    ):
        raise HTTPException(
            status_code=503,
            detail="Crypto payments are disabled",
        )

    if not re.fullmatch(
        r"[A-Za-z0-9._:-]{8,200}",
        payload.idempotency_key,
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid idempotency key",
        )

    conn = get_db()
    payment_row = None

    try:
        conn.execute("BEGIN IMMEDIATE")

        existing = conn.execute(
            """
            SELECT *
            FROM payment_transactions
            WHERE user_id = ? AND idempotency_key = ?
            """,
            (identity["user_id"], payload.idempotency_key),
        ).fetchone()

        if existing:
            conn.commit()
            payment_row = existing

        else:
            plan = get_active_plan_in_transaction(
                conn,
                payload.plan_code,
            )

            expected_method = (
                "BANK_TRANSFER"
                if plan["market"] == "IR"
                else "CRYPTO"
            )

            if method != expected_method:
                raise HTTPException(
                    status_code=400,
                    detail="Payment method does not match plan market",
                )

            if plan["market"] == "IR":
                if plan["currency"] != "IRR":
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid domestic plan currency",
                    )
            elif plan["currency"] != "USDT":
                raise HTTPException(
                    status_code=400,
                    detail="Invalid international plan currency",
                )

            destination_type, destination_id, snapshot = (
                get_destination_snapshot(
                    conn,
                    method,
                    payload.network,
                    plan["currency"],
                )
            )

            transaction_id = random_id("pay")
            created_at = utc_iso()
            expires_at = future_iso(PAYMENT_EXPIRY_HOURS)

            conn.execute(
                """
                INSERT INTO payment_transactions
                (
                    transaction_id, user_id, plan_code,
                    market, method, currency, amount,
                    status, destination_type, destination_id,
                    destination_snapshot, provider,
                    provider_reference, idempotency_key,
                    metadata_json, created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING',
                        ?, ?, ?, ?, NULL, ?, ?, ?, ?)
                """,
                (
                    transaction_id,
                    identity["user_id"],
                    plan["code"],
                    plan["market"],
                    method,
                    plan["currency"],
                    plan["amount"],
                    destination_type,
                    destination_id,
                    json.dumps(snapshot, ensure_ascii=False),
                    payload.provider,
                    payload.idempotency_key,
                    json.dumps(payload.metadata, ensure_ascii=False),
                    created_at,
                    expires_at,
                ),
            )

            payment_row = conn.execute(
                """
                SELECT *
                FROM payment_transactions
                WHERE transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()

            conn.commit()

    except HTTPException:
        conn.rollback()
        raise

    except sqlite3.IntegrityError as exc:
        conn.rollback()

        existing = get_existing_idempotent_payment(
            identity["user_id"],
            payload.idempotency_key,
        )

        if existing:
            payment_row = existing
        else:
            raise HTTPException(
                status_code=409,
                detail="Payment creation conflict",
            ) from exc

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    if payment_row is None:
        raise HTTPException(
            status_code=500,
            detail="Unable to create payment",
        )

    audit(
        "payment_created_or_reused",
        actor_id=identity["user_id"],
        actor_role=identity["role"],
        target_type="payment",
        target_id=str(payment_row["transaction_id"]),
        ip_address=request.client.host if request.client else None,
    )

    return serialize_payment(payment_row)


# ===============================================================
# PAYMENT DETAILS / OWNER REVIEW
# ===============================================================

@app.get("/commerce/payments/{transaction_id}")
def get_customer_payment(
    transaction_id: str,
    identity: Dict[str, str] = Depends(user_required),
):
    row = fetch_one(
        """
        SELECT *
        FROM payment_transactions
        WHERE transaction_id = ?
        """,
        (transaction_id,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Payment not found",
        )

    require_same_user(row["user_id"], identity)

    return serialize_payment(row)


@app.get("/owner/payments")
def list_payments(
    status: Optional[str] = None,
    limit: int = 100,
    identity: Dict[str, str] = Depends(owner_required),
):
    limit = max(1, min(int(limit), 500))

    if status:
        rows = fetch_all(
            """
            SELECT *
            FROM payment_transactions
            WHERE status = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (status.strip().upper(), limit),
        )
    else:
        rows = fetch_all(
            """
            SELECT *
            FROM payment_transactions
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

    return [serialize_payment(row) for row in rows]


def activate_subscription(
    conn: sqlite3.Connection,
    transaction: sqlite3.Row,
) -> sqlite3.Row:
    existing = conn.execute(
        """
        SELECT *
        FROM subscriptions
        WHERE source_transaction_id = ?
        """,
        (transaction["transaction_id"],),
    ).fetchone()

    if existing:
        return existing

    now = utc_now()
    subscription_id = random_id("sub")

    cur = conn.execute(
        """
        INSERT INTO subscriptions
        (
            subscription_id, user_id, plan_code,
            status, starts_at, expires_at,
            source_transaction_id, created_at, updated_at
        )
        VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
        """,
        (
            subscription_id,
            transaction["user_id"],
            transaction["plan_code"],
            now.isoformat(),
            (now + timedelta(days=SUBSCRIPTION_DAYS)).isoformat(),
            transaction["transaction_id"],
            now.isoformat(),
            now.isoformat(),
        ),
    )

    return conn.execute(
        """
        SELECT *
        FROM subscriptions
        WHERE id = ?
        """,
        (cur.lastrowid,),
    ).fetchone()


@app.post("/owner/payments/{transaction_id}/verify")
def verify_payment(
    transaction_id: str,
    payload: PaymentVerify,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    provider_reference = payload.provider_reference.strip()

    if not provider_reference:
        raise HTTPException(
            status_code=400,
            detail="Provider reference is required",
        )

    conn = get_db()
    subscription = None
    result_status = None

    try:
        conn.execute("BEGIN IMMEDIATE")

        transaction = conn.execute(
            """
            SELECT *
            FROM payment_transactions
            WHERE transaction_id = ?
            """,
            (transaction_id,),
        ).fetchone()

        if not transaction:
            raise HTTPException(
                status_code=404,
                detail="Payment not found",
            )

        if transaction["status"] == "VERIFIED":
            subscription = conn.execute(
                """
                SELECT *
                FROM subscriptions
                WHERE source_transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()

            conn.commit()

            return {
                "success": True,
                "status": "VERIFIED",
                "already_verified": True,
                "subscription": dict(subscription) if subscription else None,
            }

        if transaction["status"] != "PENDING":
            raise HTTPException(
                status_code=409,
                detail=f"Payment status is {transaction['status']}",
            )

        if not is_future(transaction["expires_at"]):
            conn.execute(
                """
                UPDATE payment_transactions
                SET status = 'EXPIRED'
                WHERE transaction_id = ?
                """,
                (transaction_id,),
            )

            conn.execute(
                """
                INSERT INTO payment_events
                (
                    transaction_id, event_type, event_id,
                    payload_hash, created_at
                )
                VALUES (?, 'EXPIRED', ?, NULL, ?)
                """,
                (
                    transaction_id,
                    random_id("evt"),
                    utc_iso(),
                ),
            )

            conn.commit()
            result_status = "EXPIRED"

        else:
            if payload.observed_destination:
                snapshot = safe_json_object(
                    transaction["destination_snapshot"]
                )

                expected_destination = (
                    snapshot.get("address")
                    if transaction["destination_type"] == "WALLET"
                    else snapshot.get("iban")
                )

                if (
                    expected_destination
                    and not constant_compare(
                        str(payload.observed_destination).strip(),
                        str(expected_destination).strip(),
                    )
                ):
                    raise HTTPException(
                        status_code=400,
                        detail="Observed destination does not match payment",
                    )

            conn.execute(
                """
                UPDATE payment_transactions
                SET status = 'VERIFIED',
                    provider = ?,
                    provider_reference = ?,
                    verified_at = ?
                WHERE transaction_id = ?
                """,
                (
                    payload.provider.strip(),
                    provider_reference,
                    utc_iso(),
                    transaction_id,
                ),
            )

            conn.execute(
                """
                INSERT INTO payment_events
                (
                    transaction_id, event_type, event_id,
                    payload_hash, created_at
                )
                VALUES (?, 'VERIFIED', ?, ?, ?)
                """,
                (
                    transaction_id,
                    random_id("evt"),
                    sha256_text(
                        json.dumps(
                            {
                                "provider": payload.provider,
                                "reference": provider_reference,
                                "note": payload.verification_note,
                            },
                            sort_keys=True,
                        )
                    ),
                    utc_iso(),
                ),
            )

            updated_transaction = conn.execute(
                """
                SELECT *
                FROM payment_transactions
                WHERE transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()

            subscription = activate_subscription(
                conn,
                updated_transaction,
            )

            conn.commit()
            result_status = "VERIFIED"

    except HTTPException:
        conn.rollback()
        raise

    except sqlite3.IntegrityError as exc:
        conn.rollback()

        raise HTTPException(
            status_code=409,
            detail="Payment verification conflict",
        ) from exc

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    audit(
        "payment_verification_processed",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="payment",
        target_id=transaction_id,
        ip_address=request.client.host if request.client else None,
        details={"status": result_status},
    )

    return {
        "success": result_status == "VERIFIED",
        "status": result_status,
        "subscription": dict(subscription) if subscription else None,
    } 
 
 # ===============================================================
# CUSTOMER SUBSCRIPTIONS
# ===============================================================

@app.get("/commerce/subscriptions/{user_id}")
def list_user_subscriptions(
    user_id: str,
    identity: Dict[str, str] = Depends(user_required),
):
    require_same_user(user_id, identity)

    rows = fetch_all(
        """
        SELECT *
        FROM subscriptions
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,),
    )

    return [dict(row) for row in rows]


@app.get("/owner/subscriptions")
def list_all_subscriptions(
    user_id: Optional[str] = None,
    limit: int = 100,
    identity: Dict[str, str] = Depends(owner_required),
):
    limit = max(1, min(int(limit), 500))

    if user_id:
        rows = fetch_all(
            """
            SELECT *
            FROM subscriptions
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, limit),
        )
    else:
        rows = fetch_all(
            """
            SELECT *
            FROM subscriptions
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

    return [dict(row) for row in rows]


# ===============================================================
# DEVICE ACTIVATION
# ===============================================================

@app.post("/commerce/devices/activate")
def activate_device(
    payload: DeviceActivate,
    request: Request,
    identity: Dict[str, str] = Depends(user_required),
):
    require_commerce()
    require_same_user(payload.user_id, identity)

    if not get_control("new_device_activation_enabled"):
        raise HTTPException(
            status_code=503,
            detail="New device activation is disabled",
        )

    device_id = payload.device_id.strip()

    if not device_id or len(device_id) > 250:
        raise HTTPException(
            status_code=400,
            detail="Invalid device ID",
        )

    conn = get_db()

    try:
        conn.execute("BEGIN IMMEDIATE")

        now = utc_now().isoformat()

        subscription = conn.execute(
            """
            SELECT *
            FROM subscriptions
            WHERE user_id = ?
              AND status = 'ACTIVE'
              AND expires_at > ?
            ORDER BY expires_at DESC
            LIMIT 1
            """,
            (identity["user_id"], now),
        ).fetchone()

        if not subscription:
            raise HTTPException(
                status_code=403,
                detail="An active subscription is required",
            )

        existing_device = conn.execute(
            """
            SELECT *
            FROM devices
            WHERE user_id = ? AND device_id = ?
            """,
            (identity["user_id"], device_id),
        ).fetchone()

        if existing_device:
            conn.execute(
                """
                UPDATE devices
                SET active = 1,
                    device_name = ?,
                    platform = ?,
                    last_seen_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (
                    payload.device_name,
                    payload.platform,
                    now,
                    existing_device["id"],
                    identity["user_id"],
                ),
            )

            device_row = conn.execute(
                """
                SELECT *
                FROM devices
                WHERE id = ?
                """,
                (existing_device["id"],),
            ).fetchone()

            conn.commit()

            return {
                "success": True,
                "device": dict(device_row),
                "already_registered": True,
            }

        active_count_row = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM devices
            WHERE user_id = ? AND active = 1
            """,
            (identity["user_id"],),
        ).fetchone()

        active_count = int(active_count_row["total"])

        control_row = conn.execute(
            """
            SELECT value
            FROM system_controls
            WHERE key = 'device_limit'
            """
        ).fetchone()

        try:
            device_limit = (
                int(control_row["value"])
                if control_row
                else DEFAULT_DEVICE_LIMIT
            )
        except (TypeError, ValueError):
            device_limit = DEFAULT_DEVICE_LIMIT

        device_limit = max(1, device_limit)

        if active_count >= device_limit:
            raise HTTPException(
                status_code=403,
                detail={
                    "message": "Device limit reached",
                    "device_limit": device_limit,
                    "active_devices": active_count,
                },
            )

        conn.execute(
            """
            INSERT INTO devices
            (
                device_id, user_id, device_name,
                platform, active, first_seen_at, last_seen_at
            )
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (
                device_id,
                identity["user_id"],
                payload.device_name,
                payload.platform,
                now,
                now,
            ),
        )

        device_row = conn.execute(
            """
            SELECT *
            FROM devices
            WHERE user_id = ? AND device_id = ?
            """,
            (identity["user_id"], device_id),
        ).fetchone()

        conn.commit()

    except HTTPException:
        conn.rollback()
        raise

    except sqlite3.IntegrityError as exc:
        conn.rollback()

        raise HTTPException(
            status_code=409,
            detail="Device registration conflict",
        ) from exc

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    audit(
        "device_activated",
        actor_id=identity["user_id"],
        actor_role=identity["role"],
        target_type="device",
        target_id=device_id,
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "device": dict(device_row),
        "already_registered": False,
    }


@app.get("/commerce/devices/{user_id}")
def list_user_devices(
    user_id: str,
    identity: Dict[str, str] = Depends(user_required),
):
    require_same_user(user_id, identity)

    rows = fetch_all(
        """
        SELECT *
        FROM devices
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,),
    )

    return [dict(row) for row in rows]


@app.get("/owner/devices")
def list_all_devices(
    user_id: Optional[str] = None,
    limit: int = 200,
    identity: Dict[str, str] = Depends(owner_required),
):
    limit = max(1, min(int(limit), 1000))

    if user_id:
        rows = fetch_all(
            """
            SELECT *
            FROM devices
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, limit),
        )
    else:
        rows = fetch_all(
            """
            SELECT *
            FROM devices
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

    return [dict(row) for row in rows]


@app.post("/owner/devices/{device_id}/disable")
def disable_device(
    device_id: str,
    request: Request,
    user_id: Optional[str] = None,
    identity: Dict[str, str] = Depends(owner_required),
):
    if user_id:
        row = fetch_one(
            """
            SELECT id, user_id, device_id
            FROM devices
            WHERE device_id = ? AND user_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (device_id, user_id),
        )
    else:
        matches = fetch_all(
            """
            SELECT id, user_id, device_id
            FROM devices
            WHERE device_id = ? AND active = 1
            ORDER BY id DESC
            """,
            (device_id,),
        )

        if len(matches) > 1:
            raise HTTPException(
                status_code=409,
                detail="Multiple devices match; provide user_id",
            )

        row = matches[0] if matches else None

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Active device not found",
        )

    execute(
        """
        UPDATE devices
        SET active = 0
        WHERE id = ?
        """,
        (row["id"],),
    )

    audit(
        "device_disabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="device",
        target_id=str(row["device_id"]),
        ip_address=request.client.host if request.client else None,
        details={"user_id": row["user_id"]},
    )

    return {
        "success": True,
        "device_id": row["device_id"],
        "user_id": row["user_id"],
    }


@app.post("/owner/devices/{device_id}/enable")
def enable_device(
    device_id: str,
    request: Request,
    user_id: str,
    identity: Dict[str, str] = Depends(owner_required),
):
    conn = get_db()

    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT *
            FROM devices
            WHERE device_id = ? AND user_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (device_id, user_id),
        ).fetchone()

        if not row:
            raise HTTPException(
                status_code=404,
                detail="Device not found",
            )

        if not int(row["active"]):
            count_row = conn.execute(
                """
                SELECT COUNT(*) AS total
                FROM devices
                WHERE user_id = ? AND active = 1
                """,
                (user_id,),
            ).fetchone()

            limit_row = conn.execute(
                """
                SELECT value
                FROM system_controls
                WHERE key = 'device_limit'
                """
            ).fetchone()

            try:
                limit = (
                    int(limit_row["value"])
                    if limit_row
                    else DEFAULT_DEVICE_LIMIT
                )
            except (ValueError, TypeError):
                limit = DEFAULT_DEVICE_LIMIT

            if int(count_row["total"]) >= max(1, limit):
                raise HTTPException(
                    status_code=403,
                    detail="Device limit reached",
                )

            conn.execute(
                "UPDATE devices SET active = 1 WHERE id = ?",
                (row["id"],),
            )

        conn.commit()

    except HTTPException:
        conn.rollback()
        raise

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    audit(
        "device_enabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="device",
        target_id=device_id,
        ip_address=request.client.host if request.client else None,
        details={"user_id": user_id},
    )

    return {"success": True}


# ===============================================================
# OWNER MFA SETUP / DISABLE
# ===============================================================

@app.post("/owner/mfa/setup")
def setup_owner_mfa(
    payload: MFASetupRequest,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    if payload.user_id != "OWNER":
        raise HTTPException(
            status_code=403,
            detail="MFA setup is restricted to OWNER",
        )

    if not re.fullmatch(r"\d{6}", payload.verification_code):
        raise HTTPException(
            status_code=400,
            detail="Invalid verification code format",
        )

    try:
        normalize_base32_secret(payload.secret)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid TOTP secret",
        ) from exc

    if not verify_totp(payload.secret, payload.verification_code):
        raise HTTPException(
            status_code=400,
            detail="MFA verification failed",
        )

    encrypted_secret = encrypt_mfa_secret(payload.secret)

    ensure_security_user("OWNER")

    execute(
        """
        UPDATE security_users
        SET mfa_secret_encrypted = ?,
            mfa_enabled = 1,
            updated_at = ?
        WHERE user_id = 'OWNER'
        """,
        (encrypted_secret, utc_iso()),
    )

    audit(
        "owner_mfa_enabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="security_user",
        target_id="OWNER",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "mfa_enabled": True,
    }


@app.post("/owner/mfa/disable")
def disable_owner_mfa(
    payload: MFAVerifyRequest,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    if payload.user_id != "OWNER":
        raise HTTPException(
            status_code=403,
            detail="MFA disable is restricted to OWNER",
        )

    row = get_security_user("OWNER")

    if not row or not int(row["mfa_enabled"] or 0):
        raise HTTPException(
            status_code=400,
            detail="OWNER MFA is not enabled",
        )

    encrypted_secret = row["mfa_secret_encrypted"]

    if not encrypted_secret:
        raise HTTPException(
            status_code=503,
            detail="OWNER MFA configuration is incomplete",
        )

    secret = decrypt_mfa_secret(encrypted_secret)

    if not verify_totp(secret, payload.code):
        raise HTTPException(
            status_code=401,
            detail="Invalid MFA code",
        )

    execute(
        """
        UPDATE security_users
        SET mfa_enabled = 0,
            mfa_secret_encrypted = NULL,
            updated_at = ?
        WHERE user_id = 'OWNER'
        """,
        (utc_iso(),),
    )

    audit(
        "owner_mfa_disabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="security_user",
        target_id="OWNER",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "mfa_enabled": False,
    }


@app.get("/owner/mfa/status")
def owner_mfa_status(
    identity: Dict[str, str] = Depends(owner_required),
):
    row = get_security_user("OWNER")

    return {
        "mfa_enabled": bool(
            row and int(row["mfa_enabled"] or 0)
        ),
        "encryption_key_configured": bool(MFA_ENCRYPTION_KEY),
    }


# ===============================================================
# OWNER RECOVERY TOKENS
# ===============================================================

@app.post("/owner/recovery/create")
def create_owner_recovery_token(
    payload: RecoveryCreate,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    if payload.user_id != "OWNER":
        raise HTTPException(
            status_code=403,
            detail="Recovery tokens are restricted to OWNER",
        )

    raw_token = secrets.token_urlsafe(40)
    token_hash = sha256_text(raw_token)

    execute(
        """
        INSERT INTO recovery_tokens
        (
            user_id, token_hash, expires_at,
            used, created_at
        )
        VALUES ('OWNER', ?, ?, 0, ?)
        """,
        (
            token_hash,
            future_iso(RECOVERY_HOURS),
            utc_iso(),
        ),
    )

    audit(
        "owner_recovery_token_created",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="recovery_token",
        target_id=sha256_text(raw_token)[:16],
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "recovery_token": raw_token,
        "expires_in_hours": RECOVERY_HOURS,
        "warning": (
            "Store this token securely. It is shown only once. "
            "A complete recovery-validation flow must be implemented "
            "before this token can recover an account."
        ),
    }


# ===============================================================
# PROVIDER SECRET DETECTION
# ===============================================================

SENSITIVE_CONFIG_KEYS = {
    "secret",
    "password",
    "privatekey",
    "apikey",
    "token",
    "accesstoken",
    "accesskey",
    "clientsecret",
    "authorization",
    "credential",
    "credentials",
    "mnemonic",
    "seedphrase",
}


def normalized_key(value: str) -> str:
    return re.sub(
        r"[^a-z0-9]",
        "",
        value.lower(),
    )


def find_sensitive_config_keys(
    value: Any,
    path: str = "",
) -> List[str]:
    found: List[str] = []

    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            normalized = normalized_key(key_text)

            sensitive = (
                normalized in SENSITIVE_CONFIG_KEYS
                or normalized.endswith("secret")
                or normalized.endswith("password")
                or normalized.endswith("privatekey")
                or normalized.endswith("apikey")
                or normalized.endswith("accesstoken")
                or normalized.endswith("accesskey")
            )

            child_path = (
                f"{path}.{key_text}"
                if path
                else key_text
            )

            if sensitive:
                found.append(child_path)
            else:
                found.extend(
                    find_sensitive_config_keys(
                        child,
                        child_path,
                    )
                )

    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(
                find_sensitive_config_keys(
                    child,
                    f"{path}[{index}]",
                )
            )

    return found


# ===============================================================
# PROVIDER MANAGEMENT
# ===============================================================

@app.post("/owner/providers")
def create_provider(
    payload: ProviderCreate,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    sensitive_keys = find_sensitive_config_keys(payload.config)

    if sensitive_keys:
        raise HTTPException(
            status_code=400,
            detail={
                "message": (
                    "Sensitive values must not be stored directly "
                    "in provider config. Use secret_ref."
                ),
                "sensitive_fields": sensitive_keys,
            },
        )

    now = utc_iso()

    try:
        provider_id = execute(
            """
            INSERT INTO providers
            (
                provider_code, provider_type, name,
                active, priority, config_json, secret_ref,
                created_at, updated_at
            )
            VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
            """,
            (
                payload.provider_code.strip(),
                payload.provider_type.strip(),
                payload.name.strip(),
                payload.priority,
                json.dumps(payload.config, ensure_ascii=False),
                payload.secret_ref,
                now,
                now,
            ),
        )

    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="Provider code already exists",
        ) from exc

    audit(
        "provider_created",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="provider",
        target_id=str(provider_id),
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "provider_id": provider_id,
    }


@app.get("/owner/providers")
def list_providers(
    identity: Dict[str, str] = Depends(owner_required),
):
    rows = fetch_all(
        """
        SELECT id, provider_code, provider_type, name,
               active, priority, config_json,
               created_at, updated_at
        FROM providers
        ORDER BY priority ASC, id DESC
        """
    )

    result = []

    for row in rows:
        item = dict(row)
        item["config"] = safe_json_object(
            item.pop("config_json", None)
        )
        result.append(item)

    return result


@app.post("/owner/providers/{provider_code}/disable")
def disable_provider(
    provider_code: str,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    row = fetch_one(
        """
        SELECT provider_code
        FROM providers
        WHERE provider_code = ?
        """,
        (provider_code,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Provider not found",
        )

    execute(
        """
        UPDATE providers
        SET active = 0, updated_at = ?
        WHERE provider_code = ?
        """,
        (utc_iso(), provider_code),
    )

    audit(
        "provider_disabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="provider",
        target_id=provider_code,
        ip_address=request.client.host if request.client else None,
    )

    return {"success": True}


@app.post("/owner/providers/{provider_code}/enable")
def enable_provider(
    provider_code: str,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    row = fetch_one(
        """
        SELECT provider_code
        FROM providers
        WHERE provider_code = ?
        """,
        (provider_code,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Provider not found",
        )

    execute(
        """
        UPDATE providers
        SET active = 1, updated_at = ?
        WHERE provider_code = ?
        """,
        (utc_iso(), provider_code),
    )

    audit(
        "provider_enabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="provider",
        target_id=provider_code,
        ip_address=request.client.host if request.client else None,
    )

    return {"success": True}


# ===============================================================
# OWNER SYSTEM CONTROLS / EMERGENCY SWITCHES
# ===============================================================

ALLOWED_CONTROL_KEYS = {
    "commerce_enabled",
    "payments_enabled",
    "crypto_payments_enabled",
    "bank_transfer_enabled",
    "new_device_activation_enabled",
    "maintenance_mode",
}


@app.get("/owner/controls")
def list_controls(
    identity: Dict[str, str] = Depends(owner_required),
):
    rows = fetch_all(
        """
        SELECT key, value, updated_at
        FROM system_controls
        ORDER BY key
        """
    )

    result = []

    for row in rows:
        item = dict(row)

        if item["key"] == "device_limit":
            try:
                item["value"] = int(item["value"])
            except (TypeError, ValueError):
                item["value"] = DEFAULT_DEVICE_LIMIT
        else:
            item["value"] = str(item["value"]).lower() == "true"

        result.append(item)

    return result


@app.post("/owner/controls")
def update_control(
    payload: ControlUpdate,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    if payload.key not in ALLOWED_CONTROL_KEYS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported control key",
        )

    set_control(payload.key, payload.enabled)

    audit(
        "system_control_updated",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="system_control",
        target_id=payload.key,
        ip_address=request.client.host if request.client else None,
        details={"enabled": payload.enabled},
    )

    return {
        "success": True,
        "key": payload.key,
        "enabled": payload.enabled,
    }


@app.post("/owner/emergency/disable-commerce")
def emergency_disable_commerce(
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    set_control("commerce_enabled", False)
    set_control("payments_enabled", False)
    set_control("new_device_activation_enabled", False)

    audit(
        "emergency_commerce_disabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="system",
        target_id="commerce",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "commerce_enabled": False,
        "payments_enabled": False,
        "new_device_activation_enabled": False,
    }


@app.post("/owner/emergency/enable-commerce")
def emergency_enable_commerce(
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    set_control("commerce_enabled", True)
    set_control("payments_enabled", True)
    set_control("new_device_activation_enabled", True)

    audit(
        "emergency_commerce_enabled",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="system",
        target_id="commerce",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "success": True,
        "commerce_enabled": True,
        "payments_enabled": True,
        "new_device_activation_enabled": True,
    }


@app.post("/owner/kill-switch")
def kill_switch(
    enabled: bool = True,
    request: Request = None,
    identity: Dict[str, str] = Depends(owner_required),
):
    set_control("maintenance_mode", enabled)

    if enabled:
        set_control("payments_enabled", False)
        set_control("new_device_activation_enabled", False)

    audit(
        "kill_switch_updated",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="system",
        target_id="kill_switch",
        ip_address=(
            request.client.host
            if request and request.client
            else None
        ),
        details={"enabled": enabled},
    )

    return {
        "success": True,
        "maintenance_mode": enabled,
    }


@app.post("/owner/device-limit")
def set_device_limit(
    limit: int,
    request: Request,
    identity: Dict[str, str] = Depends(owner_required),
):
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Device limit must be between 1 and 100",
        )

    execute(
        """
        INSERT INTO system_controls (key, value, updated_at)
        VALUES ('device_limit', ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        """,
        (str(limit), utc_iso()),
    )

    audit(
        "device_limit_updated",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="system_control",
        target_id="device_limit",
        ip_address=request.client.host if request.client else None,
        details={"limit": limit},
    )

    return {
        "success": True,
        "device_limit": limit,
    }


# ===============================================================
# PAYMENT HISTORY / EVENTS
# ===============================================================

@app.get("/owner/payments/{transaction_id}/events")
def list_payment_events(
    transaction_id: str,
    identity: Dict[str, str] = Depends(owner_required),
):
    transaction = fetch_one(
        """
        SELECT transaction_id
        FROM payment_transactions
        WHERE transaction_id = ?
        """,
        (transaction_id,),
    )

    if not transaction:
        raise HTTPException(
            status_code=404,
            detail="Payment not found",
        )

    rows = fetch_all(
        """
        SELECT *
        FROM payment_events
        WHERE transaction_id = ?
        ORDER BY id DESC
        """,
        (transaction_id,),
    )

    return [dict(row) for row in rows]


@app.get("/owner/audit")
def list_audit_logs(
    limit: int = 100,
    action: Optional[str] = None,
    identity: Dict[str, str] = Depends(owner_required),
):
    limit = max(1, min(int(limit), MAX_AUDIT_LIMIT))

    if action:
        rows = fetch_all(
            """
            SELECT *
            FROM audit_logs
            WHERE action = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (action, limit),
        )
    else:
        rows = fetch_all(
            """
            SELECT *
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

    result = []

    for row in rows:
        item = dict(row)
        item["details"] = safe_json_object(
            item.pop("details_json", None)
        )
        result.append(item)

    return result


# ===============================================================
# PAYMENT WEBHOOK
# ===============================================================

@app.post("/commerce/webhook")
async def payment_webhook(
    request: Request,
    x_arya_signature: Optional[str] = Header(default=None),
):
    if not PAYMENT_WEBHOOK_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Webhook secret is not configured",
        )

    body = await request.body()

    if len(body) > 1_000_000:
        raise HTTPException(
            status_code=413,
            detail="Webhook payload too large",
        )

    if not x_arya_signature:
        raise HTTPException(
            status_code=401,
            detail="Missing webhook signature",
        )

    supplied_signature = x_arya_signature.strip()

    if supplied_signature.lower().startswith("sha256="):
        supplied_signature = supplied_signature[7:]

    expected_signature = hmac.new(
        PAYMENT_WEBHOOK_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(
        expected_signature,
        supplied_signature,
    ):
        audit(
            "webhook_signature_failed",
            actor_id="WEBHOOK",
            actor_role="SYSTEM",
            ip_address=request.client.host if request.client else None,
            details={"payload_hash": sha256_text(body.decode("utf-8", errors="replace"))},
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid webhook signature",
        )

    payload_hash = sha256_text(
        body.decode("utf-8", errors="replace")
    )

    audit(
        "webhook_received",
        actor_id="WEBHOOK",
        actor_role="SYSTEM",
        ip_address=request.client.host if request.client else None,
        details={"payload_hash": payload_hash},
    )

    # A valid signature authenticates the sender only.
    # This endpoint intentionally does not settle payments.
    # Payment verification still requires the OWNER verification route
    # until provider-specific event validation is implemented.

    return {
        "success": True,
        "received": True,
        "settled": False,
        "payload_hash": payload_hash,
    }


# ===============================================================
# STARTUP
# ===============================================================

@app.on_event("startup")
def startup_event():
    init_database()
    seed_default_plans()


# ===============================================================
# DIRECT EXECUTION
# ===============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.getenv("ARYA_COMMERCE_HOST", "0.0.0.0"),
        port=int(os.getenv("ARYA_COMMERCE_PORT", "8013")),
    )
