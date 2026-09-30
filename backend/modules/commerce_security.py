"""
===============================================================
 ARYA Commerce & Security
 Version: 2.0.0
 Independent Commerce / Payment / OWNER Security Service
===============================================================

IMPORTANT ARCHITECTURE RULE
----------------------------
This module is independent from:

    backend/main.py
    backend/vision.py
    backend/modules/voice_language.py
    backend/modules/agri_engine.py

DO NOT modify those files from this module.

MAIN CAPABILITIES
-----------------
1. Iran bank-transfer management
2. International USDT wallet management
3. Runtime destination rotation without code changes
4. Automatic invalidation of old payment destinations
5. Historical destination snapshots
6. Payment plans and pricing
7. Payment transactions
8. Idempotency protection
9. Subscription activation
10. Device activation and device limits
11. OWNER authentication
12. OWNER session management
13. TOTP MFA
14. Recovery tokens
15. Audit logging
16. Emergency controls / Kill Switch
17. Provider architecture
18. Webhook signature verification
19. Payment verification hooks
20. Future-ready configuration

SECURITY PRINCIPLES
-------------------
- No payment address is hardcoded as the runtime source of truth.
- No private wallet key is stored by this service.
- Old payment destinations remain historical but become inactive.
- A new payment can only use an ACTIVE destination.
- Historical transactions retain the exact destination snapshot
  that was active when the transaction was created.
- Sensitive provider secrets must come from environment/secret
  management, not ordinary database configuration.
- Administrative actions are audited.
===============================================================
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
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
APP_VERSION = "2.0.0"

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

DEFAULT_DEVICE_LIMIT = int(
    os.getenv(
        "ARYA_DEFAULT_DEVICE_LIMIT",
        "3",
    )
)

PAYMENT_EXPIRY_HOURS = int(
    os.getenv(
        "ARYA_PAYMENT_EXPIRY_HOURS",
        "72",
    )
)

SUBSCRIPTION_DAYS = int(
    os.getenv(
        "ARYA_SUBSCRIPTION_DAYS",
        "30",
    )
)

SESSION_HOURS = int(
    os.getenv(
        "ARYA_OWNER_SESSION_HOURS",
        "12",
    )
)

RECOVERY_HOURS = int(
    os.getenv(
        "ARYA_RECOVERY_HOURS",
        "24",
    )
)

TOTP_STEP_SECONDS = int(
    os.getenv(
        "ARYA_TOTP_STEP_SECONDS",
        "30",
    )
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
        utc_now()
        + timedelta(hours=hours)
    ).isoformat()


def future_days(days: int) -> str:
    return (
        utc_now()
        + timedelta(days=days)
    ).isoformat()


# ===============================================================
# DATABASE
# ===============================================================

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
        check_same_thread=False,
    )

    conn.row_factory = sqlite3.Row

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    conn.execute(
        "PRAGMA busy_timeout = 30000"
    )

    return conn


def init_database() -> None:
    conn = get_db()

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

            source_transaction_id TEXT,

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
            (
                key,
                value,
                updated_at
            )
            VALUES (?, ?, ?)
            """,
            (
                key,
                value,
                utc_iso(),
            ),
        )

    conn.commit()
    conn.close()


# ===============================================================
# DATABASE HELPERS
# ===============================================================

def fetch_one(
    sql: str,
    params: tuple = (),
) -> Optional[sqlite3.Row]:

    conn = get_db()

    row = conn.execute(
        sql,
        params,
    ).fetchone()

    conn.close()

    return row


def fetch_all(
    sql: str,
    params: tuple = (),
) -> List[sqlite3.Row]:

    conn = get_db()

    rows = conn.execute(
        sql,
        params,
    ).fetchall()

    conn.close()

    return rows


def execute(
    sql: str,
    params: tuple = (),
) -> int:

    conn = get_db()

    cur = conn.execute(
        sql,
        params,
    )

    conn.commit()

    result = cur.lastrowid

    conn.close()

    return result


# ===============================================================
# CRYPTOGRAPHIC HELPERS
# ===============================================================

def sha256_text(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def random_id(
    prefix: str,
) -> str:

    return (
        f"{prefix}_"
        f"{secrets.token_hex(16)}"
    )


def constant_compare(
    a: str,
    b: str,
) -> bool:

    return hmac.compare_digest(
        a,
        b,
    )


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

    if stored.startswith(
        "pbkdf2_sha256$"
    ):
        try:
            parts = stored.split("$")

            iterations = int(parts[1])

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

            return hmac.compare_digest(
                actual,
                expected,
            )

        except Exception:
            return False

    # Backward-compatible support for an older
    # sha256 environment configuration.
    supplied_hash = sha256_text(
        supplied
    )

    return constant_compare(
        supplied_hash,
        stored,
    )


# ===============================================================
# TOTP MFA
# ===============================================================

def normalize_base32_secret(
    secret: str,
) -> bytes:

    clean = (
        secret
        .replace(" ", "")
        .replace("-", "")
        .upper()
    )

    padding = (
        "="
        * ((8 - len(clean) % 8) % 8)
    )

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

    key = normalize_base32_secret(
        secret
    )

    message = struct.pack(
        ">Q",
        counter,
    )

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

    if not supplied_code:
        return False

    now = int(time.time())

    # Allow small clock drift:
    for offset in (-1, 0, 1):

        expected = totp_code(
            secret,
            now + (
                offset
                * TOTP_STEP_SECONDS
            ),
        )

        if hmac.compare_digest(
            expected,
            supplied_code.strip(),
        ):
            return True

    return False


# ===============================================================
# SYSTEM CONTROLS
# ===============================================================

def get_control(
    key: str,
) -> bool:

    row = fetch_one(
        """
        SELECT value
        FROM system_controls
        WHERE key = ?
        """,
        (key,),
    )

    if not row:
        return False

    return (
        str(row["value"]).lower()
        == "true"
    )


def set_control(
    key: str,
    enabled: bool,
) -> None:

    execute(
        """
        INSERT INTO system_controls
        (
            key,
            value,
            updated_at
        )
        VALUES (?, ?, ?)
        ON CONFLICT(key)
        DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        """,
        (
            key,
            "true"
            if enabled
            else "false",
            utc_iso(),
        ),
    )


def require_commerce() -> None:

    if not get_control(
        "commerce_enabled"
    ):
        raise HTTPException(
            status_code=503,
            detail="ARYA Commerce is disabled",
        )


def require_payments() -> None:

    require_commerce()

    if not get_control(
        "payments_enabled"
    ):
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
            actor_id,
            actor_role,
            action,
            target_type,
            target_id,
            ip_address,
            details_json,
            created_at
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

    raw_token = secrets.token_urlsafe(
        48
    )

    token_hash = sha256_text(
        raw_token
    )

    execute(
        """
        INSERT INTO sessions
        (
            token_hash,
            user_id,
            role,
            expires_at,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
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
    credentials:
        Optional[
            HTTPAuthorizationCredentials
        ],
) -> Dict[str, str]:

    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    token_hash = sha256_text(
        credentials.credentials
    )

    row = fetch_one(
        """
        SELECT *
        FROM sessions
        WHERE token_hash = ?
          AND revoked = 0
        """,
        (token_hash,),
    )

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Invalid session",
        )

    if row["expires_at"] < utc_iso():
        raise HTTPException(
            status_code=401,
            detail="Session expired",
        )

    return {
        "user_id": row["user_id"],
        "role": row["role"],
    }


def owner_required(
    credentials:
        Optional[
            HTTPAuthorizationCredentials
        ] = Depends(security),
) -> Dict[str, str]:

    identity = authenticate(
        credentials
    )

    if identity["role"] != "OWNER":
        raise HTTPException(
            status_code=403,
            detail="OWNER access required",
        )

    return identity


# ===============================================================
# MODELS
# ===============================================================

class OwnerLoginRequest(BaseModel):
    email: str
    secret: str
    mfa_code: Optional[str] = None


class BankAccountCreate(BaseModel):
    bank_name: str
    account_holder: str
    iban: str
    account_number: Optional[str] = None
    card_number: Optional[str] = None
    currency: str = "IRR"
    label: Optional[str] = None


class WalletCreate(BaseModel):
    network: str
    currency: str = "USDT"
    address: str
    label: Optional[str] = None


class PlanCreate(BaseModel):
    code: str = Field(
        min_length=2,
        max_length=80,
    )
    name: str
    market: str
    currency: str
    amount: float = Field(gt=0)
    max_users: Optional[int] = None
    metadata: Dict[str, Any] = {}


class PaymentCreate(BaseModel):
    user_id: str
    plan_code: str
    method: str
    idempotency_key: str
    provider: Optional[str] = None
    network: Optional[str] = None
    metadata: Dict[str, Any] = {}


class PaymentVerify(BaseModel):
    provider: str
    provider_reference: str
    observed_destination: Optional[str] = None
    verification_note: Optional[str] = None


class DeviceActivate(BaseModel):
    user_id: str
    device_id: str
    device_name: Optional[str] = None
    platform: Optional[str] = None


class ProviderCreate(BaseModel):
    provider_code: str
    provider_type: str
    name: str
    priority: int = 100
    config: Dict[str, Any] = {}
    secret_ref: Optional[str] = None


class ControlUpdate(BaseModel):
    key: str
    enabled: bool


class MFASetupRequest(BaseModel):
    user_id: str
    secret: str


class MFAVerifyRequest(BaseModel):
    user_id: str
    code: str


class RecoveryCreate(BaseModel):
    user_id: str


# ===============================================================
# NORMALIZATION
# ===============================================================

def normalize_iban(
    iban: str,
) -> str:

    return (
        iban
        .replace(" ", "")
        .replace("-", "")
        .upper()
    )


def validate_iban(
    iban: str,
) -> bool:

    normalized = normalize_iban(
        iban
    )

    if not normalized:
        return False

    if not normalized.startswith(
        "IR"
    ):
        return False

    if len(normalized) != 26:
        return False

    if not normalized[2:].isdigit():
        return False

    return True


def validate_wallet_address(
    address: str,
) -> bool:

    clean = address.strip()

    if len(clean) < 20:
        return False

    if len(clean) > 200:
        return False

    return True


# ===============================================================
# DEFAULT PLANS
# ===============================================================

def seed_default_plans() -> None:

    existing = fetch_one(
        """
        SELECT id
        FROM payment_plans
        LIMIT 1
        """
    )

    if existing:
        return

    plans = [
        (
            "IR_100",
            "Iran First 100",
            "IR",
            "IRR",
            500000,
            100,
        ),
        (
            "IR_500",
            "Iran Next 500",
            "IR",
            "IRR",
            800000,
            500,
        ),
        (
            "IR_STANDARD",
            "Iran Standard",
            "IR",
            "IRR",
            1200000,
            None,
        ),
        (
            "INT_100",
            "International First 100",
            "INT",
            "USDT",
            10,
            100,
        ),
        (
            "INT_500",
            "International Next 500",
            "INT",
            "USDT",
            15,
            500,
        ),
        (
            "INT_STANDARD",
            "International Standard",
            "INT",
            "USDT",
            20,
            None,
        ),
    ]

    conn = get_db()

    now = utc_iso()

    for plan in plans:

        conn.execute(
            """
            INSERT OR IGNORE INTO payment_plans
            (
                code,
                name,
                market,
                currency,
                amount,
                max_users,
                active,
                metadata_json,
                created_at,
                updated_at
            )
            VALUES
            (
                ?, ?, ?, ?, ?, ?, 1, ?, ?, ?
            )
            """,
            (
                plan[0],
                plan[1],
                plan[2],
                plan[3],
                plan[4],
                plan[5],
                "{}",
                now,
                now,
            ),
        )

    conn.commit()
    conn.close()


# ===============================================================
# ACTIVE BANK ACCOUNT
# ===============================================================

def get_active_bank_account(
    currency: str = "IRR",
) -> Optional[sqlite3.Row]:

    return fetch_one(
        """
        SELECT *
        FROM bank_accounts
        WHERE currency = ?
          AND active = 1
        ORDER BY id DESC
        LIMIT 1
        """,
        (currency,),
    )


# ===============================================================
# ACTIVE WALLET
# ===============================================================

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
        (
            network,
            currency,
        ),
    )


# ===============================================================
# BANK ACCOUNT ROTATION
# ===============================================================

@app.post("/owner/bank-accounts/replace")
def replace_bank_account(
    payload: BankAccountCreate,
    request: Request,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    require_commerce()

    iban = normalize_iban(
        payload.iban
    )

    if not validate_iban(iban):
        raise HTTPException(
            status_code=400,
            detail="Invalid Iranian IBAN format",
        )

    now = utc_iso()

    conn = get_db()

    try:
        conn.execute(
            "BEGIN IMMEDIATE"
        )

        # IMPORTANT:
        # Every previously active account for
        # the same currency becomes invalid for
        # NEW payments from this exact moment.

        conn.execute(
            """
            UPDATE bank_accounts
            SET
                active = 0,
                disabled_at = ?
            WHERE
                currency = ?
                AND active = 1
            """,
            (
                now,
                payload.currency,
            ),
        )

        cur = conn.execute(
            """
            INSERT INTO bank_accounts
            (
                bank_name,
                account_holder,
                iban,
                account_number,
                card_number,
                currency,
                label,
                active,
                effective_from,
                created_at
            )
            VALUES
            (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                payload.bank_name,
                payload.account_holder,
                iban,
                payload.account_number,
                payload.card_number,
                payload.currency,
                payload.label,
                now,
                now,
            ),
        )

        account_id = cur.lastrowid

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    audit(
        "BANK_ACCOUNT_REPLACED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="bank_account",
        target_id=str(account_id),
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
        details={
            "new_iban": iban,
            "effective_from": now,
        },
    )

    return {
        "status": "replaced",
        "new_account_id": account_id,
        "effective_from": now,
        "old_accounts_invalid_for_new_payments": True,
    }


# ===============================================================
# BANK ACCOUNT LIST
# ===============================================================

@app.get("/owner/bank-accounts")
def list_bank_accounts(
    identity: Dict[str, str] =
        Depends(owner_required),
):

    rows = fetch_all(
        """
        SELECT
            id,
            bank_name,
            account_holder,
            iban,
            account_number,
            card_number,
            currency,
            label,
            active,
            effective_from,
            disabled_at,
            created_at
        FROM bank_accounts
        ORDER BY id DESC
        """
    )

    return [
        dict(row)
        for row in rows
    ]


# ===============================================================
# DISABLE BANK ACCOUNT
# ===============================================================

@app.post(
    "/owner/bank-accounts/{account_id}/disable"
)
def disable_bank_account(
    account_id: int,
    request: Request,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    row = fetch_one(
        """
        SELECT *
        FROM bank_accounts
        WHERE id = ?
        """,
        (account_id,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Bank account not found",
        )

    if row["active"]:

        execute(
            """
            UPDATE bank_accounts
            SET
                active = 0,
                disabled_at = ?
            WHERE id = ?
            """,
            (
                utc_iso(),
                account_id,
            ),
        )

    audit(
        "BANK_ACCOUNT_DISABLED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="bank_account",
        target_id=str(account_id),
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
    )

    return {
        "status": "disabled",
        "account_id": account_id,
    }


# ===============================================================
# WALLET ROTATION
# ===============================================================

@app.post("/owner/wallets/replace")
def replace_wallet(
    payload: WalletCreate,
    request: Request,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    require_commerce()

    network = payload.network.strip().upper()
    currency = payload.currency.strip().upper()
    address = payload.address.strip()

    if not validate_wallet_address(
        address
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid wallet address",
        )

    now = utc_iso()

    conn = get_db()

    try:
        conn.execute(
            "BEGIN IMMEDIATE"
        )

        # Critical rule:
        # all previously active wallets on the
        # same network/currency become invalid
        # for NEW payments immediately.

        conn.execute(
            """
            UPDATE wallet_destinations
            SET
                active = 0,
                disabled_at = ?
            WHERE
                network = ?
                AND currency = ?
                AND active = 1
            """,
            (
                now,
                network,
                currency,
            ),
        )

        cur = conn.execute(
            """
            INSERT INTO wallet_destinations
            (
                network,
                currency,
                address,
                label,
                active,
                effective_from,
                created_at
            )
            VALUES
            (?, ?, ?, ?, 1, ?, ?)
            """,
            (
                network,
                currency,
                address,
                payload.label,
                now,
                now,
            ),
        )

        wallet_id = cur.lastrowid

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    audit(
        "WALLET_REPLACED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="wallet",
        target_id=str(wallet_id),
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
        details={
            "network": network,
            "currency": currency,
            "effective_from": now,
        },
    )

    return {
        "status": "replaced",
        "new_wallet_id": wallet_id,
        "network": network,
        "currency": currency,
        "effective_from": now,
        "old_wallet_invalid_for_new_payments": True,
    }


# ===============================================================
# WALLET LIST
# ===============================================================

@app.get("/owner/wallets")
def list_wallets(
    identity: Dict[str, str] =
        Depends(owner_required),
):

    rows = fetch_all(
        """
        SELECT
            id,
            network,
            currency,
            address,
            label,
            active,
            effective_from,
            disabled_at,
            created_at
        FROM wallet_destinations
        ORDER BY id DESC
        """
    )

    return [
        dict(row)
        for row in rows
    ]


# ===============================================================
# DISABLE WALLET
# ===============================================================

@app.post(
    "/owner/wallets/{wallet_id}/disable"
)
def disable_wallet(
    wallet_id: int,
    request: Request,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    row = fetch_one(
        """
        SELECT *
        FROM wallet_destinations
        WHERE id = ?
        """,
        (wallet_id,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Wallet not found",
        )

    execute(
        """
        UPDATE wallet_destinations
        SET
            active = 0,
            disabled_at = ?
        WHERE id = ?
        """,
        (
            utc_iso(),
            wallet_id,
        ),
    )

    audit(
        "WALLET_DISABLED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="wallet",
        target_id=str(wallet_id),
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
    )

    return {
        "status": "disabled",
        "wallet_id": wallet_id,
    }


# ===============================================================
# PUBLIC ACTIVE PAYMENT DESTINATIONS
# ===============================================================

@app.get("/commerce/payment-destinations")
def active_payment_destinations():

    require_commerce()

    result: Dict[str, Any] = {
        "bank": None,
        "usdt": [],
    }

    if get_control(
        "bank_transfer_enabled"
    ):

        bank = get_active_bank_account(
            "IRR"
        )

        if bank:

            result["bank"] = {
                "bank_name":
                    bank["bank_name"],
                "account_holder":
                    bank["account_holder"],
                "iban":
                    bank["iban"],
                "account_number":
                    bank["account_number"],
                "card_number":
                    bank["card_number"],
                "currency":
                    bank["currency"],
                "label":
                    bank["label"],
                "effective_from":
                    bank["effective_from"],
            }

    if get_control(
        "crypto_payments_enabled"
    ):

        wallets = fetch_all(
            """
            SELECT *
            FROM wallet_destinations
            WHERE currency = 'USDT'
              AND active = 1
            ORDER BY network
            """
        )

        result["usdt"] = [
            {
                "network":
                    row["network"],
                "currency":
                    row["currency"],
                "address":
                    row["address"],
                "label":
                    row["label"],
                "effective_from":
                    row["effective_from"],
            }
            for row in wallets
        ]

    return result


# ===============================================================
# PLANS
# ===============================================================

@app.post("/owner/plans")
def create_plan(
    payload: PlanCreate,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    now = utc_iso()

    try:

        plan_id = execute(
            """
            INSERT INTO payment_plans
            (
                code,
                name,
                market,
                currency,
                amount,
                max_users,
                active,
                metadata_json,
                created_at,
                updated_at
            )
            VALUES
            (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                payload.code,
                payload.name,
                payload.market,
                payload.currency,
                payload.amount,
                payload.max_users,
                json.dumps(
                    payload.metadata,
                    ensure_ascii=False,
                ),
                now,
                now,
            ),
        )

    except sqlite3.IntegrityError:

        raise HTTPException(
            status_code=409,
            detail="Plan already exists",
        )

    audit(
        "PLAN_CREATED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="plan",
        target_id=str(plan_id),
    )

    return {
        "status": "created",
        "plan_id": plan_id,
    }


@app.get("/commerce/plans")
def list_plans():

    rows = fetch_all(
        """
        SELECT *
        FROM payment_plans
        WHERE active = 1
        ORDER BY market, amount
        """
    )

    return [
        dict(row)
        for row in rows
    ]


# ===============================================================
# PLAN LOOKUP
# ===============================================================

def get_active_plan(
    code: str,
) -> sqlite3.Row:

    row = fetch_one(
        """
        SELECT *
        FROM payment_plans
        WHERE code = ?
          AND active = 1
        """,
        (code,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Payment plan not found",
        )

    return row


# ===============================================================
# IDEMPOTENCY
# ===============================================================

def get_existing_idempotent_payment(
    key: str,
) -> Optional[sqlite3.Row]:

    return fetch_one(
        """
        SELECT *
        FROM payment_transactions
        WHERE idempotency_key = ?
        """,
        (key,),
    )


# ===============================================================
# CREATE PAYMENT
# ===============================================================

@app.post("/commerce/payments/create")
def create_payment(
    payload: PaymentCreate,
    request: Request,
):

    require_payments()

    method = (
        payload.method
        .strip()
        .upper()
    )

    if method not in {
        "BANK_TRANSFER",
        "USDT",
    }:
        raise HTTPException(
            status_code=400,
            detail="Unsupported payment method",
        )

    existing = (
        get_existing_idempotent_payment(
            payload.idempotency_key
        )
    )

    if existing:
        return {
            "status":
                "existing_transaction",
            "transaction":
                dict(existing),
        }

    plan = get_active_plan(
        payload.plan_code
    )

    if method == "BANK_TRANSFER":

        if plan["market"] != "IR":
            raise HTTPException(
                status_code=400,
                detail="Invalid Iran plan",
            )

        if not get_control(
            "bank_transfer_enabled"
        ):
            raise HTTPException(
                status_code=503,
                detail="Bank transfer disabled",
            )

        bank = get_active_bank_account(
            "IRR"
        )

        if not bank:
            raise HTTPException(
                status_code=503,
                detail=(
                    "No active bank account "
                    "is configured"
                ),
            )

        destination_type = (
            "BANK_ACCOUNT"
        )

        destination_id = bank["id"]

        destination_snapshot = json.dumps(
            {
                "bank_account_id":
                    bank["id"],
                "bank_name":
                    bank["bank_name"],
                "account_holder":
                    bank["account_holder"],
                "iban":
                    bank["iban"],
                "account_number":
                    bank["account_number"],
                "currency":
                    bank["currency"],
                "effective_from":
                    bank["effective_from"],
            },
            ensure_ascii=False,
        )

    else:

        if plan["market"] != "INT":
            raise HTTPException(
                status_code=400,
                detail=(
                    "Invalid international plan"
                ),
            )

        if not get_control(
            "crypto_payments_enabled"
        ):
            raise HTTPException(
                status_code=503,
                detail="Crypto payments disabled",
            )

        network = (
            payload.network
            or payload.metadata.get(
                "network"
            )
            or "TRC20"
        )

        network = network.strip().upper()

        wallet = get_active_wallet(
            network,
            "USDT",
        )

        if not wallet:
            raise HTTPException(
                status_code=503,
                detail=(
                    "No active USDT wallet "
                    "for this network"
                ),
            )

        destination_type = "WALLET"

        destination_id = wallet["id"]

        destination_snapshot = json.dumps(
            {
                "wallet_id":
                    wallet["id"],
                "network":
                    wallet["network"],
                "currency":
                    wallet["currency"],
                "address":
                    wallet["address"],
                "effective_from":
                    wallet["effective_from"],
            },
            ensure_ascii=False,
        )

    transaction_id = random_id(
        "pay"
    )

    now = utc_iso()

    execute(
        """
        INSERT INTO payment_transactions
        (
            transaction_id,
            user_id,
            plan_code,
            market,
            method,
            currency,
            amount,
            status,
            destination_type,
            destination_id,
            destination_snapshot,
            provider,
            idempotency_key,
            metadata_json,
            created_at,
            expires_at
        )
        VALUES
        (
            ?, ?, ?, ?, ?, ?, ?,
            'PENDING',
            ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            transaction_id,
            payload.user_id,
            plan["code"],
            plan["market"],
            method,
            plan["currency"],
            plan["amount"],
            destination_type,
            destination_id,
            destination_snapshot,
            payload.provider,
            payload.idempotency_key,
            json.dumps(
                payload.metadata,
                ensure_ascii=False,
            ),
            now,
            future_iso(
                PAYMENT_EXPIRY_HOURS
            ),
        ),
    )

    audit(
        "PAYMENT_CREATED",
        actor_id=payload.user_id,
        target_type="payment",
        target_id=transaction_id,
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
        details={
            "method": method,
            "plan": plan["code"],
            "destination_type":
                destination_type,
        },
    )

    row = fetch_one(
        """
        SELECT *
        FROM payment_transactions
        WHERE transaction_id = ?
        """,
        (transaction_id,),
    )

    return dict(row)


# ===============================================================
# PAYMENT VERIFICATION
# ===============================================================

@app.post(
    "/owner/payments/{transaction_id}/verify"
)
def verify_payment(
    transaction_id: str,
    payload: PaymentVerify,
    request: Request,
    identity: Dict[str, str] =
        Depends(owner_required),
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
            detail="Transaction not found",
        )

    if row["status"] == "VERIFIED":

        return {
            "status": "already_verified",
            "transaction_id":
                transaction_id,
        }

    if row["status"] in {
        "REJECTED",
        "CANCELLED",
        "EXPIRED",
    }:

        raise HTTPException(
            status_code=409,
            detail=(
                "Transaction cannot "
                "be verified"
            ),
        )

    # If provider supplies the destination,
    # compare it against the historical
    # destination snapshot stored at the
    # time the payment was created.

    if payload.observed_destination:

        observed = (
            payload.observed_destination
            .strip()
        )

        snapshot = json.loads(
            row["destination_snapshot"]
            or "{}"
        )

        expected = ""

        if row["destination_type"] == (
            "WALLET"
        ):
            expected = snapshot.get(
                "address",
                "",
            )

        elif row["destination_type"] == (
            "BANK_ACCOUNT"
        ):
            expected = snapshot.get(
                "iban",
                "",
            )

        if expected and observed != expected:

            execute(
                """
                UPDATE payment_transactions
                SET status = 'REJECTED'
                WHERE transaction_id = ?
                """,
                (transaction_id,),
            )

            audit(
                "PAYMENT_DESTINATION_MISMATCH",
                actor_id=identity["user_id"],
                actor_role="OWNER",
                target_type="payment",
                target_id=transaction_id,
                ip_address=(
                    request.client.host
                    if request.client
                    else None
                ),
                details={
                    "provider":
                        payload.provider,
                },
            )

            raise HTTPException(
                status_code=409,
                detail=(
                    "Payment destination does "
                    "not match the historical "
                    "destination of this transaction"
                ),
            )

    now = utc_iso()

    execute(
        """
        UPDATE payment_transactions
        SET
            status = 'VERIFIED',
            provider = ?,
            provider_reference = ?,
            verified_at = ?
        WHERE transaction_id = ?
        """,
        (
            payload.provider,
            payload.provider_reference,
            now,
            transaction_id,
        ),
    )

    event_id = random_id(
        "evt"
    )

    execute(
        """
        INSERT INTO payment_events
        (
            transaction_id,
            event_type,
            event_id,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            transaction_id,
            "PAYMENT_VERIFIED",
            event_id,
            now,
        ),
    )

    subscription_id = (
        activate_subscription(
            transaction_id
        )
    )

    audit(
        "PAYMENT_VERIFIED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="payment",
        target_id=transaction_id,
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
        details={
            "provider":
                payload.provider,
            "provider_reference":
                payload.provider_reference,
            "subscription_id":
                subscription_id,
        },
    )

    return {
        "status": "verified",
        "transaction_id":
            transaction_id,
        "subscription_id":
            subscription_id,
    }


# ===============================================================
# SUBSCRIPTION
# ===============================================================

def activate_subscription(
    transaction_id: str,
) -> str:

    payment = fetch_one(
        """
        SELECT *
        FROM payment_transactions
        WHERE transaction_id = ?
        """,
        (transaction_id,),
    )

    if not payment:
        raise ValueError(
            "Payment not found"
        )

    existing = fetch_one(
        """
        SELECT *
        FROM subscriptions
        WHERE source_transaction_id = ?
        """,
        (transaction_id,),
    )

    if existing:
        return existing[
            "subscription_id"
        ]

    subscription_id = random_id(
        "sub"
    )

    now = utc_iso()

    execute(
        """
        INSERT INTO subscriptions
        (
            subscription_id,
            user_id,
            plan_code,
            status,
            starts_at,
            expires_at,
            source_transaction_id,
            created_at,
            updated_at
        )
        VALUES
        (?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
        """,
        (
            subscription_id,
            payment["user_id"],
            payment["plan_code"],
            now,
            future_days(
                SUBSCRIPTION_DAYS
            ),
            transaction_id,
            now,
            now,
        ),
    )

    return subscription_id


@app.get(
    "/commerce/subscriptions/{user_id}"
)
def list_user_subscriptions(
    user_id: str,
):

    rows = fetch_all(
        """
        SELECT *
        FROM subscriptions
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,),
    )

    return [
        dict(row)
        for row in rows
    ]


# ===============================================================
# DEVICE ACTIVATION
# ===============================================================

@app.post("/commerce/devices/activate")
def activate_device(
    payload: DeviceActivate,
    request: Request,
):

    require_commerce()

    if not get_control(
        "new_device_activation_enabled"
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "New device activation disabled"
            ),
        )

    subscription = fetch_one(
        """
        SELECT *
        FROM subscriptions
        WHERE user_id = ?
          AND status = 'ACTIVE'
          AND expires_at > ?
        ORDER BY expires_at DESC
        LIMIT 1
        """,
        (
            payload.user_id,
            utc_iso(),
        ),
    )

    if not subscription:
        raise HTTPException(
            status_code=403,
            detail="Active subscription required",
        )

    existing = fetch_one(
        """
        SELECT *
        FROM devices
        WHERE user_id = ?
          AND device_id = ?
        """,
        (
            payload.user_id,
            payload.device_id,
        ),
    )

    if existing:

        execute(
            """
            UPDATE devices
            SET
                active = 1,
                last_seen_at = ?
            WHERE
                user_id = ?
                AND device_id = ?
            """,
            (
                utc_iso(),
                payload.user_id,
                payload.device_id,
            ),
        )

        return {
            "status":
                "already_registered",
            "device_id":
                payload.device_id,
        }

    count = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM devices
        WHERE user_id = ?
          AND active = 1
        """,
        (payload.user_id,),
    )["total"]

    if count >= DEFAULT_DEVICE_LIMIT:

        raise HTTPException(
            status_code=409,
            detail=(
                "Device limit reached"
            ),
        )

    now = utc_iso()

    execute(
        """
        INSERT INTO devices
        (
            device_id,
            user_id,
            device_name,
            platform,
            active,
            first_seen_at,
            last_seen_at
        )
        VALUES
        (?, ?, ?, ?, 1, ?, ?)
        """,
        (
            payload.device_id,
            payload.user_id,
            payload.device_name,
            payload.platform,
            now,
            now,
        ),
    )

    audit(
        "DEVICE_ACTIVATED",
        actor_id=payload.user_id,
        target_type="device",
        target_id=payload.device_id,
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
    )

    return {
        "status": "activated",
        "device_id":
            payload.device_id,
        "device_limit":
            DEFAULT_DEVICE_LIMIT,
    }


@app.get(
    "/commerce/devices/{user_id}"
)
def list_devices(
    user_id: str,
):

    rows = fetch_all(
        """
        SELECT *
        FROM devices
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,),
    )

    return [
        dict(row)
        for row in rows
    ]


@app.post(
    "/owner/devices/{device_id}/disable"
)
def disable_device(
    device_id: str,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    row = fetch_one(
        """
        SELECT *
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    execute(
        """
        UPDATE devices
        SET active = 0
        WHERE device_id = ?
        """,
        (device_id,),
    )

    audit(
        "DEVICE_DISABLED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="device",
        target_id=device_id,
    )

    return {
        "status": "disabled",
        "device_id": device_id,
    }


# ===============================================================
# OWNER LOGIN
# ===============================================================

@app.post(
    "/security/owner/login"
)
def owner_login(
    payload: OwnerLoginRequest,
    request: Request,
):

    if not OWNER_EMAIL:
        raise HTTPException(
            status_code=503,
            detail=(
                "OWNER email is not configured"
            ),
        )

    if not OWNER_SECRET_HASH:
        raise HTTPException(
            status_code=503,
            detail=(
                "OWNER secret is not configured"
            ),
        )

    if not constant_compare(
        payload.email.strip().lower(),
        OWNER_EMAIL.lower(),
    ):

        audit(
            "OWNER_LOGIN_FAILED",
            actor_id=payload.email,
            actor_role="UNKNOWN",
            ip_address=(
                request.client.host
                if request.client
                else None
            ),
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    if not verify_secret(
        payload.secret,
        OWNER_SECRET_HASH,
    ):

        audit(
            "OWNER_LOGIN_FAILED",
            actor_id=OWNER_EMAIL,
            actor_role="OWNER",
            ip_address=(
                request.client.host
                if request.client
                else None
            ),
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    # MFA is optional until configured.
    security_user = fetch_one(
        """
        SELECT *
        FROM security_users
        WHERE user_id = 'OWNER'
        """
    )

    if (
        security_user
        and security_user["mfa_enabled"]
    ):

        if not payload.mfa_code:

            raise HTTPException(
                status_code=401,
                detail="MFA code required",
            )

        secret = (
            security_user[
                "mfa_secret_encrypted"
            ]
        )

        if not secret:

            raise HTTPException(
                status_code=503,
                detail=(
                    "MFA configuration invalid"
                ),
            )

        if not verify_totp(
            secret,
            payload.mfa_code,
        ):

            audit(
                "OWNER_MFA_FAILED",
                actor_id="OWNER",
                actor_role="OWNER",
                ip_address=(
                    request.client.host
                    if request.client
                    else None
                ),
            )

            raise HTTPException(
                status_code=401,
                detail="Invalid MFA code",
            )

    token = create_session(
        "OWNER",
        "OWNER",
    )

    audit(
        "OWNER_LOGIN",
        actor_id="OWNER",
        actor_role="OWNER",
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_hours":
            SESSION_HOURS,
    }


# ===============================================================
# LOGOUT
# ===============================================================

@app.post(
    "/security/logout"
)
def logout(
    credentials:
        Optional[
            HTTPAuthorizationCredentials
        ] = Depends(security),
):

    identity = authenticate(
        credentials
    )

    token_hash = sha256_text(
        credentials.credentials
    )

    execute(
        """
        UPDATE sessions
        SET revoked = 1
        WHERE token_hash = ?
        """,
        (token_hash,),
    )

    audit(
        "LOGOUT",
        actor_id=identity["user_id"],
        actor_role=identity["role"],
    )

    return {
        "status": "logged_out"
    }


# ===============================================================
# MFA SETUP
# ===============================================================

@app.post(
    "/owner/mfa/setup"
)
def setup_mfa(
    payload: MFASetupRequest,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    try:
        normalize_base32_secret(
            payload.secret
        )
    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid Base32 MFA secret",
        )

    # Verify that the secret is actually usable
    # before activating MFA.

    test_code = totp_code(
        payload.secret
    )

    if not test_code:
        raise HTTPException(
            status_code=400,
            detail="Invalid MFA secret",
        )

    now = utc_iso()

    execute(
        """
        INSERT INTO security_users
        (
            user_id,
            mfa_enabled,
            mfa_secret_encrypted,
            created_at,
            updated_at
        )
        VALUES
        (?, 1, ?, ?, ?)
        ON CONFLICT(user_id)
        DO UPDATE SET
            mfa_enabled = 1,
            mfa_secret_encrypted = excluded.mfa_secret_encrypted,
            updated_at = excluded.updated_at
        """,
        (
            payload.user_id,
            payload.secret,
            now,
            now,
        ),
    )

    audit(
        "MFA_ENABLED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="security_user",
        target_id=payload.user_id,
    )

    return {
        "status": "mfa_enabled",
        "user_id": payload.user_id,
    }


# ===============================================================
# MFA DISABLE
# ===============================================================

@app.post(
    "/owner/mfa/{user_id}/disable"
)
def disable_mfa(
    user_id: str,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    execute(
        """
        UPDATE security_users
        SET
            mfa_enabled = 0,
            mfa_secret_encrypted = NULL,
            updated_at = ?
        WHERE user_id = ?
        """,
        (
            utc_iso(),
            user_id,
        ),
    )

    audit(
        "MFA_DISABLED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="security_user",
        target_id=user_id,
    )

    return {
        "status": "mfa_disabled"
    }


# ===============================================================
# RECOVERY TOKEN
# ===============================================================

@app.post(
    "/owner/recovery/create"
)
def create_recovery_token(
    payload: RecoveryCreate,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    raw_token = secrets.token_urlsafe(
        48
    )

    token_hash = sha256_text(
        raw_token
    )

    execute(
        """
        INSERT INTO recovery_tokens
        (
            user_id,
            token_hash,
            expires_at,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            payload.user_id,
            token_hash,
            future_iso(
                RECOVERY_HOURS
            ),
            utc_iso(),
        ),
    )

    audit(
        "RECOVERY_TOKEN_CREATED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="security_user",
        target_id=payload.user_id,
    )

    # The raw recovery token is returned once.
    # Only its hash is stored.

    return {
        "status": "created",
        "user_id":
            payload.user_id,
        "recovery_token":
            raw_token,
        "expires_in_hours":
            RECOVERY_HOURS,
    }


# ===============================================================
# PROVIDERS
# ===============================================================

@app.post(
    "/owner/providers"
)
def create_provider(
    payload: ProviderCreate,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    # SECRET VALUES MUST NOT be placed directly
    # into config_json.
    #
    # Use secret_ref to reference an environment
    # variable or external secret manager.

    if any(
        word in json.dumps(
            payload.config,
            ensure_ascii=False,
        ).lower()
        for word in (
            "secret",
            "password",
            "private_key",
            "privatekey",
            "api_key",
            "apikey",
            "token",
        )
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Sensitive credentials must "
                "use secret_ref, not config"
            ),
        )

    try:

        provider_id = execute(
            """
            INSERT INTO providers
            (
                provider_code,
                provider_type,
                name,
                active,
                priority,
                config_json,
                secret_ref,
                created_at,
                updated_at
            )
            VALUES
            (?, ?, ?, 1, ?, ?, ?, ?, ?)
            """,
            (
                payload.provider_code,
                payload.provider_type,
                payload.name,
                payload.priority,
                json.dumps(
                    payload.config,
                    ensure_ascii=False,
                ),
                payload.secret_ref,
                utc_iso(),
                utc_iso(),
            ),
        )

    except sqlite3.IntegrityError:

        raise HTTPException(
            status_code=409,
            detail="Provider already exists",
        )

    audit(
        "PROVIDER_CREATED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="provider",
        target_id=str(provider_id),
    )

    return {
        "status": "created",
        "provider_id":
            provider_id,
    }


@app.get(
    "/owner/providers"
)
def list_providers(
    identity: Dict[str, str] =
        Depends(owner_required),
):

    rows = fetch_all(
        """
        SELECT
            id,
            provider_code,
            provider_type,
            name,
            active,
            priority,
            config_json,
            secret_ref,
            created_at,
            updated_at
        FROM providers
        ORDER BY priority ASC, id ASC
        """
    )

    return [
        dict(row)
        for row in rows
    ]


# ===============================================================
# EMERGENCY CONTROLS
# ===============================================================

ALLOWED_CONTROLS = {
    "commerce_enabled",
    "payments_enabled",
    "crypto_payments_enabled",
    "bank_transfer_enabled",
    "new_device_activation_enabled",
    "maintenance_mode",
}


@app.post(
    "/owner/control"
)
def update_control(
    payload: ControlUpdate,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    if payload.key not in ALLOWED_CONTROLS:

        raise HTTPException(
            status_code=400,
            detail="Unsupported control",
        )

    set_control(
        payload.key,
        payload.enabled,
    )

    audit(
        "SYSTEM_CONTROL_CHANGED",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="system_control",
        target_id=payload.key,
        details={
            "enabled":
                payload.enabled,
        },
    )

    return {
        "key":
            payload.key,
        "enabled":
            payload.enabled,
    }


@app.get(
    "/owner/control"
)
def get_controls(
    identity: Dict[str, str] =
        Depends(owner_required),
):

    rows = fetch_all(
        """
        SELECT *
        FROM system_controls
        ORDER BY key
        """
    )

    return [
        dict(row)
        for row in rows
    ]


# ===============================================================
# KILL SWITCH
# ===============================================================

@app.post(
    "/owner/emergency/kill-switch"
)
def kill_switch(
    identity: Dict[str, str] =
        Depends(owner_required),
):

    set_control(
        "payments_enabled",
        False,
    )

    set_control(
        "crypto_payments_enabled",
        False,
    )

    set_control(
        "bank_transfer_enabled",
        False,
    )

    set_control(
        "new_device_activation_enabled",
        False,
    )

    audit(
        "EMERGENCY_KILL_SWITCH",
        actor_id=identity["user_id"],
        actor_role="OWNER",
        target_type="system",
        target_id="PAYMENT_KILL_SWITCH",
    )

    return {
        "status":
            "emergency_mode_enabled",
        "payments_enabled":
            False,
        "crypto_payments_enabled":
            False,
        "bank_transfer_enabled":
            False,
        "new_device_activation_enabled":
            False,
    }


# ===============================================================
# PAYMENT HISTORY
# ===============================================================

@app.get(
    "/owner/payments"
)
def payment_history(
    limit: int = 100,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    limit = max(
        1,
        min(
            limit,
            MAX_AUDIT_LIMIT,
        ),
    )

    rows = fetch_all(
        """
        SELECT *
        FROM payment_transactions
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )

    return [
        dict(row)
        for row in rows
    ]


# ===============================================================
# PAYMENT EVENTS
# ===============================================================

@app.get(
    "/owner/payments/{transaction_id}/events"
)
def get_payment_events(
    transaction_id: str,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    rows = fetch_all(
        """
        SELECT *
        FROM payment_events
        WHERE transaction_id = ?
        ORDER BY id ASC
        """,
        (transaction_id,),
    )

    return [
        dict(row)
        for row in rows
    ]


# ===============================================================
# AUDIT
# ===============================================================

@app.get(
    "/owner/audit"
)
def get_audit(
    limit: int = 100,
    identity: Dict[str, str] =
        Depends(owner_required),
):

    limit = max(
        1,
        min(
            limit,
            MAX_AUDIT_LIMIT,
        ),
    )

    rows = fetch_all(
        """
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )

    return [
        dict(row)
        for row in rows
    ]


# ===============================================================
# WEBHOOK SIGNATURE
# ===============================================================

def verify_webhook_signature(
    payload: bytes,
    signature: str,
) -> bool:

    if not PAYMENT_WEBHOOK_SECRET:
        return False

    expected = hmac.new(
        PAYMENT_WEBHOOK_SECRET.encode(
            "utf-8"
        ),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        expected,
        signature,
    )


@app.post(
    "/commerce/webhook/{provider}"
)
async def payment_webhook(
    provider: str,
    request: Request,
    x_arya_signature:
        Optional[str] =
        Header(default=None),
):

    require_payments()

    body = await request.body()

    if not x_arya_signature:

        raise HTTPException(
            status_code=401,
            detail=(
                "Missing webhook signature"
            ),
        )

    if not verify_webhook_signature(
        body,
        x_arya_signature,
    ):

        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid webhook signature"
            ),
        )

    payload_hash = sha256_text(
        body.decode(
            "utf-8",
            errors="replace",
        )
    )

    audit(
        "WEBHOOK_RECEIVED",
        actor_id=provider,
        actor_role="PAYMENT_PROVIDER",
        target_type="webhook",
        target_id=payload_hash,
        details={
            "provider":
                provider,
        },
    )

    return {
        "status":
            "received",
        "provider":
            provider,
        "payload_hash":
            payload_hash,
    }


# ===============================================================
# HEALTH
# ===============================================================

@app.get("/")
def root():

    return {
        "service":
            APP_NAME,
        "version":
            APP_VERSION,
        "status":
            "online",
    }


@app.get("/health")
def health():

    database_status = "error"

    conn = get_db()

    try:

        conn.execute(
            "SELECT 1"
        )

        database_status = "ok"

    except Exception:

        database_status = "error"

    finally:

        conn.close()

    return {
        "service":
            APP_NAME,
        "version":
            APP_VERSION,
        "database":
            database_status,
        "commerce_enabled":
            get_control(
                "commerce_enabled"
            ),
        "payments_enabled":
            get_control(
                "payments_enabled"
            ),
        "crypto_payments_enabled":
            get_control(
                "crypto_payments_enabled"
            ),
        "bank_transfer_enabled":
            get_control(
                "bank_transfer_enabled"
            ),
    }


# ===============================================================
# STARTUP
# ===============================================================

@app.on_event("startup")
def startup():

    init_database()

    seed_default_plans()


# ===============================================================
# LOCAL EXECUTION
# ===============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "commerce_security:app",
        host="0.0.0.0",
        port=int(
            os.getenv(
                "ARYA_COMMERCE_PORT",
                "8013",
            )
        ),
        reload=False,
    )
