"""
ARYA Commerce & Security — Additive Hardening Module
Version: 1.0.0
File: backend/arya_commerce_security_hardening.py

ماژول مستقل برای تقویت امنیت و پرداخت ARYA.
این فایل جایگزین commerce_security.py نیست و آن را تغییر نمی‌دهد.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None

try:
    from fastapi import APIRouter, HTTPException
except ImportError:
    APIRouter = None
    HTTPException = Exception


MODULE_VERSION = "1.0.0"


def _database_path() -> str:
    configured = os.getenv("ARYA_COMMERCE_DATABASE")

    if configured:
        return configured

    local_database = (
        Path(__file__).resolve().parent / "commerce_security.db"
    )

    if local_database.exists():
        return str(local_database)

    return str(Path.cwd() / "commerce_security.db")


DB_PATH = _database_path()


# ============================================================
# TIME UTILITIES
# ============================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso() -> str:
    return utc_now().isoformat(timespec="seconds")


def parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None

    try:
        result = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result.astimezone(timezone.utc)

    except (TypeError, ValueError):
        return None


# ============================================================
# DATABASE TRANSACTIONS
# ============================================================

def connect_database(
    database_path: Optional[str] = None,
) -> sqlite3.Connection:

    path = database_path or DB_PATH

    connection = sqlite3.connect(
        path,
        timeout=15,
        isolation_level=None,
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 15000")

    return connection


@contextmanager
def db_transaction(
    database_path: Optional[str] = None,
    immediate: bool = True,
):
    connection = connect_database(database_path)

    try:
        if immediate:
            connection.execute("BEGIN IMMEDIATE")
        else:
            connection.execute("BEGIN")

        yield connection

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def table_exists(
    connection: sqlite3.Connection,
    table_name: str,
) -> bool:

    row = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (table_name,),
    ).fetchone()

    return row is not None


def table_columns(
    connection: sqlite3.Connection,
    table_name: str,
) -> set[str]:

    if not table_name.replace("_", "").isalnum():
        raise ValueError("Invalid table name")

    rows = connection.execute(
        f'PRAGMA table_info("{table_name}")'
    ).fetchall()

    return {
        str(row["name"])
        for row in rows
    }


# ============================================================
# SECURITY AUDIT LOGGING
# ============================================================

def append_audit_event(
    connection: sqlite3.Connection,
    *,
    action: str,
    actor: str = "system",
    target_type: str = "",
    target_id: str = "",
    details: Optional[Mapping[str, Any]] = None,
) -> bool:

    if not table_exists(connection, "audit_logs"):
        return False

    columns = table_columns(
        connection,
        "audit_logs",
    )

    serialized_details = json.dumps(
        details or {},
        ensure_ascii=False,
        sort_keys=True,
    )

    values = {
        "action": action,
        "actor": actor,
        "target_type": target_type,
        "target_id": str(target_id),
        "details": serialized_details,
        "metadata": serialized_details,
        "event_type": action,
        "user_id": actor,
        "entity_type": target_type,
        "entity_id": str(target_id),
        "created_at": utc_iso(),
        "timestamp": utc_iso(),
    }

    selected = [
        (key, value)
        for key, value in values.items()
        if key in columns
    ]

    if not selected:
        return False

    names = ", ".join(
        f'"{key}"'
        for key, _ in selected
    )

    placeholders = ", ".join(
        "?"
        for _ in selected
    )

    connection.execute(
        f"""
        INSERT INTO audit_logs ({names})
        VALUES ({placeholders})
        """,
        tuple(value for _, value in selected),
    )

    return True


# ============================================================
# PAYMENT IDEMPOTENCY
# ============================================================

def request_fingerprint(
    *,
    user_id: str,
    plan_code: str,
    method: str,
    amount_minor: int,
    currency: str,
    destination_id: Optional[str] = None,
    provider: Optional[str] = None,
    network: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> str:

    payload = {
        "user_id": str(user_id),
        "plan_code": str(plan_code),
        "method": str(method).strip().lower(),
        "amount_minor": int(amount_minor),
        "currency": str(currency).strip().upper(),
        "destination_id": str(destination_id or ""),
        "provider": str(provider or "").strip().lower(),
        "network": str(network or "").strip().upper(),
        "metadata": metadata or {},
    }

    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def check_idempotency_reuse(
    *,
    stored_fingerprint: Optional[str],
    incoming_fingerprint: str,
) -> tuple[bool, str]:

    if not stored_fingerprint:
        return (
            False,
            "Existing idempotency key has no stored fingerprint",
        )

    same_request = hmac.compare_digest(
        str(stored_fingerprint),
        str(incoming_fingerprint),
    )

    if same_request:
        return (
            True,
            "Same request: return the original result",
        )

    return (
        False,
        "Idempotency key reused with different request data",
    )


# ============================================================
# VERIFIED PAYMENT REFERENCE VALIDATION
# ============================================================

def validate_verified_payment_reference(
    *,
    stored_reference: Optional[str],
    incoming_reference: Optional[str],
) -> None:

    existing = (stored_reference or "").strip()
    incoming = (incoming_reference or "").strip()

    if not existing or not incoming:
        raise ValueError(
            "Provider reference is required for verified payment replay"
        )

    if not hmac.compare_digest(existing, incoming):
        raise ValueError(
            "Provider reference mismatch for verified payment"
        )


# ============================================================
# SUBSCRIPTION RENEWAL
# ============================================================

def calculate_subscription_period(
    *,
    current_expires_at: Optional[str],
    duration_days: int,
    now: Optional[datetime] = None,
) -> tuple[str, str]:

    if duration_days <= 0:
        raise ValueError(
            "Subscription duration must be positive"
        )

    current_time = now or utc_now()

    if current_time.tzinfo is None:
        current_time = current_time.replace(
            tzinfo=timezone.utc
        )

    base_time = current_time

    existing_expiry = parse_datetime(
        current_expires_at
    )

    if existing_expiry and existing_expiry > base_time:
        base_time = existing_expiry

    expiry = base_time + timedelta(
        days=duration_days
    )

    return (
        current_time.isoformat(timespec="seconds"),
        expiry.isoformat(timespec="seconds"),
    )


# ============================================================
# ONE-TIME OWNER RECOVERY TOKENS
# ============================================================

def create_recovery_token() -> tuple[str, str, str]:

    raw_token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    ttl = max(
        60,
        int(
            os.getenv(
                "ARYA_OWNER_RECOVERY_TTL_SECONDS",
                "1800",
            )
        ),
    )

    expires_at = (
        utc_now() + timedelta(seconds=ttl)
    ).isoformat(timespec="seconds")

    return raw_token, token_hash, expires_at


def consume_recovery_token(
    connection: sqlite3.Connection,
    *,
    token: str,
    user_id: str,
) -> bool:

    table = "recovery_tokens"

    if not table_exists(connection, table):
        return False

    columns = table_columns(
        connection,
        table,
    )

    token_column = next(
        (
            name
            for name in (
                "token_hash",
                "token_digest",
                "hashed_token",
            )
            if name in columns
        ),
        None,
    )

    user_column = next(
        (
            name
            for name in (
                "user_id",
                "owner_id",
                "security_user_id",
            )
            if name in columns
        ),
        None,
    )

    expiry_column = next(
        (
            name
            for name in (
                "expires_at",
                "expiry",
                "expires",
            )
            if name in columns
        ),
        None,
    )

    used_column = next(
        (
            name
            for name in (
                "used_at",
                "consumed_at",
            )
            if name in columns
        ),
        None,
    )

    revoked_column = next(
        (
            name
            for name in (
                "used",
                "consumed",
                "revoked",
            )
            if name in columns
        ),
        None,
    )

    if not all(
        (
            token_column,
            user_column,
            expiry_column,
            used_column or revoked_column,
        )
    ):
        return False

    digest = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    row = connection.execute(
        f"""
        SELECT rowid, *
        FROM recovery_tokens
        WHERE "{token_column}" = ?
          AND "{user_column}" = ?
        LIMIT 1
        """,
        (digest, str(user_id)),
    ).fetchone()

    if not row:
        return False

    data = dict(row)

    if used_column and data.get(used_column):
        return False

    if revoked_column:
        revoked = str(
            data.get(revoked_column, "")
        ).lower()

        if revoked in ("1", "true", "yes"):
            return False

    expiry = parse_datetime(
        str(data.get(expiry_column, ""))
    )

    if not expiry or expiry <= utc_now():
        return False

    assignments = []
    parameters = []

    if used_column:
        assignments.append(
            f'"{used_column}" = ?'
        )
        parameters.append(utc_iso())

    if revoked_column:
        assignments.append(
            f'"{revoked_column}" = ?'
        )
        parameters.append(1)

    parameters.append(row["rowid"])

    cursor = connection.execute(
        f"""
        UPDATE recovery_tokens
        SET {", ".join(assignments)}
        WHERE rowid = ?
        """,
        tuple(parameters),
    )

    return cursor.rowcount == 1


# ============================================================
# DEVICE REACTIVATION
# ============================================================

def reactivate_device_with_audit(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    actor: str = "system",
    max_active_devices: Optional[int] = None,
) -> bool:

    table = "devices"

    if not table_exists(connection, table):
        return False

    columns = table_columns(
        connection,
        table,
    )

    id_column = next(
        (
            name
            for name in ("id", "device_id")
            if name in columns
        ),
        None,
    )

    active_column = next(
        (
            name
            for name in (
                "is_active",
                "active",
                "enabled",
            )
            if name in columns
        ),
        None,
    )

    if not id_column or not active_column:
        return False

    device = connection.execute(
        f"""
        SELECT *
        FROM devices
        WHERE CAST("{id_column}" AS TEXT) = ?
        LIMIT 1
        """,
        (str(device_id),),
    ).fetchone()

    if not device:
        return False

    if str(
        device[active_column]
    ).lower() in (
        "1",
        "true",
        "yes",
        "active",
    ):
        return True

    owner_column = next(
        (
            name
            for name in (
                "user_id",
                "owner_id",
                "security_user_id",
            )
            if name in columns
        ),
        None,
    )

    if max_active_devices is not None:
        if not owner_column:
            raise ValueError(
                "Cannot enforce device limit: owner column missing"
            )

        if max_active_devices < 1:
            raise ValueError(
                "Maximum active devices must be positive"
            )

        count = connection.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM devices
            WHERE "{owner_column}" = ?
              AND LOWER(CAST("{active_column}" AS TEXT))
                  IN ('1', 'true', 'yes', 'active')
            """,
            (device[owner_column],),
        ).fetchone()["total"]

        if int(count) >= max_active_devices:
            return False

    connection.execute(
        f"""
        UPDATE devices
        SET "{active_column}" = 1
        WHERE "{id_column}" = ?
        """,
        (device[id_column],),
    )

    append_audit_event(
        connection,
        action="device.reactivated",
        actor=actor,
        target_type="device",
        target_id=device_id,
        details={
            "device_limit_checked": (
                max_active_devices is not None
            ),
        },
    )

    return True


# ============================================================
# PAYMENT DESTINATION MANAGEMENT
# ============================================================

def disable_payment_destination_atomically(
    connection: sqlite3.Connection,
    *,
    table: str,
    destination_id: str,
    actor: str = "owner",
) -> bool:

    allowed_tables = {
        "bank_accounts",
        "wallet_destinations",
    }

    if table not in allowed_tables:
        raise ValueError(
            "Unsupported payment destination table"
        )

    if not table_exists(connection, table):
        return False

    columns = table_columns(
        connection,
        table,
    )

    id_column = next(
        (
            name
            for name in (
                "id",
                "destination_id",
            )
            if name in columns
        ),
        None,
    )

    active_column = next(
        (
            name
            for name in (
                "is_active",
                "active",
                "enabled",
                "is_enabled",
            )
            if name in columns
        ),
        None,
    )

    if not id_column or not active_column:
        return False

    cursor = connection.execute(
        f"""
        UPDATE "{table}"
        SET "{active_column}" = 0
        WHERE CAST("{id_column}" AS TEXT) = ?
        """,
        (str(destination_id),),
    )

    if cursor.rowcount:
        append_audit_event(
            connection,
            action="payment_destination.disabled",
            actor=actor,
            target_type=table,
            target_id=destination_id,
        )

    return cursor.rowcount == 1


# ============================================================
# MFA SECRET NORMALIZATION
# ============================================================

def normalize_base32_secret(secret: str) -> str:

    cleaned = "".join(
        (secret or "")
        .strip()
        .replace(" ", "")
        .upper()
        .split()
    )

    cleaned = cleaned.rstrip("=")

    if not cleaned:
        raise ValueError(
            "MFA secret is empty"
        )

    if any(
        char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        for char in cleaned
    ):
        raise ValueError(
            "MFA secret is not valid Base32"
        )

    padded = cleaned + (
        "=" * ((8 - len(cleaned) % 8) % 8)
    )

    try:
        base64.b32decode(
            padded,
            casefold=True,
        )

    except Exception as exc:
        raise ValueError(
            "MFA secret is not valid Base32"
        ) from exc

    return cleaned


def get_fernet():

    if Fernet is None:
        raise RuntimeError(
            "cryptography package is required for MFA encryption"
        )

    key = os.getenv(
        "ARYA_MFA_ENCRYPTION_KEY",
        "",
    ).strip()

    if not key:
        raise RuntimeError(
            "ARYA_MFA_ENCRYPTION_KEY is not configured"
        )

    try:
        return Fernet(
            key.encode("ascii")
        )

    except Exception as exc:
        raise RuntimeError(
            "ARYA_MFA_ENCRYPTION_KEY is invalid"
        ) from exc


def encrypt_mfa_secret(secret: str) -> str:

    canonical = normalize_base32_secret(secret)

    encrypted = get_fernet().encrypt(
        canonical.encode("ascii")
    )

    return encrypted.decode("ascii")


def decrypt_mfa_secret(encrypted: str) -> str:

    try:
        decrypted = get_fernet().decrypt(
            encrypted.encode("ascii")
        ).decode("ascii")

    except Exception as exc:
        raise ValueError(
            "Unable to decrypt MFA secret"
        ) from exc

    return normalize_base32_secret(decrypted)


# ============================================================
# PAYMENT WEBHOOK SIGNATURE
# ============================================================

def verify_provider_hmac(
    raw_body: bytes,
    supplied_signature: str,
    secret: str,
) -> bool:

    if not secret or not supplied_signature:
        return False

    expected = hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    candidate = supplied_signature.strip()

    if candidate.lower().startswith("sha256="):
        candidate = candidate[7:]

    return hmac.compare_digest(
        expected.lower(),
        candidate.lower(),
    )


# ============================================================
# OWNER LOGIN LOCKOUT
# ============================================================

def record_owner_login_failure(
    connection: sqlite3.Connection,
    *,
    owner_id: str,
    now_epoch: Optional[int] = None,
    max_attempts: Optional[int] = None,
    lockout_seconds: Optional[int] = None,
) -> tuple[int, int]:

    table = "security_users"

    if not table_exists(connection, table):
        return 0, 0

    columns = table_columns(
        connection,
        table,
    )

    id_column = next(
        (
            name
            for name in (
                "id",
                "user_id",
                "username",
                "email",
            )
            if name in columns
        ),
        None,
    )

    failures_column = next(
        (
            name
            for name in (
                "failed_attempts",
                "failed_login_attempts",
                "login_failures",
            )
            if name in columns
        ),
        None,
    )

    lock_column = next(
        (
            name
            for name in (
                "locked_until",
                "lockout_until",
                "lock_until",
            )
            if name in columns
        ),
        None,
    )

    if not id_column or not failures_column:
        return 0, 0

    now = int(
        now_epoch
        if now_epoch is not None
        else time.time()
    )

    limit = max_attempts or max(
        1,
        int(
            os.getenv(
                "ARYA_OWNER_MAX_FAILED_ATTEMPTS",
                "5",
            )
        ),
    )

    duration = lockout_seconds or max(
        30,
        int(
            os.getenv(
                "ARYA_OWNER_LOCKOUT_SECONDS",
                "900",
            )
        ),
    )

    row = connection.execute(
        f"""
        SELECT "{failures_column}"
        FROM security_users
        WHERE CAST("{id_column}" AS TEXT) = ?
        LIMIT 1
        """,
        (str(owner_id),),
    ).fetchone()

    if not row:
        return 0, 0

    failures = int(
        row[failures_column] or 0
    ) + 1

    locked_until = (
        now + duration
        if failures >= limit
        else 0
    )

    assignments = [
        f'"{failures_column}" = ?'
    ]

    parameters = [failures]

    if lock_column:
        assignments.append(
            f'"{lock_column}" = ?'
        )

        parameters.append(
            locked_until if locked_until else None
        )

    parameters.append(str(owner_id))

    connection.execute(
        f"""
        UPDATE security_users
        SET {", ".join(assignments)}
        WHERE CAST("{id_column}" AS TEXT) = ?
        """,
        tuple(parameters),
    )

    append_audit_event(
        connection,
        action="owner.login_failed",
        actor=str(owner_id),
        target_type="security_user",
        target_id=owner_id,
        details={
            "failed_attempts": failures,
            "locked_until": locked_until,
        },
    )

    return failures, locked_until


def clear_owner_login_failures(
    connection: sqlite3.Connection,
    *,
    owner_id: str,
) -> bool:

    table = "security_users"

    if not table_exists(connection, table):
        return False

    columns = table_columns(
        connection,
        table,
    )

    id_column = next(
        (
            name
            for name in (
                "id",
                "user_id",
                "username",
                "email",
            )
            if name in columns
        ),
        None,
    )

    failures_column = next(
        (
            name
            for name in (
                "failed_attempts",
                "failed_login_attempts",
                "login_failures",
            )
            if name in columns
        ),
        None,
    )

    lock_column = next(
        (
            name
            for name in (
                "locked_until",
                "lockout_until",
                "lock_until",
            )
            if name in columns
        ),
        None,
    )

    if not id_column or not failures_column:
        return False

    assignments = [
        f'"{failures_column}" = 0'
    ]

    if lock_column:
        assignments.append(
            f'"{lock_column}" = NULL'
        )

    cursor = connection.execute(
        f"""
        UPDATE security_users
        SET {", ".join(assignments)}
        WHERE CAST("{id_column}" AS TEXT) = ?
        """,
        (str(owner_id),),
    )

    return cursor.rowcount == 1


# ============================================================
# OPTIONAL FASTAPI ROUTER
# ============================================================

if APIRouter is not None:

    router = APIRouter(
        tags=["ARYA Commerce Security Hardening"]
    )

    @router.get("/hardening/health")
    def hardening_health():

        return {
            "module": "ARYA Commerce & Security Hardening",
            "version": MODULE_VERSION,
            "mode": "additive",
            "note": (
                "Security helpers require integration into "
                "the existing routes."
            ),
        }

    @router.get("/hardening/audit-check")
    def hardening_audit_check():

        try:
            connection = connect_database()

            try:
                exists = table_exists(
                    connection,
                    "audit_logs",
                )

                columns = (
                    sorted(
                        table_columns(
                            connection,
                            "audit_logs",
                        )
                    )
                    if exists
                    else []
                )

            finally:
                connection.close()

            return {
                "audit_logs_exists": exists,
                "columns": columns,
            }

        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail="Unable to inspect audit schema",
            ) from exc

else:
    router = None


# ============================================================
# PUBLIC API
# ============================================================

__all__ = [
    "MODULE_VERSION",
    "DB_PATH",
    "connect_database",
    "db_transaction",
    "table_exists",
    "table_columns",
    "append_audit_event",
    "request_fingerprint",
    "check_idempotency_reuse",
    "validate_verified_payment_reference",
    "calculate_subscription_period",
    "create_recovery_token",
    "consume_recovery_token",
    "reactivate_device_with_audit",
    "disable_payment_destination_atomically",
    "normalize_base32_secret",
    "get_fernet",
    "encrypt_mfa_secret",
    "decrypt_mfa_secret",
    "verify_provider_hmac",
    "record_owner_login_failure",
    "clear_owner_login_failures",
    "router",
]
