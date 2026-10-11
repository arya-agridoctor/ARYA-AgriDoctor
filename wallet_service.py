
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ARYA AgriDoctor - Dynamic Wallet & Payment Management
Version: 2.0.0

- Dynamic wallet addresses stored in SQLite.
- Wallet changes do not require a client application update.
- Historical wallet addresses and payment destinations are retained.
- Payment state transitions are protected by database transactions.
- Wallet administration requires a backend owner token.
- Payment verification requires an authorized owner or trusted provider.

IMPORTANT:
The owner token must remain on the backend. Never put it in Flutter,
Windows clients, public API responses, or source-controlled configuration.

This module does not independently verify blockchain transactions.
"""

import hashlib
import hmac
import json
import os
import re
import sqlite3

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Optional


DATABASE = os.getenv("ARYA_DATABASE", "arya.db")
ADMIN_TOKEN_ENV = "ARYA_WALLET_ADMIN_TOKEN"

PAYMENT_STATUSES = {
    "pending",
    "verified",
    "rejected",
    "cancelled",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(
        DATABASE,
        timeout=30,
        isolation_level="DEFERRED",
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _require_admin(admin_token: Optional[str]) -> None:
    expected = os.getenv(ADMIN_TOKEN_ENV)

    if not expected or not admin_token:
        raise PermissionError(
            "Wallet administration is not configured or authorized."
        )

    if not hmac.compare_digest(
        expected.encode("utf-8"),
        admin_token.encode("utf-8"),
    ):
        raise PermissionError("Invalid wallet administration credentials.")


def _normalize_currency(currency: str) -> str:
    if not isinstance(currency, str):
        raise ValueError("Currency must be text.")

    value = currency.strip().upper()

    if not value or len(value) > 16:
        raise ValueError("Invalid currency.")

    if not re.fullmatch(r"[A-Z0-9._-]+", value):
        raise ValueError("Invalid currency format.")

    return value


def _normalize_network(network: str) -> str:
    if not isinstance(network, str):
        raise ValueError("Network must be text.")

    value = network.strip()

    if not value or len(value) > 64:
        raise ValueError("Invalid network.")

    if any(ord(ch) < 32 for ch in value):
        raise ValueError("Invalid network format.")

    return value


def _normalize_address(address: str) -> str:
    if not isinstance(address, str):
        raise ValueError("Wallet address must be text.")

    value = address.strip()

    if not value or len(value) > 512:
        raise ValueError("Invalid wallet address.")

    if any(ch.isspace() for ch in value):
        raise ValueError("Wallet address cannot contain whitespace.")

    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        raise ValueError("Invalid wallet address characters.")

    return value


def _normalize_amount(amount: Any) -> str:
    try:
        value = Decimal(str(amount).strip())
    except (InvalidOperation, ValueError, AttributeError):
        raise ValueError("Invalid payment amount.") from None

    if not value.is_finite() or value <= 0:
        raise ValueError(
            "Payment amount must be a positive finite number."
        )

    if value.adjusted() > 30 or value.as_tuple().exponent < -18:
        raise ValueError("Payment amount exceeds supported precision.")

    return format(value.normalize(), "f")


def _address_fingerprint(address: str) -> str:
    return hashlib.sha256(address.encode("utf-8")).hexdigest()


def _audit(
    conn: sqlite3.Connection,
    action: str,
    details: dict[str, Any],
) -> None:
    conn.execute(
        """
        INSERT INTO wallet_change_audit
            (action, details, created_at)
        VALUES (?, ?, ?)
        """,
        (
            action,
            json.dumps(
                details,
                ensure_ascii=False,
                sort_keys=True,
            ),
            utc_now(),
        ),
    )


def _columns(
    conn: sqlite3.Connection,
    table: str,
) -> set[str]:
    # Only internal, constant table names may be passed here.
    return {
        str(row["name"])
        for row in conn.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }


def initialize_wallet_tables() -> None:
    """
    Create wallet tables and apply additive migrations.

    Existing wallet and payment records are retained.
    """
    conn = _connect()

    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS wallet_networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                currency TEXT NOT NULL,
                network TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(currency, network)
            );

            CREATE TABLE IF NOT EXISTS wallet_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                currency TEXT NOT NULL,
                network TEXT NOT NULL,
                address TEXT NOT NULL,
                address_fingerprint TEXT NOT NULL,
                label TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                deactivated_at TEXT,
                UNIQUE(currency, network, address)
            );

            CREATE TABLE IF NOT EXISTS wallet_change_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payment_intents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                currency TEXT NOT NULL,
                network TEXT NOT NULL,
                amount TEXT NOT NULL,
                wallet_address TEXT NOT NULL,
                wallet_address_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                transaction_id TEXT,
                verification_provider TEXT,
                verification_reference TEXT,
                created_at TEXT NOT NULL,
                verified_at TEXT
            );
            """
        )

        wallet_columns = _columns(conn, "wallet_addresses")

        if "label" not in wallet_columns:
            conn.execute(
                "ALTER TABLE wallet_addresses ADD COLUMN label TEXT"
            )

        if "deactivated_at" not in wallet_columns:
            conn.execute(
                """
                ALTER TABLE wallet_addresses
                ADD COLUMN deactivated_at TEXT
                """
            )

        payment_columns = _columns(conn, "payment_intents")

        migrations = {
            "wallet_address_fingerprint": "TEXT",
            "status": "TEXT NOT NULL DEFAULT 'pending'",
            "transaction_id": "TEXT",
            "verification_provider": "TEXT",
            "verification_reference": "TEXT",
            "created_at": "TEXT",
            "verified_at": "TEXT",
        }

        for column, sql_type in migrations.items():
            if column not in payment_columns:
                conn.execute(
                    f"""
                    ALTER TABLE payment_intents
                    ADD COLUMN {column} {sql_type}
                    """
                )

        conn.execute(
            """
            UPDATE payment_intents
            SET created_at = ?
            WHERE created_at IS NULL OR created_at = ''
            """,
            (utc_now(),),
        )

        # Backfill fingerprints for legacy payment records.
        rows = conn.execute(
            """
            SELECT id, wallet_address
            FROM payment_intents
            WHERE wallet_address_fingerprint IS NULL
               OR wallet_address_fingerprint = ''
            """
        ).fetchall()

        for row in rows:
            conn.execute(
                """
                UPDATE payment_intents
                SET wallet_address_fingerprint = ?
                WHERE id = ?
                """,
                (
                    _address_fingerprint(row["wallet_address"]),
                    row["id"],
                ),
            )

        # Ensure there is only one active wallet per currency/network.
        # Preserve all records; deactivate older active records.
        active_rows = conn.execute(
            """
            SELECT id, currency, network
            FROM wallet_addresses
            WHERE is_active = 1
            ORDER BY id DESC
            """
        ).fetchall()

        seen: set[tuple[str, str]] = set()

        for row in active_rows:
            key = (
                str(row["currency"]).strip().upper(),
                str(row["network"]).strip(),
            )

            if key in seen:
                conn.execute(
                    """
                    UPDATE wallet_addresses
                    SET is_active = 0,
                        deactivated_at = COALESCE(deactivated_at, ?)
                    WHERE id = ?
                    """,
                    (utc_now(), row["id"]),
                )
            else:
                seen.add(key)

        network_rows = conn.execute(
            """
            SELECT DISTINCT currency, network
            FROM wallet_addresses
            """
        ).fetchall()

        now = utc_now()

        for row in network_rows:
            currency = str(row["currency"]).strip().upper()
            network = str(row["network"]).strip()

            active_count = conn.execute(
                """
                SELECT COUNT(*) AS total
                FROM wallet_addresses
                WHERE currency = ?
                  AND network = ?
                  AND is_active = 1
                """,
                (currency, network),
            ).fetchone()["total"]

            conn.execute(
                """
                INSERT INTO wallet_networks (
                    currency, network, is_active, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(currency, network)
                DO UPDATE SET
                    is_active = excluded.is_active,
                    updated_at = excluded.updated_at
                """,
                (
                    currency,
                    network,
                    int(active_count > 0),
                    now,
                    now,
                ),
            )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_wallet_addresses_active
            ON wallet_addresses(currency, network, is_active)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_payment_intents_user
            ON payment_intents(user_id)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_payment_intents_status
            ON payment_intents(status)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_payment_intents_transaction
            ON payment_intents(transaction_id)
            """
        )

        # SQLite permits multiple NULL values in this unique index.
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_unique_transaction
            ON payment_intents(transaction_id)
            WHERE transaction_id IS NOT NULL
              AND transaction_id != ''
            """
        )

        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_wallet_one_active_per_network
            ON wallet_addresses(currency, network)
            WHERE is_active = 1
            """
        )

        conn.commit()

    finally:
        conn.close()


def add_wallet(
    currency: str,
    network: str,
    address: str,
    label: Optional[str] = None,
    *,
    admin_token: Optional[str] = None,
) -> int:
    """
    Add a new wallet or reactivate a historical wallet.

    The selected wallet becomes the active destination for the specified
    currency/network. The previous destination is retained as inactive.

    Call this function only from an owner-authenticated backend route.
    """
    _require_admin(admin_token)
    initialize_wallet_tables()

    currency = _normalize_currency(currency)
    network = _normalize_network(network)
    address = _normalize_address(address)

    if label is not None:
        if not isinstance(label, str) or len(label) > 120:
            raise ValueError("Wallet label must be at most 120 characters.")
        label = label.strip() or None

    fingerprint = _address_fingerprint(address)
    now = utc_now()

    conn = _connect()

    try:
        conn.execute("BEGIN IMMEDIATE")

        # Deactivate the current destination first.
        conn.execute(
            """
            UPDATE wallet_addresses
            SET is_active = 0,
                deactivated_at = ?
            WHERE currency = ?
              AND network = ?
              AND is_active = 1
            """,
            (now, currency, network),
        )

        # Reuse a historical record if the exact address already exists.
        conn.execute(
            """
            INSERT INTO wallet_addresses (
                currency, network, address,
                address_fingerprint, label, is_active,
                created_at, deactivated_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?, NULL)
            ON CONFLICT(currency, network, address)
            DO UPDATE SET
                address_fingerprint = excluded.address_fingerprint,
                label = excluded.label,
                is_active = 1,
                deactivated_at = NULL
            """,
            (
                currency,
                network,
                address,
                fingerprint,
                label,
                now,
            ),
        )

        row = conn.execute(
            """
            SELECT id
            FROM wallet_addresses
            WHERE currency = ?
              AND network = ?
              AND address = ?
            """,
            (currency, network, address),
        ).fetchone()

        wallet_id = int(row["id"])

        conn.execute(
            """
            INSERT INTO wallet_networks (
                currency, network, is_active, created_at, updated_at
            )
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(currency, network)
            DO UPDATE SET
                is_active = 1,
                updated_at = excluded.updated_at
            """,
            (currency, network, now, now),
        )

        _audit(
            conn,
            "wallet_activated",
            {
                "wallet_id": wallet_id,
                "currency": currency,
                "network": network,
                "address_fingerprint": fingerprint,
                "label": label,
            },
        )

        conn.commit()
        return wallet_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def set_active_wallet(
    wallet_id: int,
    *,
    admin_token: Optional[str] = None,
) -> bool:
    """Reactivate a historical wallet without deleting other records."""
    _require_admin(admin_token)
    initialize_wallet_tables()

    conn = _connect()

    try:
        conn.execute("BEGIN IMMEDIATE")

        target = conn.execute(
            "SELECT * FROM wallet_addresses WHERE id = ?",
            (wallet_id,),
        ).fetchone()

        if target is None:
            conn.rollback()
            return False

        now = utc_now()
        currency = target["currency"]
        network = target["network"]

        conn.execute(
            """
            UPDATE wallet_addresses
            SET is_active = 0,
                deactivated_at = ?
            WHERE currency = ?
              AND network = ?
              AND is_active = 1
            """,
            (now, currency, network),
        )

        conn.execute(
            """
            UPDATE wallet_addresses
            SET is_active = 1,
                deactivated_at = NULL
            WHERE id = ?
            """,
            (wallet_id,),
        )

        conn.execute(
            """
            INSERT INTO wallet_networks (
                currency, network, is_active, created_at, updated_at
            )
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(currency, network)
            DO UPDATE SET
                is_active = 1,
                updated_at = excluded.updated_at
            """,
            (currency, network, now, now),
        )

        _audit(
            conn,
            "wallet_reactivated",
            {
                "wallet_id": wallet_id,
                "currency": currency,
                "network": network,
                "address_fingerprint": target["address_fingerprint"],
            },
        )

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def deactivate_wallet(
    wallet_id: int,
    *,
    admin_token: Optional[str] = None,
) -> bool:
    """Deactivate a wallet while preserving its record and payment history."""
    _require_admin(admin_token)
    initialize_wallet_tables()

    conn = _connect()

    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            "SELECT * FROM wallet_addresses WHERE id = ?",
            (wallet_id,),
        ).fetchone()

        if row is None:
            conn.rollback()
            return False

        if not row["is_active"]:
            conn.commit()
            return True

        now = utc_now()

        conn.execute(
            """
            UPDATE wallet_addresses
            SET is_active = 0,
                deactivated_at = ?
            WHERE id = ?
            """,
            (now, wallet_id),
        )

        active_count = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM wallet_addresses
            WHERE currency = ?
              AND network = ?
              AND is_active = 1
            """,
            (row["currency"], row["network"]),
        ).fetchone()["total"]

        conn.execute(
            """
            UPDATE wallet_networks
            SET is_active = ?,
                updated_at = ?
            WHERE currency = ?
              AND network = ?
            """,
            (
                int(active_count > 0),
                now,
                row["currency"],
                row["network"],
            ),
        )

        _audit(
            conn,
            "wallet_deactivated",
            {
                "wallet_id": wallet_id,
                "currency": row["currency"],
                "network": row["network"],
                "address_fingerprint": row["address_fingerprint"],
            },
        )

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def list_active_wallets(
    currency: Optional[str] = None,
    network: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Return active public wallet destinations."""
    initialize_wallet_tables()

    clauses = ["is_active = 1"]
    params: list[Any] = []

    if currency:
        clauses.append("currency = ?")
        params.append(_normalize_currency(currency))

    if network:
        clauses.append("network = ?")
        params.append(_normalize_network(network))

    conn = _connect()

    try:
        rows = conn.execute(
            f"""
            SELECT id, currency, network, address, label, created_at
            FROM wallet_addresses
            WHERE {" AND ".join(clauses)}
            ORDER BY currency, network
            """,
            params,
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def list_wallet_history(
    *,
    admin_token: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Return all wallet records to the authenticated owner."""
    _require_admin(admin_token)
    initialize_wallet_tables()

    conn = _connect()

    try:
        rows = conn.execute(
            """
            SELECT id, currency, network, address, address_fingerprint,
                   label, is_active, created_at, deactivated_at
            FROM wallet_addresses
            ORDER BY id DESC
            """
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def create_payment_intent(
    user_id: Optional[int],
    currency: str,
    network: str,
    amount: str,
) -> dict[str, Any]:
    """
    Create a payment request and permanently snapshot its destination.

    Subsequent wallet changes do not alter existing payment destinations.
    """
    initialize_wallet_tables()

    currency = _normalize_currency(currency)
    network = _normalize_network(network)
    amount = _normalize_amount(amount)

    if user_id is not None:
        if isinstance(user_id, bool) or not isinstance(user_id, int):
            raise ValueError("Invalid user ID.")
        if user_id <= 0:
            raise ValueError("Invalid user ID.")

    conn = _connect()

    try:
        conn.execute("BEGIN IMMEDIATE")

        wallet = conn.execute(
            """
            SELECT id, currency, network, address,
                   address_fingerprint, label
            FROM wallet_addresses
            WHERE currency = ?
              AND network = ?
              AND is_active = 1
            LIMIT 1
            """,
            (currency, network),
        ).fetchone()

        if wallet is None:
            raise ValueError(
                "No active wallet is configured for this currency and network."
            )

        now = utc_now()

        cursor = conn.execute(
            """
            INSERT INTO payment_intents (
                user_id, currency, network, amount,
                wallet_address, wallet_address_fingerprint,
                status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                user_id,
                currency,
                network,
                amount,
                wallet["address"],
                wallet["address_fingerprint"],
                now,
            ),
        )

        payment_id = int(cursor.lastrowid)

        _audit(
            conn,
            "payment_intent_created",
            {
                "payment_id": payment_id,
                "user_id": user_id,
                "currency": currency,
                "network": network,
                "amount": amount,
                "wallet_id": wallet["id"],
                "wallet_address_fingerprint": wallet[
                    "address_fingerprint"
                ],
            },
        )

        conn.commit()

        return {
            "payment_id": payment_id,
            "user_id": user_id,
            "currency": currency,
            "network": network,
            "amount": amount,
            "wallet_address": wallet["address"],
            "wallet_label": wallet["label"],
            "status": "pending",
            "created_at": now,
        }

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_payment_intent(
    payment_id: int,
) -> Optional[dict[str, Any]]:
    """
    Fetch a payment record.

    The API route must check that the requesting user owns this payment
    or is an authorized owner. Do not expose this function without that check.
    """
    initialize_wallet_tables()

    conn = _connect()

    try:
        row = conn.execute(
            "SELECT * FROM payment_intents WHERE id = ?",
            (payment_id,),
        ).fetchone()

        return dict(row) if row is not None else None

    finally:
        conn.close()


def list_payment_intents(
    *,
    admin_token: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """List payment requests for the authenticated owner."""
    _require_admin(admin_token)
    initialize_wallet_tables()

    if status is not None and status not in PAYMENT_STATUSES:
        raise ValueError("Invalid payment status.")

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("Invalid limit.")

    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("Invalid offset.")

    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    conn = _connect()

    try:
        if status:
            rows = conn.execute(
                """
                SELECT *
                FROM payment_intents
                WHERE status = ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (status, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT *
                FROM payment_intents
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def mark_payment_verified(
    payment_id: int,
    transaction_id: str,
    provider: Optional[str] = None,
    verification_reference: Optional[str] = None,
    *,
    admin_token: Optional[str] = None,
) -> bool:
    """
    Mark a payment as verified by an authorized backend owner.

    This function records a verification decision; it does not independently
    prove that a blockchain transaction exists or has sufficient confirmations.
    """
    _require_admin(admin_token)
    initialize_wallet_tables()

    if isinstance(payment_id, bool) or not isinstance(payment_id, int):
        raise ValueError("Invalid payment ID.")

    if payment_id <= 0:
        raise ValueError("Invalid payment ID.")

    if not isinstance(transaction_id, str):
        raise ValueError("Transaction ID must be text.")

    transaction_id = transaction_id.strip()

    if not transaction_id or len(transaction_id) > 256:
        raise ValueError("Invalid transaction ID.")

    if any(ord(ch) < 33 or ord(ch) == 127 for ch in transaction_id):
        raise ValueError("Invalid transaction ID characters.")

    if provider is not None:
        provider = str(provider).strip()
        if not provider or len(provider) > 100:
            raise ValueError("Invalid verification provider.")

    if verification_reference is not None:
        verification_reference = str(verification_reference).strip()
        if len(verification_reference) > 512:
            raise ValueError("Verification reference is too long.")

    conn = _connect()

    try:
        conn.execute("BEGIN IMMEDIATE")

        payment = conn.execute(
            "SELECT * FROM payment_intents WHERE id = ?",
            (payment_id,),
        ).fetchone()

        if payment is None:
            conn.rollback()
            return False

        if payment["status"] == "verified":
            old_tx = payment["transaction_id"] or ""

            if hmac.compare_digest(old_tx, transaction_id):
                conn.commit()
                return True

            raise ValueError(
                "Payment is already verified with a different transaction ID."
            )

        if payment["status"] != "pending":
            raise ValueError(
                f"Payment cannot be verified from status "
                f"{payment['status']!r}."
            )

        duplicate = conn.execute(
            """
            SELECT id
            FROM payment_intents
            WHERE transaction_id = ?
              AND id != ?
            LIMIT 1
            """,
            (transaction_id, payment_id),
        ).fetchone()

        if duplicate is not None:
            raise ValueError(
                "This transaction ID is already assigned to another payment."
            )

        now = utc_now()

        conn.execute(
            """
            UPDATE payment_intents
            SET status = 'verified',
                transaction_id = ?,
                verification_provider = ?,
                verification_reference = ?,
                verified_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (
                transaction_id,
                provider,
                verification_reference,
                now,
                payment_id,
            ),
        )

        _audit(
            conn,
            "payment_verified",
            {
                "payment_id": payment_id,
                "transaction_id_fingerprint": hashlib.sha256(
                    transaction_id.encode("utf-8")
                ).hexdigest(),
                "provider": provider,
                "verification_reference": verification_reference,
                "currency": payment["currency"],
                "network": payment["network"],
                "amount": payment["amount"],
                "wallet_address_fingerprint": payment[
                    "wallet_address_fingerprint"
                ],
            },
        )

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def reject_payment(
    payment_id: int,
    reason: str,
    *,
    admin_token: Optional[str] = None,
) -> bool:
    """Reject a pending payment while retaining its history."""
    _require_admin(admin_token)
    initialize_wallet_tables()

    if isinstance(payment_id, bool) or not isinstance(payment_id, int):
        raise ValueError("Invalid payment ID.")

    if payment_id <= 0:
        raise ValueError("Invalid payment ID.")

    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("A rejection reason is required.")

    reason = reason.strip()

    if len(reason) > 1000:
        raise ValueError("Rejection reason is too long.")

    conn = _connect()

    try:
        conn.execute("BEGIN IMMEDIATE")

        payment = conn.execute(
            """
            SELECT id, status, currency, network, amount,
                   wallet_address_fingerprint
            FROM payment_intents
            WHERE id = ?
            """,
            (payment_id,),
        ).fetchone()

        if payment is None:
            conn.rollback()
            return False

        if payment["status"] != "pending":
            raise ValueError("Only pending payments can be rejected.")

        conn.execute(
            """
            UPDATE payment_intents
            SET status = 'rejected'
            WHERE id = ? AND status = 'pending'
            """,
            (payment_id,),
        )

        _audit(
            conn,
            "payment_rejected",
            {
                "payment_id": payment_id,
                "reason": reason,
                "currency": payment["currency"],
                "network": payment["network"],
                "amount": payment["amount"],
                "wallet_address_fingerprint": payment[
                    "wallet_address_fingerprint"
                ],
            },
        )

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def cancel_payment_intent(
    payment_id: int,
    *,
    user_id: Optional[int] = None,
    admin_token: Optional[str] = None,
) -> bool:
    """
    Cancel a pending payment.

    Owner authorization takes precedence. Otherwise, a caller must supply
    the authenticated user's ID. The API must derive that ID from the
    verified session/token, never from untrusted request data.
    """
    is_admin = False
    expected = os.getenv(ADMIN_TOKEN_ENV)

    if admin_token and expected:
        is_admin = hmac.compare_digest(
            expected.encode("utf-8"),
            admin_token.encode("utf-8"),
        )

    if not is_admin:
        if (
            isinstance(user_id, bool)
            or not isinstance(user_id, int)
            or user_id <= 0
        ):
            raise PermissionError("Authenticated user identity is required.")

    if isinstance(payment_id, bool) or not isinstance(payment_id, int):
        raise ValueError("Invalid payment ID.")

    if payment_id <= 0:
        raise ValueError("Invalid payment ID.")

    initialize_wallet_tables()
    conn = _connect()

    try:
        conn.execute("BEGIN IMMEDIATE")

        if is_admin:
            payment = conn.execute(
                """
                SELECT id, user_id, status
                FROM payment_intents
                WHERE id = ?
                """,
                (payment_id,),
            ).fetchone()
        else:
            payment = conn.execute(
                """
                SELECT id, user_id, status
                FROM payment_intents
                WHERE id = ? AND user_id = ?
                """,
                (payment_id, user_id),
            ).fetchone()

        if payment is None:
            conn.rollback()
            return False

        if payment["status"] != "pending":
            raise ValueError("Only pending payments can be cancelled.")

        conn.execute(
            """
            UPDATE payment_intents
            SET status = 'cancelled'
            WHERE id = ? AND status = 'pending'
            """,
            (payment_id,),
        )

        _audit(
            conn,
            "payment_cancelled",
            {
                "payment_id": payment_id,
                "user_id": payment["user_id"],
                "cancelled_by": "owner" if is_admin else "user",
            },
        )

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_wallet_configuration(
    *,
    admin_token: Optional[str] = None,
) -> dict[str, Any]:
    """Return current wallet settings for the authenticated owner."""
    _require_admin(admin_token)
    initialize_wallet_tables()

    conn = _connect()

    try:
        networks = conn.execute(
            """
            SELECT currency, network, is_active, created_at, updated_at
            FROM wallet_networks
            ORDER BY currency, network
            """
        ).fetchall()

        wallets = conn.execute(
            """
            SELECT id, currency, network, address, label,
                   is_active, created_at, deactivated_at
            FROM wallet_addresses
            ORDER BY id DESC
            """
        ).fetchall()

        return {
            "networks": [dict(row) for row in networks],
            "wallets": [dict(row) for row in wallets],
            "generated_at": utc_now(),
        }

    finally:
        conn.close()


def get_wallet_public_configuration() -> dict[str, Any]:
    """Return only currently active wallet destinations."""
    return {
        "wallets": list_active_wallets(),
        "updated_at": utc_now(),
    }


def list_wallet_audit(
    *,
    admin_token: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return audit records for the authenticated owner."""
    _require_admin(admin_token)
    initialize_wallet_tables()

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("Invalid limit.")

    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("Invalid offset.")

    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    conn = _connect()

    try:
        rows = conn.execute(
            """
            SELECT id, action, details, created_at
            FROM wallet_change_audit
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

        result = []

        for row in rows:
            item = dict(row)

            try:
                item["details"] = json.loads(item["details"])
            except (TypeError, json.JSONDecodeError):
                item["details"] = {}

            result.append(item)

        return result

    finally:
        conn.close()


def self_test() -> dict[str, Any]:
    """
    Basic isolated database test.

    Uses a temporary database and does not intentionally modify
    the configured production database.
    """
    import tempfile

    original_database = DATABASE
    original_token = os.environ.get(ADMIN_TOKEN_ENV)

    results: dict[str, Any] = {
        "ok": False,
        "checks": [],
        "errors": [],
    }

    test_token = "arya-wallet-self-test-token"

    try:
        with tempfile.TemporaryDirectory(
            prefix="arya-wallet-test-"
        ) as temp_dir:
            globals()["DATABASE"] = os.path.join(
                temp_dir,
                "wallet-test.db",
            )
            os.environ[ADMIN_TOKEN_ENV] = test_token

            initialize_wallet_tables()
            results["checks"].append("initialize_tables")

            first_wallet_id = add_wallet(
                "USDT",
                "TRC20",
                "TTestWalletAddress123",
                "Test wallet A",
                admin_token=test_token,
            )
            results["checks"].append("add_wallet")

            payment = create_payment_intent(
                user_id=1,
                currency="USDT",
                network="TRC20",
                amount="10",
            )
            results["checks"].append("create_payment_intent")

            add_wallet(
                "USDT",
                "TRC20",
                "TTestWalletAddress456",
                "Test wallet B",
                admin_token=test_token,
            )

            old_payment = get_payment_intent(payment["payment_id"])

            if (
                old_payment is None
                or old_payment["wallet_address"]
                != "TTestWalletAddress123"
            ):
                raise AssertionError(
                    "Changing the wallet altered an existing payment."
                )

            results["checks"].append("historical_destination_preserved")

            active = list_active_wallets("USDT", "TRC20")

            if (
                len(active) != 1
                or active[0]["address"] != "TTestWalletAddress456"
            ):
                raise AssertionError("Active wallet selection failed.")

            results["checks"].append("single_active_wallet")

            if not deactivate_wallet(
                active[0]["id"],
                admin_token=test_token,
            ):
                raise AssertionError("Wallet deactivation failed.")

            if list_active_wallets("USDT", "TRC20"):
                raise AssertionError("Deactivated wallet remains active.")

            results["checks"].append("deactivate_wallet")

            if not set_active_wallet(
                first_wallet_id,
                admin_token=test_token,
            ):
                raise AssertionError("Wallet reactivation failed.")

            results["checks"].append("reactivate_wallet")

            if not mark_payment_verified(
                payment["payment_id"],
                "TEST-TX-001",
                provider="self-test",
                verification_reference="offline-test",
                admin_token=test_token,
            ):
                raise AssertionError("Payment verification failed.")

            results["checks"].append("verify_payment")

            try:
                create_payment_intent(
                    user_id=2,
                    currency="USDT",
                    network="TRC20",
                    amount="-1",
                )
            except ValueError:
                results["checks"].append("reject_invalid_amount")
            else:
                raise AssertionError("Invalid amount was accepted.")

            try:
                mark_payment_verified(
                    payment["payment_id"],
                    "TEST-TX-002",
                    admin_token=test_token,
                )
            except ValueError:
                results["checks"].append("prevent_transaction_replacement")
            else:
                raise AssertionError(
                    "Verified payment transaction was unexpectedly replaced."
                )

            results["ok"] = True

    except Exception as exc:
        results["errors"].append(
            f"{type(exc).__name__}: {exc}"
        )

    finally:
        globals()["DATABASE"] = original_database

        if original_token is None:
            os.environ.pop(ADMIN_TOKEN_ENV, None)
        else:
            os.environ[ADMIN_TOKEN_ENV] = original_token

    return results


if __name__ == "__main__":
    print(
        json.dumps(
            self_test(),
            ensure_ascii=False,
            indent=2,
        )
    )
