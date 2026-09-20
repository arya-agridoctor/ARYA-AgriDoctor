import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional


DATABASE = os.getenv("ARYA_DATABASE", "arya.db")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


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
            json.dumps(details, ensure_ascii=False),
            utc_now(),
        ),
    )


def _address_fingerprint(address: str) -> str:
    return hashlib.sha256(
        address.encode("utf-8")
    ).hexdigest()


def initialize_wallet_tables() -> None:
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

            CREATE INDEX IF NOT EXISTS idx_wallet_addresses_active
            ON wallet_addresses(currency, network, is_active);

            CREATE INDEX IF NOT EXISTS idx_payment_intents_user
            ON payment_intents(user_id);

            CREATE INDEX IF NOT EXISTS idx_payment_intents_status
            ON payment_intents(status);
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
) -> int:
    initialize_wallet_tables()

    currency = currency.strip().upper()
    network = network.strip()
    address = address.strip()

    if not currency:
        raise ValueError("Currency is required.")

    if not network:
        raise ValueError("Network is required.")

    if not address:
        raise ValueError("Wallet address is required.")

    fingerprint = _address_fingerprint(address)
    now = utc_now()

    conn = _connect()

    try:
        cursor = conn.execute(
            """
            INSERT INTO wallet_addresses
            (
                currency,
                network,
                address,
                address_fingerprint,
                label,
                is_active,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?)
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

        conn.execute(
            """
            INSERT INTO wallet_networks
            (
                currency,
                network,
                is_active,
                created_at,
                updated_at
            )
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(currency, network)
            DO UPDATE SET
                is_active = 1,
                updated_at = excluded.updated_at
            """,
            (
                currency,
                network,
                now,
                now,
            ),
        )

        _audit(
            conn,
            "wallet_added",
            {
                "wallet_id": cursor.lastrowid,
                "currency": currency,
                "network": network,
                "address_fingerprint": fingerprint,
                "label": label,
            },
        )

        conn.commit()

        return int(cursor.lastrowid)

    finally:
        conn.close()


def deactivate_wallet(wallet_id: int) -> bool:
    initialize_wallet_tables()

    conn = _connect()

    try:
        row = conn.execute(
            """
            SELECT *
            FROM wallet_addresses
            WHERE id = ?
            """,
            (wallet_id,),
        ).fetchone()

        if row is None:
            return False

        if not row["is_active"]:
            return True

        now = utc_now()

        conn.execute(
            """
            UPDATE wallet_addresses
            SET
                is_active = 0,
                deactivated_at = ?
            WHERE id = ?
            """,
            (
                now,
                wallet_id,
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

    finally:
        conn.close()


def list_active_wallets(
    currency: Optional[str] = None,
    network: Optional[str] = None,
) -> list[dict[str, Any]]:
    initialize_wallet_tables()

    conn = _connect()

    try:
        query = """
            SELECT
                id,
                currency,
                network,
                address,
                label,
                created_at
            FROM wallet_addresses
            WHERE is_active = 1
        """

        params: list[Any] = []

        if currency:
            query += " AND currency = ?"
            params.append(currency.strip().upper())

        if network:
            query += " AND network = ?"
            params.append(network.strip())

        query += " ORDER BY id DESC"

        rows = conn.execute(
            query,
            params,
        ).fetchall()

        return [
            {
                "id": row["id"],
                "currency": row["currency"],
                "network": row["network"],
                "address": row["address"],
                "label": row["label"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    finally:
        conn.close()


def create_payment_intent(
    user_id: Optional[int],
    currency: str,
    network: str,
    amount: str,
) -> dict[str, Any]:
    initialize_wallet_tables()

    currency = currency.strip().upper()
    network = network.strip()
    amount = str(amount).strip()

    if not currency:
        raise ValueError("Currency is required.")

    if not network:
        raise ValueError("Network is required.")

    if not amount:
        raise ValueError("Amount is required.")

    conn = _connect()

    try:
        wallet = conn.execute(
            """
            SELECT *
            FROM wallet_addresses
            WHERE currency = ?
              AND network = ?
              AND is_active = 1
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                currency,
                network,
            ),
        ).fetchone()

        if wallet is None:
            raise ValueError(
                "No active wallet is configured for this currency and network."
            )

        now = utc_now()

        cursor = conn.execute(
            """
            INSERT INTO payment_intents
            (
                user_id,
                currency,
                network,
                amount,
                wallet_address,
                wallet_address_fingerprint,
                status,
                created_at
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

    finally:
        conn.close()


def get_payment_intent(
    payment_id: int,
) -> Optional[dict[str, Any]]:
    initialize_wallet_tables()

    conn = _connect()

    try:
        row = conn.execute(
            """
            SELECT *
            FROM payment_intents
            WHERE id = ?
            """,
            (payment_id,),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()


def mark_payment_verified(
    payment_id: int,
    transaction_id: str,
    provider: Optional[str] = None,
    verification_reference
