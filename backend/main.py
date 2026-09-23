import os
import sqlite3
import hashlib
import secrets
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

import requests
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field


# ============================================================
# ARYA AgriDoctor Backend
# Stage 2 - Security / Authentication
# ============================================================

APP_NAME = "ARYA AgriDoctor Backend"
APP_VERSION = "1.0.0"

DATABASE = os.getenv("ARYA_DATABASE", "arya.db")

MASTER_EMAIL = os.getenv("ARYA_MASTER_EMAIL", "")
MASTER_SECRET = os.getenv("ARYA_MASTER_SECRET", "")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")

DAILY_AI_LIMIT = int(os.getenv("ARYA_DAILY_AI_LIMIT", "30"))
DEVICE_LIMIT = int(os.getenv("ARYA_DEVICE_LIMIT", "3"))

AI_INPUT_COST_PER_1M = float(
    os.getenv("AI_INPUT_COST_PER_1M", "0")
)

AI_OUTPUT_COST_PER_1M = float(
    os.getenv("AI_OUTPUT_COST_PER_1M", "0")
)

PASSWORD_ITERATIONS = int(
    os.getenv("ARYA_PASSWORD_ITERATIONS", "200000")
)

USER_TOKEN_DAYS = int(
    os.getenv("ARYA_USER_TOKEN_DAYS", "30")
)

OWNER_TOKEN_HOURS = int(
    os.getenv("ARYA_OWNER_TOKEN_HOURS", "12")
)


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
)


# ============================================================
# DATABASE
# ============================================================

def db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def ensure_column(
    connection,
    table: str,
    column: str,
    definition: str,
):
    columns = {
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }

    if column not in columns:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_db():
    connection = db()
    cursor = connection.cursor()

    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            phone TEXT,
            country TEXT,
            language TEXT DEFAULT 'fa',
            role TEXT DEFAULT 'user',
            password_hash TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS farms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT,
            country TEXT,
            region TEXT,
            latitude REAL,
            longitude REAL,
            climate TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farm_id INTEGER NOT NULL,
            name TEXT,
            area REAL,
            area_unit TEXT DEFAULT 'hectare',
            soil_type TEXT,
            irrigation_type TEXT,
            latitude REAL,
            longitude REAL,
            boundary_json TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS crops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farm_id INTEGER,
            land_id INTEGER,
            name TEXT,
            variety TEXT,
            planting_date TEXT,
            area REAL,
            status TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS soil_lab_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            land_id INTEGER,
            test_date TEXT,
            ph REAL,
            ec REAL,
            nitrogen REAL,
            phosphorus REAL,
            potassium REAL,
            organic_matter REAL,
            salinity TEXT,
            laboratory TEXT,
            raw_json TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS water_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farm_id INTEGER,
            name TEXT,
            source_type TEXT,
            latitude REAL,
            longitude REAL,
            quantity REAL,
            quality TEXT,
            raw_json TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS weather_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farm_id INTEGER,
            location TEXT,
            latitude REAL,
            longitude REAL,
            observed_at TEXT,
            temperature REAL,
            humidity REAL,
            rainfall REAL,
            wind_speed REAL,
            raw_json TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            farm_id INTEGER,
            category TEXT,
            question TEXT,
            recommendation TEXT,
            confidence REAL,
            risk TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            request_id TEXT,
            model TEXT,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            input_cost REAL DEFAULT 0,
            output_cost REAL DEFAULT 0,
            total_cost REAL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            country TEXT,
            method TEXT,
            amount REAL,
            currency TEXT,
            reference TEXT,
            status TEXT DEFAULT 'pending',
            verified_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            plan TEXT,
            started_at TEXT,
            expires_at TEXT,
            status TEXT DEFAULT 'inactive',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activation_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_hash TEXT UNIQUE,
            duration_days INTEGER DEFAULT 365,
            used INTEGER DEFAULT 0,
            used_by INTEGER,
            created_at TEXT NOT NULL,
            used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_hash TEXT,
            device_name TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            category TEXT,
            original_language TEXT,
            original_text TEXT,
            persian_translation TEXT,
            status TEXT DEFAULT 'new',
            attachment TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS feedback_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feedback_id INTEGER,
            sender_role TEXT,
            original_language TEXT,
            original_text TEXT,
            persian_text TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            action TEXT,
            target TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_change_proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            change_json TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewed_by TEXT
        );

        CREATE TABLE IF NOT EXISTS knowledge_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT,
            title TEXT,
            content TEXT,
            status TEXT DEFAULT 'draft',
            created_at TEXT NOT NULL,
            approved_at TEXT
        );

        CREATE TABLE IF NOT EXISTS sync_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            operation_id TEXT UNIQUE,
            operation TEXT,
            payload TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            processed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            body TEXT,
            type TEXT,
            read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            last_seen TEXT
        );
        """
    )

    # Migration for databases created by older versions.
    ensure_column(
        connection,
        "users",
        "password_hash",
        "TEXT",
    )

    connection.commit()
    connection.close()


init_db()


# ============================================================
# GENERAL HELPERS
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def sha256(value: str):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


# ============================================================
# PASSWORD SECURITY
# ============================================================

def hash_password(password: str):
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = secrets.token_bytes(32)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )

    return (
        f"pbkdf2_sha256$"
        f"{PASSWORD_ITERATIONS}$"
        f"{salt.hex()}$"
        f"{derived.hex()}"
    )


def verify_password(
    password: str,
    stored_hash: Optional[str],
):
    if not password or not stored_hash:
        return False

    try:
        parts = stored_hash.split("$")

        if len(parts) != 4:
            return False

        algorithm = parts[0]
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected = parts[3]

        if algorithm != "pbkdf2_sha256":
            return False

        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return secrets.compare_digest(
            derived.hex(),
            expected,
        )

    except Exception:
        return False


# ============================================================
# AUDIT
# ============================================================

def audit(
    actor: str,
    action: str,
    target: str = "",
    details: Any = None,
):
    connection = db()

    connection.execute(
        """
        INSERT INTO audit_logs
        (
            actor,
            action,
            target,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            actor,
            action,
            target,
            json.dumps(
                details,
                ensure_ascii=False,
            )
            if details is not None
            else "",
            now_iso(),
        ),
    )

    connection.commit()
    connection.close()


# ============================================================
# USER HELPERS
# ============================================================

def get_user(user_id: int):
    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    connection.close()

    return row


def get_user_by_email(email: str):
    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM users
        WHERE lower(email) = lower(?)
        """,
        (email,),
    ).fetchone()

    connection.close()

    return row


# ============================================================
# AUTH TOKEN HELPERS
# ============================================================

def create_auth_token(
    user_id: Optional[int],
    role: str,
    lifetime: timedelta,
):
    raw_token = secrets.token_urlsafe(48)

    token_hash = sha256(raw_token)

    created = datetime.now(timezone.utc)

    expires = created + lifetime

    connection = db()

    connection.execute(
        """
        INSERT INTO auth_tokens
        (
            token_hash,
            user_id,
            role,
            created_at,
            expires_at,
            revoked,
            last_seen
        )
        VALUES (?, ?, ?, ?, ?, 0, ?)
        """,
        (
            token_hash,
            user_id,
            role,
            created.isoformat(),
            expires.isoformat(),
            created.isoformat(),
        ),
    )

    connection.commit()
    connection.close()

    return raw_token, expires.isoformat()


def extract_bearer_token(
    authorization: Optional[str],
):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization token is required.",
        )

    parts = authorization.strip().split()

    if len(parts) != 2:
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header.",
        )

    if parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Authorization must use Bearer token.",
        )

    if not parts[1]:
        raise HTTPException(
            status_code=401,
            detail="Invalid bearer token.",
        )

    return parts[1]


def authenticate(
    authorization: Optional[str],
):
    raw_token = extract_bearer_token(
        authorization
    )

    token_hash = sha256(raw_token)

    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM auth_tokens
        WHERE token_hash = ?
        AND revoked = 0
        """,
        (token_hash,),
    ).fetchone()

    if not row:
        connection.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked token.",
        )

    try:
        expires = datetime.fromisoformat(
            row["expires_at"]
        )
    except Exception:
        connection.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid token expiration.",
        )

    if expires <= datetime.now(timezone.utc):
        connection.execute(
            """
            UPDATE auth_tokens
            SET revoked = 1
            WHERE id = ?
            """,
            (row["id"],),
        )

        connection.commit()
        connection.close()

        raise HTTPException(
            status_code=401,
            detail="Token expired.",
        )

    connection.execute(
        """
        UPDATE auth_tokens
        SET last_seen = ?
        WHERE id = ?
        """,
        (
            now_iso(),
            row["id"],
        ),
    )

    connection.commit()
    connection.close()

    return {
        "token_id": row["id"],
        "user_id": row["user_id"],
        "role": row["role"],
    }


def require_owner(
    authorization: Optional[str],
):
    auth = authenticate(authorization)

    if auth["role"] != "owner":
        raise HTTPException(
            status_code=403,
            detail="OWNER access required.",
        )

    return auth


def require_user(
    user_id: int,
    authorization: Optional[str],
):
    auth = authenticate(authorization)

    if auth["role"] == "owner":
        return auth

    if auth["user_id"] != user_id:
        raise HTTPException(
            status_code=403,
            detail="Access denied for this user.",
        )

    return auth


# ============================================================
# OWNERSHIP HELPERS
# ============================================================

def farm_owned_by_user(
    farm_id: int,
    user_id: int,
):
    connection = db()

    row = connection.execute(
        """
        SELECT id
        FROM farms
        WHERE id = ?
        AND user_id = ?
        """,
        (
            farm_id,
            user_id,
        ),
    ).fetchone()

    connection.close()

    return row is not None


def land_owned_by_user(
    land_id: int,
    user_id: int,
):
    connection = db()

    row = connection.execute(
        """
        SELECT lands.id
        FROM lands
        JOIN farms
            ON farms.id = lands.farm_id
        WHERE lands.id = ?
        AND farms.user_id = ?
        """,
        (
            land_id,
            user_id,
        ),
    ).fetchone()

    connection.close()

    return row is not None


def crop_owned_by_user(
    farm_id: Optional[int],
    land_id: Optional[int],
    user_id: int,
):
    connection = db()

    if farm_id is not None:
        row = connection.execute(
            """
            SELECT crops.id
            FROM crops
            LEFT JOIN farms
                ON farms.id = crops.farm_id
            LEFT JOIN lands
                ON lands.id = crops.land_id
            LEFT JOIN farms AS land_farms
                ON land_farms.id = lands.farm_id
            WHERE (
                farms.user_id = ?
                OR land_farms.user_id = ?
            )
            AND crops.farm_id = ?
            LIMIT 1
            """,
            (
                user_id,
                user_id,
                farm_id,
            ),
        ).fetchone()

    elif land_id is not None:
        row = connection.execute(
            """
            SELECT crops.id
            FROM crops
            JOIN lands
                ON lands.id = crops.land_id
            JOIN farms
                ON farms.id = lands.farm_id
            WHERE crops.land_id = ?
            AND farms.user_id = ?
            LIMIT 1
            """,
            (
                land_id,
                user_id,
            ),
        ).fetchone()

    else:
        row = None

    connection.close()

    return row is not None


# ============================================================
# AI USAGE
# ============================================================

def ai_requests_today(user_id: int):
    connection = db()

    row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM ai_usage
        WHERE user_id = ?
        AND created_at >= ?
        """,
        (
            user_id,
            datetime.now(timezone.utc)
            .replace(
                hour=0,
                minute=0,
                second=0,
                microsecond=0,
            )
            .isoformat(),
        ),
    ).fetchone()

    connection.close()

    return int(row["count"])


def save_ai_usage(
    user_id: int,
    request_id: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
):
    input_cost = (
        input_tokens / 1_000_000
    ) * AI_INPUT_COST_PER_1M

    output_cost = (
        output_tokens / 1_000_000
    ) * AI_OUTPUT_COST_PER_1M

    total_cost = (
        input_cost + output_cost
    )

    connection = db()

    connection.execute(
        """
        INSERT INTO ai_usage
        (
            user_id,
            request_id,
            model,
            input_tokens,
            output_tokens,
            input_cost,
            output_cost,
            total_cost,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            request_id,
            model,
            input_tokens,
            output_tokens,
            input_cost,
            output_cost,
            total_cost,
            now_iso(),
        ),
    )

    connection.commit()
    connection.close()


# ============================================================
# MODELS
# ============================================================

class UserCreate(BaseModel):
    name: Optional[str] = None
    email: str
    password: str = Field(
        min_length=8,
        max_length=128,
    )
    phone: Optional[str] = None
    country: Optional[str] = None
    language: str = "fa"


class UserLogin(BaseModel):
    email: str
    password: str


class OwnerLogin(BaseModel):
    email: str
    secret: str


class FarmCreate(BaseModel):
    user_id: int
    name: str
    country: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    climate: Optional[str] = None


class LandCreate(BaseModel):
    farm_id: int
    name: str
    area: Optional[float] = None
    area_unit: str = "hectare"
    soil_type: Optional[str] = None
    irrigation_type: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    boundary_json: Optional[str] = None


class CropCreate(BaseModel):
    farm_id: Optional[int] = None
    land_id: Optional[int] = None
    name: str
    variety: Optional[str] = None
    planting_date: Optional[str] = None
    area: Optional[float] = None
    status: Optional[str] = "active"


class SoilLabCreate(BaseModel):
    land_id: int
    test_date: Optional[str] = None
    ph: Optional[float] = None
    ec: Optional[float] = None
    nitrogen: Optional[float] = None
    phosphorus: Optional[float] = None
    potassium: Optional[float] = None
    organic_matter: Optional[float] = None
    salinity: Optional[str] = None
    laboratory: Optional[str] = None
    raw_json: Optional[dict] = None


class WaterSourceCreate(BaseModel):
    farm_id: int
    name: str
    source_type: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    quantity: Optional[float] = None
    quality: Optional[str] = None
    raw_json: Optional[dict] = None


class AIAsk(BaseModel):
    user_id: int
    question: str
    farm_id: Optional[int] = None
    crop: Optional[str] = None
    region: Optional[str] = None
    language: str = "fa"
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class PaymentCreate(BaseModel):
    user_id: int
    country: str
    method: str
    amount: float
    currency: str
    reference: Optional[str] = None


class ActivationUse(BaseModel):
    user_id: int
    code: str
    device_id: Optional[str] = None


class DeviceCreate(BaseModel):
    user_id: int
    device_id: str
    device_name: Optional[str] = None


class FeedbackCreate(BaseModel):
    user_id: Optional[int] = None
    category: str
    original_language: str
    original_text: str
    attachment: Optional[str] = None


class AIProposalCreate(BaseModel):
    title: str
    description: str
    change_json: Optional[dict] = None


class ProposalDecision(BaseModel):
    decision: str
    reviewer: str


class KnowledgeCreate(BaseModel):
    version: str
    title: str
    content: str


class SyncCreate(BaseModel):
    user_id: int
    operation_id: str
    operation: str
    payload: dict


# ============================================================
# ROOT / HEALTH
# ============================================================

@app.get("/")
def root():
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "time": now_iso(),
    }


# ============================================================
# AUTHENTICATION
# ============================================================

@app.post("/auth/register")
def auth_register(data: UserCreate):
    password_hash = hash_password(
        data.password
    )

    connection = db()

    try:
        cursor = connection.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                phone,
                country,
                language,
                role,
                password_hash,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, 'user', ?, ?)
            """,
            (
                data.name,
                data.email.strip(),
                data.phone,
                data.country,
                data.language,
                password_hash,
                now_iso(),
            ),
        )

        connection.commit()

        user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        connection.close()

        raise HTTPException(
            status_code=409,
            detail="User email already exists.",
        )

    connection.close()

    audit(
        "system",
        "create_user",
        str(user_id),
    )

    return {
        "id": user_id,
        "status": "created",
        "login_required": True,
    }


@app.post("/auth/login")
def auth_login(data: UserLogin):
    user = get_user_by_email(
        data.email.strip()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    if not verify_password(
        data.password,
        user["password_hash"],
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    role = user["role"] or "user"

    token, expires_at = create_auth_token(
        user_id=int(user["id"]),
        role=role,
        lifetime=timedelta(
            days=USER_TOKEN_DAYS
        ),
    )

    audit(
        str(user["id"]),
        "user_login",
        str(user["id"]),
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "country": user["country"],
            "language": user["language"],
            "role": role,
        },
    }


@app.post("/owner/login")
def owner_login(data: OwnerLogin):
    if not MASTER_EMAIL or not MASTER_SECRET:
        raise HTTPException(
            status_code=503,
            detail=(
                "OWNER credentials are not configured "
                "on the backend."
            ),
        )

    email_ok = secrets.compare_digest(
        data.email.strip(),
        MASTER_EMAIL,
    )

    secret_ok = secrets.compare_digest(
        data.secret,
        MASTER_SECRET,
    )

    if not email_ok or not secret_ok:
        audit(
            "unknown",
            "owner_login_failed",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid OWNER credentials.",
        )

    token, expires_at = create_auth_token(
        user_id=None,
        role="owner",
        lifetime=timedelta(
            hours=OWNER_TOKEN_HOURS
        ),
    )

    audit(
        "owner",
        "owner_login",
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "role": "owner",
    }


@app.get("/auth/me")
def auth_me(
    authorization: Optional[str] = Header(None),
):
    auth = authenticate(
        authorization
    )

    if auth["role"] == "owner":
        return {
            "authenticated": True,
            "role": "owner",
        }

    user = get_user(
        int(auth["user_id"])
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User account not found.",
        )

    return {
        "authenticated": True,
        "role": user["role"] or "user",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "country": user["country"],
            "language": user["language"],
        },
    }


@app.post("/auth/logout")
def auth_logout(
    authorization: Optional[str] = Header(None),
):
    raw_token = extract_bearer_token(
        authorization
    )

    token_hash = sha256(raw_token)

    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM auth_tokens
        WHERE token_hash = ?
        AND revoked = 0
        """,
        (token_hash,),
    ).fetchone()

    if not row:
        connection.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked token.",
        )

    connection.execute(
        """
        UPDATE auth_tokens
        SET revoked = 1
        WHERE id = ?
        """,
        (row["id"],),
    )

    connection.commit()
    connection.close()

    actor = (
        "owner"
        if row["role"] == "owner"
        else str(row["user_id"])
    )

    audit(
        actor,
        "logout",
    )

    return {
        "status": "logged_out",
    }


# ============================================================
# USERS
# ============================================================

@app.post("/users")
def create_user(
    data: UserCreate,
):
    password_hash = hash_password(
        data.password
    )

    connection = db()

    try:
        cursor = connection.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                phone,
                country,
                language,
                role,
                password_hash,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, 'user', ?, ?)
            """,
            (
                data.name,
                data.email.strip(),
                data.phone,
                data.country,
                data.language,
                password_hash,
                now_iso(),
            ),
        )

        connection.commit()

        user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        connection.close()

        raise HTTPException(
            status_code=409,
            detail="User email already exists.",
        )

    connection.close()

    audit(
        "system",
        "create_user",
        str(user_id),
    )

    return {
        "id": user_id,
        "status": "created",
    }


@app.get("/users/{user_id}")
def user_details(
    user_id: int,
    authorization: Optional[str] = Header(None),
):
    require_user(
        user_id,
        authorization,
    )

    user = get_user(user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    result = dict(user)

    # Never expose password hashes.
    result.pop("password_hash", None)

    return result


@app.get("/users")
def users(
    authorization: Optional[str] = Header(None),
):
    require_owner(
        authorization
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT
            id,
            name,
            email,
            phone,
            country,
            language,
            role,
            created_at
        FROM users
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# FARMS
# ============================================================

@app.post("/farms")
def create_farm(
    data: FarmCreate,
    authorization: Optional[str] = Header(None),
):
    require_user(
        data.user_id,
        authorization,
    )

    if not get_user(data.user_id):
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    connection = db()

    cursor = connection.execute(
        """
        INSERT INTO farms
        (
            user_id,
            name,
            country,
            region,
            latitude,
            longitude,
            climate,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.user_id,
            data.name,
            data.country,
            data.region,
            data.latitude,
            data.longitude,
            data.climate,
            now_iso(),
        ),
    )

    connection.commit()

    farm_id = cursor.lastrowid

    connection.close()

    return {
        "id": farm_id,
        "status": "created",
    }


@app.get("/farms/{user_id}")
def get_farms(
    user_id: int,
    authorization: Optional[str] = Header(None),
):
    require_user(
        user_id,
        authorization,
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM farms
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,),
    ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# LANDS
# ============================================================

@app.post("/lands")
def create_land(
    data: LandCreate,
    authorization: Optional[str] = Header(None),
):
    auth = authenticate(
        authorization
    )

    connection = db()

    farm = connection.execute(
        """
        SELECT *
        FROM farms
        WHERE id = ?
        """,
        (data.farm_id,),
    ).fetchone()

    connection.close()

    if not farm:
        raise HTTPException(
            status_code=404,
            detail="Farm not found.",
        )

    if auth["role"] != "owner":
        if auth["user_id"] != farm["user_id"]:
            raise HTTPException(
                status_code=403,
                detail="Access denied for this farm.",
            )

    connection = db()

    cursor = connection.execute(
        """
        INSERT INTO lands
        (
            farm_id,
            name,
            area,
            area_unit,
            soil_type,
            irrigation_type,
            latitude,
            longitude,
            boundary_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.farm_id,
            data.name,
            data.area,
            data.area_unit,
            data.soil_type,
            data.irrigation_type,
            data.latitude,
            data.longitude,
            data.boundary_json,
            now_iso(),
        ),
    )

    connection.commit()

    land_id = cursor.lastrowid

    connection.close()

    return {
        "id": land_id,
        "status": "created",
    }


@app.get("/lands")
def lands(
    farm_id: Optional[int] = None,
    authorization: Optional[str] = Header(None),
):
    auth = authenticate(
        authorization
    )

    connection = db()

    if farm_id is None:
        if auth["role"] != "owner":
            connection.close()

            raise HTTPException(
                status_code=403,
                detail=(
                    "farm_id is required for user access."
                ),
            )

        rows = connection.execute(
            """
            SELECT *
            FROM lands
            ORDER BY id DESC
            """
        ).fetchall()

    else:
        if auth["role"] != "owner":
            farm = connection.execute(
                """
                SELECT user_id
                FROM farms
                WHERE id = ?
                """,
                (farm_id,),
            ).fetchone()

            if not farm:
                connection.close()

                raise HTTPException(
                    status_code=404,
                    detail="Farm not found.",
                )

            if farm["user_id"] != auth["user_id"]:
                connection.close()

                raise HTTPException(
                    status_code=403,
                    detail="Access denied.",
                )

        rows = connection.execute(
            """
            SELECT *
            FROM lands
            WHERE farm_id = ?
            ORDER BY id DESC
            """,
            (farm_id,),
        ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# CROPS
# ============================================================

@app.post("/crops")
def create_crop(
    data: CropCreate,
    authorization: Optional[str] = Header(None),
):
    auth = authenticate(
        authorization
    )

    if (
        data.farm_id is None
        and data.land_id is None
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "farm_id or land_id is required."
            ),
        )

    connection = db()

    if data.land_id is not None:
        land = connection.execute(
            """
            SELECT
                lands.id,
                lands.farm_id,
                farms.user_id
            FROM lands
            JOIN farms
                ON farms.id = lands.farm_id
            WHERE lands.id = ?
            """,
            (data.land_id,),
        ).fetchone()

        if not land:
            connection.close()

            raise HTTPException(
                status_code=404,
                detail="Land not found.",
            )

        if (
            auth["role"] != "owner"
            and land["user_id"] != auth["user_id"]
        ):
            connection.close()

            raise HTTPException(
                status_code=403,
                detail="Access denied.",
            )

    if data.farm_id is not None:
        farm = connection.execute(
            """
            SELECT user_id
            FROM farms
            WHERE id = ?
            """,
            (data.farm_id,),
        ).fetchone()

        if not farm:
            connection.close()

            raise HTTPException(
                status_code=404,
                detail="Farm not found.",
            )

        if (
            auth["role"] != "owner"
            and farm["user_id"] != auth["user_id"]
        ):
            connection.close()

            raise HTTPException(
                status_code=403,
                detail="Access denied.",
            )

    cursor = connection.execute(
        """
        INSERT INTO crops
        (
            farm_id,
            land_id,
            name,
            variety,
            planting_date,
            area,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.farm_id,
            data.land_id,
            data.name,
            data.variety,
            data.planting_date,
            data.area,
            data.status,
            now_iso(),
        ),
    )

    connection.commit()

    crop_id = cursor.lastrowid

    connection.close()

    return {
        "id": crop_id,
        "status": "created",
    }


@app.get("/crops")
def crops(
    farm_id: Optional[int] = None,
    land_id: Optional[int] = None,
    authorization: Optional[str] = Header(None),
):
    auth = authenticate(
        authorization
    )

    connection = db()

    if auth["role"] != "owner":

        if (
            farm_id is None
            and land_id is None
        ):
            connection.close()

            raise HTTPException(
                status_code=403,
                detail=(
                    "farm_id or land_id is required "
                    "for user access."
                ),
            )

        if farm_id is not None:
            farm = connection.execute(
                """
                SELECT user_id
                FROM farms
                WHERE id = ?
                """,
                (farm_id,),
            ).fetchone()

            if not farm:
                connection.close()

                raise HTTPException(
                    status_code=404,
                    detail="Farm not found.",
                )

            if farm["user_id"] != auth["user_id"]:
                connection.close()

                raise HTTPException(
                    status_code=403,
                    detail="Access denied.",
                )

        if land_id is not None:
            land = connection.execute(
                """
                SELECT farms.user_id
                FROM lands
                JOIN farms
                    ON farms.id = lands.farm_id
                WHERE lands.id = ?
                """,
                (land_id,),
            ).fetchone()

            if not land:
                connection.close()

                raise HTTPException(
                    status_code=404,
                    detail="Land not found.",
                )

            if land["user_id"] != auth["user_id"]:
                connection.close()

                raise HTTPException(
                    status_code=403,
                    detail="Access denied.",
                )

    query = (
        "SELECT * FROM crops WHERE 1=1"
    )

    params = []

    if farm_id is not None:
        query += " AND farm_id = ?"
        params.append(farm_id)

    if land_id is not None:
        query += " AND land_id = ?"
        params.append(land_id)

    query += " ORDER BY id DESC"

    rows = connection.execute(
        query,
        params,
    ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# SOIL LAB
# ============================================================

@app.post("/soil/lab")
def save_soil_lab(
    data: SoilLabCreate,
    authorization: Optional[str] = Header(None),
):
    auth = authenticate(
        authorization
    )

    if auth["role"] != "owner":
        if not land_owned_by_user(
            data.land_id,
            auth["user_id"],
        ):
            raise HTTPException(
                status_code=403,
                detail="Access denied.",
            )

    connection = db()

    land = connection.execute(
        """
        SELECT id
        FROM lands
        WHERE id = ?
        """,
        (data.land_id,),
    ).fetchone()

    if not land:
        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Land not found.",
        )

    cursor = connection.execute(
        """
        INSERT INTO soil_lab_tests
        (
            land_id,
            test_date,
            ph,
            ec,
            nitrogen,
            phosphorus,
            potassium,
            organic_matter,
            salinity,
            laboratory,
            raw_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.land_id,
            data.test_date,
            data.ph,
            data.ec,
            data.nitrogen,
            data.phosphorus,
            data.potassium,
            data.organic_matter,
            data.salinity,
            data.laboratory,
            json.dumps(
                data.raw_json,
                ensure_ascii=False,
            )
            if data.raw_json
            else None,
            now_iso(),
        ),
    )

    connection.commit()

    record_id = cursor.lastrowid

    connection.close()

    return {
        "id": record_id,
        "status": "saved",
    }


@app.get("/soil/lab")
def get_soil_lab(
    land_id: Optional[int] = None,
    authorization: Optional[str] = Header(None),
):
    auth = authenticate(
        authorization
    )

    connection = db()

    if land_id is None:

        if auth["role"] != "owner":
            connection.close()

            raise HTTPException(
                status_code=403,
                detail=(
                    "land_id is required for user access."
                ),
            )

        rows = connection.execute(
            """
            SELECT *
            FROM soil_lab_tests
            ORDER BY id DESC
            """
        ).fetchall()

    else:

        if auth["role"] != "owner":
            land = connection.execute(
                """
                SELECT farms.user_id
                FROM lands
                JOIN farms
                    ON farms.id = lands.farm_id
                WHERE lands.id = ?
                """,
                (land_id,),
            ).fetchone()

            if not land:
                connection.close()

                raise HTTPException(
                    status_code=404,
                    detail="Land not found.",
                )

            if land["user_id"] != auth["user_id"]:
                connection.close()

                raise HTTPException(
                    status_code=403,
                    detail="Access denied.",
                )

        rows = connection.execute(
            """
            SELECT *
            FROM soil_lab_tests
            WHERE land_id = ?
            ORDER BY id DESC
            """,
            (land_id,),
        ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# WATER
# ============================================================

@app.post("/water")
def create_water_source(
    data: WaterSourceCreate,
    authorization: Optional[str] = Header(None),
):
    auth = authenticate(
        authorization
    )

    if auth["role"] != "owner":
        if not farm_owned_by_user(
            data.farm_id,
            auth["user_id"],
        ):
            raise HTTPException(
                status_code=403,
                detail="Access denied.",
            )

    connection = db()

    farm = connection.execute(
        """
        SELECT id
        FROM farms
        WHERE id = ?
        """,
        (data.farm_id,),
    ).fetchone()

    if not farm:
        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Farm not found.",
        )

    cursor = connection.execute(
        """
        INSERT INTO water_sources
        (
            farm_id,
            name,
            source_type,
            latitude,
            longitude,
            quantity,
            quality,
            raw_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.farm_id,
            data.name,
            data.source_type,
            data.latitude,
            data.longitude,
            data.quantity,
            data.quality,
            json.dumps(
                data.raw_json,
                ensure_ascii=False,
            )
            if data.raw_json
            else None,
            now_iso(),
        ),
    )

    connection.commit()

    water_id = cursor.lastrowid

    connection.close()

    return {
        "id": water_id,
        "status": "created",
    }


# ============================================================
# WEATHER
# ============================================================

@app.get("/weather")
def weather(
    latitude: float,
    longitude: float,
):
    try:
        forecast_url = (
            "https://api.open-meteo.com/v1/forecast"
        )

        params = {
            "latitude": latitude,
            "longitude": longitude,
            "current": (
                "temperature_2m,"
                "relative_humidity_2m,"
                "precipitation,"
                "wind_speed_10m"
            ),
            "daily": (
                "temperature_2m_max,"
                "temperature_2m_min,"
                "precipitation_sum"
            ),
            "timezone": "auto",
            "forecast_days": 7,
        }

        response = requests.get(
            forecast_url,
            params=params,
            timeout=15,
        )

        response.raise_for_status()

        result = response.json()

        return {
            "status": "ok",
            "latitude": latitude,
            "longitude": longitude,
            "data": result,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                f"Weather service error: {exc}"
            ),
        )


# ============================================================
# AI
# ============================================================

def local_agri_answer(
    question: str,
    crop: Optional[str] = None,
):
    q = question.lower()

    if (
        "زرد" in q
        or "زردی" in q
        or "برگ" in q
    ):
        return (
            "زردی برگ می‌تواند علت‌های مختلفی داشته باشد؛ "
            "از کمبود عناصر غذایی و مشکل آبیاری تا بیماری ریشه "
            "یا شرایط نامناسب خاک. برای تشخیص دقیق‌تر باید "
            "نوع گیاه، سن، محل زردی، وضعیت آبیاری، خاک و در "
            "صورت امکان تصویر برگ بررسی شود."
        )

    if (
        "آبیاری" in q
        or "آب" in q
    ):
        return (
            "برنامه آبیاری باید بر اساس نوع محصول، مرحله رشد، "
            "نوع خاک، دما، بارندگی، روش آبیاری و رطوبت خاک "
            "تنظیم شود. از آبیاری صرفاً بر اساس یک فاصله زمانی "
            "ثابت خودداری کنید."
        )

    if "کود" in q:
        return (
            "انتخاب کود باید بر اساس نیاز محصول و در صورت "
            "امکان نتیجه آزمایش خاک و آب انجام شود. مقدار "
            "کود بدون اطلاعات آزمایشگاهی نباید به‌صورت قطعی "
            "تجویز شود."
        )

    if (
        "سم" in q
        or "آفت" in q
        or "بیماری" in q
    ):
        return (
            "برای انتخاب روش کنترل، ابتدا باید آفت یا بیماری "
            "شناسایی شود. تصویر، محصول، مرحله رشد، منطقه و "
            "علائم لازم است. استفاده از سم بدون شناسایی دقیق "
            "می‌تواند باعث خسارت و مقاومت آفت شود."
        )

    return (
        "برای تحلیل دقیق‌تر، ARYA باید اطلاعات محصول، منطقه، "
        "شرایط آب‌وهوا، خاک، آب، مرحله رشد و علائم موجود را "
        "دریافت و اعتبارسنجی کند. در صورت کمبود اطلاعات، "
        "ابتدا فقط داده‌های ضروری را درخواست می‌کند."
    )


def openai_answer(
    question: str,
    language: str,
):
    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=OPENAI_API_KEY
        )

        system_prompt = """
You are ARYA AgriDoctor, an agricultural AI assistant.

You must:
- distinguish known facts from uncertainty
- never claim zero-error diagnosis
- request missing critical agricultural data
- consider crop, growth stage, location, weather,
  soil, water, irrigation and images when available
- avoid unsafe pesticide prescriptions without sufficient data
- explain uncertainty and confidence
- recommend expert/laboratory verification when appropriate
"""

        response = client.responses.create(
            model=OPENAI_MODEL,
            input=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": (
                        f"Language: {language}\n"
                        f"Question: {question}"
                    ),
                },
            ],
        )

        text = response.output_text

        usage = getattr(
            response,
            "usage",
            None,
        )

        input_tokens = (
            getattr(
                usage,
                "input_tokens",
                0,
            )
            if usage
            else 0
        )

        output_tokens = (
            getattr(
                usage,
                "output_tokens",
                0,
            )
            if usage
            else 0
        )

        return (
            text,
            input_tokens,
            output_tokens,
        )

    except Exception:
        raise


@app.post("/ai/ask")
def ai_ask(
    data: AIAsk,
    authorization: Optional[str] = Header(None),
):
    require_user(
        data.user_id,
        authorization,
    )

    user = get_user(
        data.user_id
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    if data.farm_id is not None:
        auth = authenticate(
            authorization
        )

        if auth["role"] != "owner":
            if not farm_owned_by_user(
                data.farm_id,
                data.user_id,
            ):
                raise HTTPException(
                    status_code=403,
                    detail="Access denied for this farm.",
                )

    used_today = ai_requests_today(
        data.user_id
    )

    if used_today >= DAILY_AI_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=(
                "Daily AI request limit reached."
            ),
        )

    request_id = secrets.token_hex(16)

    missing = []

    if not data.crop:
        missing.append("crop")

    if not data.region:
        missing.append("region")

    answer = None

    input_tokens = 0
    output_tokens = 0

    model = "local-rule-engine"

    if OPENAI_API_KEY:
        try:
            (
                answer,
                input_tokens,
                output_tokens,
            ) = openai_answer(
                data.question,
                data.language,
            )

            model = OPENAI_MODEL

        except Exception:
            answer = local_agri_answer(
                data.question,
                data.crop,
            )

    else:
        answer = local_agri_answer(
            data.question,
            data.crop,
        )

    save_ai_usage(
        data.user_id,
        request_id,
        model,
        input_tokens,
        output_tokens,
    )

    confidence = 0.55

    if data.crop and data.region:
        confidence = 0.70

    connection = db()

    connection.execute(
        """
        INSERT INTO recommendations
        (
            user_id,
            farm_id,
            category,
            question,
            recommendation,
            confidence,
            risk,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.user_id,
            data.farm_id,
            "ai",
            data.question,
            answer,
            confidence,
            "requires_validation",
            now_iso(),
        ),
    )

    connection.commit()
    connection.close()

    return {
        "request_id": request_id,
        "answer": answer,
        "model": model,
        "confidence": confidence,
        "risk": "requires_validation",
        "missing_data": missing,
        "daily_requests_used": used_today + 1,
        "daily_limit": DAILY_AI_LIMIT,
    }


# ============================================================
# PRICING
# ============================================================

@app.get("/pricing")
def pricing(
    country: str,
):
    connection = db()

    row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM payments
        WHERE country = ?
        AND status = 'verified'
        """,
        (country,),
    ).fetchone()

    connection.close()

    count = int(row["count"])

    if country.lower() in (
        "iran",
        "ایران",
    ):
        currency = "TOMAN"

        if count < 100:
            amount = 500000
        elif count < 600:
            amount = 800000
        else:
            amount = 1200000

        method = "shaba_bank_transfer"

    else:
        currency = "USDT"

        if count < 100:
            amount = 10
        elif count < 600:
            amount = 15
        else:
            amount = 20

        method = "crypto"

    return {
        "country": country,
        "verified_customer_count": count,
        "amount": amount,
        "currency": currency,
        "payment_method": method,
        "duration_days": 365,
    }


# ============================================================
# PAYMENTS
# ============================================================

@app.post("/payments")
def create_payment(
    data: PaymentCreate,
    authorization: Optional[str] = Header(None),
):
    require_user(
        data.user_id,
        authorization,
    )

    if not get_user(data.user_id):
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    connection = db()

    cursor = connection.execute(
        """
        INSERT INTO payments
        (
            user_id,
            country,
            method,
            amount,
            currency,
            reference,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            data.user_id,
            data.country,
            data.method,
            data.amount,
            data.currency,
            data.reference,
            now_iso(),
        ),
    )

    connection.commit()

    payment_id = cursor.lastrowid

    connection.close()

    audit(
        str(data.user_id),
        "create_payment",
        str(payment_id),
    )

    return {
        "payment_id": payment_id,
        "status": "pending",
    }


@app.post("/payments/{payment_id}/verify")
def verify_payment(
    payment_id: int,
    authorization: Optional[str] = Header(None),
):
    require_owner(
        authorization
    )

    connection = db()

    payment = connection.execute(
        """
        SELECT *
        FROM payments
        WHERE id = ?
        """,
        (payment_id,),
    ).fetchone()

    if not payment:
        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Payment not found.",
        )

    if payment["status"] == "verified":
        existing_subscription = connection.execute(
            """
            SELECT *
            FROM subscriptions
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (payment["user_id"],),
        ).fetchone()

        connection.close()

        return {
            "payment_id": payment_id,
            "status": "already_verified",
            "subscription": (
                dict(existing_subscription)
                if existing_subscription
                else None
            ),
        }

    connection.execute(
        """
        UPDATE payments
        SET status = 'verified',
            verified_at = ?
        WHERE id = ?
        """,
        (
            now_iso(),
            payment_id,
        ),
    )

    started = datetime.now(
        timezone.utc
    )

    expires = (
        started
        + timedelta(days=365)
    )

    connection.execute(
        """
        INSERT INTO subscriptions
        (
            user_id,
            plan,
            started_at,
            expires_at,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, 'active', ?)
        """,
        (
            payment["user_id"],
            "annual",
            started.isoformat(),
            expires.isoformat(),
            now_iso(),
        ),
    )

    connection.commit()
    connection.close()

    audit(
        "owner",
        "verify_payment",
        str(payment_id),
    )

    return {
        "payment_id": payment_id,
        "status": "verified",
        "subscription": "active",
        "expires_at": expires.isoformat(),
    }


@app.get("/subscriptions/{user_id}")
def subscription(
    user_id: int,
    authorization: Optional[str] = Header(None),
):
    require_user(
        user_id,
        authorization,
    )

    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM subscriptions
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()

    connection.close()

    if not row:
        return {
            "status": "inactive"
        }

    result = dict(row)

    try:
        expires = datetime.fromisoformat(
            result["expires_at"]
        )

        if expires <= datetime.now(
            timezone.utc
        ):
            result["status"] = "expired"

    except Exception:
        pass

    return result


# ============================================================
# ACTIVATION CODES
# ============================================================

@app.post("/owner/activation-code")
def create_activation_code(
    duration_days: int = 365,
    authorization: Optional[str] = Header(None),
):
    require_owner(
        authorization
    )

    if duration_days <= 0:
        raise HTTPException(
            status_code=400,
            detail="duration_days must be positive.",
        )

    if duration_days > 3650:
        raise HTTPException(
            status_code=400,
            detail=(
                "duration_days cannot exceed 3650."
            ),
        )

    raw_code = secrets.token_urlsafe(18)

    code_hash = sha256(
        raw_code
    )

    connection = db()

    connection.execute(
        """
        INSERT INTO activation_codes
        (
            code_hash,
            duration_days,
            created_at
        )
        VALUES (?, ?, ?)
        """,
        (
            code_hash,
            duration_days,
            now_iso(),
        ),
    )

    connection.commit()
    connection.close()

    audit(
        "owner",
        "create_activation_code",
    )

    return {
        "code": raw_code,
        "duration_days": duration_days,
    }


@app.post("/activation/use")
def use_activation_code(
    data: ActivationUse,
    authorization: Optional[str] = Header(None),
):
    require_user(
        data.user_id,
        authorization,
    )

    code_hash = sha256(
        data.code
    )

    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM activation_codes
        WHERE code_hash = ?
        AND used = 0
        """,
        (code_hash,),
    ).fetchone()

    if not row:
        connection.close()

        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid or already used "
                "activation code."
            ),
        )

    started = datetime.now(
        timezone.utc
    )

    expires = (
        started
        + timedelta(
            days=int(
                row["duration_days"]
            )
        )
    )

    connection.execute(
        """
        UPDATE activation_codes
        SET used = 1,
            used_by = ?,
            used_at = ?
        WHERE id = ?
        """,
        (
            data.user_id,
            now_iso(),
            row["id"],
        ),
    )

    connection.execute(
        """
        INSERT INTO subscriptions
        (
            user_id,
            plan,
            started_at,
            expires_at,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, 'active', ?)
        """,
        (
            data.user_id,
            "activation",
            started.isoformat(),
            expires.isoformat(),
            now_iso(),
        ),
    )

    connection.commit()
    connection.close()

    audit(
        str(data.user_id),
        "use_activation_code",
        str(row["id"]),
    )

    return {
        "status": "activated",
        "expires_at": expires.isoformat(),
    }


# ============================================================
# DEVICES
# ============================================================

@app.post("/devices")
def register_device(
    data: DeviceCreate,
    authorization: Optional[str] = Header(None),
):
    require_user(
        data.user_id,
        authorization,
    )

    if not get_user(data.user_id):
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    device_hash = sha256(
        data.device_id
    )

    connection = db()

    existing = connection.execute(
        """
        SELECT *
        FROM devices
        WHERE user_id = ?
        AND device_hash = ?
        """,
        (
            data.user_id,
            device_hash,
        ),
    ).fetchone()

    if existing:
        connection.execute(
            """
            UPDATE devices
            SET last_seen = ?,
                active = 1
            WHERE id = ?
            """,
            (
                now_iso(),
                existing["id"],
            ),
        )

        connection.commit()
        connection.close()

        return {
            "status": "already_registered",
            "device_id": existing["id"],
        }

    count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM devices
        WHERE user_id = ?
        AND active = 1
        """,
        (data.user_id,),
    ).fetchone()["count"]

    if int(count) >= DEVICE_LIMIT:
        connection.close()

        raise HTTPException(
            status_code=403,
            detail="Device limit reached.",
        )

    cursor = connection.execute(
        """
        INSERT INTO devices
        (
            user_id,
            device_hash,
            device_name,
            created_at,
            last_seen
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            data.user_id,
            device_hash,
            data.device_name,
            now_iso(),
            now_iso(),
        ),
    )

    connection.commit()

    device_db_id = cursor.lastrowid

    connection.close()

    audit(
        str(data.user_id),
        "register_device",
        str(device_db_id),
    )

    return {
        "status": "registered",
        "device_id": device_db_id,
    }


# ============================================================
# FEEDBACK
# ============================================================

@app.post("/feedback")
def create_feedback(
    data: FeedbackCreate,
    authorization: Optional[str] = Header(None),
):
    if data.user_id is not None:
        require_user(
            data.user_id,
            authorization,
        )
    else:
        # Public feedback is allowed when no user account
        # is associated with the message.
        pass

    connection = db()

    cursor = connection.execute(
        """
        INSERT INTO feedback
        (
            user_id,
            category,
            original_language,
            original_text,
            persian_translation,
            status,
            attachment,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, 'new', ?, ?)
        """,
        (
            data.user_id,
            data.category,
            data.original_language,
            data.original_text,
            None,
            data.attachment,
            now_iso(),
        ),
    )

    connection.commit()

    feedback_id = cursor.lastrowid

    connection.close()

    return {
        "id": feedback_id,
        "status": "received",
        "translation_status": "pending",
    }


@app.get("/owner/feedback")
def owner_feedback(
    status: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    require_owner(
        authorization
    )

    connection = db()

    if status:
        rows = connection.execute(
            """
            SELECT *
            FROM feedback
            WHERE status = ?
            ORDER BY id DESC
            """,
            (status,),
        ).fetchall()

    else:
        rows = connection.execute(
            """
            SELECT *
            FROM feedback
            ORDER BY id DESC
            """
        ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# OWNER AI PROPOSALS
# ============================================================

@app.post("/owner/ai/proposals")
def create_ai_proposal(
    data: AIProposalCreate,
    authorization: Optional[str] = Header(None),
):
    require_owner(
        authorization
    )

    connection = db()

    cursor = connection.execute(
        """
        INSERT INTO ai_change_proposals
        (
            title,
            description,
            change_json,
            status,
            created_at
        )
        VALUES (?, ?, ?, 'pending', ?)
        """,
        (
            data.title,
            data.description,
            json.dumps(
                data.change_json,
                ensure_ascii=False,
            )
            if data.change_json
            else None,
            now_iso(),
        ),
    )

    connection.commit()

    proposal_id = cursor.lastrowid

    connection.close()

    audit(
        "owner",
        "create_change_proposal",
        str(proposal_id),
    )

    return {
        "id": proposal_id,
        "status": "pending",
    }


@app.get("/owner/ai/proposals")
def ai_proposals(
    authorization: Optional[str] = Header(None),
):
    require_owner(
        authorization
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM ai_change_proposals
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


@app.post(
    "/owner/ai/proposals/{proposal_id}/decision"
)
def decide_ai_proposal(
    proposal_id: int,
    data: ProposalDecision,
    authorization: Optional[str] = Header(None),
):
    auth = require_owner(
        authorization
    )

    if data.decision not in (
        "approve",
        "reject",
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Decision must be approve or reject."
            ),
        )

    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM ai_change_proposals
        WHERE id = ?
        """,
        (proposal_id,),
    ).fetchone()

    if not row:
        connection.close()

        raise HTTPException(
            status_code=404,
            detail="Proposal not found.",
        )

    status = (
        "approved"
        if data.decision == "approve"
        else "rejected"
    )

    reviewer = (
        data.reviewer.strip()
        if data.reviewer.strip()
        else "owner"
    )

    connection.execute(
        """
        UPDATE ai_change_proposals
        SET status = ?,
            reviewed_at = ?,
            reviewed_by = ?
        WHERE id = ?
        """,
        (
            status,
            now_iso(),
            reviewer,
            proposal_id,
        ),
    )

    connection.commit()
    connection.close()

    audit(
        "owner",
        f"ai_proposal_{status}",
        str(proposal_id),
        {
            "reviewer": reviewer,
            "token_id": auth["token_id"],
        },
    )

    return {
        "id": proposal_id,
        "status": status,
    }


# ============================================================
# KNOWLEDGE
# ============================================================

@app.post("/owner/knowledge")
def create_knowledge(
    data: KnowledgeCreate,
    authorization: Optional[str] = Header(None),
):
    require_owner(
        authorization
    )

    connection = db()

    cursor = connection.execute(
        """
        INSERT INTO knowledge_versions
        (
            version,
            title,
            content,
            status,
            created_at
        )
        VALUES (?, ?, ?, 'draft', ?)
        """,
        (
            data.version,
            data.title,
            data.content,
            now_iso(),
        ),
    )

    connection.commit()

    knowledge_id = cursor.lastrowid

    connection.close()

    audit(
        "owner",
        "create_knowledge_version",
        str(knowledge_id),
    )

    return {
        "id": knowledge_id,
        "status": "draft",
    }


# ============================================================
# AUDIT
# ============================================================

@app.get("/owner/audit")
def owner_audit(
    limit: int = 100,
    authorization: Optional[str] = Header(None),
):
    require_owner(
        authorization
    )

    limit = max(
        1,
        min(limit, 1000),
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# OFFLINE SYNC
# ============================================================

@app.post("/sync")
def sync_operation(
    data: SyncCreate,
    authorization: Optional[str] = Header(None),
):
    require_user(
        data.user_id,
        authorization,
    )

    connection = db()

    existing = connection.execute(
        """
        SELECT *
        FROM sync_queue
        WHERE operation_id = ?
        """,
        (data.operation_id,),
    ).fetchone()

    if existing:
        connection.close()

        return {
            "operation_id": data.operation_id,
            "status": existing["status"],
            "duplicate": True,
        }

    connection.execute(
        """
        INSERT INTO sync_queue
        (
            user_id,
            operation_id,
            operation,
            payload,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, 'pending', ?)
        """,
        (
            data.user_id,
            data.operation_id,
            data.operation,
            json.dumps(
                data.payload,
                ensure_ascii=False,
            ),
            now_iso(),
        ),
    )

    connection.commit()
    connection.close()

    return {
        "operation_id": data.operation_id,
        "status": "queued",
    }


# ============================================================
# SERVER TIME
# ============================================================

@app.get("/server-time")
def server_time():
    current = datetime.now(
        timezone.utc
    )

    return {
        "utc": current.isoformat(),
        "unix": int(
            current.timestamp()
        ),
    }


# ============================================================
# SYSTEM INFO
# ============================================================

@app.get("/system/info")
def system_info(
    authorization: Optional[str] = Header(None),
):
    require_owner(
        authorization
    )

    connection = db()

    users_count = connection.execute(
        """
        SELECT COUNT(*) AS c
        FROM users
        """
    ).fetchone()["c"]

    farms_count = connection.execute(
        """
        SELECT COUNT(*) AS c
        FROM farms
        """
    ).fetchone()["c"]

    ai_count = connection.execute(
        """
        SELECT COUNT(*) AS c
        FROM ai_usage
        """
    ).fetchone()["c"]

    ai_cost = connection.execute(
        """
        SELECT COALESCE(
            SUM(total_cost),
            0
        ) AS c
        FROM ai_usage
        """
    ).fetchone()["c"]

    active_tokens = connection.execute(
        """
        SELECT COUNT(*) AS c
        FROM auth_tokens
        WHERE revoked = 0
        AND expires_at > ?
        """,
        (now_iso(),),
    ).fetchone()["c"]

    connection.close()

    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "users": users_count,
        "farms": farms_count,
        "ai_requests": ai_count,
        "ai_recorded_cost": ai_cost,
        "active_auth_tokens": active_tokens,
        "daily_ai_limit": DAILY_AI_LIMIT,
        "device_limit": DEVICE_LIMIT,
        "time": now_iso(),
    }
