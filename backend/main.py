import os
import re
import json
import time
import uuid
import hmac
import base64
import hashlib
import secrets
import struct
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import requests
from fastapi import (
    FastAPI,
    HTTPException,
    Header,
    UploadFile,
    File,
    Query,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
try:
    from arya_analysis_adapter import (
        analyze_request,
        health_check,
    )
except ImportError:
    from .arya_analysis_adapter import (
        analyze_request,
        health_check,
    )


# ============================================================
# ARYA AGRIDOCTOR
# SINGLE FILE PRODUCTION-ORIENTED BACKEND
# ============================================================

APP_NAME = "ARYA AgriDoctor"
VERSION = "5.0.0"

BASE_DIR = Path(
    os.getenv("ARYA_BASE_DIR", ".")
).resolve()

DB_PATH = Path(
    os.getenv(
        "ARYA_DATABASE",
        str(BASE_DIR / "arya.db"),
    )
)

MEDIA_DIR = Path(
    os.getenv(
        "ARYA_MEDIA_DIR",
        str(BASE_DIR / "media"),
    )
)

MEDIA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

OPENAI_API_KEY = os.getenv(
    "OPENAI_API_KEY",
    "",
)

OPENAI_MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-5",
)

OPENAI_BASE_URL = os.getenv(
    "OPENAI_BASE_URL",
    "https://api.openai.com/v1",
).rstrip("/")

TRANSLATION_API_URL = os.getenv(
    "ARYA_TRANSLATION_API_URL",
    "",
)

TRANSLATION_API_KEY = os.getenv(
    "ARYA_TRANSLATION_API_KEY",
    "",
)

WEATHER_TIMEOUT = int(
    os.getenv(
        "ARYA_WEATHER_TIMEOUT",
        "20",
    )
)

TOKEN_DAYS = int(
    os.getenv(
        "ARYA_TOKEN_DAYS",
        "30",
    )
)

RESET_HOURS = int(
    os.getenv(
        "ARYA_RESET_HOURS",
        "2",
    )
)

DAILY_AI_LIMIT = int(
    os.getenv(
        "ARYA_DAILY_AI_LIMIT",
        "30",
    )
)

DEVICE_LIMIT = int(
    os.getenv(
        "ARYA_DEVICE_LIMIT",
        "3",
    )
)

PBKDF2_ITERATIONS = int(
    os.getenv(
        "ARYA_PBKDF2_ITERATIONS",
        "310000",
    )
)

MAX_UPLOAD_MB = int(
    os.getenv(
        "ARYA_MAX_UPLOAD_MB",
        "15",
    )
)

OWNER_BOOTSTRAP_SECRET = os.getenv(
    "ARYA_OWNER_BOOTSTRAP_SECRET",
    "",
)

OWNER_EMAIL = os.getenv(
    "ARYA_OWNER_EMAIL",
    "",
)

CORS_ORIGINS = [
    x.strip()
    for x in os.getenv(
        "ARYA_CORS",
        "*",
    ).split(",")
    if x.strip()
]


app = FastAPI(
    title=APP_NAME,
    version=VERSION,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=(
        CORS_ORIGINS != ["*"]
    ),
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# UTILITIES
# ============================================================

def now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def today() -> str:
    return datetime.now(
        timezone.utc
    ).date().isoformat()


def hash_password(
    password: str,
    salt: Optional[bytes] = None,
) -> str:
    if len(password) < 8:
        raise HTTPException(
            400,
            "password must be at least 8 characters",
        )

    salt = salt or secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        PBKDF2_ITERATIONS,
    )

    return (
        base64.urlsafe_b64encode(
            salt
        ).decode()
        + "$"
        + base64.urlsafe_b64encode(
            digest
        ).decode()
    )


def verify_password(
    password: str,
    stored: str,
) -> bool:
    try:
        salt_s, digest_s = stored.split(
            "$",
            1,
        )

        salt = base64.urlsafe_b64decode(
            salt_s.encode()
        )

        expected = base64.urlsafe_b64decode(
            digest_s.encode()
        )

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            PBKDF2_ITERATIONS,
        )

        return hmac.compare_digest(
            actual,
            expected,
        )

    except Exception:
        return False


def totp_code(
    secret: str,
    timestamp: Optional[int] = None,
) -> str:
    if not secret:
        return ""

    timestamp = (
        timestamp
        if timestamp is not None
        else int(time.time())
    )

    counter = timestamp // 30

    key = base64.b32decode(
        secret.upper()
        + "=" * (
            (8 - len(secret) % 8) % 8
        )
    )

    msg = struct.pack(
        ">Q",
        counter,
    )

    digest = hmac.new(
        key,
        msg,
        hashlib.sha1,
    ).digest()

    offset = digest[-1] & 0x0F

    number = (
        struct.unpack(
            ">I",
            digest[
                offset:offset + 4
            ],
        )[0]
        & 0x7FFFFFFF
    ) % 1000000

    return f"{number:06d}"


def verify_totp(
    secret: str,
    code: str,
) -> bool:
    if not re.fullmatch(
        r"\d{6}",
        code or "",
    ):
        return False

    current = int(time.time())

    return any(
        hmac.compare_digest(
            totp_code(
                secret,
                current + delta,
            ),
            code,
        )
        for delta in (-30, 0, 30)
    )


def sha256_bytes(
    data: bytes,
) -> str:
    return hashlib.sha256(
        data
    ).hexdigest()


def token_hash(
    token: str,
) -> str:
    return hashlib.sha256(
        token.encode()
    ).hexdigest()


def norm_email(
    value: str,
) -> str:
    return value.strip().lower()


def jdump(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def jload(
    value: Any,
    default=None,
):
    if value is None:
        return default

    try:
        return json.loads(value)
    except Exception:
        return default


def validate_coords(
    lat: Optional[float],
    lon: Optional[float],
):
    if lat is not None and not (
        -90 <= lat <= 90
    ):
        raise HTTPException(
            422,
            "invalid latitude",
        )

    if lon is not None and not (
        -180 <= lon <= 180
    ):
        raise HTTPException(
            422,
            "invalid longitude",
        )


def validate_ph(
    value: Optional[float],
):
    if value is not None and not (
        0 <= value <= 14
    ):
        raise HTTPException(
            422,
            "pH must be between 0 and 14",
        )


def db():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
    )

    conn.row_factory = sqlite3.Row

    conn.execute(
        "PRAGMA foreign_keys=ON"
    )

    conn.execute(
        "PRAGMA journal_mode=WAL"
    )

    return conn


def q(
    sql: str,
    args=(),
    one=False,
    many=False,
):
    conn = db()

    try:
        cursor = conn.execute(
            sql,
            args,
        )

        if one:
            row = cursor.fetchone()
            conn.commit()
            return (
                dict(row)
                if row
                else None
            )

        if many:
            rows = cursor.fetchall()
            conn.commit()
            return [
                dict(row)
                for row in rows
            ]

        conn.commit()

        return cursor.lastrowid

    finally:
        conn.close()


def audit(
    user_id: Optional[int],
    action: str,
    entity: str = "",
    entity_id: Optional[int] = None,
    details=None,
):
    try:
        q(
            """
            INSERT INTO audit_logs(
                user_id,
                action,
                entity,
                entity_id,
                details,
                created_at
            )
            VALUES(?,?,?,?,?,?)
            """,
            (
                user_id,
                action,
                entity,
                entity_id,
                jdump(details or {}),
                now_iso(),
            ),
        )
    except Exception:
        pass


def require_owner(
    user,
):
    if user["role"] != "owner":
        raise HTTPException(
            403,
            "owner access required",
        )


def safe_filename(
    filename: str,
) -> str:
    filename = (
        Path(filename or "file")
        .name
    )

    filename = re.sub(
        r"[^A-Za-z0-9._-]",
        "_",
        filename,
    )

    return filename[:180] or "file"


# ============================================================
# DATABASE
# ============================================================

def init_db():
    conn = db()

    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT DEFAULT '',
                phone TEXT DEFAULT '',
                country TEXT DEFAULT '',
                language TEXT DEFAULT 'fa',
                role TEXT DEFAULT 'user',
                active INTEGER DEFAULT 1,
                mfa_enabled INTEGER DEFAULT 0,
                mfa_secret TEXT DEFAULT '',
                recovery_hash TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_tokens(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS password_resets(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS farms(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                country TEXT DEFAULT '',
                region TEXT DEFAULT '',
                address TEXT DEFAULT '',
                latitude REAL,
                longitude REAL,
                area_ha REAL,
                soil_type TEXT DEFAULT '',
                climate_type TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS lands(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                farm_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                area_ha REAL,
                latitude REAL,
                longitude REAL,
                soil_type TEXT DEFAULT '',
                irrigation_type TEXT DEFAULT '',
                water_source TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(farm_id)
                    REFERENCES farms(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS crops(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                land_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                variety TEXT DEFAULT '',
                planted_at TEXT,
                harvest_at TEXT,
                area_ha REAL,
                growth_stage TEXT DEFAULT '',
                irrigation_l_day REAL,
                expected_yield_min REAL,
                expected_yield_max REAL,
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(land_id)
                    REFERENCES lands(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS trees(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                land_id INTEGER NOT NULL,
                species TEXT NOT NULL,
                variety TEXT DEFAULT '',
                age_years REAL,
                tree_count INTEGER,
                health TEXT DEFAULT '',
                irrigation_l_day REAL,
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(land_id)
                    REFERENCES lands(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS soil_tests(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                land_id INTEGER NOT NULL,
                test_date TEXT,
                ph REAL,
                ec REAL,
                organic_matter REAL,
                nitrogen REAL,
                phosphorus REAL,
                potassium REAL,
                calcium REAL,
                magnesium REAL,
                sulfur REAL,
                zinc REAL,
                iron REAL,
                boron REAL,
                soil_texture TEXT DEFAULT '',
                salinity TEXT DEFAULT '',
                raw_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY(land_id)
                    REFERENCES lands(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS water_tests(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                land_id INTEGER NOT NULL,
                test_date TEXT,
                ph REAL,
                ec REAL,
                tss REAL,
                hardness REAL,
                sodium REAL,
                chloride REAL,
                bicarbonate REAL,
                boron REAL,
                sar REAL,
                raw_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY(land_id)
                    REFERENCES lands(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS weather_observations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                lat REAL,
                lon REAL,
                observed_at TEXT,
                temperature REAL,
                humidity REAL,
                rain_mm REAL,
                wind_kmh REAL,
                source TEXT DEFAULT 'manual',
                raw_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS location_records(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                lat REAL,
                lon REAL,
                address TEXT DEFAULT '',
                region TEXT DEFAULT '',
                country TEXT DEFAULT '',
                source TEXT DEFAULT 'manual',
                confidence REAL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                entity TEXT DEFAULT '',
                entity_id INTEGER,
                details TEXT DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS system_settings(
                key TEXT PRIMARY KEY,
                value TEXT DEFAULT '',
                secret INTEGER DEFAULT 0,
                updated_by INTEGER,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ai_usage(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                usage_date TEXT NOT NULL,
                tokens INTEGER DEFAULT 0,
                requests INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ai_requests(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                prompt TEXT NOT NULL,
                language TEXT DEFAULT 'fa',
                context_json TEXT DEFAULT '{}',
                response_json TEXT DEFAULT '{}',
                provider TEXT DEFAULT '',
                verified INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS media_files(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                original_name TEXT DEFAULT '',
                stored_name TEXT NOT NULL,
                mime_type TEXT DEFAULT '',
                size_bytes INTEGER DEFAULT 0,
                sha256 TEXT NOT NULL,
                status TEXT DEFAULT 'stored',
                analysis_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS feedback(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                text TEXT NOT NULL,
                language TEXT DEFAULT 'fa',
                status TEXT DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS feedback_messages(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feedback_id INTEGER NOT NULL,
                sender_user_id INTEGER,
                sender_role TEXT DEFAULT 'user',
                language TEXT DEFAULT 'fa',
                text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(feedback_id)
                    REFERENCES feedback(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS payments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                currency TEXT NOT NULL,
                method TEXT NOT NULL,
                reference TEXT DEFAULT '',
                note TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                destination TEXT DEFAULT '',
                network TEXT DEFAULT '',
                approved_by INTEGER,
                approved_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payment_destinations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT NOT NULL,
                currency TEXT NOT NULL,
                network TEXT DEFAULT '',
                destination TEXT NOT NULL,
                active INTEGER DEFAULT 1,
                created_by INTEGER,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS subscriptions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan TEXT NOT NULL,
                amount REAL DEFAULT 0,
                currency TEXT DEFAULT '',
                starts_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                payment_id INTEGER,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activation_codes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT UNIQUE NOT NULL,
                plan TEXT DEFAULT '',
                expires_at TEXT,
                used INTEGER DEFAULT 0,
                user_id INTEGER,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                device_name TEXT DEFAULT '',
                platform TEXT DEFAULT '',
                active INTEGER DEFAULT 1,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id,device_id)
            );

            CREATE TABLE IF NOT EXISTS notifications(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                language TEXT DEFAULT 'fa',
                type TEXT DEFAULT 'general',
                read_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agricultural_alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                farm_id INTEGER,
                alert_type TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                data_json TEXT DEFAULT '{}',
                active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_event_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                payload_json TEXT DEFAULT '{}',
                status TEXT DEFAULT 'accepted',
                created_at TEXT NOT NULL,
                UNIQUE(user_id,client_event_id)
            );

            CREATE TABLE IF NOT EXISTS backups(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_by INTEGER NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_items(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                language TEXT DEFAULT 'fa',
                source TEXT DEFAULT '',
                version TEXT DEFAULT '1',
                active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS external_providers(
                key TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                base_url TEXT DEFAULT '',
                health_url TEXT DEFAULT '',
                auth_env TEXT DEFAULT '',
                enabled INTEGER DEFAULT 0,
                required INTEGER DEFAULT 0,
                notes TEXT DEFAULT '',
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tokens_user
                ON auth_tokens(user_id);

            CREATE INDEX IF NOT EXISTS idx_tokens_hash
                ON auth_tokens(token_hash);

            CREATE INDEX IF NOT EXISTS idx_farms_user
                ON farms(user_id);

            CREATE INDEX IF NOT EXISTS idx_lands_farm
                ON lands(farm_id);

            CREATE INDEX IF NOT EXISTS idx_crops_land
                ON crops(land_id);

            CREATE INDEX IF NOT EXISTS idx_trees_land
                ON trees(land_id);

            CREATE INDEX IF NOT EXISTS idx_soil_land
                ON soil_tests(land_id);

            CREATE INDEX IF NOT EXISTS idx_water_land
                ON water_tests(land_id);

            CREATE INDEX IF NOT EXISTS idx_feedback_user
                ON feedback(user_id);

            CREATE INDEX IF NOT EXISTS idx_payments_user
                ON payments(user_id);

            CREATE INDEX IF NOT EXISTS idx_subscriptions_user
                ON subscriptions(user_id);

            CREATE INDEX IF NOT EXISTS idx_devices_user
                ON devices(user_id);

            CREATE INDEX IF NOT EXISTS idx_notifications_user
                ON notifications(user_id);

            CREATE INDEX IF NOT EXISTS idx_alerts_user
                ON agricultural_alerts(user_id);

            CREATE INDEX IF NOT EXISTS idx_ai_usage_user_date
                ON ai_usage(user_id,usage_date);
            """
        )

        conn.execute(
            """
            INSERT INTO schema_meta(
                key,
                value
            )
            VALUES('version',?)
            ON CONFLICT(key)
            DO UPDATE SET
                value=excluded.value
            """,
            (VERSION,),
        )

        conn.commit()

    finally:
        conn.close()


# ============================================================
# SCHEMAS
# ============================================================

class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    name: str = ""
    phone: str = ""
    country: str = ""
    language: str = "fa"


class LoginIn(BaseModel):
    email: EmailStr
    password: str
    mfa_code: str = ""


class PasswordResetRequestIn(BaseModel):
    email: EmailStr


class PasswordResetConfirmIn(BaseModel):
    token: str
    new_password: str


class OwnerBootstrapIn(BaseModel):
    secret: str


class MFAEnableIn(BaseModel):
    code: str


class FarmIn(BaseModel):
    name: str
    description: str = ""
    country: str = ""
    region: str = ""
    address: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    area_ha: Optional[float] = None
    soil_type: str = ""
    climate_type: str = ""


class LandIn(BaseModel):
    farm_id: int
    name: str
    area_ha: Optional[float] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    soil_type: str = ""
    irrigation_type: str = ""
    water_source: str = ""
    notes: str = ""


class CropIn(BaseModel):
    land_id: int
    name: str
    variety: str = ""
    planted_at: Optional[str] = None
    harvest_at: Optional[str] = None
    area_ha: Optional[float] = None
    growth_stage: str = ""
    irrigation_l_day: Optional[float] = None
    expected_yield_min: Optional[float] = None
    expected_yield_max: Optional[float] = None
    notes: str = ""


class TreeIn(BaseModel):
    land_id: int
    species: str
    variety: str = ""
    age_years: Optional[float] = None
    tree_count: Optional[int] = None
    health: str = ""
    irrigation_l_day: Optional[float] = None
    notes: str = ""


class SoilTestIn(BaseModel):
    land_id: int
    test_date: Optional[str] = None
    ph: Optional[float] = None
    ec: Optional[float] = None
    organic_matter: Optional[float] = None
    nitrogen: Optional[float] = None
    phosphorus: Optional[float] = None
    potassium: Optional[float] = None
    calcium: Optional[float] = None
    magnesium: Optional[float] = None
    sulfur: Optional[float] = None
    zinc: Optional[float] = None
    iron: Optional[float] = None
    boron: Optional[float] = None
    soil_texture: str = ""
    salinity: str = ""
    raw: dict = Field(
        default_factory=dict
    )


class WaterTestIn(BaseModel):
    land_id: int
    test_date: Optional[str] = None
    ph: Optional[float] = None
    ec: Optional[float] = None
    tss: Optional[float] = None
    hardness: Optional[float] = None
    sodium: Optional[float] = None
    chloride: Optional[float] = None
    bicarbonate: Optional[float] = None
    boron: Optional[float] = None
    sar: Optional[float] = None
    raw: dict = Field(
        default_factory=dict
    )


class WeatherIn(BaseModel):
    latitude: float
    longitude: float
    observed_at: Optional[str] = None
    temperature: Optional[float] = None
    humidity: Optional[float] = None
    rain_mm: Optional[float] = None
    wind_kmh: Optional[float] = None
    source: str = "manual"
    raw: dict = Field(
        default_factory=dict
    )


class LocationIn(BaseModel):
    latitude: float
    longitude: float
    address: str = ""
    region: str = ""
    country: str = ""
    source: str = "manual"


class FeedbackIn(BaseModel):
    subject: str
    text: str
    language: str = "fa"


class FeedbackMessageIn(BaseModel):
    text: str
    language: str = "fa"


class AIRequestIn(BaseModel):
    prompt: str
    language: str = "fa"
    context: dict = Field(
        default_factory=dict
    )


class RecommendationIn(BaseModel):
    land_id: int
    crop_name: str = ""
    goal: str = ""
    context: dict = Field(
        default_factory=dict
    )


class PaymentIn(BaseModel):
    amount: float
    currency: str
    method: str
    reference: str = ""
    note: str = ""


class PaymentDecisionIn(BaseModel):
    note: str = ""


class ActivationIn(BaseModel):
    code: str
    device_id: str


class DeviceIn(BaseModel):
    device_id: str
    device_name: str = ""
    platform: str = ""


class SettingIn(BaseModel):
    value: str
    secret: bool = False


class SyncIn(BaseModel):
    client_event_id: str
    operation: str
    payload: dict = Field(
        default_factory=dict
    )


class ProviderConfigIn(BaseModel):
    base_url: str = ""
    health_url: str = ""
    enabled: bool = False
    required: bool = False
    notes: str = ""


class DestinationIn(BaseModel):
    method: str
    currency: str
    network: str = ""
    destination: str


class KnowledgeIn(BaseModel):
    category: str
    title: str
    content: str
    language: str = "fa"
    source: str = ""
    version: str = "1"


# ============================================================
# PROVIDERS
# ============================================================

PROVIDERS = [
    (
        "weather",
        "Open-Meteo",
        "https://api.open-meteo.com",
        "",
        "",
        1,
        "Weather"
    ),
    (
        "openai",
        "OpenAI",
        OPENAI_BASE_URL,
        "",
        "OPENAI_API_KEY",
        1,
        "AI"
    ),
    (
        "geocoding",
        "Geocoding Provider",
        "",
        "",
        "ARYA_GEOCODING_API_KEY",
        0,
        "Geocoding"
    ),
    (
        "maps",
        "Maps Provider",
        "",
        "",
        "ARYA_MAPS_API_KEY",
        0,
        "Maps"
    ),
    (
        "soil",
        "Soil Data Provider",
        "",
        "",
        "ARYA_SOIL_API_KEY",
        0,
        "Soil"
    ),
    (
        "satellite",
        "Satellite Provider",
        "",
        "",
        "ARYA_SATELLITE_API_KEY",
        0,
        "Satellite"
    ),
    (
        "et0",
        "ET0 Provider",
        "",
        "",
        "ARYA_ET0_API_KEY",
        0,
        "ET0"
    ),
    (
        "crop_knowledge",
        "Crop Knowledge Provider",
        "",
        "",
        "ARYA_CROP_KNOWLEDGE_API_KEY",
        0,
        "Crop knowledge"
    ),
    (
        "pest_disease",
        "Pest Disease Provider",
        "",
        "",
        "ARYA_PEST_API_KEY",
        0,
        "Pests"
    ),
    (
        "pesticide",
        "Pesticide Provider",
        "",
        "",
        "ARYA_PESTICIDE_API_KEY",
        0,
        "Pesticides"
    ),
    (
        "fertilizer",
        "Fertilizer Provider",
        "",
        "",
        "ARYA_FERTILIZER_API_KEY",
        0,
        "Fertilizers"
    ),
    (
        "market",
        "Market Provider",
        "",
        "",
        "ARYA_MARKET_API_KEY",
        0,
        "Market"
    ),
    (
        "translation",
        "Translation Provider",
        TRANSLATION_API_URL,
        "",
        "ARYA_TRANSLATION_API_KEY",
        0,
        "Translation"
    ),
    (
        "email",
        "Email Provider",
        "",
        "",
        "ARYA_EMAIL_API_KEY",
        0,
        "Email"
    ),
    (
        "sms",
        "SMS Provider",
        "",
        "",
        "ARYA_SMS_API_KEY",
        0,
        "SMS"
    ),
    (
        "push",
        "Push Provider",
        "",
        "",
        "ARYA_PUSH_API_KEY",
        0,
        "Push"
    ),
    (
        "blockchain",
        "Blockchain Provider",
        "",
        "",
        "ARYA_BLOCKCHAIN_API_KEY",
        0,
        "USDT verification"
    ),
    (
        "bank",
        "Bank Provider",
        "",
        "",
        "ARYA_BANK_API_KEY",
        0,
        "Bank verification"
    ),
]

PROVIDER_KEYS = {
    item[0]
    for item in PROVIDERS
}


def init_providers():
    conn = db()

    try:
        for (
            key,
            name,
            base,
            health,
            auth,
            required,
            notes,
        ) in PROVIDERS:

            conn.execute(
                """
                INSERT INTO external_providers(
                    key,
                    name,
                    base_url,
                    health_url,
                    auth_env,
                    enabled,
                    required,
                    notes,
                    updated_at
                )
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(key)
                DO UPDATE SET
                    name=excluded.name,
                    auth_env=excluded.auth_env,
                    required=excluded.required
                """,
                (
                    key,
                    name,
                    base,
                    health,
                    auth,
                    int(bool(base)),
                    required,
                    notes,
                    now_iso(),
                ),
            )

        conn.commit()

    finally:
        conn.close()


def provider_row(
    key: str,
):
    return q(
        """
        SELECT *
        FROM external_providers
        WHERE key=?
        """,
        (key,),
        one=True,
    )


def provider_enabled(
    key: str,
) -> bool:
    row = provider_row(key)

    return bool(
        row
        and row["enabled"]
        and row["base_url"]
    )


def provider_headers(
    key: str,
):
    row = provider_row(key)

    if not row:
        return {}

    env = row["auth_env"] or ""

    secret = (
        os.getenv(env, "")
        if env
        else ""
    )

    if not secret:
        return {}

    return {
        "Authorization":
            f"Bearer {secret}",
        "X-API-Key":
            secret,
    }


def provider_request(
    key: str,
    path: str = "",
    params=None,
    method: str = "GET",
    json_body=None,
):
    row = provider_row(key)

    if not row:
        raise HTTPException(
            404,
            "provider not found",
        )

    if not row["enabled"]:
        raise HTTPException(
            503,
            "provider disabled",
        )

    base = (
        row["base_url"] or ""
    ).rstrip("/")

    if not base:
        raise HTTPException(
            503,
            "provider not configured",
        )

    url = (
        base
        + "/"
        + path.lstrip("/")
    )

    try:
        response = requests.request(
            method,
            url,
            params=params,
            json=json_body,
            headers=provider_headers(
                key
            ),
            timeout=WEATHER_TIMEOUT,
        )

        response.raise_for_status()

        try:
            return response.json()
        except Exception:
            return {
                "text": response.text
            }

    except requests.RequestException as exc:
        raise HTTPException(
            502,
            f"provider request failed: {exc}",
        )


def provider_status(
    key: str,
):
    row = provider_row(key)

    if not row:
        return {
            "key": key,
            "configured": False,
            "healthy": False,
        }

    if not row["enabled"]:
        return {
            "key": key,
            "configured": bool(
                row["base_url"]
            ),
            "enabled": False,
            "healthy": None,
        }

    url = (
        row["health_url"]
        or row["base_url"]
    )

    if not url:
        return {
            "key": key,
            "configured": False,
            "healthy": False,
        }

    try:
        response = requests.get(
            url,
            headers=provider_headers(
                key
            ),
            timeout=10,
        )

        return {
            "key": key,
            "configured": True,
            "healthy": response.ok,
            "status_code":
                response.status_code,
        }

    except requests.RequestException as exc:
        return {
            "key": key,
            "configured": True,
            "healthy": False,
            "error": str(exc),
        }


# ============================================================
# AUTH
# ============================================================

def create_token(
    user_id: int,
):
    raw = secrets.token_urlsafe(48)

    expires = (
        datetime.now(timezone.utc)
        + timedelta(days=TOKEN_DAYS)
    ).isoformat()

    q(
        """
        INSERT INTO auth_tokens(
            user_id,
            token_hash,
            expires_at,
            revoked,
            created_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            user_id,
            token_hash(raw),
            expires,
            0,
            now_iso(),
        ),
    )

    return raw, expires


def current_user(
    authorization: Optional[str] = None,
):
    if not authorization:
        raise HTTPException(
            401,
            "authorization required",
        )

    token = authorization.strip()

    if token.lower().startswith(
        "bearer "
    ):
        token = token[7:].strip()

    row = q(
        """
        SELECT
            u.*,
            t.expires_at AS token_expires
        FROM auth_tokens t
        JOIN users u
            ON u.id=t.user_id
        WHERE t.token_hash=?
          AND t.revoked=0
          AND u.active=1
        """,
        (
            token_hash(token),
        ),
        one=True,
    )

    if not row:
        raise HTTPException(
            401,
            "invalid token",
        )

    try:
        expires = datetime.fromisoformat(
            row["token_expires"]
        )

        if expires < datetime.now(
            timezone.utc
        ):
            raise HTTPException(
                401,
                "token expired",
            )

    except ValueError:
        raise HTTPException(
            401,
            "invalid token expiration",
        )

    return row


# ============================================================
# AUTH ROUTES
# ============================================================

@app.post("/auth/register")
def register(
    x: RegisterIn,
):
    email = norm_email(x.email)

    if q(
        "SELECT id FROM users WHERE email=?",
        (email,),
        one=True,
    ):
        raise HTTPException(
            409,
            "email already registered",
        )

    created = now_iso()

    user_id = q(
        """
        INSERT INTO users(
            email,
            password_hash,
            name,
            phone,
            country,
            language,
            role,
            active,
            created_at,
            updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?)
        """,
        (
            email,
            hash_password(x.password),
            x.name,
            x.phone,
            x.country,
            x.language,
            "user",
            1,
            created,
            created,
        ),
    )

    audit(
        user_id,
        "register",
        "users",
        user_id,
    )

    return {
        "ok": True,
        "user_id": user_id,
    }


@app.post("/auth/login")
def login(
    x: LoginIn,
):
    user = q(
        """
        SELECT *
        FROM users
        WHERE email=?
        """,
        (
            norm_email(x.email),
        ),
        one=True,
    )

    if not user:
        raise HTTPException(
            401,
            "invalid credentials",
        )

    if not user["active"]:
        raise HTTPException(
            403,
            "user disabled",
        )

    if not verify_password(
        x.password,
        user["password_hash"],
    ):
        raise HTTPException(
            401,
            "invalid credentials",
        )

    if user["mfa_enabled"]:
        if not verify_totp(
            user["mfa_secret"],
            x.mfa_code,
        ):
            raise HTTPException(
                401,
                "mfa required or invalid",
            )

    token, expires = create_token(
        user["id"]
    )

    audit(
        user["id"],
        "login",
        "users",
        user["id"],
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
            "language": user["language"],
        },
    }


@app.post("/auth/logout")
def logout(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    token = authorization.strip()

    if token.lower().startswith(
        "bearer "
    ):
        token = token[7:].strip()

    q(
        """
        UPDATE auth_tokens
        SET revoked=1
        WHERE token_hash=?
        """,
        (
            token_hash(token),
        ),
    )

    audit(
        user["id"],
        "logout",
        "auth_tokens",
    )

    return {"ok": True}


@app.get("/auth/me")
def me(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "phone": user["phone"],
        "country": user["country"],
        "language": user["language"],
        "role": user["role"],
        "mfa_enabled":
            bool(user["mfa_enabled"]),
    }


@app.post(
    "/auth/password-reset/request"
)
def password_reset_request(
    x: PasswordResetRequestIn,
):
    user = q(
        """
        SELECT *
        FROM users
        WHERE email=?
        """,
        (
            norm_email(x.email),
        ),
        one=True,
    )

    result = {
        "ok": True,
        "message":
            "If the account exists, "
            "reset instructions will be sent.",
    }

    if not user:
        return result

    raw = secrets.token_urlsafe(48)

    expires = (
        datetime.now(timezone.utc)
        + timedelta(hours=RESET_HOURS)
    ).isoformat()

    q(
        """
        INSERT INTO password_resets(
            user_id,
            token_hash,
            expires_at,
            used,
            created_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            user["id"],
            token_hash(raw),
            expires,
            0,
            now_iso(),
        ),
    )

    if os.getenv(
        "ARYA_RESET_RETURN_TOKEN",
        "0",
    ) == "1":
        result["reset_token"] = raw

    return result


@app.post(
    "/auth/password-reset/confirm"
)
def password_reset_confirm(
    x: PasswordResetConfirmIn,
):
    row = q(
        """
        SELECT *
        FROM password_resets
        WHERE token_hash=?
          AND used=0
        """,
        (
            token_hash(x.token),
        ),
        one=True,
    )

    if not row:
        raise HTTPException(
            400,
            "invalid reset token",
        )

    try:
        if datetime.fromisoformat(
            row["expires_at"]
        ) < datetime.now(
            timezone.utc
        ):
            raise HTTPException(
                400,
                "reset token expired",
            )
    except ValueError:
        raise HTTPException(
            400,
            "invalid reset expiration",
        )

    q(
        """
        UPDATE users
        SET password_hash=?,
            updated_at=?
        WHERE id=?
        """,
        (
            hash_password(
                x.new_password
            ),
            now_iso(),
            row["user_id"],
        ),
    )

    q(
        """
        UPDATE password_resets
        SET used=1
        WHERE id=?
        """,
        (row["id"],),
    )

    q(
        """
        UPDATE auth_tokens
        SET revoked=1
        WHERE user_id=?
        """,
        (row["user_id"],),
    )

    audit(
        row["user_id"],
        "password_reset",
        "users",
        row["user_id"],
    )

    return {"ok": True}


# ============================================================
# OWNER / MFA
# ============================================================

@app.post("/owner/bootstrap")
def owner_bootstrap(
    x: OwnerBootstrapIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if not OWNER_BOOTSTRAP_SECRET:
        raise HTTPException(
            503,
            "owner bootstrap secret is not configured",
        )

    if not hmac.compare_digest(
        x.secret,
        OWNER_BOOTSTRAP_SECRET,
    ):
        raise HTTPException(
            403,
            "invalid bootstrap secret",
        )

    existing = q(
        """
        SELECT id
        FROM users
        WHERE role='owner'
        LIMIT 1
        """,
        one=True,
    )

    if existing:
        raise HTTPException(
            409,
            "owner already initialized",
        )

    if OWNER_EMAIL and (
        norm_email(user["email"])
        != norm_email(OWNER_EMAIL)
    ):
        raise HTTPException(
            403,
            "owner email mismatch",
        )

    q(
        """
        UPDATE users
        SET role='owner',
            updated_at=?
        WHERE id=?
        """,
        (
            now_iso(),
            user["id"],
        ),
    )

    audit(
        user["id"],
        "owner_bootstrap",
        "users",
        user["id"],
    )

    return {
        "ok": True,
        "role": "owner",
    }


@app.post("/owner/mfa/setup")
def owner_mfa_setup(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    require_owner(user)

    secret = user["mfa_secret"]

    if not secret:
        secret = base64.b32encode(
            secrets.token_bytes(20)
        ).decode().rstrip("=")

        q(
            """
            UPDATE users
            SET mfa_secret=?,
                updated_at=?
            WHERE id=?
            """,
            (
                secret,
                now_iso(),
                user["id"],
            ),
        )

    return {
        "secret": secret,
        "issuer": APP_NAME,
        "account": user["email"],
    }


@app.post("/owner/mfa/enable")
def owner_mfa_enable(
    x: MFAEnableIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    require_owner(user)

    if not verify_totp(
        user["mfa_secret"],
        x.code,
    ):
        raise HTTPException(
            400,
            "invalid mfa code",
        )

    q(
        """
        UPDATE users
        SET mfa_enabled=1,
            updated_at=?
        WHERE id=?
        """,
        (
            now_iso(),
            user["id"],
        ),
    )

    audit(
        user["id"],
        "mfa_enable",
        "users",
        user["id"],
    )

    return {
        "ok": True,
        "mfa_enabled": True,
    }


@app.post("/owner/mfa/disable")
def owner_mfa_disable(
    x: MFAEnableIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    require_owner(user)

    if not verify_totp(
        user["mfa_secret"],
        x.code,
    ):
        raise HTTPException(
            400,
            "invalid mfa code",
        )

    q(
        """
        UPDATE users
        SET mfa_enabled=0,
            updated_at=?
        WHERE id=?
        """,
        (
            now_iso(),
            user["id"],
        ),
    )

    return {
        "ok": True,
        "mfa_enabled": False,
    }


# ============================================================
# FARM / LAND / CROP / TREE
# ============================================================

@app.post("/farms")
def create_farm(
    x: FarmIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    validate_coords(
        x.latitude,
        x.longitude,
    )

    farm_id = q(
        """
        INSERT INTO farms(
            user_id,
            name,
            description,
            country,
            region,
            address,
            latitude,
            longitude,
            area_ha,
            soil_type,
            climate_type,
            created_at,
            updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            x.name,
            x.description,
            x.country,
            x.region,
            x.address,
            x.latitude,
            x.longitude,
            x.area_ha,
            x.soil_type,
            x.climate_type,
            now_iso(),
            now_iso(),
        ),
    )

    audit(
        user["id"],
        "farm_create",
        "farms",
        farm_id,
    )

    return q(
        "SELECT * FROM farms WHERE id=?",
        (farm_id,),
        one=True,
    )


@app.get("/farms")
def list_farms(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT *
        FROM farms
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user["id"],),
        many=True,
    )


@app.get("/farms/{farm_id}")
def get_farm(
    farm_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    row = q(
        """
        SELECT *
        FROM farms
        WHERE id=?
          AND user_id=?
        """,
        (
            farm_id,
            user["id"],
        ),
        one=True,
    )

    if not row:
        raise HTTPException(
            404,
            "farm not found",
        )

    return row


@app.post("/lands")
def create_land(
    x: LandIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    farm = q(
        """
        SELECT id
        FROM farms
        WHERE id=?
          AND user_id=?
        """,
        (
            x.farm_id,
            user["id"],
        ),
        one=True,
    )

    if not farm:
        raise HTTPException(
            404,
            "farm not found",
        )

    validate_coords(
        x.latitude,
        x.longitude,
    )

    land_id = q(
        """
        INSERT INTO lands(
            farm_id,
            name,
            area_ha,
            latitude,
            longitude,
            soil_type,
            irrigation_type,
            water_source,
            notes,
            created_at,
            updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            x.farm_id,
            x.name,
            x.area_ha,
            x.latitude,
            x.longitude,
            x.soil_type,
            x.irrigation_type,
            x.water_source,
            x.notes,
            now_iso(),
            now_iso(),
        ),
    )

    return q(
        "SELECT * FROM lands WHERE id=?",
        (land_id,),
        one=True,
    )


@app.get("/farms/{farm_id}/lands")
def list_lands(
    farm_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if not q(
        """
        SELECT id
        FROM farms
        WHERE id=?
          AND user_id=?
        """,
        (
            farm_id,
            user["id"],
        ),
        one=True,
    ):
        raise HTTPException(
            404,
            "farm not found",
        )

    return q(
        """
        SELECT *
        FROM lands
        WHERE farm_id=?
        ORDER BY id DESC
        """,
        (farm_id,),
        many=True,
    )


@app.post("/crops")
def create_crop(
    x: CropIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if not q(
        """
        SELECT l.id
        FROM lands l
        JOIN farms f
            ON f.id=l.farm_id
        WHERE l.id=?
          AND f.user_id=?
        """,
        (
            x.land_id,
            user["id"],
        ),
        one=True,
    ):
        raise HTTPException(
            404,
            "land not found",
        )

    crop_id = q(
        """
        INSERT INTO crops(
            land_id,
            name,
            variety,
            planted_at,
            harvest_at,
            area_ha,
            growth_stage,
            irrigation_l_day,
            expected_yield_min,
            expected_yield_max,
            notes,
            created_at,
            updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            x.land_id,
            x.name,
            x.variety,
            x.planted_at,
            x.harvest_at,
            x.area_ha,
            x.growth_stage,
            x.irrigation_l_day,
            x.expected_yield_min,
            x.expected_yield_max,
            x.notes,
            now_iso(),
            now_iso(),
        ),
    )

    return q(
        "SELECT * FROM crops WHERE id=?",
        (crop_id,),
        one=True,
    )


@app.get("/lands/{land_id}/crops")
def list_crops(
    land_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT c.*
        FROM crops c
        JOIN lands l
            ON l.id=c.land_id
        JOIN farms f
            ON f.id=l.farm_id
        WHERE c.land_id=?
          AND f.user_id=?
        ORDER BY c.id DESC
        """,
        (
            land_id,
            user["id"],
        ),
        many=True,
    )


@app.post("/trees")
def create_tree(
    x: TreeIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if not q(
        """
        SELECT l.id
        FROM lands l
        JOIN farms f
            ON f.id=l.farm_id
        WHERE l.id=?
          AND f.user_id=?
        """,
        (
            x.land_id,
            user["id"],
        ),
        one=True,
    ):
        raise HTTPException(
            404,
            "land not found",
        )

    tree_id = q(
        """
        INSERT INTO trees(
            land_id,
            species,
            variety,
            age_years,
            tree_count,
            health,
            irrigation_l_day,
            notes,
            created_at,
            updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?)
        """,
        (
            x.land_id,
            x.species,
            x.variety,
            x.age_years,
            x.tree_count,
            x.health,
            x.irrigation_l_day,
            x.notes,
            now_iso(),
            now_iso(),
        ),
    )

    return q(
        "SELECT * FROM trees WHERE id=?",
        (tree_id,),
        one=True,
    )


@app.get("/lands/{land_id}/trees")
def list_trees(
    land_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT t.*
        FROM trees t
        JOIN lands l
            ON l.id=t.land_id
        JOIN farms f
            ON f.id=l.farm_id
        WHERE t.land_id=?
          AND f.user_id=?
        ORDER BY t.id DESC
        """,
        (
            land_id,
            user["id"],
        ),
        many=True,
    )


# ============================================================
# SOIL / WATER
# ============================================================

@app.post("/soil/tests")
def create_soil_test(
    x: SoilTestIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if not q(
        """
        SELECT l.id
        FROM lands l
        JOIN farms f
            ON f.id=l.farm_id
        WHERE l.id=?
          AND f.user_id=?
        """,
        (
            x.land_id,
            user["id"],
        ),
        one=True,
    ):
        raise HTTPException(
            404,
            "land not found",
        )

    validate_ph(x.ph)

    test_id = q(
        """
        INSERT INTO soil_tests(
            land_id,
            test_date,
            ph,
            ec,
            organic_matter,
            nitrogen,
            phosphorus,
            potassium,
            calcium,
            magnesium,
            sulfur,
            zinc,
            iron,
            boron,
            soil_texture,
            salinity,
            raw_json,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            x.land_id,
            x.test_date,
            x.ph,
            x.ec,
            x.organic_matter,
            x.nitrogen,
            x.phosphorus,
            x.potassium,
            x.calcium,
            x.magnesium,
            x.sulfur,
            x.zinc,
            x.iron,
            x.boron,
            x.soil_texture,
            x.salinity,
            jdump(x.raw),
            now_iso(),
        ),
    )

    return q(
        "SELECT * FROM soil_tests WHERE id=?",
        (test_id,),
        one=True,
    )


@app.get("/lands/{land_id}/soil/tests")
def list_soil_tests(
    land_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT s.*
        FROM soil_tests s
        JOIN lands l
            ON l.id=s.land_id
        JOIN farms f
            ON f.id=l.farm_id
        WHERE s.land_id=?
          AND f.user_id=?
        ORDER BY s.id DESC
        """,
        (
            land_id,
            user["id"],
        ),
        many=True,
    )


@app.post("/water/tests")
def create_water_test(
    x: WaterTestIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if not q(
        """
        SELECT l.id
        FROM lands l
        JOIN farms f
            ON f.id=l.farm_id
        WHERE l.id=?
          AND f.user_id=?
        """,
        (
            x.land_id,
            user["id"],
        ),
        one=True,
    ):
        raise HTTPException(
            404,
            "land not found",
        )

    validate_ph(x.ph)

    test_id = q(
        """
        INSERT INTO water_tests(
            land_id,
            test_date,
            ph,
            ec,
            tss,
            hardness,
            sodium,
            chloride,
            bicarbonate,
            boron,
            sar,
            raw_json,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            x.land_id,
            x.test_date,
            x.ph,
            x.ec,
            x.tss,
            x.hardness,
            x.sodium,
            x.chloride,
            x.bicarbonate,
            x.boron,
            x.sar,
            jdump(x.raw),
            now_iso(),
        ),
    )

    return q(
        "SELECT * FROM water_tests WHERE id=?",
        (test_id,),
        one=True,
    )


@app.get("/lands/{land_id}/water/tests")
def list_water_tests(
    land_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT w.*
        FROM water_tests w
        JOIN lands l
            ON l.id=w.land_id
        JOIN farms f
            ON f.id=l.farm_id
        WHERE w.land_id=?
          AND f.user_id=?
        ORDER BY w.id DESC
        """,
        (
            land_id,
            user["id"],
        ),
        many=True,
    )


# ============================================================
# WEATHER / LOCATION
# ============================================================

@app.get("/weather/current")
def weather_current(
    latitude: float,
    longitude: float,
    authorization: Optional[str] = Header(None),
):
    current_user(
        authorization
    )

    validate_coords(
        latitude,
        longitude,
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
        "timezone": "auto",
    }

    try:
        response = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params=params,
            timeout=WEATHER_TIMEOUT,
        )

        response.raise_for_status()

        return {
            "verified": True,
            "provider": "open-meteo",
            "data": response.json(),
        }

    except requests.RequestException as exc:
        return {
            "verified": False,
            "provider": "open-meteo",
            "error": str(exc),
        }


@app.get("/weather/forecast")
def weather_forecast(
    latitude: float,
    longitude: float,
    days: int = 7,
    authorization: Optional[str] = Header(None),
):
    current_user(
        authorization
    )

    validate_coords(
        latitude,
        longitude,
    )

    days = max(
        1,
        min(days, 16),
    )

    try:
        response = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude": latitude,
                "longitude": longitude,
                "forecast_days": days,
                "daily": (
                    "temperature_2m_max,"
                    "temperature_2m_min,"
                    "precipitation_sum,"
                    "wind_speed_10m_max"
                ),
                "timezone": "auto",
            },
            timeout=WEATHER_TIMEOUT,
        )

        response.raise_for_status()

        return {
            "verified": True,
            "provider": "open-meteo",
            "data": response.json(),
        }

    except requests.RequestException as exc:
        return {
            "verified": False,
            "provider": "open-meteo",
            "error": str(exc),
        }


@app.post("/weather/observation")
def weather_observation(
    x: WeatherIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    validate_coords(
        x.latitude,
        x.longitude,
    )

    oid = q(
        """
        INSERT INTO weather_observations(
            user_id,
            lat,
            lon,
            observed_at,
            temperature,
            humidity,
            rain_mm,
            wind_kmh,
            source,
            raw_json,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            x.latitude,
            x.longitude,
            x.observed_at or now_iso(),
            x.temperature,
            x.humidity,
            x.rain_mm,
            x.wind_kmh,
            x.source,
            jdump(x.raw),
            now_iso(),
        ),
    )

    return q(
        """
        SELECT *
        FROM weather_observations
        WHERE id=?
        """,
        (oid,),
        one=True,
    )


@app.post("/location")
def create_location(
    x: LocationIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    validate_coords(
        x.latitude,
        x.longitude,
    )

    lid = q(
        """
        INSERT INTO location_records(
            user_id,
            lat,
            lon,
            address,
            region,
            country,
            source,
            confidence,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            x.latitude,
            x.longitude,
            x.address,
            x.region,
            x.country,
            x.source,
            1,
            now_iso(),
        ),
    )

    return q(
        """
        SELECT *
        FROM location_records
        WHERE id=?
        """,
        (lid,),
        one=True,
    )


@app.get("/location/reverse")
def reverse_geocode(
    lat: float,
    lon: float,
    authorization: Optional[str] = Header(None),
):
    current_user(
        authorization
    )

    validate_coords(
        lat,
        lon,
    )

    if not provider_enabled(
        "geocoding"
    ):
        return {
            "status": "unavailable",
            "verified": False,
            "latitude": lat,
            "longitude": lon,
            "reason":
                "No approved geocoding provider configured.",
        }

    return {
        "status": "ok",
        "verified": True,
        "provider": "geocoding",
        "data": provider_request(
            "geocoding",
            "reverse",
            {
                "lat": lat,
                "lon": lon,
            },
        ),
    }


# ============================================================
# AI
# ============================================================

def ai_daily_count(
    user_id: int,
) -> int:
    row = q(
        """
        SELECT COALESCE(
            SUM(requests),
            0
        ) n
        FROM ai_usage
        WHERE user_id=?
          AND usage_date=?
        """,
        (
            user_id,
            today(),
        ),
        one=True,
    )

    return int(row["n"])


def record_ai_usage(
    user_id: int,
    tokens: int = 0,
):
    q(
        """
        INSERT INTO ai_usage(
            user_id,
            usage_date,
            tokens,
            requests,
            created_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            user_id,
            today(),
            tokens,
            1,
            now_iso(),
        ),
    )


def openai_chat(
    prompt: str,
    context: dict,
    language: str,
):
    if not OPENAI_API_KEY:
        return None

    url = (
        OPENAI_BASE_URL
        + "/chat/completions"
    )

    system = """
You are ARYA AgriDoctor, a specialist
agricultural decision-support assistant.

Use supplied data first.
Do not invent weather, pesticide doses,
fertilizer rates, market prices, diagnoses,
laboratory values or guaranteed yields.

If reliable data is missing, explicitly say
what is missing.

Distinguish:
1. verified data
2. user-provided data
3. inference
4. recommendation.

Never guarantee agricultural outcomes.
"""

    body = {
        "model": OPENAI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": system,
            },
            {
                "role": "user",
                "content": (
                    f"Language: {language}\n"
                    f"Context:\n{jdump(context)}\n\n"
                    f"Question:\n{prompt}"
                ),
            },
        ],
    }

    try:
        response = requests.post(
            url,
            headers={
                "Authorization":
                    f"Bearer {OPENAI_API_KEY}",
                "Content-Type":
                    "application/json",
            },
            json=body,
            timeout=60,
        )

        response.raise_for_status()

        data = response.json()

        choices = data.get(
            "choices",
            [],
        )

        if not choices:
            return None

        content = (
            choices[0]
            .get("message", {})
            .get("content", "")
        )

        usage = data.get(
            "usage",
            {},
        )

        return {
            "text": content,
            "usage": usage,
            "provider": "openai",
            "verified": True,
        }

    except requests.RequestException:
        return None


def local_ai_fallback(
    prompt: str,
    context: dict,
    language: str,
):
    return {
        "text":
            "برای ارائه پاسخ تخصصی و قابل اتکا، "
            "داده معتبر کافی در دسترس نیست. "
            "لطفاً اطلاعات مزرعه، محصول، خاک، آب، "
            "موقعیت و شرایط فعلی را تکمیل کنید.",
        "provider": "local-safe-fallback",
        "verified": False,
        "language": language,
    }


@app.post("/ai/analyze")
def ai_analyze(
    x: AIRequestIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if ai_daily_count(
        user["id"]
    ) >= DAILY_AI_LIMIT:
        raise HTTPException(
            429,
            "daily AI limit reached",
        )

    # ========================================================
    # ARYA SPECIALIST ANALYSIS ENGINE
    # ========================================================
    specialist_result = analyze_request(
        {
            "prompt": x.prompt,
            "language": x.language,
            "context": x.context,
        }
    )

    # --------------------------------------------------------
    # Preserve the original user context and add the
    # specialist agricultural analysis.
    # --------------------------------------------------------
    enhanced_context = {}

    if isinstance(
        x.context,
        dict,
    ):
        enhanced_context.update(
            x.context
        )

    enhanced_context[
        "arya_specialist_analysis"
    ] = specialist_result

    # ========================================================
    # EXISTING AI PROVIDER
    # ========================================================
    result = openai_chat(
        x.prompt,
        enhanced_context,
        x.language,
    )

    # ========================================================
    # EXISTING LOCAL FALLBACK
    # ========================================================
    if result is None:
        result = local_ai_fallback(
            x.prompt,
            enhanced_context,
            x.language,
        )

    # --------------------------------------------------------
    # Safety: make sure result is always a dictionary.
    # --------------------------------------------------------
    if not isinstance(
        result,
        dict,
    ):
        result = {
            "provider": "arya_backend",
            "verified": False,
            "text": str(result),
        }

    # ========================================================
    # Attach specialist analysis without destroying the
    # existing provider response.
    # ========================================================
    result[
        "arya_specialist_analysis"
    ] = specialist_result

    # ========================================================
    # Token accounting
    # ========================================================
    tokens = int(
        result.get(
            "usage",
            {},
        ).get(
            "total_tokens",
            0,
        )
        if isinstance(
            result.get(
                "usage",
                {},
            ),
            dict,
        )
        else 0
    )

    record_ai_usage(
        user["id"],
        tokens,
    )

    # ========================================================
    # Database record
    # ========================================================
    request_id = q(
        """
        INSERT INTO ai_requests(
            user_id,
            prompt,
            language,
            context_json,
            response_json,
            provider,
            verified,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            x.prompt,
            x.language,
            jdump(enhanced_context),
            jdump(result),
            result.get(
                "provider",
                "",
            ),
            int(
                bool(
                    result.get(
                        "verified",
                        False,
                    )
                )
            ),
            now_iso(),
        ),
    )

    # ========================================================
    # Audit
    # ========================================================
    audit(
        user["id"],
        "ai_analyze",
        "ai_requests",
        request_id,
    )

    # ========================================================
    # Final response
    # ========================================================
    return {
        "id": request_id,
        **result,
    }


@app.post("/recommendations")
def recommendation(
    x: RecommendationIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    land = q(
        """
        SELECT
            l.*,
            f.name AS farm_name,
            f.region,
            f.country,
            f.latitude AS farm_latitude,
            f.longitude AS farm_longitude,
            f.climate_type
        FROM lands l
        JOIN farms f
            ON f.id=l.farm_id
        WHERE l.id=?
          AND f.user_id=?
        """,
        (
            x.land_id,
            user["id"],
        ),
        one=True,
    )

    if not land:
        raise HTTPException(
            404,
            "land not found",
        )

    context = {
        "land": land,
        "crop_name": x.crop_name,
        "goal": x.goal,
        **x.context,
    }

    prompt = (
        "بر اساس اطلاعات مزرعه، "
        "زمین، خاک، آب و محصول، "
        "یک تحلیل کشاورزی محافظه‌کارانه ارائه کن."
    )

    result = openai_chat(
        prompt,
        context,
        user["language"],
    )

    if result is None:
        result = local_ai_fallback(
            prompt,
            context,
            user["language"],
        )

    return {
        "verified": result.get(
            "verified",
            False,
        ),
        "provider": result.get(
            "provider"
        ),
        "recommendation":
            result.get("text"),
        "warning":
            "این پاسخ توصیه تصمیم‌یار است و تضمین نتیجه نیست.",
    }


# ============================================================
# MEDIA
# ============================================================

@app.post("/media/upload")
async def media_upload(
    kind: str = Query(
        "image"
    ),
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if kind not in (
        "image",
        "voice",
        "document",
    ):
        raise HTTPException(
            400,
            "invalid media kind",
        )

    data = await file.read()

    max_bytes = (
        MAX_UPLOAD_MB
        * 1024
        * 1024
    )

    if len(data) > max_bytes:
        raise HTTPException(
            413,
            "file too large",
        )

    digest = sha256_bytes(data)

    stored = (
        f"{uuid.uuid4().hex}_"
        f"{safe_filename(file.filename)}"
    )

    path = MEDIA_DIR / stored

    path.write_bytes(data)

    media_id = q(
        """
        INSERT INTO media_files(
            user_id,
            kind,
            original_name,
            stored_name,
            mime_type,
            size_bytes,
            sha256,
            status,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            kind,
            file.filename or "",
            stored,
            file.content_type or "",
            len(data),
            digest,
            "stored",
            now_iso(),
        ),
    )

    return {
        "id": media_id,
        "kind": kind,
        "size_bytes": len(data),
        "sha256": digest,
        "status": "stored",
        "analysis": {
            "verified": False,
            "message":
                "File stored. No diagnosis was invented.",
        },
    }


@app.get("/media")
def list_media(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT
            id,
            kind,
            original_name,
            mime_type,
            size_bytes,
            sha256,
            status,
            analysis_json,
            created_at
        FROM media_files
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (
            user["id"],
        ),
        many=True,
    )


# ============================================================
# FEEDBACK / SUPPORT
# ============================================================

@app.post("/feedback")
def create_feedback(
    x: FeedbackIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    fid = q(
        """
        INSERT INTO feedback(
            user_id,
            subject,
            text,
            language,
            status,
            created_at,
            updated_at
        )
        VALUES(?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            x.subject,
            x.text,
            x.language,
            "open",
            now_iso(),
            now_iso(),
        ),
    )

    q(
        """
        INSERT INTO feedback_messages(
            feedback_id,
            sender_user_id,
            sender_role,
            language,
            text,
            created_at
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            fid,
            user["id"],
            user["role"],
            x.language,
            x.text,
            now_iso(),
        ),
    )

    audit(
        user["id"],
        "feedback_create",
        "feedback",
        fid,
    )

    return q(
        "SELECT * FROM feedback WHERE id=?",
        (fid,),
        one=True,
    )


@app.get("/feedback")
def list_feedback(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if user["role"] == "owner":
        return q(
            """
            SELECT *
            FROM feedback
            ORDER BY id DESC
            """,
            many=True,
        )

    return q(
        """
        SELECT *
        FROM feedback
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (
            user["id"],
        ),
        many=True,
    )


@app.post(
    "/feedback/{feedback_id}/messages"
)
def feedback_message(
    feedback_id: int,
    x: FeedbackMessageIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    feedback = q(
        """
        SELECT *
        FROM feedback
        WHERE id=?
        """,
        (feedback_id,),
        one=True,
    )

    if not feedback:
        raise HTTPException(
            404,
            "feedback not found",
        )

    if (
        user["role"] != "owner"
        and feedback["user_id"]
        != user["id"]
    ):
        raise HTTPException(
            403,
            "access denied",
        )

    role = (
        "owner"
        if user["role"] == "owner"
        else "user"
    )

    mid = q(
        """
        INSERT INTO feedback_messages(
            feedback_id,
            sender_user_id,
            sender_role,
            language,
            text,
            created_at
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            feedback_id,
            user["id"],
            role,
            x.language,
            x.text,
            now_iso(),
        ),
    )

    q(
        """
        UPDATE feedback
        SET updated_at=?,
            status=?
        WHERE id=?
        """,
        (
            now_iso(),
            "answered"
            if role == "owner"
            else "open",
            feedback_id,
        ),
    )

    return q(
        """
        SELECT *
        FROM feedback_messages
        WHERE id=?
        """,
        (mid,),
        one=True,
    )


# ============================================================
# PAYMENTS / PRICING
# ============================================================

def pricing_for(
    country: str,
    user_number: int,
):
    if (
        country or ""
    ).strip().lower() in (
        "iran",
        "ir",
        "ایران",
    ):
        if user_number <= 100:
            return 500000, "IRR"
        if user_number <= 600:
            return 800000, "IRR"
        return 1200000, "IRR"

    if user_number <= 100:
        return 10, "USDT"

    if user_number <= 600:
        return 15, "USDT"

    return 20, "USDT"


@app.get("/pricing")
def pricing(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    count_row = q(
        """
        SELECT COUNT(*) n
        FROM users
        WHERE role='user'
        """,
        one=True,
    )

    number = int(
        count_row["n"]
    )

    amount, currency = pricing_for(
        user["country"],
        number,
    )

    return {
        "user_number": number,
        "amount": amount,
        "currency": currency,
        "iran_method": "bank_transfer",
        "international_method": "USDT",
    }


@app.post("/payments")
def create_payment(
    x: PaymentIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    method = x.method.lower()
    currency = x.currency.upper()

    if method == "bank_transfer":
        if user["country"].lower() not in (
            "iran",
            "ir",
            "ایران",
        ):
            raise HTTPException(
                400,
                "bank transfer is restricted to Iran",
            )

    if method == "usdt":
        if currency != "USDT":
            raise HTTPException(
                400,
                "USDT payment requires USDT currency",
            )

    if method not in (
        "bank_transfer",
        "usdt",
    ):
        raise HTTPException(
            400,
            "unsupported payment method",
        )

    destination = q(
        """
        SELECT *
        FROM payment_destinations
        WHERE method=?
          AND currency=?
          AND active=1
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            method,
            currency,
        ),
        one=True,
    )

    pid = q(
        """
        INSERT INTO payments(
            user_id,
            amount,
            currency,
            method,
            reference,
            note,
            status,
            destination,
            network,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            x.amount,
            currency,
            method,
            x.reference,
            x.note,
            "pending",
            destination[
                "destination"
            ]
            if destination
            else "",
            destination[
                "network"
            ]
            if destination
            else "",
            now_iso(),
        ),
    )

    return q(
        "SELECT * FROM payments WHERE id=?",
        (pid,),
        one=True,
    )


@app.get("/payments")
def list_payments(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    if user["role"] == "owner":
        return q(
            """
            SELECT *
            FROM payments
            ORDER BY id DESC
            """,
            many=True,
        )

    return q(
        """
        SELECT *
        FROM payments
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (
            user["id"],
        ),
        many=True,
    )


@app.post(
    "/owner/payments/{payment_id}/approve"
)
def approve_payment(
    payment_id: int,
    x: PaymentDecisionIn,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    payment = q(
        """
        SELECT *
        FROM payments
        WHERE id=?
        """,
        (payment_id,),
        one=True,
    )

    if not payment:
        raise HTTPException(
            404,
            "payment not found",
        )

    q(
        """
        UPDATE payments
        SET status='approved',
            approved_by=?,
            approved_at=?,
            note=?
        WHERE id=?
        """,
        (
            owner["id"],
            now_iso(),
            x.note,
            payment_id,
        ),
    )

    starts = datetime.now(
        timezone.utc
    )

    expires = starts + timedelta(
        days=30
    )

    q(
        """
        INSERT INTO subscriptions(
            user_id,
            plan,
            amount,
            currency,
            starts_at,
            expires_at,
            status,
            payment_id,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            payment["user_id"],
            "standard",
            payment["amount"],
            payment["currency"],
            starts.isoformat(),
            expires.isoformat(),
            "active",
            payment_id,
            now_iso(),
        ),
    )

    audit(
        owner["id"],
        "payment_approve",
        "payments",
        payment_id,
    )

    return {
        "ok": True,
        "payment_id": payment_id,
        "subscription_days": 30,
    }


@app.post(
    "/owner/payments/{payment_id}/reject"
)
def reject_payment(
    payment_id: int,
    x: PaymentDecisionIn,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    q(
        """
        UPDATE payments
        SET status='rejected',
            approved_by=?,
            approved_at=?,
            note=?
        WHERE id=?
        """,
        (
            owner["id"],
            now_iso(),
            x.note,
            payment_id,
        ),
    )

    return {
        "ok": True
    }


# ============================================================
# PAYMENT DESTINATIONS
# ============================================================

@app.get(
    "/owner/payment-destinations"
)
def payment_destinations(
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    return q(
        """
        SELECT *
        FROM payment_destinations
        ORDER BY id DESC
        """,
        many=True,
    )


@app.post(
    "/owner/payment-destinations"
)
def create_payment_destination(
    x: DestinationIn,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    did = q(
        """
        INSERT INTO payment_destinations(
            method,
            currency,
            network,
            destination,
            active,
            created_by,
            created_at
        )
        VALUES(?,?,?,?,?,?,?)
        """,
        (
            x.method,
            x.currency.upper(),
            x.network,
            x.destination,
            1,
            owner["id"],
            now_iso(),
        ),
    )

    return q(
        """
        SELECT *
        FROM payment_destinations
        WHERE id=?
        """,
        (did,),
        one=True,
    )


@app.post(
    "/owner/payment-destinations/{destination_id}/disable"
)
def disable_payment_destination(
    destination_id: int,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    q(
        """
        UPDATE payment_destinations
        SET active=0
        WHERE id=?
        """,
        (destination_id,),
    )

    return {
        "ok": True
    }


# ============================================================
# SUBSCRIPTIONS / ACTIVATION / DEVICES
# ============================================================

@app.get("/subscriptions")
def subscriptions(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    rows = q(
        """
        SELECT *
        FROM subscriptions
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (
            user["id"],
        ),
        many=True,
    )

    return rows


@app.post("/devices/register")
def register_device(
    x: DeviceIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    existing = q(
        """
        SELECT *
        FROM devices
        WHERE user_id=?
          AND device_id=?
        """,
        (
            user["id"],
            x.device_id,
        ),
        one=True,
    )

    if existing:
        q(
            """
            UPDATE devices
            SET device_name=?,
                platform=?,
                active=1,
                last_seen=?
            WHERE id=?
            """,
            (
                x.device_name,
                x.platform,
                now_iso(),
                existing["id"],
            ),
        )

        return {
            "ok": True,
            "device_id": x.device_id,
        }

    count = q(
        """
        SELECT COUNT(*) n
        FROM devices
        WHERE user_id=?
          AND active=1
        """,
        (
            user["id"],
        ),
        one=True,
    )["n"]

    if int(count) >= DEVICE_LIMIT:
        raise HTTPException(
            409,
            "device limit reached",
        )

    did = q(
        """
        INSERT INTO devices(
            user_id,
            device_id,
            device_name,
            platform,
            active,
            last_seen,
            created_at
        )
        VALUES(?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            x.device_id,
            x.device_name,
            x.platform,
            1,
            now_iso(),
            now_iso(),
        ),
    )

    return {
        "ok": True,
        "id": did,
        "device_id": x.device_id,
    }


@app.get("/devices")
def list_devices(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT *
        FROM devices
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (
            user["id"],
        ),
        many=True,
    )


@app.post("/activate")
def activate(
    x: ActivationIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    row = q(
        """
        SELECT *
        FROM activation_codes
        WHERE code_hash=?
          AND used=0
        """,
        (
            token_hash(x.code),
        ),
        one=True,
    )

    if not row:
        raise HTTPException(
            400,
            "invalid activation code",
        )

    if row["expires_at"]:
        if datetime.fromisoformat(
            row["expires_at"]
        ) < datetime.now(
            timezone.utc
        ):
            raise HTTPException(
                400,
                "activation expired",
            )

    q(
        """
        UPDATE activation_codes
        SET used=1,
            user_id=?
        WHERE id=?
        """,
        (
            user["id"],
            row["id"],
        ),
    )

    starts = datetime.now(
        timezone.utc
    )

    expires = starts + timedelta(
        days=30
    )

    q(
        """
        INSERT INTO subscriptions(
            user_id,
            plan,
            amount,
            currency,
            starts_at,
            expires_at,
            status,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            row["plan"] or "standard",
            0,
            "",
            starts.isoformat(),
            expires.isoformat(),
            "active",
            now_iso(),
        ),
    )

    return {
        "ok": True,
        "expires_at":
            expires.isoformat(),
    }


# ============================================================
# NOTIFICATIONS / ALERTS
# ============================================================

@app.get("/notifications")
def notifications(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT *
        FROM notifications
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 200
        """,
        (
            user["id"],
        ),
        many=True,
    )


@app.post(
    "/notifications/{notification_id}/read"
)
def notification_read(
    notification_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    q(
        """
        UPDATE notifications
        SET read_at=?
        WHERE id=?
          AND user_id=?
        """,
        (
            now_iso(),
            notification_id,
            user["id"],
        ),
    )

    return {"ok": True}


@app.get("/alerts")
def alerts(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT *
        FROM agricultural_alerts
        WHERE
            user_id=?
            OR user_id IS NULL
        ORDER BY id DESC
        """,
        (
            user["id"],
        ),
        many=True,
    )


# ============================================================
# OFFLINE SYNC
# ============================================================

@app.post("/sync")
def sync(
    x: SyncIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    existing = q(
        """
        SELECT *
        FROM sync_events
        WHERE user_id=?
          AND client_event_id=?
        """,
        (
            user["id"],
            x.client_event_id,
        ),
        one=True,
    )

    if existing:
        return existing

    event_id = q(
        """
        INSERT INTO sync_events(
            user_id,
            client_event_id,
            operation,
            payload_json,
            status,
            created_at
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            user["id"],
            x.client_event_id,
            x.operation,
            jdump(x.payload),
            "accepted",
            now_iso(),
        ),
    )

    return q(
        """
        SELECT *
        FROM sync_events
        WHERE id=?
        """,
        (event_id,),
        one=True,
    )


@app.get("/sync")
def sync_list(
    authorization: Optional[str] = Header(None),
):
    user = current_user(
        authorization
    )

    return q(
        """
        SELECT *
        FROM sync_events
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 500
        """,
        (
            user["id"],
        ),
        many=True,
    )


# ============================================================
# KNOWLEDGE
# ============================================================

@app.get("/knowledge")
def knowledge(
    category: str = "",
    language: str = "fa",
    authorization: Optional[str] = Header(None),
):
    current_user(
        authorization
    )

    if category:
        return q(
            """
            SELECT *
            FROM knowledge_items
            WHERE category=?
              AND language=?
              AND active=1
            ORDER BY id DESC
            """,
            (
                category,
                language,
            ),
            many=True,
        )

    return q(
        """
        SELECT *
        FROM knowledge_items
        WHERE language=?
          AND active=1
        ORDER BY id DESC
        """,
        (
            language,
        ),
        many=True,
    )


@app.post("/owner/knowledge")
def create_knowledge(
    x: KnowledgeIn,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    kid = q(
        """
        INSERT INTO knowledge_items(
            category,
            title,
            content,
            language,
            source,
            version,
            active,
            created_at,
            updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            x.category,
            x.title,
            x.content,
            x.language,
            x.source,
            x.version,
            1,
            now_iso(),
            now_iso(),
        ),
    )

    return q(
        """
        SELECT *
        FROM knowledge_items
        WHERE id=?
        """,
        (kid,),
        one=True,
    )


# ============================================================
# PROVIDER MANAGEMENT
# ============================================================

@app.get("/integrations/status")
def integrations_status(
    authorization: Optional[str] = Header(None),
):
    current_user(
        authorization
    )

    rows = q(
        """
        SELECT
            key,
            name,
            base_url,
            health_url,
            enabled,
            required,
            notes,
            updated_at
        FROM external_providers
        ORDER BY key
        """,
        many=True,
    )

    result = []

    for row in rows:
        item = dict(row)

        item[
            "base_url_configured"
        ] = bool(
            item["base_url"]
        )

        item.pop(
            "base_url",
            None,
        )

        item.pop(
            "health_url",
            None,
        )

        item["healthy"] = (
            provider_status(
                item["key"]
            ).get("healthy")
            if item["enabled"]
            else None
        )

        result.append(item)

    return {
        "version": VERSION,
        "providers": result,
    }


@app.get("/owner/providers")
def owner_providers(
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    rows = q(
        """
        SELECT *
        FROM external_providers
        ORDER BY key
        """,
        many=True,
    )

    for row in rows:
        row["secret_configured"] = bool(
            row["auth_env"]
            and os.getenv(
                row["auth_env"],
                "",
            )
        )

    return rows


@app.put("/owner/providers/{key}")
def owner_provider_config(
    key: str,
    x: ProviderConfigIn,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    if key not in PROVIDER_KEYS:
        raise HTTPException(
            404,
            "unknown provider",
        )

    if (
        x.enabled
        and not x.base_url.strip()
    ):
        raise HTTPException(
            400,
            "base_url required",
        )

    q(
        """
        UPDATE external_providers
        SET base_url=?,
            health_url=?,
            enabled=?,
            required=?,
            notes=?,
            updated_at=?
        WHERE key=?
        """,
        (
            x.base_url.strip(),
            x.health_url.strip(),
            int(x.enabled),
            int(x.required),
            x.notes,
            now_iso(),
            key,
        ),
    )

    audit(
        owner["id"],
        "provider_config_update",
        "external_providers",
        None,
        {
            "key": key,
            "enabled": x.enabled,
        },
    )

    return {
        "ok": True,
        "key": key,
    }


@app.post(
    "/owner/providers/{key}/health"
)
def owner_provider_health(
    key: str,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    if key not in PROVIDER_KEYS:
        raise HTTPException(
            404,
            "unknown provider",
        )

    result = provider_status(
        key
    )

    audit(
        owner["id"],
        "provider_health_check",
        "external_providers",
        None,
        {
            "key": key,
            "healthy":
                result.get("healthy"),
        },
    )

    return result


@app.get(
    "/agri/provider-query/{provider}"
)
def provider_query(
    provider: str,
    path: str = "",
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    if provider not in PROVIDER_KEYS:
        raise HTTPException(
            404,
            "unknown provider",
        )

    return provider_request(
        provider,
        path,
    )
# ============================================================
# LEGACY AI COMPATIBILITY
# ============================================================

class LegacyAIAskIn(BaseModel):
    question: str = Field(
        ...,
        min_length=1,
        max_length=20000,
    )
    language: str = Field(
        default="fa",
        max_length=20,
    )
    context: dict = Field(
        default_factory=dict,
    )


@app.post("/ai/ask")
def legacy_ai_ask(
    x: LegacyAIAskIn,
    authorization: Optional[str] = Header(None),
):
    request_data = AIRequestIn(
        prompt=x.question,
        language=x.language,
        context=x.context,
    )

    return ai_analyze(
        request_data,
        authorization=authorization,
    )


# ============================================================
# END LEGACY AI COMPATIBILITY
# ============================================================

# ============================================================
# OWNER SETTINGS / STATS / USERS
# ============================================================

@app.get("/owner/settings")
def owner_settings(
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    rows = q(
        """
        SELECT *
        FROM system_settings
        ORDER BY key
        """,
        many=True,
    )

    for row in rows:
        if row["secret"]:
            row["value"] = "***"

    return rows


@app.put("/owner/settings/{key}")
def owner_setting(
    key: str,
    x: SettingIn,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    q(
        """
        INSERT INTO system_settings(
            key,
            value,
            secret,
            updated_by,
            updated_at
        )
        VALUES(?,?,?,?,?)
        ON CONFLICT(key)
        DO UPDATE SET
            value=excluded.value,
            secret=excluded.secret,
            updated_by=excluded.updated_by,
            updated_at=excluded.updated_at
        """,
        (
            key,
            x.value,
            int(x.secret),
            owner["id"],
            now_iso(),
        ),
    )

    return {"ok": True}


@app.get("/owner/users")
def owner_users(
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    return q(
        """
        SELECT
            id,
            email,
            name,
            phone,
            country,
            language,
            role,
            active,
            mfa_enabled,
            created_at
        FROM users
        ORDER BY id DESC
        """,
        many=True,
    )


@app.post(
    "/owner/users/{user_id}/disable"
)
def owner_disable_user(
    user_id: int,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    if user_id == owner["id"]:
        raise HTTPException(
            400,
            "cannot disable current owner",
        )

    q(
        """
        UPDATE users
        SET active=0,
            updated_at=?
        WHERE id=?
        """,
        (
            now_iso(),
            user_id,
        ),
    )

    q(
        """
        UPDATE auth_tokens
        SET revoked=1
        WHERE user_id=?
        """,
        (user_id,),
    )

    return {"ok": True}


@app.get("/owner/stats")
def owner_stats(
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    def count(
        table: str,
        where: str = "",
        args=(),
    ):
        row = q(
            f"""
            SELECT COUNT(*) n
            FROM {table}
            {where}
            """,
            args,
            one=True,
        )

        return row["n"]

    return {
        "users":
            count(
                "users",
                "WHERE role='user'",
            ),
        "owners":
            count(
                "users",
                "WHERE role='owner'",
            ),
        "farms":
            count("farms"),
        "lands":
            count("lands"),
        "crops":
            count("crops"),
        "trees":
            count("trees"),
        "payments_pending":
            count(
                "payments",
                "WHERE status='pending'",
            ),
        "payments_approved":
            count(
                "payments",
                "WHERE status='approved'",
            ),
        "active_subscriptions":
            count(
                "subscriptions",
                "WHERE status='active'",
            ),
        "feedback_open":
            count(
                "feedback",
                "WHERE status='open'",
            ),
        "ai_today":
            count(
                "ai_usage",
                "WHERE usage_date=?",
                (today(),),
            ),
        "devices":
            count("devices"),
    }


@app.get("/owner/audit")
def owner_audit(
    limit: int = 200,
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    return q(
        """
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (
            max(
                1,
                min(limit, 1000),
            ),
        ),
        many=True,
    )


# ============================================================
# BACKUP
# ============================================================

def create_backup_file():
    conn = db()

    try:
        tables = [
            row["name"]
            for row in conn.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                  AND name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        ]

        data = {}

        for table in tables:
            data[table] = [
                dict(row)
                for row in conn.execute(
                    f"SELECT * FROM {table}"
                ).fetchall()
            ]

    finally:
        conn.close()

    payload = jdump(
        {
            "version": VERSION,
            "created_at": now_iso(),
            "tables": data,
        }
    ).encode()

    path = (
        BASE_DIR
        / (
            "arya_backup_"
            + datetime.now(
                timezone.utc
            ).strftime(
                "%Y%m%dT%H%M%SZ"
            )
            + ".json"
        )
    )

    path.write_bytes(
        payload
    )

    return (
        path,
        sha256_bytes(payload),
    )


@app.post("/owner/backup")
def create_backup(
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    path, digest = (
        create_backup_file()
    )

    backup_id = q(
        """
        INSERT INTO backups(
            created_by,
            path,
            sha256,
            created_at
        )
        VALUES(?,?,?,?)
        """,
        (
            owner["id"],
            str(path),
            digest,
            now_iso(),
        ),
    )

    return {
        "id": backup_id,
        "path": str(path),
        "sha256": digest,
    }


@app.get("/owner/backups")
def list_backups(
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    return q(
        """
        SELECT *
        FROM backups
        ORDER BY id DESC
        """,
        many=True,
    )


# ============================================================
# EMERGENCY CONTROLS
# ============================================================

@app.post(
    "/owner/emergency/revoke-all-sessions"
)
def revoke_all_sessions(
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    q(
        """
        UPDATE auth_tokens
        SET revoked=1
        WHERE user_id!=?
        """,
        (
            owner["id"],
        ),
    )

    audit(
        owner["id"],
        "emergency_revoke_all_sessions",
    )

    return {"ok": True}


@app.post(
    "/owner/emergency/expire-all-subscriptions"
)
def expire_all_subscriptions(
    authorization: Optional[str] = Header(None),
):
    owner = current_user(
        authorization
    )

    require_owner(owner)

    q(
        """
        UPDATE subscriptions
        SET status='expired'
        WHERE status='active'
          AND user_id!=?
        """,
        (
            owner["id"],
        ),
    )

    audit(
        owner["id"],
        "emergency_expire_all_subscriptions",
    )

    return {"ok": True}


# ============================================================
# HEALTH / SYSTEM
# ============================================================

@app.get("/health")
def health():
    try:
        row = q(
            "SELECT 1 AS ok",
            one=True,
        )

        return {
            "ok": bool(row),
            "app": APP_NAME,
            "version": VERSION,
            "database": True,
            "time": now_iso(),
        }

    except Exception as exc:
        return {
            "ok": False,
            "app": APP_NAME,
            "version": VERSION,
            "database": False,
            "error": str(exc),
        }


@app.get("/")
def root():
    return {
        "app": APP_NAME,
        "version": VERSION,
        "status": "online",
        "docs": "/docs",
        "health": "/health",
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup():
    init_db()
    init_providers()


if __name__ == "__main__":
    import uvicorn

    init_db()
    init_providers()

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "8000",
            )
        ),
    )
