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
from typing import Any, Optional, Literal

import requests
from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr

# ============================================================
# ARYA AGRIDOCTOR — SINGLE FILE BACKEND
# Production-oriented foundation. External providers are explicit;
# the backend never invents diagnoses, doses, prices, or weather.
# ============================================================

APP_NAME = "ARYA AgriDoctor"
VERSION = "4.0.0"
BASE_DIR = Path(os.getenv("ARYA_BASE_DIR", ".")).resolve()
DB_PATH = Path(os.getenv("ARYA_DATABASE", str(BASE_DIR / "arya.db")))
MEDIA_DIR = Path(os.getenv("ARYA_MEDIA_DIR", str(BASE_DIR / "media")))
MEDIA_DIR.mkdir(parents=True, exist_ok=True)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
TRANSLATION_API_URL = os.getenv("ARYA_TRANSLATION_API_URL", "")
TRANSLATION_API_KEY = os.getenv("ARYA_TRANSLATION_API_KEY", "")
WEATHER_TIMEOUT = int(os.getenv("ARYA_WEATHER_TIMEOUT", "20"))
TOKEN_DAYS = int(os.getenv("ARYA_TOKEN_DAYS", "30"))
RESET_HOURS = int(os.getenv("ARYA_RESET_HOURS", "2"))
DAILY_AI_LIMIT = int(os.getenv("ARYA_DAILY_AI_LIMIT", "30"))
DEVICE_LIMIT = int(os.getenv("ARYA_DEVICE_LIMIT", "3"))
PBKDF2_ITERATIONS = int(os.getenv("ARYA_PBKDF2_ITERATIONS", "310000"))
MAX_UPLOAD_MB = int(os.getenv("ARYA_MAX_UPLOAD_MB", "15"))
OWNER_BOOTSTRAP_SECRET = os.getenv("ARYA_OWNER_BOOTSTRAP_SECRET", "")
OWNER_EMAIL = os.getenv("ARYA_OWNER_EMAIL", "")

app = FastAPI(title=APP_NAME, version=VERSION)

CORS_ORIGINS = [
    x.strip()
    for x in os.getenv("ARYA_CORS", "*").split(",")
    if x.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=(CORS_ORIGINS != ["*"]),
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------- utilities -----------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if len(password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        PBKDF2_ITERATIONS,
    )
    return (
        base64.urlsafe_b64encode(salt).decode()
        + "$"
        + base64.urlsafe_b64encode(dk).decode()
    )


def totp_code(secret: str, timestamp: Optional[int] = None) -> str:
    if not secret:
        return ""

    timestamp = timestamp or int(time.time())
    counter = timestamp // 30

    key = base64.b32decode(
        secret.upper()
        + "=" * ((8 - len(secret) % 8) % 8)
    )

    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F

    num = (
        struct.unpack(">I", digest[off:off + 4])[0]
        & 0x7FFFFFFF
    ) % 1000000

    return f"{num:06d}"


def verify_totp(secret: str, code: str) -> bool:
    if not re.fullmatch(r"\d{6}", code or ""):
        return False

    t = int(time.time())

    return any(
        hmac.compare_digest(
            totp_code(secret, t + d),
            code,
        )
        for d in (-30, 0, 30)
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_s, digest_s = stored.split("$", 1)

        salt = base64.urlsafe_b64decode(
            salt_s.encode()
        )

        digest = base64.urlsafe_b64decode(
            digest_s.encode()
        )

        test = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            PBKDF2_ITERATIONS,
        )

        return hmac.compare_digest(test, digest)

    except Exception:
        return False


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def norm_email(v: str) -> str:
    return v.strip().lower()


def jdump(v: Any) -> str:
    return json.dumps(
        v,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def jload(v: Any, default=None):
    if v is None:
        return default

    try:
        return json.loads(v)
    except Exception:
        return default


def validate_coords(
    lat: Optional[float],
    lon: Optional[float],
):
    if lat is not None and not -90 <= lat <= 90:
        raise HTTPException(422, "invalid latitude")

    if lon is not None and not -180 <= lon <= 180:
        raise HTTPException(422, "invalid longitude")


def validate_pH(ph: Optional[float]):
    if ph is not None and not 0 <= ph <= 14:
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

    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")

    return conn


def q(
    sql: str,
    args=(),
    one=False,
    many=False,
):
    conn = db()

    try:
        cur = conn.execute(sql, args)

        rows = (
            cur.fetchall()
            if (one or many)
            else None
        )

        conn.commit()

        if one:
            return (
                dict(rows[0])
                if rows
                else None
            )

        if many:
            return [
                dict(x)
                for x in rows
            ]

        return cur.lastrowid

    finally:
        conn.close()


def execmany(sql: str, rows):
    conn = db()

    try:
        conn.executemany(sql, rows)
        conn.commit()

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


# ----------------------------- database -----------------------------

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
            """
        )

        conn.commit()

    finally:
        conn.close()


# ----------------------------- schemas -----------------------------

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
    raw: dict = Field(default_factory=dict)


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
    raw: dict = Field(default_factory=dict)


class WeatherIn(BaseModel):
    latitude: float
    longitude: float
    observed_at: Optional[str] = None
    temperature: Optional[float] = None
    humidity: Optional[float] = None
    rain_mm: Optional[float] = None
    wind_kmh: Optional[float] = None
    source: str = "manual"
    raw: dict = Field(default_factory=dict)


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


class AIRequestIn(BaseModel):
    prompt: str
    language: str = "fa"
    context: dict = Field(default_factory=dict)


class RecommendationIn(BaseModel):
    land_id: int
    crop_name: str = ""
    goal: str = ""
    context: dict = Field(default_factory=dict)


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
    payload: dict = Field(default_factory=dict)


# ----------------------------- provider infrastructure -----------------------------

PROVIDERS = [
    (
        "weather",
        "Open-Meteo",
        "https://api.open-meteo.com",
        "",
        "",
        1,
        "Current weather and forecast"
    ),
    (
        "openai",
        "OpenAI",
        OPENAI_BASE_URL,
        "",
        "OPENAI_API_KEY",
        1,
        "AI analysis and multimodal processing"
    ),
    (
        "geocoding",
        "Geocoding Provider",
        "",
        "",
        "ARYA_GEOCODING_API_KEY",
        0,
        "Address and reverse geocoding"
    ),
    (
        "maps",
        "Maps Provider",
        "",
        "",
        "ARYA_MAPS_API_KEY",
        0,
        "Maps and spatial services"
    ),
    (
        "soil",
        "Soil Data Provider",
        "",
        "",
        "ARYA_SOIL_API_KEY",
        0,
        "Soil data"
    ),
    (
        "satellite",
        "Satellite Provider",
        "",
        "",
        "ARYA_SATELLITE_API_KEY",
        0,
        "Satellite imagery and remote sensing"
    ),
    (
        "et0",
        "ET0 Provider",
        "",
        "",
        "ARYA_ET0_API_KEY",
        0,
        "Reference evapotranspiration"
    ),
    (
        "crop_knowledge",
        "Crop Knowledge Provider",
        "",
        "",
        "ARYA_CROP_KNOWLEDGE_API_KEY",
        0,
        "Crop knowledge and suitability"
    ),
    (
        "pest_disease",
        "Pest Disease Provider",
        "",
        "",
        "ARYA_PEST_API_KEY",
        0,
        "Pest and disease information"
    ),
    (
        "pesticide",
        "Pesticide Provider",
        "",
        "",
        "ARYA_PESTICIDE_API_KEY",
        0,
        "Pesticide database"
    ),
    (
        "fertilizer",
        "Fertilizer Provider",
        "",
        "",
        "ARYA_FERTILIZER_API_KEY",
        0,
        "Fertilizer data"
    ),
    (
        "market",
        "Market Provider",
        "",
        "",
        "ARYA_MARKET_API_KEY",
        0,
        "Agricultural market data"
    ),
    (
        "translation",
        "Translation Provider",
        "",
        "",
        "ARYA_TRANSLATION_API_KEY",
        0,
        "Multilingual translation"
    ),
    (
        "email",
        "Email Provider",
        "",
        "",
        "ARYA_EMAIL_API_KEY",
        0,
        "Transactional email"
    ),
    (
        "sms",
        "SMS Provider",
        "",
        "",
        "ARYA_SMS_API_KEY",
        0,
        "SMS notifications"
    ),
    (
        "push",
        "Push Provider",
        "",
        "",
        "ARYA_PUSH_API_KEY",
        0,
        "Push notifications"
    ),
    (
        "blockchain",
        "Blockchain Provider",
        "",
        "",
        "ARYA_BLOCKCHAIN_API_KEY",
        0,
        "USDT payment verification"
    ),
    (
        "bank",
        "Bank Provider",
        "",
        "",
        "ARYA_BANK_API_KEY",
        0,
        "Bank transfer verification"
    ),
]

PROVIDER_KEYS = {x[0] for x in PROVIDERS}


def init_providers():
    conn = db()

    try:
        conn.execute(
            """
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
            )
            """
        )

        for key, name, base, health, auth, required, notes in PROVIDERS:
            conn.execute(
                """
                INSERT INTO external_providers(
                    key,name,base_url,health_url,
                    auth_env,enabled,required,notes,updated_at
                )
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(key) DO NOTHING
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

        conn.execute(
            """
            INSERT INTO schema_meta(key,value)
            VALUES('version',?)
            ON CONFLICT(key)
            DO UPDATE SET value=excluded.value
            """,
            (VERSION,),
        )

        conn.commit()

    finally:
        conn.close()


def provider_row(key: str):
    return q(
        """
        SELECT *
        FROM external_providers
        WHERE key=?
        """,
        (key,),
        one=True,
    )


def provider_enabled(key: str) -> bool:
    row = provider_row(key)

    return bool(
        row
        and row["enabled"]
        and row["base_url"]
    )


def provider_headers(key: str):
    row = provider_row(key)

    if not row:
        return {}

    env = row["auth_env"] or ""
    secret = os.getenv(env, "") if env else ""

    if not secret:
        return {}

    return {
        "Authorization": f"Bearer {secret}",
        "X-API-Key": secret,
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
            f"provider not found: {key}",
        )

    if not row["enabled"]:
        raise HTTPException(
            503,
            f"provider disabled: {key}",
        )

    base = (row["base_url"] or "").rstrip("/")

    if not base:
        raise HTTPException(
            503,
            f"provider not configured: {key}",
        )

    url = base + "/" + path.lstrip("/")

    try:
        response = requests.request(
            method,
            url,
            params=params,
            json=json_body,
            headers=provider_headers(key),
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
            f"provider request failed: {key}: {exc}",
        )


def provider_status(key: str):
    row = provider_row(key)

    if not row:
        return {
            "key": key,
            "configured": False,
            "healthy": False,
            "reason": "provider not found",
        }

    if not row["enabled"]:
        return {
            "key": key,
            "configured": bool(row["base_url"]),
            "healthy": None,
            "enabled": False,
        }

    url = row["health_url"] or row["base_url"]

    if not url:
        return {
            "key": key,
            "configured": False,
            "healthy": False,
            "reason": "no URL configured",
        }

    try:
        r = requests.get(
            url,
            headers=provider_headers(key),
            timeout=10,
        )

        return {
            "key": key,
            "configured": True,
            "healthy": r.ok,
            "status_code": r.status_code,
        }

    except requests.RequestException as exc:
        return {
            "key": key,
            "configured": True,
            "healthy": False,
            "error": str(exc),
        }


# ----------------------------- authentication -----------------------------

def create_token(user_id: int):
    token = secrets.token_urlsafe(48)

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
            token_hash(token),
            expires,
            0,
            now_iso(),
        ),
    )

    return token, expires


def current_user(
    authorization: Optional[str] = None,
):
    if not authorization:
        raise HTTPException(
            401,
            "authorization required",
        )

    token = authorization

    if token.lower().startswith("bearer "):
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
        (token_hash(token),),
        one=True,
    )

    if not row:
        raise HTTPException(
            401,
            "invalid token",
        )

    try:
        exp = datetime.fromisoformat(
            row["token_expires"]
        )

        if exp < datetime.now(timezone.utc):
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


def require_owner(user):
    if user["role"] != "owner":
        raise HTTPException(
            403,
            "owner access required",
        )


# ----------------------------- auth endpoints -----------------------------

@app.post("/auth/register")
def register(x: RegisterIn):
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

    uid = q(
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
        uid,
        "register",
        "users",
        uid,
    )

    return {
        "ok": True,
        "user_id": uid,
    }


@app.post("/auth/login")
def login(x: LoginIn):
    email = norm_email(x.email)

    user = q(
        """
        SELECT *
        FROM users
        WHERE email=?
        """,
        (email,),
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
    user = current_user(authorization)

    token = authorization

    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    q(
        """
        UPDATE auth_tokens
        SET revoked=1
        WHERE token_hash=?
        """,
        (token_hash(token),),
    )

    audit(
        user["id"],
        "logout",
        "auth_tokens",
    )

    return {
        "ok": True
    }


@app.get("/auth/me")
def me(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "phone": user["phone"],
        "country": user["country"],
        "language": user["language"],
        "role": user["role"],
        "mfa_enabled": bool(
            user["mfa_enabled"]
        ),
    }


@app.post("/auth/password-reset/request")
def password_reset_request(
    x: PasswordResetRequestIn,
):
    email = norm_email(x.email)

    user = q(
        """
        SELECT *
        FROM users
        WHERE email=?
        """,
        (email,),
        one=True,
    )

    # Do not disclose whether account exists.
    result = {
        "ok": True,
        "message": "If the account exists, reset instructions will be sent."
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

    # Development/owner-controlled optional return.
    # Production should deliver through an approved provider.
    if os.getenv(
        "ARYA_RESET_RETURN_TOKEN",
        "0",
    ) == "1":
        result["reset_token"] = raw

    return result


@app.post("/auth/password-reset/confirm")
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
        (token_hash(x.token),),
        one=True,
    )

    if not row:
        raise HTTPException(
            400,
            "invalid reset token",
        )

    try:
        exp = datetime.fromisoformat(
            row["expires_at"]
        )

        if exp < datetime.now(timezone.utc):
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

    return {
        "ok": True
    }


# ----------------------------- owner bootstrap / MFA -----------------------------

@app.post("/owner/bootstrap")
def owner_bootstrap(
    x: OwnerBootstrapIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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
    user = current_user(authorization)
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
    user = current_user(authorization)
    require_owner(user)

    if not user["mfa_secret"]:
        raise HTTPException(
            400,
            "run mfa setup first",
        )

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
    user = current_user(authorization)
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

    audit(
        user["id"],
        "mfa_disable",
        "users",
        user["id"],
    )

    return {
        "ok": True,
        "mfa_enabled": False,
    }


# ----------------------------- farms / lands -----------------------------

@app.post("/farms")
def create_farm(
    x: FarmIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

    validate_coords(
        x.latitude,
        x.longitude,
    )

    fid = q(
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
        fid,
    )

    return q(
        "SELECT * FROM farms WHERE id=?",
        (fid,),
        one=True,
    )


@app.get("/farms")
def list_farms(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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
    user = current_user(authorization)

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
    user = current_user(authorization)

    farm = q(
        """
        SELECT *
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

    lid = q(
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

    audit(
        user["id"],
        "land_create",
        "lands",
        lid,
    )

    return q(
        "SELECT * FROM lands WHERE id=?",
        (lid,),
        one=True,
    )


@app.get("/farms/{farm_id}/lands")
def list_lands(
    farm_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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
    user = current_user(authorization)

    land = q(
        """
        SELECT l.*
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

    cid = q(
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

    audit(
        user["id"],
        "crop_create",
        "crops",
        cid,
    )

    return q(
        "SELECT * FROM crops WHERE id=?",
        (cid,),
        one=True,
    )


@app.get("/lands/{land_id}/crops")
def list_crops(
    land_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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
    user = current_user(authorization)

    land = q(
        """
        SELECT l.*
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

    tid = q(
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

    audit(
        user["id"],
        "tree_create",
        "trees",
        tid,
    )

    return q(
        "SELECT * FROM trees WHERE id=?",
        (tid,),
        one=True,
    )


@app.get("/lands/{land_id}/trees")
def list_trees(
    land_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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


# ----------------------------- soil / water -----------------------------

@app.post("/soil/tests")
def create_soil_test(
    x: SoilTestIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

    land = q(
        """
        SELECT l.*
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

    validate_pH(x.ph)

    sid = q(
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

    audit(
        user["id"],
        "soil_test_create",
        "soil_tests",
        sid,
    )

    return q(
        "SELECT * FROM soil_tests WHERE id=?",
        (sid,),
        one=True,
    )


@app.get("/lands/{land_id}/soil/tests")
def list_soil_tests(
    land_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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
    user = current_user(authorization)

    land = q(
        """
        SELECT l.*
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

    validate_pH(x.ph)

    wid = q(
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

    audit(
        user["id"],
        "water_test_create",
        "water_tests",
        wid,
    )

    return q(
        "SELECT * FROM water_tests WHERE id=?",
        (wid,),
        one=True,
    )


@app.get("/lands/{land_id}/water/tests")
def list_water_tests(
    land_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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


# ----------------------------- weather -----------------------------

@app.get("/weather/current")
def weather_current(
    latitude: float,
    longitude: float,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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
        r = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params=params,
            timeout=WEATHER_TIMEOUT,
        )

        r.raise_for_status()

        data = r.json()

        return {
            "verified": True,
            "provider": "open-meteo",
            "data": data,
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
    user = current_user(authorization)

    validate_coords(
        latitude,
        longitude,
    )

    days = max(
        1,
        min(days, 16),
    )

    params = {
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
    }

    try:
        r = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params=params,
            timeout=WEATHER_TIMEOUT,
        )

        r.raise_for_status()

        return {
            "verified": True,
            "provider": "open-meteo",
            "data": r.json(),
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
    user = current_user(authorization)

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


# ----------------------------- location -----------------------------

@app.post("/location")
def create_location(
    x: LocationIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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


# ----------------------------- provider management / health -----------------------------

@app.get("/integrations/status")
def integrations_status(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

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

    for r in rows:
        x = dict(r)

        x["base_url_configured"] = bool(
            x["base_url"]
        )

        x.pop("base_url", None)
        x.pop("health_url", None)

        x["healthy"] = (
            provider_status(x["key"])["healthy"]
            if x["enabled"]
            else None
        )

        result.append(x)

    return {
        "version": VERSION,
        "providers": result,
    }


@app.get("/owner/providers")
def owner_providers(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    rows = q(
        """
        SELECT
            key,
            name,
            base_url,
            health_url,
            auth_env,
            enabled,
            required,
            notes,
            updated_at
        FROM external_providers
        ORDER BY key
        """,
        many=True,
    )

    for r in rows:
        r["secret_configured"] = bool(
            r["auth_env"]
            and os.getenv(
                r["auth_env"],
                "",
            )
        )

    return rows


class ProviderConfigIn(BaseModel):
    base_url: str = ""
    health_url: str = ""
    enabled: bool = False
    required: bool = False
    notes: str = ""


@app.put("/owner/providers/{key}")
def owner_provider_config(
    key: str,
    x: ProviderConfigIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    if key not in PROVIDER_KEYS:
        raise HTTPException(
            404,
            "unknown provider",
        )

    if x.enabled and not x.base_url:
        raise HTTPException(
            400,
            "base_url required when enabling provider",
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
        user["id"],
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
        "enabled": x.enabled,
    }


@app.post("/owner/providers/{key}/health")
def owner_provider_health(
    key: str,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    if key not in PROVIDER_KEYS:
        raise HTTPException(
            404,
            "unknown provider",
        )

    result = provider_status(key)

    audit(
        user["id"],
        "provider_health_check",
        "external_providers",
        None,
        {
            "key": key,
            "healthy": result.get("healthy"),
        },
    )

    return result


@app.get("/location/reverse")
def reverse_geocode(
    lat: float,
    lon: float,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)

    validate_coords(
        lat,
        lon,
    )

    if not provider_enabled("geocoding"):
        return {
            "status": "unavailable",
            "verified": False,
            "latitude": lat,
            "longitude": lon,
            "reason": (
                "No approved reverse-geocoding "
                "provider configured."
            ),
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


@app.get("/agri/provider-query/{provider}")
def provider_query(
    provider: str,
    path: str = "",
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    if provider not in PROVIDER_KEYS:
        raise HTTPException(
            404,
            "unknown provider",
        )

    return provider_request(
        provider,
        path,
    )


# ----------------------------- settings / owner stats / audit -----------------------------

@app.get("/owner/settings")
def owner_settings(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    rows = q(
        """
        SELECT
            key,
            value,
            secret,
            updated_at
        FROM system_settings
        ORDER BY key
        """,
        many=True,
    )

    for r in rows:
        if r["secret"]:
            r["value"] = "***"

    return rows


@app.put("/owner/settings/{key}")
def owner_setting(
    key: str,
    x: SettingIn,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

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
            user["id"],
            now_iso(),
        ),
    )

    audit(
        user["id"],
        "setting_update",
        "system_settings",
        None,
        {"key": key},
    )

    return {
        "ok": True
    }


@app.get("/owner/stats")
def owner_stats(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    def count(
        table,
        where="",
        args=(),
    ):
        return q(
            f"""
            SELECT COUNT(*) n
            FROM {table}
            {where}
            """,
            args,
            one=True,
        )["n"]

    return {
        "users": count(
            "users",
            "WHERE role='user'",
        ),
        "owners": count(
            "users",
            "WHERE role='owner'",
        ),
        "farms": count("farms"),
        "payments_pending": count(
            "payments",
            "WHERE status='pending'",
        ),
        "payments_approved": count(
            "payments",
            "WHERE status='approved'",
        ),
        "subscriptions": count(
            "subscriptions",
            "WHERE status='active'",
        ),
        "feedback_open": count(
            "feedback",
            "WHERE status='open'",
        ),
        "ai_today": count(
            "ai_usage",
            "WHERE usage_date=?",
            (today(),),
        ),
    }


@app.get("/owner/audit")
def owner_audit(
    limit: int = 200,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

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


@app.get("/owner/users")
def owner_users(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    return q(
        """
        SELECT
            id,
            email,
            name,
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


@app.post("/owner/users/{user_id}/disable")
def owner_disable_user(
    user_id: int,
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    if user_id == user["id"]:
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

    audit(
        user["id"],
        "user_disable",
        "users",
        user_id,
    )

    return {
        "ok": True
    }


# ----------------------------- backup -----------------------------

def create_backup_file():
    conn = db()
    rows = {}

    try:
        tables = [
            r["name"]
            for r in conn.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                  AND name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        ]

        for t in tables:
            rows[t] = [
                dict(x)
                for x in conn.execute(
                    f"SELECT * FROM {t}"
                ).fetchall()
            ]

    finally:
        conn.close()

    path = (
        BASE_DIR
        / f"arya_backup_"
          f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
          f".json"
    )

    data = jdump(
        {
            "version": VERSION,
            "created_at": now_iso(),
            "tables": rows,
        }
    ).encode()

    path.write_bytes(data)

    return path, sha256_bytes(data)


@app.post("/owner/backup")
def backup(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    path, digest = create_backup_file()

    bid = q(
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
            user["id"],
            str(path),
            digest,
            now_iso(),
        ),
    )

    audit(
        user["id"],
        "backup",
        "backups",
        bid,
    )

    return {
        "id": bid,
        "path": str(path),
        "sha256": digest,
    }


@app.get("/owner/backups")
def backups(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    return q(
        """
        SELECT *
        FROM backups
        ORDER BY id DESC
        """,
        many=True,
    )


# ----------------------------- owner emergency audit controls -----------------------------

@app.post("/owner/emergency/revoke-all-sessions")
def revoke_all_sessions(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    q(
        """
        UPDATE auth_tokens
        SET revoked=1
        WHERE user_id!=?
        """,
        (user["id"],),
    )

    audit(
        user["id"],
        "emergency_revoke_all_sessions",
    )

    return {
        "ok": True
    }


@app.post("/owner/emergency/expire-all-subscriptions")
def expire_all_subscriptions(
    authorization: Optional[str] = Header(None),
):
    user = current_user(authorization)
    require_owner(user)

    q(
        """
        UPDATE subscriptions
        SET status='expired'
        WHERE status='active'
          AND user_id!=?
        """,
        (user["id"],),
    )

    audit(
        user["id"],
        "emergency_expire_all_subscriptions",
    )

    return {
        "ok": True
    }


# ----------------------------- startup -----------------------------

@app.on_event("startup")
def startup():
    init_db()


if __name__ == "__main__":
    import uvicorn

    init_db()

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
