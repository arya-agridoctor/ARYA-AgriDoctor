# backend/main.py
# ARYA AgriDoctor - Integrated Backend
# FastAPI + SQLite + Open-Meteo + OpenAI
# نسخه یکپارچه

import os
import re
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

import requests
from fastapi import FastAPI, HTTPException, Header, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "ARYA AgriDoctor"
VERSION = "2.0.0"

DB_PATH = os.getenv("ARYA_DB_PATH", "arya.db")

MASTER_EMAIL = os.getenv("ARYA_MASTER_EMAIL", "")
MASTER_SECRET = os.getenv("ARYA_MASTER_SECRET", "")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")

DAILY_AI_LIMIT = int(os.getenv("ARYA_DAILY_AI_LIMIT", "30"))
DEVICE_LIMIT = int(os.getenv("ARYA_DEVICE_LIMIT", "3"))

ACCESS_TOKEN_DAYS = int(os.getenv("ARYA_ACCESS_TOKEN_DAYS", "30"))
RESET_TOKEN_HOURS = int(os.getenv("ARYA_RESET_TOKEN_HOURS", "2"))

PBKDF2_ITERATIONS = 310000

OPEN_METEO_TIMEOUT = 20


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    description="ARYA AgriDoctor Agricultural Intelligence Backend",
)

security = HTTPBearer(auto_error=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# GENERAL HELPERS
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def json_loads(value: Any, default=None):
    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return value

    try:
        return json.loads(value)
    except Exception:
        return default


def hash_password(password: str, salt: Optional[str] = None) -> str:
    if not password:
        raise ValueError("password required")

    if salt is None:
        salt = secrets.token_hex(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    )

    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)

        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            PBKDF2_ITERATIONS,
        ).hex()

        return secrets.compare_digest(calculated, digest)
    except Exception:
        return False


def normalize_text(value: Optional[str]) -> str:
    if not value:
        return ""

    return re.sub(r"\s+", " ", value.strip())


def safe_float(value):
    try:
        return float(value)
    except Exception:
        return None


# ============================================================
# DATABASE
# ============================================================

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def execute(
    sql: str,
    params: tuple = (),
    commit: bool = False,
):
    conn = db()

    try:
        cur = conn.execute(sql, params)

        if commit:
            conn.commit()

        return cur
    finally:
        conn.close()


def fetchone(sql: str, params: tuple = ()):
    conn = db()

    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def fetchall(sql: str, params: tuple = ()):
    conn = db()

    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def init_db():

    conn = db()

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT DEFAULT '',
            language TEXT DEFAULT 'fa',
            role TEXT DEFAULT 'user',
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS farms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT DEFAULT '',
            region TEXT DEFAULT '',
            address TEXT DEFAULT '',
            latitude REAL,
            longitude REAL,
            climate TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farm_id INTEGER NOT NULL,
            name TEXT DEFAULT '',
            area REAL,
            soil_type TEXT DEFAULT '',
            irrigation TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS crops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farm_id INTEGER,
            land_id INTEGER,
            name TEXT NOT NULL,
            variety TEXT DEFAULT '',
            growth_stage TEXT DEFAULT '',
            planting_date TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS soil_lab_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farm_id INTEGER NOT NULL,
            land_id INTEGER,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS water_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farm_id INTEGER NOT NULL,
            name TEXT DEFAULT '',
            source_type TEXT DEFAULT '',
            salinity REAL,
            ph REAL,
            data TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS weather_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farm_id INTEGER,
            latitude REAL,
            longitude REAL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            farm_id INTEGER,
            question TEXT,
            answer TEXT,
            confidence REAL,
            data TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            usage_date TEXT NOT NULL,
            count INTEGER DEFAULT 0,
            UNIQUE(user_id, usage_date)
        );

        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount REAL,
            currency TEXT,
            method TEXT,
            destination TEXT DEFAULT '',
            transaction_id TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            data TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            plan TEXT DEFAULT '',
            status TEXT DEFAULT 'inactive',
            expires_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activation_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            active INTEGER DEFAULT 1,
            expires_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            platform TEXT DEFAULT '',
            last_seen TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            UNIQUE(user_id, device_id)
        );

        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            language TEXT DEFAULT 'fa',
            message TEXT NOT NULL,
            translated_message TEXT DEFAULT '',
            status TEXT DEFAULT 'new',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS feedback_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feedback_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            language TEXT DEFAULT 'fa',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            data TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_change_proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS knowledge_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            title TEXT DEFAULT '',
            content TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sync_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            data TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            message TEXT,
            read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT '',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )

    conn.commit()
    conn.close()


init_db()


# ============================================================
# MODELS
# ============================================================

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str = ""
    language: str = "fa"


class LoginRequest(BaseModel):
    email: str
    password: str


class FarmCreate(BaseModel):
    user_id: int
    name: str = ""
    region: str = ""
    address: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class LandCreate(BaseModel):
    user_id: int
    farm_id: int
    name: str = ""
    area: Optional[float] = None
    soil_type: str = ""
    irrigation: str = ""
    notes: str = ""


class CropCreate(BaseModel):
    user_id: int
    farm_id: int
    land_id: Optional[int] = None
    name: str
    variety: str = ""
    growth_stage: str = ""
    planting_date: str = ""
    notes: str = ""


class SoilLabRequest(BaseModel):
    user_id: int
    farm_id: int
    land_id: Optional[int] = None
    data: dict = {}


class WaterCreate(BaseModel):
    user_id: int
    farm_id: int
    name: str = ""
    source_type: str = ""
    salinity: Optional[float] = None
    ph: Optional[float] = None
    data: dict = {}


class WeatherRequest(BaseModel):
    latitude: float
    longitude: float


class AIAsk(BaseModel):
    user_id: int
    question: str
    farm_id: Optional[int] = None
    crop: Optional[str] = None
    region: Optional[str] = None
    language: str = "fa"

    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None

    use_current_location: bool = False
    use_user_provided_data: bool = True
    use_global_knowledge: bool = True

    deep_agricultural_analysis: bool = True
    validate_user_information: bool = True
    generate_alternatives: bool = True
    generate_action_plan: bool = True
    generate_schedule: bool = True
    generate_alerts: bool = True

    weather_analysis: bool = True
    climate_analysis: bool = True
    soil_analysis: bool = True
    water_analysis: bool = True
    crop_suitability: bool = True
    pest_disease_analysis: bool = True
    fertilizer_analysis: bool = True
    image_analysis_ready: bool = True


class RegionAnalysisRequest(BaseModel):
    user_id: int
    language: str = "fa"

    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None
    region: Optional[str] = None

    use_current_location: bool = False
    use_global_knowledge: bool = True


class LocationResolveRequest(BaseModel):
    address: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class FeedbackRequest(BaseModel):
    user_id: int
    message: str
    language: str = "fa"


class PaymentRequest(BaseModel):
    user_id: int
    amount: float
    currency: str
    method: str
    transaction_id: str = ""
    destination: str = ""


# ============================================================
# AUTH
# ============================================================

def create_token(user_id: int) -> str:

    token = secrets.token_urlsafe(48)

    expires = (
        datetime.now(timezone.utc)
        + timedelta(days=ACCESS_TOKEN_DAYS)
    ).isoformat()

    execute(
        """
        INSERT INTO auth_tokens
        (user_id, token, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, token, expires, utc_now()),
        True,
    )

    return token


def get_user_from_token(token: Optional[str]):
    if not token:
        return None

    row = fetchone(
        """
        SELECT u.*
        FROM auth_tokens t
        JOIN users u ON u.id=t.user_id
        WHERE t.token=?
        """,
        (token,),
    )

    if not row:
        return None

    try:
        expires = datetime.fromisoformat(row["expires_at"])

        if expires < datetime.now(timezone.utc):
            return None
    except Exception:
        return None

    return row


def require_user(
    authorization: Optional[str],
    user_id: Optional[int] = None,
):

    if not authorization:
        raise HTTPException(401, "Authentication required")

    token = authorization

    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

    user = get_user_from_token(token)

    if not user:
        raise HTTPException(401, "Invalid or expired token")

    if user_id is not None and int(user["id"]) != int(user_id):
        if user["role"] != "owner":
            raise HTTPException(403, "Access denied")

    return user


# ============================================================
# HEALTH
# ============================================================

@app.get("/")
def root():
    return {
        "service": APP_NAME,
        "version": VERSION,
        "status": "ok",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": APP_NAME,
        "version": VERSION,
        "timestamp": utc_now(),
    }


# ============================================================
# REGISTER / LOGIN
# ============================================================

@app.post("/auth/register")
def register(data: RegisterRequest):

    email = normalize_text(data.email).lower()

    if not email or "@" not in email:
        raise HTTPException(400, "Invalid email")

    if len(data.password) < 6:
        raise HTTPException(400, "Password must contain at least 6 characters")

    exists = fetchone(
        "SELECT id FROM users WHERE email=?",
        (email,),
    )

    if exists:
        raise HTTPException(409, "Email already registered")

    password_hash = hash_password(data.password)

    cur = execute(
        """
        INSERT INTO users
        (email,password_hash,name,language,role,active,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            email,
            password_hash,
            normalize_text(data.name),
            data.language,
            "user",
            1,
            utc_now(),
        ),
        True,
    )

    user_id = cur.lastrowid

    token = create_token(user_id)

    return {
        "status": "ok",
        "user_id": user_id,
        "token": token,
    }


@app.post("/auth/login")
def login(data: LoginRequest):

    email = normalize_text(data.email).lower()

    user = fetchone(
        "SELECT * FROM users WHERE email=?",
        (email,),
    )

    if not user or not verify_password(
        data.password,
        user["password_hash"],
    ):
        raise HTTPException(401, "Invalid email or password")

    if not user["active"]:
        raise HTTPException(403, "Account disabled")

    token = create_token(user["id"])

    return {
        "status": "ok",
        "user_id": user["id"],
        "token": token,
        "role": user["role"],
    }


@app.get("/auth/me")
def auth_me(
    authorization: Optional[str] = Header(None),
):

    user = require_user(authorization)

    return {
        "status": "ok",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "language": user["language"],
            "role": user["role"],
        },
    }


@app.post("/auth/logout")
def logout(
    authorization: Optional[str] = Header(None),
):

    if authorization:

        token = authorization

        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()

        execute(
            "DELETE FROM auth_tokens WHERE token=?",
            (token,),
            True,
        )

    return {"status": "ok"}


# ============================================================
# FARMS
# ============================================================

@app.post("/farms")
def create_farm(
    data: FarmCreate,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, data.user_id)

    cur = execute(
        """
        INSERT INTO farms
        (user_id,name,region,address,latitude,longitude,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            data.user_id,
            data.name,
            data.region,
            data.address,
            data.latitude,
            data.longitude,
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",
        "farm_id": cur.lastrowid,
    }


@app.get("/farms/{user_id}")
def get_farms(
    user_id: int,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, user_id)

    rows = fetchall(
        "SELECT * FROM farms WHERE user_id=? ORDER BY id DESC",
        (user_id,),
    )

    return {
        "status": "ok",
        "farms": [dict(r) for r in rows],
    }


def verify_farm_owner(user_id: int, farm_id: int):

    row = fetchone(
        "SELECT * FROM farms WHERE id=? AND user_id=?",
        (farm_id, user_id),
    )

    if not row:
        raise HTTPException(403, "Farm not found or access denied")

    return row


# ============================================================
# LANDS
# ============================================================

@app.post("/lands")
def create_land(
    data: LandCreate,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, data.user_id)

    verify_farm_owner(data.user_id, data.farm_id)

    cur = execute(
        """
        INSERT INTO lands
        (farm_id,name,area,soil_type,irrigation,notes,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            data.farm_id,
            data.name,
            data.area,
            data.soil_type,
            data.irrigation,
            data.notes,
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",
        "land_id": cur.lastrowid,
    }


@app.get("/lands/{farm_id}")
def get_lands(
    farm_id: int,
    user_id: int,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, user_id)

    verify_farm_owner(user_id, farm_id)

    rows = fetchall(
        "SELECT * FROM lands WHERE farm_id=?",
        (farm_id,),
    )

    return {
        "status": "ok",
        "lands": [dict(r) for r in rows],
    }


# ============================================================
# CROPS
# ============================================================

@app.post("/crops")
def create_crop(
    data: CropCreate,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, data.user_id)

    verify_farm_owner(data.user_id, data.farm_id)

    cur = execute(
        """
        INSERT INTO crops
        (farm_id,land_id,name,variety,growth_stage,
         planting_date,notes,created_at)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            data.farm_id,
            data.land_id,
            data.name,
            data.variety,
            data.growth_stage,
            data.planting_date,
            data.notes,
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",
        "crop_id": cur.lastrowid,
    }


@app.get("/crops/{farm_id}")
def get_crops(
    farm_id: int,
    user_id: int,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, user_id)

    verify_farm_owner(user_id, farm_id)

    rows = fetchall(
        "SELECT * FROM crops WHERE farm_id=?",
        (farm_id,),
    )

    return {
        "status": "ok",
        "crops": [dict(r) for r in rows],
    }


# ============================================================
# SOIL LAB
# ============================================================

@app.post("/soil/lab")
def save_soil_lab(
    data: SoilLabRequest,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, data.user_id)

    verify_farm_owner(data.user_id, data.farm_id)

    cur = execute(
        """
        INSERT INTO soil_lab_tests
        (farm_id,land_id,data,created_at)
        VALUES (?,?,?,?)
        """,
        (
            data.farm_id,
            data.land_id,
            json_dumps(data.data),
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",
        "soil_lab_id": cur.lastrowid,
    }


@app.get("/soil/lab/{farm_id}")
def get_soil_lab(
    farm_id: int,
    user_id: int,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, user_id)

    verify_farm_owner(user_id, farm_id)

    rows = fetchall(
        """
        SELECT * FROM soil_lab_tests
        WHERE farm_id=?
        ORDER BY id DESC
        """,
        (farm_id,),
    )

    result = []

    for row in rows:

        item = dict(row)
        item["data"] = json_loads(item["data"], {})

        result.append(item)

    return {
        "status": "ok",
        "tests": result,
    }


# ============================================================
# WATER
# ============================================================

@app.post("/water")
def create_water(
    data: WaterCreate,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, data.user_id)

    verify_farm_owner(data.user_id, data.farm_id)

    cur = execute(
        """
        INSERT INTO water_sources
        (farm_id,name,source_type,salinity,ph,data,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            data.farm_id,
            data.name,
            data.source_type,
            data.salinity,
            data.ph,
            json_dumps(data.data),
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",
        "water_id": cur.lastrowid,
    }


@app.get("/water/{farm_id}")
def get_water(
    farm_id: int,
    user_id: int,
    authorization: Optional[str] = Header(None),
):

    require_user(authorization, user_id)

    verify_farm_owner(user_id, farm_id)

    rows = fetchall(
        "SELECT * FROM water_sources WHERE farm_id=?",
        (farm_id,),
    )

    result = []

    for row in rows:

        item = dict(row)
        item["data"] = json_loads(item["data"], {})

        result.append(item)

    return {
        "status": "ok",
        "water": result,
    }


# ============================================================
# WEATHER
# ============================================================

def get_weather_data(latitude: float, longitude: float):

    url = "https://api.open-meteo.com/v1/forecast"

    params = {
        "latitude": latitude,
        "longitude": longitude,
        "current": (
            "temperature_2m,"
            "relative_humidity_2m,"
            "precipitation,"
            "wind_speed_10m,"
            "weather_code"
        ),
        "daily": (
            "temperature_2m_max,"
            "temperature_2m_min,"
            "precipitation_sum,"
            "wind_speed_10m_max,"
            "relative_humidity_2m_max,"
            "relative_humidity_2m_min"
        ),
        "forecast_days": 7,
        "timezone": "auto",
    }

    response = requests.get(
        url,
        params=params,
        timeout=OPEN_METEO_TIMEOUT,
    )

    response.raise_for_status()

    return response.json()


@app.post("/weather")
def weather(
    data: WeatherRequest,
):

    try:

        result = get_weather_data(
            data.latitude,
            data.longitude,
        )

        return {
            "status": "ok",
            "latitude": data.latitude,
            "longitude": data.longitude,
            "data": result,
        }

    except Exception as exc:

        return {
            "status": "error",
            "message": str(exc),
        }


# ============================================================
# CLIMATE / MULTI-YEAR DATA
# ============================================================

def get_climate_data(
    latitude: float,
    longitude: float,
    years: int = 5,
):

    end = datetime.now(timezone.utc).date()

    start = end.replace(
        year=max(1940, end.year - years)
    )

    url = "https://archive-api.open-meteo.com/v1/archive"

    params = {
        "latitude": latitude,
        "longitude": longitude,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "daily": (
            "temperature_2m_mean,"
            "temperature_2m_max,"
            "temperature_2m_min,"
            "precipitation_sum"
        ),
        "timezone": "auto",
    }

    response = requests.get(
        url,
        params=params,
        timeout=OPEN_METEO_TIMEOUT,
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# GEOCODING
# ============================================================

def geocode_address(address: str):

    if not address:
        return None

    response = requests.get(
        "https://geocoding-api.open-meteo.com/v1/search",
        params={
            "name": address,
            "count": 5,
            "language": "en",
            "format": "json",
        },
        timeout=OPEN_METEO_TIMEOUT,
    )

    response.raise_for_status()

    data = response.json()

    results = data.get("results") or []

    if not results:
        return None

    result = results[0]

    return {
        "name": result.get("name"),
        "country": result.get("country"),
        "country_code": result.get("country_code"),
        "admin1": result.get("admin1"),
        "latitude": result.get("latitude"),
        "longitude": result.get("longitude"),
        "timezone": result.get("timezone"),
    }


@app.post("/location/resolve")
def resolve_location(data: LocationResolveRequest):

    latitude = data.latitude
    longitude = data.longitude

    geocoded = None

    if latitude is not None and longitude is not None:

        if not -90 <= latitude <= 90:
            raise HTTPException(400, "Invalid latitude")

        if not -180 <= longitude <= 180:
            raise HTTPException(400, "Invalid longitude")

    elif data.address or data.region:

        query = data.address or data.region

        try:
            geocoded = geocode_address(query)
        except Exception as exc:
            return {
                "status": "error",
                "message": f"Location lookup failed: {exc}",
            }

        if not geocoded:
            return {
                "status": "not_found",
                "message": "Location not found",
            }

        latitude = geocoded["latitude"]
        longitude = geocoded["longitude"]

    else:

        return {
            "status": "missing",
            "message": "Provide address, region, or coordinates",
        }

    return {
        "status": "ok",
        "latitude": latitude,
        "longitude": longitude,
        "address": data.address,
        "region": data.region,
        "resolved": geocoded,
    }


# ============================================================
# FARM CONTEXT
# ============================================================

def collect_farm_context(
    user_id: int,
    farm_id: Optional[int],
):

    context = {
        "farm": None,
        "lands": [],
        "crops": [],
        "soil_lab": [],
        "water": [],
    }

    if not farm_id:
        return context

    farm = verify_farm_owner(
        user_id,
        farm_id,
    )

    context["farm"] = dict(farm)

    lands = fetchall(
        "SELECT * FROM lands WHERE farm_id=?",
        (farm_id,),
    )

    context["lands"] = [
        dict(x) for x in lands
    ]

    crops = fetchall(
        "SELECT * FROM crops WHERE farm_id=?",
        (farm_id,),
    )

    context["crops"] = [
        dict(x) for x in crops
    ]

    soil = fetchall(
        "SELECT * FROM soil_lab_tests WHERE farm_id=?",
        (farm_id,),
    )

    for item in soil:

        obj = dict(item)
        obj["data"] = json_loads(
            obj.get("data"),
            {},
        )

        context["soil_lab"].append(obj)

    water = fetchall(
        "SELECT * FROM water_sources WHERE farm_id=?",
        (farm_id,),
    )

    for item in water:

        obj = dict(item)
        obj["data"] = json_loads(
            obj.get("data"),
            {},
        )

        context["water"].append(obj)

    return context


# ============================================================
# USER DATA VALIDATION
# ============================================================

def validate_location(
    latitude,
    longitude,
):

    errors = []
    warnings = []

    if latitude is None or longitude is None:
        errors.append(
            "مختصات جغرافیایی برای تحلیل مکانی کامل موجود نیست."
        )
        return {
            "valid": False,
            "errors": errors,
            "warnings": warnings,
        }

    if not -90 <= latitude <= 90:
        errors.append("عرض جغرافیایی نامعتبر است.")

    if not -180 <= longitude <= 180:
        errors.append("طول جغرافیایی نامعتبر است.")

    if latitude == 0 and longitude == 0:
        warnings.append(
            "مختصات صفر وارد شده و ممکن است مختصات واقعی مزرعه نباشد."
        )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }


def validate_user_context(context: dict):

    warnings = []
    contradictions = []

    farm = context.get("farm") or {}

    area_values = []

    for land in context.get("lands", []):

        area = safe_float(
            land.get("area")
        )

        if area is not None:
            area_values.append(area)

            if area < 0:
                contradictions.append(
                    "مساحت زمین نمی‌تواند منفی باشد."
                )

    for crop in context.get("crops", []):

        name = normalize_text(
            crop.get("name")
        )

        if not name:
            contradictions.append(
                "یک رکورد کشت بدون نام محصول وجود دارد."
            )

    for soil in context.get("soil_lab", []):

        data = soil.get("data") or {}

        ph = safe_float(
            data.get("ph")
            if isinstance(data, dict)
            else None
        )

        if ph is not None:

            if ph < 0 or ph > 14:
                contradictions.append(
                    "pH آزمایش خاک خارج از محدوده معتبر است."
                )

    return {
        "valid": len(contradictions) == 0,
        "warnings": warnings,
        "contradictions": contradictions,
        "farm_name": farm.get("name", ""),
        "total_land_records": len(
            context.get("lands", [])
        ),
        "crop_records": len(
            context.get("crops", [])
        ),
    }


# ============================================================
# LOCAL AGRICULTURAL ENGINE
# ============================================================

def local_agri_answer(
    question: str,
    crop: Optional[str] = None,
    region: Optional[str] = None,
):

    q = normalize_text(question).lower()

    points = []

    if any(
        x in q
        for x in [
            "زرد",
            "زردی",
            "yellow",
            "برگ",
            "leaf",
        ]
    ):
        points.extend(
            [
                "کمبود یا عدم تعادل عناصر غذایی",
                "مشکل آبیاری یا زهکشی",
                "شوری خاک یا آب",
                "آسیب ریشه",
                "بیماری یا آفت",
            ]
        )

    if any(
        x in q
        for x in [
            "آبیاری",
            "آب",
            "irrigation",
            "water",
        ]
    ):
        points.extend(
            [
                "نیاز آبی باید بر اساس محصول، مرحله رشد، بافت خاک، دما و تبخیرتعرق بررسی شود.",
                "آبیاری بیش از نیاز می‌تواند باعث کمبود اکسیژن ریشه و افزایش بیماری‌های ریشه‌ای شود.",
            ]
        )

    if any(
        x in q
        for x in [
            "کود",
            "fertilizer",
            "ازت",
            "نیتروژن",
            "فسفر",
            "پتاس",
        ]
    ):
        points.extend(
            [
                "انتخاب کود باید بر اساس آزمایش خاک، محصول، مرحله رشد و هدف تولید انجام شود.",
                "مصرف کود بدون بررسی شرایط خاک و محصول می‌تواند باعث عدم تعادل غذایی یا شوری شود.",
            ]
        )

    if any(
        x in q
        for x in [
            "آفت",
            "حشره",
            "بیماری",
            "سم",
            "pest",
            "disease",
            "pesticide",
        ]
    ):
        points.extend(
            [
                "تشخیص آفت یا بیماری فقط از روی یک علامت قطعی نیست.",
                "برای انتخاب سم باید محصول، عامل، مرحله رشد، شدت آلودگی و برچسب رسمی محصول مشخص باشد.",
            ]
        )

    if not points:

        points.append(
            "برای پاسخ دقیق، محصول، مرحله رشد، محل مزرعه، وضعیت خاک، آب، "
            "شرایط آب‌وهوا و علائم مشاهده‌شده باید بررسی شوند."
        )

    return {
        "answer": "\n".join(
            f"• {x}" for x in points
        ),
        "confidence": 0.45 if not crop else 0.60,
    }


# ============================================================
# OPENAI AGRICULTURAL ENGINE
# ============================================================

def build_agri_system_prompt(language: str):

    return f"""
You are ARYA AgriDoctor, a professional agricultural intelligence system.

Answer language: {language}

Your job is to provide practical, technically reasoned agricultural analysis.

You must consider, when available:

- exact farm location
- coordinates
- climate
- current weather
- multi-year climate information
- crop and cultivar
- growth stage
- soil type
- laboratory soil analysis
- irrigation
- water quality
- pests
- diseases
- symptoms
- fertilizer
- agricultural management
- images when provided
- user observations
- global agricultural knowledge

IMPORTANT:

1. Never invent laboratory results.
2. Never pretend an uncertain diagnosis is certain.
3. Separate confirmed facts, probable causes and possibilities.
4. If information conflicts, identify the conflict.
5. If user-provided information appears incorrect, explain why.
6. Do not blindly accept user data.
7. If important data is missing, identify exactly what is missing.
8. If a crop is unsuitable for a region, explain the limiting factors and provide suitable alternatives.
9. For pesticides, do not invent doses.
10. Pesticide recommendations must depend on registered product, active ingredient,
   crop, pest/disease, formulation, local regulations and label.
11. Fertilizer recommendations must consider soil test, crop and growth stage.
12. Do not claim guaranteed yield.
13. When yield is discussed, give a conditional range and explain assumptions.
14. Provide an actionable plan when sufficient information exists.
15. Provide a schedule when timing is important.
16. Provide warnings when there are important risks.
17. Use metric units unless the user asks otherwise.
18. If an image is not available, do not pretend that you analyzed an image.
19. Do not respond with phrases such as "request registered" as the actual answer.
20. Give the agricultural answer directly.
21. If several explanations are possible, rank them by evidence,
    but clearly state that the ranking is provisional.
22. Consider local climate and season.
23. Consider both the user's supplied data and broader agricultural knowledge.
24. If user data and broader evidence disagree, show both and explain the discrepancy.

Return a structured agricultural answer containing:

- direct_answer
- facts
- likely_causes
- data_validation
- missing_data
- recommendations
- alternatives
- action_plan
- schedule
- alerts
- confidence

Do not fabricate unavailable data.
"""


def openai_answer(
    question: str,
    language: str,
    context_packet: dict,
):

    if not OPENAI_API_KEY:
        return None

    try:

        from openai import OpenAI

        client = OpenAI(
            api_key=OPENAI_API_KEY
        )

        prompt = (
            "USER QUESTION:\n"
            + question
            + "\n\nAGRICULTURAL CONTEXT:\n"
            + json_dumps(context_packet)
        )

        response = client.responses.create(
            model=OPENAI_MODEL,
            instructions=build_agri_system_prompt(
                language
            ),
            input=prompt,
        )

        text = getattr(
            response,
            "output_text",
            None,
        )

        if not text:
            return None

        return text

    except Exception as exc:

        return {
            "error": str(exc)
        }


# ============================================================
# AI USAGE
# ============================================================

def check_ai_limit(user_id: int):

    date = today_utc()

    row = fetchone(
        """
        SELECT * FROM ai_usage
        WHERE user_id=? AND usage_date=?
        """,
        (user_id, date),
    )

    if not row:

        execute(
            """
            INSERT INTO ai_usage
            (user_id,usage_date,count)
            VALUES (?,?,0)
            """,
            (user_id, date),
            True,
        )

        return True

    return int(row["count"]) < DAILY_AI_LIMIT


def increment_ai_usage(user_id: int):

    date = today_utc()

    execute(
        """
        UPDATE ai_usage
        SET count=count+1
        WHERE user_id=? AND usage_date=?
        """,
        (user_id, date),
        True,
    )


# ============================================================
# REGION ANALYSIS
# ============================================================

def create_region_analysis(
    latitude,
    longitude,
    region,
    language,
):

    weather_data = None
    climate_data = None

    if latitude is not None and longitude is not None:

        try:
            weather_data = get_weather_data(
                latitude,
                longitude,
            )
        except Exception:
            weather_data = None

        try:
            climate_data = get_climate_data(
                latitude,
                longitude,
                5,
            )
        except Exception:
            climate_data = None

    return {
        "region": region,
        "latitude": latitude,
        "longitude": longitude,
        "weather": weather_data,
        "climate": climate_data,
        "note": (
            "تحلیل منطقه بر اساس مختصات، "
            "آب‌وهوا و داده‌های اقلیمی موجود انجام می‌شود."
        ),
    }


@app.post("/ai/region-analysis")
def region_analysis(
    data: RegionAnalysisRequest,
    authorization: Optional[str] = Header(None),
):

    require_user(
        authorization,
        data.user_id,
    )

    latitude = data.latitude
    longitude = data.longitude
    resolved = None

    if (
        latitude is None
        or longitude is None
    ):

        if data.address or data.region:

            resolved = geocode_address(
                data.address or data.region
            )

            if resolved:

                latitude = resolved["latitude"]
                longitude = resolved["longitude"]

    validation = validate_location(
        latitude,
        longitude,
    )

    analysis = create_region_analysis(
        latitude,
        longitude,
        data.region,
        data.language,
    )

    return {
        "status": "ok",
        "location": {
            "latitude": latitude,
            "longitude": longitude,
            "region": data.region,
            "resolved": resolved,
        },
        "validation": validation,
        "analysis": analysis,
    }


# ============================================================
# MAIN AI ASK
# ============================================================

@app.post("/ai/ask")
def ask_ai(
    data: AIAsk,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
):
    authorization = (
        f"{credentials.scheme} {credentials.credentials}"
        if credentials
        else None
    )

    require_user(
        authorization,
        data.user_id,
    )

    if not check_ai_limit(data.user_id):

        raise HTTPException(
            429,
            "Daily AI limit reached",
        )

    farm_context = collect_farm_context(
        data.user_id,
        data.farm_id,
    )

    farm = farm_context.get("farm") or {}

    latitude = data.latitude
    longitude = data.longitude

    # --------------------------------------------------------
    # Farm coordinates
    # --------------------------------------------------------

    if (
        latitude is None
        or longitude is None
    ):

        latitude = farm.get("latitude")
        longitude = farm.get("longitude")

    # --------------------------------------------------------
    # Manual address / region
    # --------------------------------------------------------

    resolved_location = None

    if (
        data.address
        and (
            latitude is None
            or longitude is None
        )
    ):

        try:

            resolved_location = geocode_address(
                data.address
            )

            if resolved_location:

                latitude = resolved_location[
                    "latitude"
                ]

                longitude = resolved_location[
                    "longitude"
                ]

        except Exception:
            resolved_location = None

    elif (
        data.region
        and (
            latitude is None
            or longitude is None
        )
    ):

        try:

            resolved_location = geocode_address(
                data.region
            )

            if resolved_location:

                latitude = resolved_location[
                    "latitude"
                ]

                longitude = resolved_location[
                    "longitude"
                ]

        except Exception:
            resolved_location = None

    # --------------------------------------------------------
    # Location validation
    # --------------------------------------------------------

    location_validation = validate_location(
        latitude,
        longitude,
    )

    # --------------------------------------------------------
    # Weather
    # --------------------------------------------------------

    weather_data = None

    if (
        data.weather_analysis
        and latitude is not None
        and longitude is not None
    ):

        try:

            weather_data = get_weather_data(
                latitude,
                longitude,
            )

        except Exception:
            weather_data = None

    # --------------------------------------------------------
    # Climate
    # --------------------------------------------------------

    climate_data = None

    if (
        data.climate_analysis
        and latitude is not None
        and longitude is not None
    ):

        try:

            climate_data = get_climate_data(
                latitude,
                longitude,
                5,
            )

        except Exception:
            climate_data = None

    # --------------------------------------------------------
    # User data validation
    # --------------------------------------------------------

    user_validation = (
        validate_user_context(
            farm_context
        )
        if data.validate_user_information
        else {}
    )

    # --------------------------------------------------------
    # Crop
    # --------------------------------------------------------

    crop_name = data.crop

    if not crop_name:

        crops = farm_context.get(
            "crops",
            [],
        )

        if crops:
            crop_name = crops[0].get(
                "name"
            )

    # --------------------------------------------------------
    # Context packet
    # --------------------------------------------------------

    context_packet = {
        "application": APP_NAME,
        "version": VERSION,

        "question": data.question,

        "location": {
            "latitude": latitude,
            "longitude": longitude,
            "address": data.address,
            "region": data.region,
            "resolved": resolved_location,
            "use_current_location":
                data.use_current_location,
        },

        "location_validation":
            location_validation,

        "crop": crop_name,

        "farm_context":
            farm_context
            if data.use_user_provided_data
            else {},

        "user_data_validation":
            user_validation
            if data.validate_user_information
            else {},

        "weather":
            weather_data
            if data.weather_analysis
            else None,

        "climate":
            climate_data
            if data.climate_analysis
            else None,

        "analysis_options": {
            "deep_agricultural_analysis":
                data.deep_agricultural_analysis,

            "validate_user_information":
                data.validate_user_information,

            "generate_alternatives":
                data.generate_alternatives,

            "generate_action_plan":
                data.generate_action_plan,

            "generate_schedule":
                data.generate_schedule,

            "generate_alerts":
                data.generate_alerts,

            "weather_analysis":
                data.weather_analysis,

            "climate_analysis":
                data.climate_analysis,

            "soil_analysis":
                data.soil_analysis,

            "water_analysis":
                data.water_analysis,

            "crop_suitability":
                data.crop_suitability,

            "pest_disease_analysis":
                data.pest_disease_analysis,

            "fertilizer_analysis":
                data.fertilizer_analysis,

            "image_analysis_ready":
                data.image_analysis_ready,
        },

        "global_knowledge_requested":
            data.use_global_knowledge,
    }

    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    ai_result = openai_answer(
        data.question,
        data.language,
        context_packet,
    )

    increment_ai_usage(
        data.user_id
    )

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    if isinstance(ai_result, dict) and ai_result.get(
        "error"
    ):

        ai_result = None

    if not ai_result:

        local = local_agri_answer(
            data.question,
            crop_name,
            data.region,
        )

        answer = local["answer"]
        confidence = local["confidence"]

    else:

        answer = ai_result
        confidence = 0.78

        if not location_validation.get(
            "valid",
            False,
        ):
            confidence -= 0.08

        if user_validation.get(
            "contradictions"
        ):
            confidence -= 0.08

        confidence = max(
            0.35,
            min(0.95, confidence),
        )

    # --------------------------------------------------------
    # Missing data
    # --------------------------------------------------------

    missing_data = []

    if not crop_name:
        missing_data.append(
            "نام محصول یا درخت"
        )

    if latitude is None or longitude is None:
        missing_data.append(
            "موقعیت مزرعه"
        )

    if not farm_context.get("soil_lab"):
        missing_data.append(
            "آزمایش خاک"
        )

    if not farm_context.get("water"):
        missing_data.append(
            "اطلاعات کیفیت آب"
        )

    # --------------------------------------------------------
    # Save recommendation
    # --------------------------------------------------------

    execute(
        """
        INSERT INTO recommendations
        (user_id,farm_id,question,answer,confidence,data,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            data.user_id,
            data.farm_id,
            data.question,
            answer,
            confidence,
            json_dumps(context_packet),
            utc_now(),
        ),
        True,
    )

    # --------------------------------------------------------
    # Audit
    # --------------------------------------------------------

    execute(
        """
        INSERT INTO audit_logs
        (user_id,action,data,created_at)
        VALUES (?,?,?,?)
        """,
        (
            data.user_id,
            "ai_ask",
            json_dumps(
                {
                    "crop": crop_name,
                    "farm_id": data.farm_id,
                    "latitude": latitude,
                    "longitude": longitude,
                }
            ),
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",

        "answer": answer,

        "confidence": confidence,

        "location": {
            "latitude": latitude,
            "longitude": longitude,
            "address": data.address,
            "region": data.region,
            "resolved": resolved_location,
        },

        "weather": weather_data,

        "climate": climate_data,

        "validation": {
            "location": location_validation,
            "user_data": user_validation,
        },

        "missing_data": missing_data,

        "crop": crop_name,

        "farm_context": farm_context,

        "recommendations": [],

        "alternatives": [],

        "action_plan": [],

        "schedule": [],

        "alerts": [],

        "ai": {
            "provider": (
                "openai"
                if OPENAI_API_KEY and ai_result
                else "local"
            ),
            "model": (
                OPENAI_MODEL
                if OPENAI_API_KEY and ai_result
                else None
            ),
        },
    }


# ============================================================
# AI HISTORY
# ============================================================

@app.get("/ai/history/{user_id}")
def ai_history(
    user_id: int,
    authorization: Optional[str] = Header(None),
):

    require_user(
        authorization,
        user_id,
    )

    rows = fetchall(
        """
        SELECT id,farm_id,question,answer,
               confidence,created_at
        FROM recommendations
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 100
        """,
        (user_id,),
    )

    return {
        "status": "ok",
        "items": [dict(r) for r in rows],
    }


# ============================================================
# PRICING
# ============================================================

def pricing_for(
    country: str,
    users_count: int,
):

    if country.lower() in [
        "iran",
        "ir",
        "ایران",
    ]:

        if users_count < 100:
            return {
                "amount": 500000,
                "currency": "IRR",
            }

        if users_count < 600:
            return {
                "amount": 800000,
                "currency": "IRR",
            }

        return {
            "amount": 1200000,
            "currency": "IRR",
        }

    if users_count < 100:
        return {
            "amount": 10,
            "currency": "USDT",
        }

    if users_count < 600:
        return {
            "amount": 15,
            "currency": "USDT",
        }

    return {
        "amount": 20,
        "currency": "USDT",
    }


@app.get("/pricing")
def pricing(
    country: str = "international",
):

    count_row = fetchone(
        "SELECT COUNT(*) AS c FROM users"
    )

    users_count = int(
        count_row["c"]
    )

    price = pricing_for(
        country,
        users_count,
    )

    return {
        "status": "ok",
        "country": country,
        "registered_users": users_count,
        **price,
    }


# ============================================================
# PAYMENTS
# ============================================================

@app.post("/payments")
def create_payment(
    data: PaymentRequest,
    authorization: Optional[str] = Header(None),
):

    require_user(
        authorization,
        data.user_id,
    )

    method = data.method.lower()

    if method not in [
        "bank",
        "bank_transfer",
        "crypto",
        "usdt",
    ]:

        raise HTTPException(
            400,
            "Unsupported payment method",
        )

    cur = execute(
        """
        INSERT INTO payments
        (user_id,amount,currency,method,
         destination,transaction_id,status,
         data,created_at)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (
            data.user_id,
            data.amount,
            data.currency,
            method,
            data.destination,
            data.transaction_id,
            "pending",
            "{}",
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",
        "payment_id": cur.lastrowid,
        "payment_status": "pending",
    }


@app.get("/payments/{user_id}")
def get_payments(
    user_id: int,
    authorization: Optional[str] = Header(None),
):

    require_user(
        authorization,
        user_id,
    )

    rows = fetchall(
        """
        SELECT *
        FROM payments
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user_id,),
    )

    return {
        "status": "ok",
        "payments": [
            dict(x) for x in rows
        ],
    }


# ============================================================
# SUBSCRIPTION
# ============================================================

@app.get("/subscription/{user_id}")
def get_subscription(
    user_id: int,
    authorization: Optional[str] = Header(None),
):

    require_user(
        authorization,
        user_id,
    )

    row = fetchone(
        """
        SELECT *
        FROM subscriptions
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (user_id,),
    )

    if not row:

        return {
            "status": "ok",
            "active": False,
            "subscription": None,
        }

    active = row["status"] == "active"

    if row["expires_at"]:

        try:

            expires = datetime.fromisoformat(
                row["expires_at"]
            )

            if expires < datetime.now(
                timezone.utc
            ):
                active = False

        except Exception:
            pass

    return {
        "status": "ok",
        "active": active,
        "subscription": dict(row),
    }


# ============================================================
# DEVICE ACTIVATION
# ============================================================

@app.post("/devices/register")
def register_device(
    user_id: int,
    device_id: str,
    platform: str = "",
    authorization: Optional[str] = Header(None),
):

    require_user(
        authorization,
        user_id,
    )

    existing = fetchone(
        """
        SELECT id
        FROM devices
        WHERE user_id=? AND device_id=?
        """,
        (user_id, device_id),
    )

    if existing:

        execute(
            """
            UPDATE devices
            SET last_seen=?,active=1,platform=?
            WHERE id=?
            """,
            (
                utc_now(),
                platform,
                existing["id"],
            ),
            True,
        )

        return {
            "status": "ok",
            "device_id": device_id,
        }

    count = fetchone(
        """
        SELECT COUNT(*) AS c
        FROM devices
        WHERE user_id=? AND active=1
        """,
        (user_id,),
    )

    if int(count["c"]) >= DEVICE_LIMIT:

        raise HTTPException(
            403,
            "Device limit reached",
        )

    execute(
        """
        INSERT INTO devices
        (user_id,device_id,platform,last_seen,active)
        VALUES (?,?,?,?,1)
        """,
        (
            user_id,
            device_id,
            platform,
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",
        "device_id": device_id,
    }


# ============================================================
# FEEDBACK
# ============================================================

@app.post("/feedback")
def send_feedback(
    data: FeedbackRequest,
    authorization: Optional[str] = Header(None),
):

    require_user(
        authorization,
        data.user_id,
    )

    cur = execute(
        """
        INSERT INTO feedback
        (user_id,language,message,
         translated_message,status,created_at)
        VALUES (?,?,?,?,?,?)
        """,
        (
            data.user_id,
            data.language,
            data.message,
            "",
            "new",
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",
        "feedback_id": cur.lastrowid,
    }


# ============================================================
# OWNER
# ============================================================

def require_owner(
    authorization: Optional[str],
):

    user = require_user(
        authorization
    )

    if user["role"] != "owner":

        if MASTER_EMAIL:
            if user["email"] != MASTER_EMAIL:
                raise HTTPException(
                    403,
                    "Owner access required",
                )
        else:
            raise HTTPException(
                403,
                "Owner access required",
            )

    return user


@app.get("/owner/stats")
def owner_stats(
    authorization: Optional[str] = Header(None),
):

    require_owner(authorization)

    users = fetchone(
        "SELECT COUNT(*) AS c FROM users"
    )

    farms = fetchone(
        "SELECT COUNT(*) AS c FROM farms"
    )

    payments = fetchone(
        "SELECT COUNT(*) AS c FROM payments"
    )

    recommendations = fetchone(
        "SELECT COUNT(*) AS c FROM recommendations"
    )

    return {
        "status": "ok",
        "users": users["c"],
        "farms": farms["c"],
        "payments": payments["c"],
        "ai_requests": recommendations["c"],
    }


@app.get("/owner/feedback")
def owner_feedback(
    authorization: Optional[str] = Header(None),
):

    require_owner(authorization)

    rows = fetchall(
        """
        SELECT *
        FROM feedback
        ORDER BY id DESC
        LIMIT 200
        """
    )

    return {
        "status": "ok",
        "feedback": [
            dict(x) for x in rows
        ],
    }


@app.get("/owner/audit")
def owner_audit(
    authorization: Optional[str] = Header(None),
):

    require_owner(authorization)

    rows = fetchall(
        """
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 500
        """
    )

    return {
        "status": "ok",
        "logs": [
            dict(x) for x in rows
        ],
    }


# ============================================================
# KNOWLEDGE
# ============================================================

@app.get("/knowledge")
def knowledge():

    rows = fetchall(
        """
        SELECT *
        FROM knowledge_versions
        WHERE active=1
        ORDER BY id DESC
        """
    )

    return {
        "status": "ok",
        "knowledge": [
            dict(x) for x in rows
        ],
    }


# ============================================================
# SERVER TIME
# ============================================================

@app.get("/server-time")
def server_time():

    return {
        "status": "ok",
        "utc": utc_now(),
        "timestamp": datetime.now(
            timezone.utc
        ).timestamp(),
    }


# ============================================================
# SYSTEM INFO
# ============================================================

@app.get("/system-info")
def system_info():

    return {
        "status": "ok",
        "service": APP_NAME,
        "version": VERSION,
        "ai_configured": bool(
            OPENAI_API_KEY
        ),
        "model": OPENAI_MODEL
        if OPENAI_API_KEY
        else None,
        "weather_provider": "Open-Meteo",
        "database": "SQLite",
    }


# ============================================================
# SYNC
# ============================================================

@app.post("/sync")
def sync_data(
    user_id: int,
    data: dict,
    authorization: Optional[str] = Header(None),
):

    require_user(
        authorization,
        user_id,
    )

    execute(
        """
        INSERT INTO sync_queue
        (user_id,data,status,created_at)
        VALUES (?,?,?,?)
        """,
        (
            user_id,
            json_dumps(data),
            "pending",
            utc_now(),
        ),
        True,
    )

    return {
        "status": "ok",
        "synced": True,
    }


# ============================================================
# NOTIFICATIONS
# ============================================================

@app.get("/notifications/{user_id}")
def notifications(
    user_id: int,
    authorization: Optional[str] = Header(None),
):

    require_user(
        authorization,
        user_id,
    )

    rows = fetchall(
        """
        SELECT *
        FROM notifications
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 100
        """,
        (user_id,),
    )

    return {
        "status": "ok",
        "notifications": [
            dict(x) for x in rows
        ],
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup():

    init_db()

    print(
        f"{APP_NAME} {VERSION} started"
    )
