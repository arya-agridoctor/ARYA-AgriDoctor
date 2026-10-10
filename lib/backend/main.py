import os
import uuid
import json
import hashlib
import secrets
import sqlite3
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional, Any

import requests
from fastapi import FastAPI, HTTPException, Header, APIRouter
from pydantic import BaseModel, Field, ConfigDict

# ============================================================
# ARYA AgriDoctor - Cloud Backend
# Corrected Foundation Version
# ============================================================

APP_NAME = "ARYA AgriDoctor Backend"
APP_VERSION = "1.1.0"

DATABASE = os.getenv("ARYA_DATABASE", "arya.db")
MASTER_EMAIL = os.getenv("ARYA_MASTER_EMAIL", "").strip().lower()
MASTER_SECRET = os.getenv("ARYA_MASTER_SECRET", "").strip()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "")

AI_INPUT_COST_PER_1M = float(
    os.getenv("AI_INPUT_COST_PER_1M", "0")
)
AI_OUTPUT_COST_PER_1M = float(
    os.getenv("AI_OUTPUT_COST_PER_1M", "0")
)

DAILY_AI_LIMIT = max(
    1, int(os.getenv("ARYA_DAILY_AI_LIMIT", "30"))
)
DEVICE_LIMIT = max(
    1, int(os.getenv("ARYA_DEVICE_LIMIT", "3"))
)

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="ARYA AgriDoctor agricultural AI backend",
)

# ============================================================
# DATABASE
# ============================================================

def db():
    conn = sqlite3.connect(
        DATABASE,
        timeout=30,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def uid():
    return str(uuid.uuid4())


def sha256(value: str):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def init_db():
    conn = db()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            phone TEXT,
            name TEXT,
            country TEXT,
            language TEXT DEFAULT 'fa',
            role TEXT DEFAULT 'USER',
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS farms (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT,
            country TEXT,
            region TEXT,
            latitude REAL,
            longitude REAL,
            climate TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lands (
            id TEXT PRIMARY KEY,
            farm_id TEXT NOT NULL,
            name TEXT,
            area REAL,
            area_unit TEXT DEFAULT 'hectare',
            soil_type TEXT,
            irrigation_type TEXT,
            latitude REAL,
            longitude REAL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS crops (
            id TEXT PRIMARY KEY,
            farm_id TEXT NOT NULL,
            land_id TEXT,
            name TEXT,
            variety TEXT,
            planting_date TEXT,
            expected_harvest TEXT,
            area REAL,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS soil_lab_tests (
            id TEXT PRIMARY KEY,
            farm_id TEXT NOT NULL,
            ph REAL,
            ec REAL,
            nitrogen REAL,
            phosphorus REAL,
            potassium REAL,
            organic_matter REAL,
            raw_data TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS water_sources (
            id TEXT PRIMARY KEY,
            farm_id TEXT NOT NULL,
            source_type TEXT,
            quality TEXT,
            ec REAL,
            ph REAL,
            raw_data TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS weather_observations (
            id TEXT PRIMARY KEY,
            farm_id TEXT,
            latitude REAL,
            longitude REAL,
            temperature REAL,
            humidity REAL,
            precipitation REAL,
            wind_speed REAL,
            weather_code INTEGER,
            raw_data TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recommendations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            farm_id TEXT,
            category TEXT,
            question TEXT,
            recommendation TEXT,
            confidence REAL,
            risk_level TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_usage (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            provider TEXT,
            model TEXT,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            estimated_cost REAL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            country TEXT,
            currency TEXT,
            amount REAL,
            method TEXT,
            status TEXT DEFAULT 'pending',
            transaction_reference TEXT,
            created_at TEXT NOT NULL,
            verified_at TEXT
        );

        CREATE TABLE IF NOT EXISTS subscriptions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            plan TEXT,
            currency TEXT,
            amount REAL,
            started_at TEXT,
            expires_at TEXT,
            status TEXT DEFAULT 'pending',
            payment_id TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activation_codes (
            id TEXT PRIMARY KEY,
            code_hash TEXT UNIQUE NOT NULL,
            plan TEXT,
            duration_days INTEGER,
            status TEXT DEFAULT 'unused',
            user_id TEXT,
            created_at TEXT NOT NULL,
            used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            device_hash TEXT NOT NULL,
            device_name TEXT,
            platform TEXT,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS feedback (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            category TEXT,
            original_language TEXT,
            original_text TEXT,
            persian_translation TEXT,
            status TEXT DEFAULT 'new',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS feedback_messages (
            id TEXT PRIMARY KEY,
            feedback_id TEXT NOT NULL,
            sender_role TEXT,
            original_text TEXT,
            language TEXT,
            persian_text TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            actor_id TEXT,
            action TEXT,
            target_type TEXT,
            target_id TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_change_proposals (
            id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            proposed_change TEXT,
            status TEXT DEFAULT 'pending',
            created_by TEXT,
            approved_by TEXT,
            created_at TEXT NOT NULL,
            approved_at TEXT
        );

        CREATE TABLE IF NOT EXISTS knowledge_versions (
            id TEXT PRIMARY KEY,
            version TEXT,
            title TEXT,
            content TEXT,
            status TEXT DEFAULT 'draft',
            created_by TEXT,
            approved_by TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sync_queue (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            operation_id TEXT UNIQUE,
            entity_type TEXT,
            entity_id TEXT,
            operation TEXT,
            payload TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            user_id TEXT,
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

        CREATE INDEX IF NOT EXISTS idx_farms_user
            ON farms(user_id);
        CREATE INDEX IF NOT EXISTS idx_lands_farm
            ON lands(farm_id);
        CREATE INDEX IF NOT EXISTS idx_crops_farm
            ON crops(farm_id);
        CREATE INDEX IF NOT EXISTS idx_ai_usage_user_date
            ON ai_usage(user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_payments_user
            ON payments(user_id);
        CREATE INDEX IF NOT EXISTS idx_subscriptions_user
            ON subscriptions(user_id);
        CREATE INDEX IF NOT EXISTS idx_devices_user_status
            ON devices(user_id, status);
        CREATE INDEX IF NOT EXISTS idx_feedback_created
            ON feedback(created_at);
        """)
        conn.commit()
    finally:
        conn.close()


init_db()

# ============================================================
# HELPERS AND ACCESS CONTROL
# ============================================================

def audit(
    actor_id,
    action,
    target_type="",
    target_id="",
    details=None,
):
    conn = db()
    try:
        conn.execute(
            """
            INSERT INTO audit_logs
            (id, actor_id, action, target_type,
             target_id, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uid(),
                actor_id,
                action,
                target_type,
                target_id,
                json.dumps(details or {}, ensure_ascii=False),
                now_iso(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_user(user_id):
    conn = db()
    try:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()


def require_user(user_id):
    if not user_id:
        raise HTTPException(401, "شناسه کاربر لازم است")

    user = get_user(user_id)

    if not user:
        raise HTTPException(404, "کاربر پیدا نشد")

    if user["status"] != "active":
        raise HTTPException(403, "حساب کاربر فعال نیست")

    return user


def require_owner(owner_id):
    user = require_user(owner_id)

    if user["role"] != "OWNER":
        raise HTTPException(403, "دسترسی OWNER لازم است")

    return user


def check_owner_secret(owner_secret):
    if not MASTER_SECRET:
        raise HTTPException(
            503,
            "تنظیم ARYA_MASTER_SECRET روی سرور الزامی است",
        )

    if not owner_secret or not hmac.compare_digest(
        owner_secret, MASTER_SECRET
    ):
        raise HTTPException(403, "تأیید دسترسی OWNER ناموفق بود")


def count_users():
    conn = db()
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]
    finally:
        conn.close()


def pricing(country: str):
    iran = str(country or "").strip().lower() in {
        "iran", "ایران", "ir"
    }

    count = count_users()

    if iran:
        currency = "TOMAN"
        if count < 100:
            amount, tier = 500000, "IR_FIRST_100"
        elif count < 600:
            amount, tier = 800000, "IR_NEXT_500"
        else:
            amount, tier = 1200000, "IR_AFTER_600"
    else:
        currency = "USDT"
        if count < 100:
            amount, tier = 10, "GLOBAL_FIRST_100"
        elif count < 600:
            amount, tier = 15, "GLOBAL_NEXT_500"
        else:
            amount, tier = 20, "GLOBAL_AFTER_600"

    return {
        "currency": currency,
        "amount": amount,
        "tier": tier,
        "user_count_at_quote": count,
    }


def get_owned_farm(conn, farm_id, user_id):
    farm = conn.execute(
        "SELECT * FROM farms WHERE id = ? AND user_id = ?",
        (farm_id, user_id),
    ).fetchone()

    if not farm:
        raise HTTPException(404, "مزرعه پیدا نشد یا متعلق به این کاربر نیست")

    return farm


# ============================================================
# MODELS
# ============================================================

class UserCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: Optional[str] = None
    phone: Optional[str] = None
    name: Optional[str] = None
    country: str = ""
    language: str = "fa"


class FarmCreate(BaseModel):
    user_id: str
    name: str
    country: str = ""
    region: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    climate: Optional[str] = None


class LandCreate(BaseModel):
    farm_id: str
    name: str
    area: Optional[float] = Field(default=None, ge=0)
    area_unit: str = "hectare"
    soil_type: Optional[str] = None
    irrigation_type: Optional[str] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    user_id: Optional[str] = None


class CropCreate(BaseModel):
    farm_id: str
    land_id: Optional[str] = None
    name: str
    variety: Optional[str] = None
    planting_date: Optional[str] = None
    expected_harvest: Optional[str] = None
    area: Optional[float] = Field(default=None, ge=0)
    user_id: Optional[str] = None


class SoilTestCreate(BaseModel):
    farm_id: str
    ph: Optional[float] = Field(default=None, ge=0, le=14)
    ec: Optional[float] = Field(default=None, ge=0)
    nitrogen: Optional[float] = Field(default=None, ge=0)
    phosphorus: Optional[float] = Field(default=None, ge=0)
    potassium: Optional[float] = Field(default=None, ge=0)
    organic_matter: Optional[float] = Field(default=None, ge=0)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    user_id: Optional[str] = None


class AIRequest(BaseModel):
    user_id: str
    question: str = Field(min_length=1, max_length=20000)
    farm_id: Optional[str] = None
    language: str = "fa"
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    region: Optional[str] = None


class PaymentCreate(BaseModel):
    user_id: str
    country: str
    method: str
    transaction_reference: Optional[str] = None


class FeedbackCreate(BaseModel):
    user_id: Optional[str] = None
    category: str = "suggestion"
    language: str = "fa"
    text: str = Field(min_length=1, max_length=20000)


class ActivationRequest(BaseModel):
    user_id: str
    code: str
    device_id: Optional[str] = None


class DeviceCreate(BaseModel):
    user_id: str
    device_hash: str = Field(min_length=8, max_length=512)
    device_name: str = ""
    platform: str = "android"


class ProposalCreate(BaseModel):
    owner_id: str
    title: str
    description: str
    proposed_change: str


class ProposalApproval(BaseModel):
    owner_id: str
    approve: bool


# ============================================================
# SYSTEM
# ============================================================

@app.get("/")
def root():
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "server_time": now_iso(),
        "message": "ARYA AgriDoctor Backend",
    }


@app.get("/health")
def health():
    conn = db()
    try:
        conn.execute("SELECT 1").fetchone()
        database_ok = True
    except sqlite3.Error:
        database_ok = False
    finally:
        conn.close()

    return {
        "status": "ok" if database_ok else "degraded",
        "database": DATABASE,
        "database_ok": database_ok,
        "server_time": now_iso(),
        "ai_configured": bool(OPENAI_API_KEY and OPENAI_MODEL),
        "owner_security_configured": bool(MASTER_SECRET),
    }


# ============================================================
# USERS
# ============================================================

@app.post("/users")
def create_user(data: UserCreate):
    email = data.email.strip().lower() if data.email else None
    phone = data.phone.strip() if data.phone else None

    if not email and not phone:
        raise HTTPException(400, "ایمیل یا شماره تلفن لازم است")

    user_id = uid()
    conn = db()

    try:
        conn.execute(
            """
            INSERT INTO users
            (id, email, phone, name, country, language, role, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'USER', 'active', ?)
            """,
            (
                user_id,
                email,
                phone,
                data.name,
                data.country,
                data.language,
                now_iso(),
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "این ایمیل قبلاً ثبت شده است")
    finally:
        conn.close()

    audit(user_id, "USER_CREATED", "user", user_id)

    return {
        "user_id": user_id,
        "status": "created",
        "pricing": pricing(data.country),
    }


@app.get("/users/{user_id}")
def user_info(user_id: str):
    return dict(require_user(user_id))


# ============================================================
# FARMS
# ============================================================

@app.post("/farms")
def create_farm(data: FarmCreate):
    require_user(data.user_id)

    farm_id = uid()
    conn = db()

    try:
        conn.execute(
            """
            INSERT INTO farms
            (id, user_id, name, country, region,
             latitude, longitude, climate, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                farm_id,
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
        conn.commit()
    finally:
        conn.close()

    audit(data.user_id, "FARM_CREATED", "farm", farm_id)

    return {"farm_id": farm_id, "status": "created"}


@app.get("/farms/{user_id}")
def list_farms(user_id: str):
    require_user(user_id)
    conn = db()

    try:
        rows = conn.execute(
            "SELECT * FROM farms WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ============================================================
# LAND
# ============================================================

@app.post("/lands")
def create_land(data: LandCreate):
    conn = db()

    try:
        farm = conn.execute(
            "SELECT * FROM farms WHERE id = ?",
            (data.farm_id,),
        ).fetchone()

        if not farm:
            raise HTTPException(404, "مزرعه پیدا نشد")

        if data.user_id:
            require_user(data.user_id)
            if farm["user_id"] != data.user_id:
                raise HTTPException(403, "این مزرعه متعلق به کاربر نیست")

        land_id = uid()
        conn.execute(
            """
            INSERT INTO lands
            (id, farm_id, name, area, area_unit, soil_type,
             irrigation_type, latitude, longitude, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                land_id,
                data.farm_id,
                data.name,
                data.area,
                data.area_unit,
                data.soil_type,
                data.irrigation_type,
                data.latitude,
                data.longitude,
                now_iso(),
            ),
        )
        conn.commit()
        return {"land_id": land_id, "status": "created"}
    finally:
        conn.close()


# ============================================================
# CROPS
# ============================================================

@app.post("/crops")
def create_crop(data: CropCreate):
    conn = db()

    try:
        farm = conn.execute(
            "SELECT * FROM farms WHERE id = ?",
            (data.farm_id,),
        ).fetchone()

        if not farm:
            raise HTTPException(404, "مزرعه پیدا نشد")

        if data.user_id:
            require_user(data.user_id)
            if farm["user_id"] != data.user_id:
                raise HTTPException(403, "این مزرعه متعلق به کاربر نیست")

        if data.land_id:
            land = conn.execute(
                "SELECT * FROM lands WHERE id = ? AND farm_id = ?",
                (data.land_id, data.farm_id),
            ).fetchone()
            if not land:
                raise HTTPException(400, "زمین انتخاب‌شده متعلق به این مزرعه نیست")

        crop_id = uid()
        conn.execute(
            """
            INSERT INTO crops
            (id, farm_id, land_id, name, variety,
             planting_date, expected_harvest, area, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                crop_id,
                data.farm_id,
                data.land_id,
                data.name,
                data.variety,
                data.planting_date,
                data.expected_harvest,
                data.area,
                now_iso(),
            ),
        )
        conn.commit()
        return {"crop_id": crop_id, "status": "created"}
    finally:
        conn.close()


# ============================================================
# SOIL LAB
# ============================================================

@app.post("/soil/lab")
def create_soil_test(data: SoilTestCreate):
    conn = db()

    try:
        farm = conn.execute(
            "SELECT * FROM farms WHERE id = ?",
            (data.farm_id,),
        ).fetchone()

        if not farm:
            raise HTTPException(404, "مزرعه پیدا نشد")

        if data.user_id:
            require_user(data.user_id)
            if farm["user_id"] != data.user_id:
                raise HTTPException(403, "این مزرعه متعلق به کاربر نیست")

        test_id = uid()
        conn.execute(
            """
            INSERT INTO soil_lab_tests
            (id, farm_id, ph, ec, nitrogen, phosphorus,
             potassium, organic_matter, raw_data, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                test_id,
                data.farm_id,
                data.ph,
                data.ec,
                data.nitrogen,
                data.phosphorus,
                data.potassium,
                data.organic_matter,
                json.dumps(data.raw_data, ensure_ascii=False),
                now_iso(),
            ),
        )
        conn.commit()
        return {"test_id": test_id, "status": "saved"}
    finally:
        conn.close()


# ============================================================
# WEATHER
# ============================================================

def validate_coordinates(latitude, longitude):
    if not -90 <= latitude <= 90:
        raise HTTPException(400, "عرض جغرافیایی نامعتبر است")
    if not -180 <= longitude <= 180:
        raise HTTPException(400, "طول جغرافیایی نامعتبر است")


def geocode_region(region: str):
    try:
        response = requests.get(
            "https://geocoding-api.open-meteo.com/v1/search",
            params={
                "name": region,
                "count": 1,
                "language": "en",
                "format": "json",
            },
            timeout=15,
        )
        response.raise_for_status()
        results = response.json().get("results") or []
        return results[0] if results else None
    except requests.RequestException as exc:
        raise HTTPException(502, "سرویس مکان‌یابی موقتاً در دسترس نیست") from exc


def weather_by_coordinates(latitude: float, longitude: float):
    validate_coordinates(latitude, longitude)

    try:
        response = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude": latitude,
                "longitude": longitude,
                "current": (
                    "temperature_2m,relative_humidity_2m,"
                    "precipitation,wind_speed_10m,weather_code"
                ),
                "hourly": (
                    "temperature_2m,relative_humidity_2m,"
                    "precipitation_probability,precipitation,"
                    "et0_fao_evapotranspiration,"
                    "soil_moisture_0_to_1cm,"
                    "soil_moisture_1_to_3cm,"
                    "soil_moisture_3_to_9cm"
                ),
                "daily": (
                    "temperature_2m_max,temperature_2m_min,"
                    "precipitation_sum,precipitation_probability_max,"
                    "wind_speed_10m_max,et0_fao_evapotranspiration"
                ),
                "timezone": "auto",
                "forecast_days": 7,
            },
            timeout=20,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise HTTPException(502, "دریافت اطلاعات آب‌وهوا ناموفق بود") from exc


@app.get("/weather")
def weather(
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
    region: Optional[str] = None,
):
    if latitude is None or longitude is None:
        if not region or not region.strip():
            raise HTTPException(400, "latitude/longitude یا region لازم است")

        location = geocode_region(region.strip())

        if not location:
            raise HTTPException(404, "مکان پیدا نشد")

        latitude = location["latitude"]
        longitude = location["longitude"]

    data = weather_by_coordinates(latitude, longitude)

    return {
        "location": {
            "latitude": latitude,
            "longitude": longitude,
        },
        "current": data.get("current", {}),
        "hourly": data.get("hourly", {}),
        "daily": data.get("daily", {}),
        "timezone": data.get("timezone"),
        "source": "Open-Meteo",
    }


# ============================================================
# AI
# ============================================================

def local_agri_analysis(question: str):
    q = question.lower()

    if any(x in q for x in ["زرد", "زردی", "برگ زرد"]):
        return (
            "برای تشخیص زردی برگ، اطلاعات محصول، سن گیاه، نوع خاک، "
            "آبیاری، نتیجه آزمایش خاک و وضعیت آب‌وهوا لازم است. "
            "بدون این اطلاعات تشخیص قطعی انجام نمی‌شود."
        )

    if any(x in q for x in ["آبیاری", "آب", "خشکی"]):
        return (
            "برای تعیین مقدار و زمان آبیاری باید محصول، سطح زمین، "
            "نوع خاک، روش آبیاری، مرحله رشد، دما، بارندگی و رطوبت "
            "خاک بررسی شود."
        )

    if any(x in q for x in ["کود", "کوددهی", "نیتروژن", "فسفر", "پتاسیم"]):
        return (
            "توصیه کودی باید بر اساس محصول، مرحله رشد و در صورت امکان "
            "آزمایش خاک و آب انجام شود. مقدار دقیق بدون این اطلاعات "
            "قابل اعتماد نیست."
        )

    if any(x in q for x in ["سم", "آفت", "بیماری", "حشره"]):
        return (
            "برای انتخاب درمان، ابتدا باید عامل احتمالی، محصول، مرحله رشد، "
            "شدت خسارت و شرایط آب‌وهوایی مشخص شود. در صورت امکان تصویر "
            "گیاه نیز ارسال شود."
        )

    return (
        "برای تحلیل کشاورزی، ابتدا اطلاعات منطقه، محصول، مرحله رشد، خاک، "
        "آب و شرایط آب‌وهوایی را جمع‌آوری کنید. سپس می‌توان گزینه‌ها، "
        "ریسک‌ها و برنامه اقدام را بررسی کرد."
    )


def call_openai(question: str, context: dict, language: str = "fa"):
    if not OPENAI_API_KEY or not OPENAI_MODEL:
        return None, 0, 0

    try:
        from openai import OpenAI

        client = OpenAI(api_key=OPENAI_API_KEY)

        system_prompt = """
You are ARYA AgriDoctor, an agricultural AI assistant.

Analyze agricultural questions using supplied farm, crop, soil,
water and weather data. Distinguish known facts from assumptions.
Do not claim certainty when data are insufficient. Ask only for
missing information that materially changes the recommendation.
Give practical steps and explain risks.

Never invent pesticide or fertilizer labels, legal approvals, doses,
pre-harvest intervals or restrictions. Recommend checking the local
official product label and agricultural authority before chemical
application. For high-risk decisions, recommend qualified agronomist
verification. Answer in the requested language.
"""

        context_text = json.dumps(context, ensure_ascii=False)

        response = client.responses.create(
            model=OPENAI_MODEL,
            input=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": (
                        "Requested language: " + language
                        + "\nFARM CONTEXT:\n" + context_text
                        + "\n\nQUESTION:\n" + question
                    ),
                },
            ],
        )

        answer = getattr(response, "output_text", None)
        if not answer or not answer.strip():
            return None, 0, 0

        usage = getattr(response, "usage", None)

        input_tokens = getattr(usage, "input_tokens", 0) if usage else 0
        output_tokens = getattr(usage, "output_tokens", 0) if usage else 0

        return answer.strip(), input_tokens, output_tokens

    except Exception:
        # Do not expose API keys, credentials or provider internals.
        return None, 0, 0


def calculate_ai_cost(input_tokens, output_tokens):
    return (
        (input_tokens / 1_000_000) * AI_INPUT_COST_PER_1M
        + (output_tokens / 1_000_000) * AI_OUTPUT_COST_PER_1M
    )


@app.post("/ai/ask")
def ai_ask(data: AIRequest):
    user = require_user(data.user_id)
    conn = db()

    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM ai_usage
            WHERE user_id = ?
              AND date(created_at) = date('now')
            """,
            (data.user_id,),
        ).fetchone()

        daily_count = row["count"]

        if daily_count >= DAILY_AI_LIMIT:
            raise HTTPException(
                429,
                "سقف استفاده روزانه از AI تکمیل شده است",
            )

        farm_context = {
            "user": {
                "country": user["country"],
                "language": data.language or user["language"],
            },
            "farm": None,
            "crops": [],
            "lands": [],
            "soil_tests": [],
            "weather": None,
            "region": data.region,
        }

        if data.farm_id:
            farm = get_owned_farm(conn, data.farm_id, data.user_id)
            farm_context["farm"] = dict(farm)

            farm_context["lands"] = [
                dict(r) for r in conn.execute(
                    "SELECT * FROM lands WHERE farm_id = ?",
                    (data.farm_id,),
                ).fetchall()
            ]

            farm_context["crops"] = [
                dict(r) for r in conn.execute(
                    "SELECT * FROM crops WHERE farm_id = ?",
                    (data.farm_id,),
                ).fetchall()
            ]

            farm_context["soil_tests"] = [
                dict(r) for r in conn.execute(
                    """
                    SELECT * FROM soil_lab_tests
                    WHERE farm_id = ?
                    ORDER BY created_at DESC LIMIT 5
                    """,
                    (data.farm_id,),
                ).fetchall()
            ]

            lat, lon = farm["latitude"], farm["longitude"]

            if lat is not None and lon is not None:
                try:
                    farm_context["weather"] = weather_by_coordinates(lat, lon)
                except HTTPException:
                    farm_context["weather"] = None

        if (
            farm_context["weather"] is None
            and data.latitude is not None
            and data.longitude is not None
        ):
            try:
                farm_context["weather"] = weather_by_coordinates(
                    data.latitude, data.longitude
                )
            except HTTPException:
                farm_context["weather"] = None

    finally:
        conn.close()

    answer, input_tokens, output_tokens = call_openai(
        data.question,
        farm_context,
        data.language,
    )

    provider = "openai" if answer else "local-rule-engine"

    if not answer:
        answer = local_agri_analysis(data.question)

    estimated_cost = calculate_ai_cost(input_tokens, output_tokens)
    usage_id = uid()
    recommendation_id = uid()
    timestamp = now_iso()

    conn = db()
    try:
        conn.execute(
            """
            INSERT INTO ai_usage
            (id, user_id, provider, model, input_tokens,
             output_tokens, estimated_cost, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                usage_id,
                data.user_id,
                provider,
                OPENAI_MODEL if provider == "openai" else "local",
                input_tokens,
                output_tokens,
                estimated_cost,
                timestamp,
            ),
        )

        conn.execute(
            """
            INSERT INTO recommendations
            (id, user_id, farm_id, category, question,
             recommendation, confidence, risk_level, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                recommendation_id,
                data.user_id,
                data.farm_id,
                "AI",
                data.question,
                answer,
                0.0 if provider == "local-rule-engine" else 0.70,
                "needs_validation",
                timestamp,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "recommendation_id": recommendation_id,
        "answer": answer,
        "provider": provider,
        "model": OPENAI_MODEL if provider == "openai" else "local",
        "weather_loaded": bool(farm_context["weather"]),
        "estimated_ai_cost": estimated_cost,
        "daily_usage": daily_count + 1,
        "daily_limit": DAILY_AI_LIMIT,
        "validation_required": True,
    }


# ============================================================
# PRICING
# ============================================================

@app.get("/pricing")
def get_pricing(country: str):
    return pricing(country)


# ============================================================
# PAYMENTS
# ============================================================

@app.post("/payments")
def create_payment(data: PaymentCreate):
    require_user(data.user_id)

    allowed_methods = {
        "bank_transfer", "local_transfer", "crypto", "usdt"
    }
    method = data.method.strip().lower()

    if method not in allowed_methods:
        raise HTTPException(400, "روش پرداخت پشتیبانی نمی‌شود")

    price = pricing(data.country)
    payment_id = uid()

    conn = db()
    try:
        conn.execute(
            """
            INSERT INTO payments
            (id, user_id, country, currency, amount, method,
             status, transaction_reference, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                payment_id,
                data.user_id,
                data.country,
                price["currency"],
                price["amount"],
                method,
                data.transaction_reference,
                now_iso(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "payment_id": payment_id,
        "status": "pending",
        "currency": price["currency"],
        "amount": price["amount"],
        "tier": price["tier"],
        "message": "پرداخت پس از تأیید واقعی فعال خواهد شد.",
    }


@app.post("/payments/{payment_id}/verify")
def verify_payment(
    payment_id: str,
    owner_id: str,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    require_owner(owner_id)
    check_owner_secret(x_owner_secret)

    conn = db()
    try:
        payment = conn.execute(
            "SELECT * FROM payments WHERE id = ?",
            (payment_id,),
        ).fetchone()

        if not payment:
            raise HTTPException(404, "پرداخت پیدا نشد")

        existing = conn.execute(
            "SELECT * FROM subscriptions WHERE payment_id = ?",
            (payment_id,),
        ).fetchone()

        if payment["status"] == "verified" and existing:
            return {
                "status": "already_verified",
                "subscription_id": existing["id"],
                "expires_at": existing["expires_at"],
            }

        if payment["status"] != "pending":
            raise HTTPException(409, "وضعیت پرداخت قابل تأیید نیست")

        start = datetime.now(timezone.utc)
        expires = start + timedelta(days=365)
        subscription_id = uid()

        conn.execute(
            """
            UPDATE payments
            SET status = 'verified', verified_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (start.isoformat(), payment_id),
        )

        conn.execute(
            """
            INSERT INTO subscriptions
            (id, user_id, plan, currency, amount, started_at,
             expires_at, status, payment_id, created_at)
            VALUES (?, ?, 'ANNUAL', ?, ?, ?, ?, 'active', ?, ?)
            """,
            (
                subscription_id,
                payment["user_id"],
                payment["currency"],
                payment["amount"],
                start.isoformat(),
                expires.isoformat(),
                payment_id,
                start.isoformat(),
            ),
        )

        conn.commit()
    finally:
        conn.close()

    audit(owner_id, "PAYMENT_VERIFIED", "payment", payment_id)

    return {
        "status": "verified",
        "subscription_id": subscription_id,
        "expires_at": expires.isoformat(),
    }


# ============================================================
# SUBSCRIPTIONS
# ============================================================

@app.get("/subscriptions/{user_id}")
def subscription(user_id: str):
    require_user(user_id)
    conn = db()

    try:
        row = conn.execute(
            """
            SELECT * FROM subscriptions
            WHERE user_id = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (user_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return {"status": "none", "server_time": now_iso()}

    result = dict(row)
    expires = datetime.fromisoformat(result["expires_at"])

    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    expired = datetime.now(timezone.utc) >= expires
    result["server_time"] = now_iso()
    result["expired"] = expired

    if expired and result["status"] == "active":
        result["status"] = "expired"

    return result


# ============================================================
# ACTIVATION CODES
# ============================================================

@app.post("/owner/activation-code")
def create_activation_code(
    owner_id: str,
    plan: str = "ANNUAL",
    duration_days: int = 365,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    require_owner(owner_id)
    check_owner_secret(x_owner_secret)

    if duration_days < 1 or duration_days > 3650:
        raise HTTPException(400, "مدت اعتبار باید بین ۱ تا ۳۶۵۰ روز باشد")

    raw_code = (
        "ARYA-"
        + secrets.token_hex(4).upper()
        + "-"
        + secrets.token_hex(4).upper()
    )

    conn = db()
    try:
        conn.execute(
            """
            INSERT INTO activation_codes
            (id, code_hash, plan, duration_days, status, created_at)
            VALUES (?, ?, ?, ?, 'unused', ?)
            """,
            (uid(), sha256(raw_code), plan, duration_days, now_iso()),
        )
        conn.commit()
    finally:
        conn.close()

    audit(owner_id, "ACTIVATION_CODE_CREATED")

    return {
        "activation_code": raw_code,
        "plan": plan,
        "duration_days": duration_days,
    }


@app.post("/activation/use")
def use_activation(data: ActivationRequest):
    require_user(data.user_id)

    conn = db()
    try:
        # BEGIN IMMEDIATE prevents concurrent requests from consuming
        # the same activation code.
        conn.execute("BEGIN IMMEDIATE")

        code = conn.execute(
            "SELECT * FROM activation_codes WHERE code_hash = ?",
            (sha256(data.code.strip()),),
        ).fetchone()

        if not code:
            raise HTTPException(404, "کد فعال‌سازی معتبر نیست")

        if code["status"] != "unused":
            raise HTTPException(409, "این کد قبلاً استفاده شده است")

        start = datetime.now(timezone.utc)
        expires = start + timedelta(days=code["duration_days"])
        subscription_id = uid()

        conn.execute(
            """
            INSERT INTO subscriptions
            (id, user_id, plan, currency, amount, started_at,
             expires_at, status, payment_id, created_at)
            VALUES (?, ?, ?, 'ACTIVATION', 0, ?, ?, 'active', NULL, ?)
            """,
            (
                subscription_id,
                data.user_id,
                code["plan"],
                start.isoformat(),
                expires.isoformat(),
                now_iso(),
            ),
        )

        updated = conn.execute(
            """
            UPDATE activation_codes
            SET status = 'used', user_id = ?, used_at = ?
            WHERE id = ? AND status = 'unused'
            """,
            (data.user_id, now_iso(), code["id"]),
        )

        if updated.rowcount != 1:
            raise HTTPException(409, "کد هم‌زمان توسط درخواست دیگری مصرف شد")

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "status": "activated",
        "subscription_id": subscription_id,
        "expires_at": expires.isoformat(),
    }


# ============================================================
# DEVICES
# ============================================================

@app.post("/devices")
def register_device(data: DeviceCreate):
    require_user(data.user_id)
    device_hash = sha256(data.device_hash)

    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")

        existing = conn.execute(
            """
            SELECT * FROM devices
            WHERE user_id = ? AND device_hash = ?
            """,
            (data.user_id, device_hash),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE devices
                SET status = 'active', device_name = ?,
                    platform = ?, last_seen = ?
                WHERE id = ?
                """,
                (
                    data.device_name,
                    data.platform,
                    now_iso(),
                    existing["id"],
                ),
            )
            conn.commit()
            return {
                "device_id": existing["id"],
                "status": "active",
                "existing_device": True,
            }

        count = conn.execute(
            """
            SELECT COUNT(*) FROM devices
            WHERE user_id = ? AND status = 'active'
            """,
            (data.user_id,),
        ).fetchone()[0]

        if count >= DEVICE_LIMIT:
            raise HTTPException(403, "تعداد دستگاه‌های مجاز تکمیل شده است")

        device_id = uid()
        timestamp = now_iso()

        conn.execute(
            """
            INSERT INTO devices
            (id, user_id, device_hash, device_name, platform,
             status, created_at, last_seen)
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (
                device_id,
                data.user_id,
                device_hash,
                data.device_name,
                data.platform,
                timestamp,
                timestamp,
            ),
        )
        conn.commit()
        return {"device_id": device_id, "status": "active"}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# FEEDBACK
# ============================================================

@app.post("/feedback")
def create_feedback(data: FeedbackCreate):
    if data.user_id:
        require_user(data.user_id)

    feedback_id = uid()
    conn = db()

    try:
        conn.execute(
            """
            INSERT INTO feedback
            (id, user_id, category, original_language,
             original_text, persian_translation, status, created_at)
            VALUES (?, ?, ?, ?, ?, NULL, 'new', ?)
            """,
            (
                feedback_id,
                data.user_id,
                data.category,
                data.language,
                data.text,
                now_iso(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "feedback_id": feedback_id,
        "status": "new",
        "translation_status": "pending",
    }


@app.get("/owner/feedback")
def owner_feedback(
    owner_id: str,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    require_owner(owner_id)
    check_owner_secret(x_owner_secret)

    conn = db()
    try:
        rows = conn.execute(
            "SELECT * FROM feedback ORDER BY created_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ============================================================
# AI MAINTENANCE PROPOSALS
# ============================================================

@app.post("/owner/ai/proposals")
def create_ai_proposal(
    data: ProposalCreate,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    require_owner(data.owner_id)
    check_owner_secret(x_owner_secret)

    proposal_id = uid()
    conn = db()

    try:
        conn.execute(
            """
            INSERT INTO ai_change_proposals
            (id, title, description, proposed_change, status,
             created_by, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                proposal_id,
                data.title,
                data.description,
                data.proposed_change,
                data.owner_id,
                now_iso(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    audit(
        data.owner_id,
        "AI_CHANGE_PROPOSAL_CREATED",
        "ai_change_proposal",
        proposal_id,
    )

    return {
        "proposal_id": proposal_id,
        "status": "pending",
        "message": "نیازمند بررسی و تأیید OWNER است.",
    }


@app.post("/owner/ai/proposals/{proposal_id}/decision")
def decide_ai_proposal(
    proposal_id: str,
    data: ProposalApproval,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    require_owner(data.owner_id)
    check_owner_secret(x_owner_secret)

    conn = db()
    try:
        proposal = conn.execute(
            "SELECT * FROM ai_change_proposals WHERE id = ?",
            (proposal_id,),
        ).fetchone()

        if not proposal:
            raise HTTPException(404, "پیشنهاد پیدا نشد")

        if proposal["status"] != "pending":
            raise HTTPException(409, "این پیشنهاد قبلاً تعیین تکلیف شده است")

        status = "approved" if data.approve else "rejected"

        conn.execute(
            """
            UPDATE ai_change_proposals
            SET status = ?, approved_by = ?, approved_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (status, data.owner_id, now_iso(), proposal_id),
        )
        conn.commit()
    finally:
        conn.close()

    audit(
        data.owner_id,
        "AI_CHANGE_PROPOSAL_DECISION",
        "ai_change_proposal",
        proposal_id,
        {"decision": status},
    )

    return {"proposal_id": proposal_id, "status": status}


# ============================================================
# KNOWLEDGE VERSIONING
# ============================================================

@app.post("/owner/knowledge")
def create_knowledge_version(
    owner_id: str,
    title: str,
    content: str,
    version: str,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    require_owner(owner_id)
    check_owner_secret(x_owner_secret)

    knowledge_id = uid()
    conn = db()

    try:
        conn.execute(
            """
            INSERT INTO knowledge_versions
            (id, version, title, content, status, created_by, created_at)
            VALUES (?, ?, ?, ?, 'draft', ?, ?)
            """,
            (
                knowledge_id,
                version,
                title,
                content,
                owner_id,
                now_iso(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return {"knowledge_id": knowledge_id, "status": "draft"}


# ============================================================
# AUDIT
# ============================================================

@app.get("/owner/audit")
def audit_logs(
    owner_id: str,
    limit: int = 100,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    require_owner(owner_id)
    check_owner_secret(x_owner_secret)
    limit = min(max(limit, 1), 500)

    conn = db()
    try:
        rows = conn.execute(
            """
            SELECT * FROM audit_logs
            ORDER BY created_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ============================================================
# OFFLINE SYNC
# ============================================================

@app.post("/sync")
def sync_operation(
    user_id: str,
    operation_id: str,
    entity_type: str,
    entity_id: str,
    operation: str,
    payload: dict,
):
    require_user(user_id)

    allowed_operations = {"create", "update", "delete"}
    if operation not in allowed_operations:
        raise HTTPException(400, "نوع عملیات همگام‌سازی نامعتبر است")

    if not operation_id.strip() or len(operation_id) > 200:
        raise HTTPException(400, "شناسه عملیات نامعتبر است")

    conn = db()
    try:
        existing = conn.execute(
            "SELECT * FROM sync_queue WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()

        if existing:
            if existing["user_id"] != user_id:
                raise HTTPException(409, "شناسه عملیات قبلاً استفاده شده است")

            return {
                "status": "already_received",
                "operation_id": operation_id,
            }

        conn.execute(
            """
            INSERT INTO sync_queue
            (id, user_id, operation_id, entity_type, entity_id,
             operation, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uid(),
                user_id,
                operation_id,
                entity_type,
                entity_id,
                operation,
                json.dumps(payload, ensure_ascii=False),
                now_iso(),
            ),
        )
        conn.commit()
        return {"status": "queued", "operation_id": operation_id}
    except sqlite3.IntegrityError:
        conn.rollback()
        raise HTTPException(409, "شناسه عملیات تکراری است")
    finally:
        conn.close()


# ============================================================
# SERVER TIME
# ============================================================

@app.get("/server-time")
def server_time():
    current = datetime.now(timezone.utc)
    return {
        "utc": current.isoformat(),
        "unix": int(current.timestamp()),
    }


# ============================================================
# DYNAMIC WALLET AND PAYMENT API
# ============================================================
# This section requires backend/wallet_service.py.
# The module must provide the functions imported below.
# ============================================================

try:
    from wallet_service import (
        initialize_wallet_tables,
        add_wallet,
        deactivate_wallet,
        list_active_wallets,
        create_payment_intent,
        get_payment_intent,
        mark_payment_verified,
        secure_compare,
    )
except ImportError as exc:
    raise RuntimeError(
        "ماژول wallet_service.py پیدا نشد یا توابع موردنیاز آن موجود نیست. "
        "برای فعال‌شدن بخش کیف‌پول، این ماژول باید در مسیر قابل import "
        "برنامه قرار داشته باشد."
    ) from exc


initialize_wallet_tables()

wallet_router = APIRouter(
    prefix="/wallets",
    tags=["Dynamic Wallets"],
)


def _check_owner_secret(owner_secret: Optional[str]) -> None:
    if not MASTER_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Owner security is not configured.",
        )

    if not owner_secret or not secure_compare(
        owner_secret,
        MASTER_SECRET,
    ):
        raise HTTPException(
            status_code=403,
            detail="Owner authorization failed.",
        )


@wallet_router.get("/active")
def get_active_wallets(
    currency: Optional[str] = None,
    network: Optional[str] = None,
):
    return {
        "ok": True,
        "wallets": list_active_wallets(
            currency=currency,
            network=network,
        ),
    }


@wallet_router.post("/owner/add")
def owner_add_wallet(
    currency: str,
    network: str,
    address: str,
    label: Optional[str] = None,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    _check_owner_secret(x_owner_secret)

    try:
        wallet_id = add_wallet(
            currency=currency,
            network=network,
            address=address,
            label=label,
        )
        return {
            "ok": True,
            "wallet_id": wallet_id,
            "message": "Wallet added successfully.",
        }
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@wallet_router.post("/owner/{wallet_id}/deactivate")
def owner_deactivate_wallet(
    wallet_id: int,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    _check_owner_secret(x_owner_secret)

    success = deactivate_wallet(wallet_id)

    if not success:
        raise HTTPException(404, "Wallet not found.")

    return {
        "ok": True,
        "wallet_id": wallet_id,
        "message": "Wallet deactivated.",
    }


@wallet_router.post("/payment-intent")
def create_wallet_payment_intent(
    user_id: Optional[int],
    currency: str,
    network: str,
    amount: str,
):
    try:
        payment = create_payment_intent(
            user_id=user_id,
            currency=currency,
            network=network,
            amount=amount,
        )
        return {"ok": True, "payment": payment}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@wallet_router.get("/payment-intent/{payment_id}")
def get_wallet_payment_intent(payment_id: int):
    payment = get_payment_intent(payment_id)

    if payment is None:
        raise HTTPException(404, "Payment intent not found.")

    return {"ok": True, "payment": payment}


@wallet_router.post("/owner/payment/{payment_id}/verify")
def owner_verify_wallet_payment(
    payment_id: int,
    transaction_id: str,
    provider: Optional[str] = None,
    verification_reference: Optional[str] = None,
    x_owner_secret: Optional[str] = Header(
        default=None,
        alias="X-Owner-Secret",
    ),
):
    _check_owner_secret(x_owner_secret)

    try:
        success = mark_payment_verified(
            payment_id=payment_id,
            transaction_id=transaction_id,
            provider=provider,
            verification_reference=verification_reference,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    if not success:
        raise HTTPException(404, "Payment intent not found.")

    return {
        "ok": True,
        "payment_id": payment_id,
        "status": "verified",
    }


# Register wallet endpoints BEFORE running Uvicorn.
app.include_router(wallet_router)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=False,
    )
