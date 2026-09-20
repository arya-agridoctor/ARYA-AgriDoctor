import os
import uuid
import json
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Any

import requests
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field


# ============================================================
# ARYA AgriDoctor - Cloud Backend
# Version: 1.0 Foundation
# ============================================================

APP_NAME = "ARYA AgriDoctor Backend"
APP_VERSION = "1.0.0"

DATABASE = os.getenv("ARYA_DATABASE", "arya.db")
MASTER_EMAIL = os.getenv("ARYA_MASTER_EMAIL", "")
MASTER_SECRET = os.getenv("ARYA_MASTER_SECRET", "")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "")

# Cost configuration is intentionally environment based.
# Do NOT put real provider prices directly in source code.
AI_INPUT_COST_PER_1M = float(os.getenv("AI_INPUT_COST_PER_1M", "0"))
AI_OUTPUT_COST_PER_1M = float(os.getenv("AI_OUTPUT_COST_PER_1M", "0"))

DAILY_AI_LIMIT = int(os.getenv("ARYA_DAILY_AI_LIMIT", "30"))
DEVICE_LIMIT = int(os.getenv("ARYA_DEVICE_LIMIT", "3"))

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="ARYA AgriDoctor agricultural AI backend"
)


# ============================================================
# DATABASE
# ============================================================

def db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    conn = db()
    cur = conn.cursor()

    cur.executescript("""
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
    """)

    conn.commit()
    conn.close()


init_db()


# ============================================================
# HELPERS
# ============================================================

def uid():
    return str(uuid.uuid4())


def sha256(value: str):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def audit(actor_id, action, target_type="", target_id="", details=None):
    conn = db()
    conn.execute(
        """
        INSERT INTO audit_logs
        (id, actor_id, action, target_type, target_id, details, created_at)
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
    conn.close()


def get_user(user_id):
    conn = db()
    row = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    conn.close()
    return row


def require_user(user_id):
    user = get_user(user_id)
    if not user:
        raise HTTPException(404, "کاربر پیدا نشد")
    if user["status"] != "active":
        raise HTTPException(403, "حساب کاربر فعال نیست")
    return user


def require_owner(user_id):
    user = require_user(user_id)
    if user["role"] != "OWNER":
        raise HTTPException(403, "دسترسی OWNER لازم است")
    return user


def passwordless_token():
    return secrets.token_urlsafe(32)


def count_users():
    conn = db()
    count = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]
    conn.close()
    return count


def pricing(country: str):
    iran = str(country or "").strip().lower() in {
        "iran",
        "ایران",
        "ir"
    }

    count = count_users()

    if iran:
        currency = "TOMAN"
        if count < 100:
            amount = 500000
            tier = "IR_FIRST_100"
        elif count < 600:
            amount = 800000
            tier = "IR_NEXT_500"
        else:
            amount = 1200000
            tier = "IR_AFTER_600"
    else:
        currency = "USDT"
        if count < 100:
            amount = 10
            tier = "GLOBAL_FIRST_100"
        elif count < 600:
            amount = 15
            tier = "GLOBAL_NEXT_500"
        else:
            amount = 20
            tier = "GLOBAL_AFTER_600"

    return {
        "currency": currency,
        "amount": amount,
        "tier": tier,
        "user_count_at_quote": count,
    }


# ============================================================
# MODELS
# ============================================================

class UserCreate(BaseModel):
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
    area: Optional[float] = None
    area_unit: str = "hectare"
    soil_type: Optional[str] = None
    irrigation_type: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class CropCreate(BaseModel):
    farm_id: str
    land_id: Optional[str] = None
    name: str
    variety: Optional[str] = None
    planting_date: Optional[str] = None
    expected_harvest: Optional[str] = None
    area: Optional[float] = None


class SoilTestCreate(BaseModel):
    farm_id: str
    ph: Optional[float] = None
    ec: Optional[float] = None
    nitrogen: Optional[float] = None
    phosphorus: Optional[float] = None
    potassium: Optional[float] = None
    organic_matter: Optional[float] = None
    raw_data: dict = {}


class AIRequest(BaseModel):
    user_id: str
    question: str
    farm_id: Optional[str] = None
    language: str = "fa"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
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
    text: str


class ActivationRequest(BaseModel):
    user_id: str
    code: str
    device_id: Optional[str] = None


class DeviceCreate(BaseModel):
    user_id: str
    device_hash: str
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
        "message": "ARYA AgriDoctor Backend"
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "database": DATABASE,
        "server_time": now_iso(),
        "ai_configured": bool(OPENAI_API_KEY and OPENAI_MODEL)
    }


# ============================================================
# USERS
# ============================================================

@app.post("/users")
def create_user(data: UserCreate):
    user_id = uid()

    conn = db()

    try:
        conn.execute(
            """
            INSERT INTO users
            (id, email, phone, name, country, language, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'USER', ?)
            """,
            (
                user_id,
                data.email,
                data.phone,
                data.name,
                data.country,
                data.language,
                now_iso(),
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(409, "ایمیل قبلاً ثبت شده است")

    conn.close()

    audit(
        user_id,
        "USER_CREATED",
        "user",
        user_id
    )

    return {
        "user_id": user_id,
        "status": "created",
        "pricing": pricing(data.country)
    }


@app.get("/users/{user_id}")
def user_info(user_id: str):
    user = require_user(user_id)

    return dict(user)


# ============================================================
# FARMS
# ============================================================

@app.post("/farms")
def create_farm(data: FarmCreate):
    require_user(data.user_id)

    farm_id = uid()

    conn = db()
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
    conn.close()

    audit(data.user_id, "FARM_CREATED", "farm", farm_id)

    return {
        "farm_id": farm_id,
        "status": "created"
    }


@app.get("/farms/{user_id}")
def list_farms(user_id: str):
    require_user(user_id)

    conn = db()
    rows = conn.execute(
        "SELECT * FROM farms WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()

    return [dict(row) for row in rows]


# ============================================================
# LAND
# ============================================================

@app.post("/lands")
def create_land(data: LandCreate):
    conn = db()

    farm = conn.execute(
        "SELECT * FROM farms WHERE id = ?",
        (data.farm_id,)
    ).fetchone()

    if not farm:
        conn.close()
        raise HTTPException(404, "مزرعه پیدا نشد")

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
    conn.close()

    return {
        "land_id": land_id,
        "status": "created"
    }


# ============================================================
# CROPS
# ============================================================

@app.post("/crops")
def create_crop(data: CropCreate):
    conn = db()

    farm = conn.execute(
        "SELECT id FROM farms WHERE id = ?",
        (data.farm_id,)
    ).fetchone()

    if not farm:
        conn.close()
        raise HTTPException(404, "مزرعه پیدا نشد")

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
    conn.close()

    return {
        "crop_id": crop_id,
        "status": "created"
    }


# ============================================================
# SOIL LAB
# ============================================================

@app.post("/soil/lab")
def create_soil_test(data: SoilTestCreate):
    test_id = uid()

    conn = db()
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
    conn.close()

    return {
        "test_id": test_id,
        "status": "saved"
    }


# ============================================================
# WEATHER
# ============================================================

def geocode_region(region: str):
    url = "https://geocoding-api.open-meteo.com/v1/search"

    response = requests.get(
        url,
        params={
            "name": region,
            "count": 1,
            "language": "en",
            "format": "json",
        },
        timeout=15,
    )

    response.raise_for_status()

    data = response.json()
    results = data.get("results") or []

    if not results:
        return None

    return results[0]


def weather_by_coordinates(latitude: float, longitude: float):
    url = "https://api.open-meteo.com/v1/forecast"

    response = requests.get(
        url,
        params={
            "latitude": latitude,
            "longitude": longitude,
            "current": (
                "temperature_2m,"
                "relative_humidity_2m,"
                "precipitation,"
                "wind_speed_10m,"
                "weather_code"
            ),
            "hourly": (
                "temperature_2m,"
                "relative_humidity_2m,"
                "precipitation_probability,"
                "precipitation,"
                "et0_fao_evapotranspiration,"
                "soil_moisture_0_to_1cm,"
                "soil_moisture_1_to_3cm,"
                "soil_moisture_3_to_9cm"
            ),
            "daily": (
                "temperature_2m_max,"
                "temperature_2m_min,"
                "precipitation_sum,"
                "precipitation_probability_max,"
                "wind_speed_10m_max,"
                "et0_fao_evapotranspiration"
            ),
            "timezone": "auto",
            "forecast_days": 7,
        },
        timeout=20,
    )

    response.raise_for_status()
    return response.json()


@app.get("/weather")
def weather(
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
    region: Optional[str] = None
):
    if latitude is None or longitude is None:

        if not region:
            raise HTTPException(
                400,
                "latitude/longitude یا region لازم است"
            )

        location = geocode_region(region)

        if not location:
            raise HTTPException(
                404,
                "مکان پیدا نشد"
            )

        latitude = location["latitude"]
        longitude = location["longitude"]

    data = weather_by_coordinates(
        latitude,
        longitude
    )

    current = data.get("current", {})

    return {
        "location": {
            "latitude": latitude,
            "longitude": longitude
        },
        "current": current,
        "hourly": data.get("hourly", {}),
        "daily": data.get("daily", {}),
        "timezone": data.get("timezone"),
        "source": "Open-Meteo"
    }


# ============================================================
# AI
# ============================================================

def local_agri_analysis(question: str):
    q = question.lower()

    if any(x in q for x in ["زرد", "زردی", "برگ زرد"]):
        return (
            "برای تشخیص زردی برگ، اطلاعات محصول، سن گیاه، "
            "نوع خاک، آبیاری، نتیجه آزمایش خاک و وضعیت آب‌وهوا "
            "لازم است. بدون این اطلاعات تشخیص قطعی انجام نمی‌شود."
        )

    if any(x in q for x in ["آبیاری", "آب", "خشکی"]):
        return (
            "برای تعیین مقدار و زمان آبیاری باید محصول، سطح زمین، "
            "نوع خاک، روش آبیاری، مرحله رشد، دما، بارندگی و "
            "رطوبت خاک بررسی شود."
        )

    if any(x in q for x in ["کود", "کوددهی", "نیتروژن", "فسفر", "پتاسیم"]):
        return (
            "توصیه کودی باید بر اساس محصول، مرحله رشد و در صورت "
            "امکان آزمایش خاک و آب انجام شود. مقدار دقیق بدون این "
            "اطلاعات قابل اعتماد نیست."
        )

    if any(x in q for x in ["سم", "آفت", "بیماری", "حشره"]):
        return (
            "برای انتخاب درمان، ابتدا باید عامل احتمالی، محصول، "
            "مرحله رشد، شدت خسارت و شرایط آب‌وهوایی مشخص شود. "
            "در صورت امکان تصویر گیاه نیز ارسال شود."
        )

    return (
        "برای تحلیل کشاورزی، ARYA ابتدا اطلاعات منطقه، محصول، "
        "مرحله رشد، خاک، آب و شرایط آب‌وهوایی را جمع‌آوری می‌کند "
        "و سپس گزینه‌ها، ریسک‌ها و برنامه اقدام را ارائه می‌دهد."
    )


def call_openai(question: str, context: dict):
    if not OPENAI_API_KEY or not OPENAI_MODEL:
        return None, 0, 0

    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=OPENAI_API_KEY
        )

        system_prompt = """
You are ARYA AgriDoctor, an agricultural AI assistant.

Your role:
- Analyze agricultural questions.
- Use supplied farm, crop, soil, water and weather data.
- Clearly distinguish known data from assumptions.
- Never claim certainty when data are insufficient.
- Ask only for missing information that materially changes the recommendation.
- Give practical steps.
- Explain risks.
- For pesticides and fertilizers, do not invent labels,
  legal approvals, doses, PHI or restrictions.
- Recommend checking the local official label and agricultural
  authority before chemical application.
- For high-risk agricultural decisions, recommend professional
  agronomist verification.
- Answer in the requested language.
"""

        context_text = json.dumps(
            context,
            ensure_ascii=False
        )

        response = client.responses.create(
            model=OPENAI_MODEL,
            input=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": (
                        "FARM CONTEXT:\n"
                        + context_text
                        + "\n\nQUESTION:\n"
                        + question
                    )
                }
            ]
        )

        text = response.output_text

        usage = getattr(response, "usage", None)

        input_tokens = (
            getattr(usage, "input_tokens", 0)
            if usage else 0
        )

        output_tokens = (
            getattr(usage, "output_tokens", 0)
            if usage else 0
        )

        return (
            text,
            input_tokens,
            output_tokens
        )

    except Exception as exc:
        print("AI ERROR:", exc)
        return None, 0, 0


def calculate_ai_cost(input_tokens, output_tokens):
    input_cost = (
        input_tokens / 1_000_000
    ) * AI_INPUT_COST_PER_1M

    output_cost = (
        output_tokens / 1_000_000
    ) * AI_OUTPUT_COST_PER_1M

    return input_cost + output_cost


@app.post("/ai/ask")
def ai_ask(data: AIRequest):
    user = require_user(data.user_id)

    # --------------------------------------------------------
    # Daily usage limit
    # --------------------------------------------------------

    conn = db()

    row = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM ai_usage
        WHERE user_id = ?
        AND date(created_at) = date('now')
        """,
        (data.user_id,)
    ).fetchone()

    daily_count = row["count"]

    if daily_count >= DAILY_AI_LIMIT:
        conn.close()
        raise HTTPException(
            429,
            "سقف استفاده روزانه از AI تکمیل شده است"
        )

    # --------------------------------------------------------
    # Farm context
    # --------------------------------------------------------

    farm_context = {
        "user": {
            "country": user["country"],
            "language": user["language"]
        },
        "farm": None,
        "weather": None,
    }

    if data.farm_id:
        farm = conn.execute(
            "SELECT * FROM farms WHERE id = ?",
            (data.farm_id,)
        ).fetchone()

        if farm:
            farm_context["farm"] = dict(farm)

            lat = farm["latitude"]
            lon = farm["longitude"]

            if lat is not None and lon is not None:
                try:
                    farm_context["weather"] = weather_by_coordinates(
                        lat,
                        lon
                    )
                except Exception:
                    farm_context["weather"] = None

    # If the app directly sends location,
    # use it when farm coordinates are not available.
    if (
        farm_context["weather"] is None
        and data.latitude is not None
        and data.longitude is not None
    ):
        try:
            farm_context["weather"] = weather_by_coordinates(
                data.latitude,
                data.longitude
            )
        except Exception:
            pass

    conn.close()

    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    answer, input_tokens, output_tokens = call_openai(
        data.question,
        farm_context
    )

    provider = "openai" if answer else "local-rule-engine"

    if not answer:
        answer = local_agri_analysis(
            data.question
        )

    estimated_cost = calculate_ai_cost(
        input_tokens,
        output_tokens
    )

    usage_id = uid()

    conn = db()

    conn.execute(
        """
        INSERT INTO ai_usage
        (id, user_id, provider, model,
         input_tokens, output_tokens,
         estimated_cost, created_at)
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
            now_iso(),
        )
    )

    recommendation_id = uid()

    conn.execute(
        """
        INSERT INTO recommendations
        (id, user_id, farm_id, category,
         question, recommendation,
         confidence, risk_level, created_at)
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
            now_iso(),
        )
    )

    conn.commit()
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
        "validation_required": True
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

    price = pricing(data.country)

    payment_id = uid()

    conn = db()

    conn.execute(
        """
        INSERT INTO payments
        (id, user_id, country, currency, amount,
         method, status, transaction_reference, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
        (
            payment_id,
            data.user_id,
            data.country,
            price["currency"],
            price["amount"],
            data.method,
            data.transaction_reference,
            now_iso(),
        )
    )

    conn.commit()
    conn.close()

    return {
        "payment_id": payment_id,
        "status": "pending",
        "currency": price["currency"],
        "amount": price["amount"],
        "tier": price["tier"],
        "message": (
            "پرداخت پس از تأیید واقعی فعال خواهد شد."
        )
    }


# ============================================================
# PAYMENT VERIFICATION
# ============================================================

@app.post("/payments/{payment_id}/verify")
def verify_payment(
    payment_id: str,
    owner_id: str
):
    require_owner(owner_id)

    conn = db()

    payment = conn.execute(
        "SELECT * FROM payments WHERE id = ?",
        (payment_id,)
    ).fetchone()

    if not payment:
        conn.close()
        raise HTTPException(404, "پرداخت پیدا نشد")

    if payment["status"] == "verified":
        conn.close()
        return {
            "status": "already_verified"
        }

    conn.execute(
        """
        UPDATE payments
        SET status = 'verified',
            verified_at = ?
        WHERE id = ?
        """,
        (now_iso(), payment_id)
    )

    start = datetime.now(timezone.utc)
    expires = start + timedelta(days=365)

    subscription_id = uid()

    conn.execute(
        """
        INSERT INTO subscriptions
        (id, user_id, plan, currency, amount,
         started_at, expires_at, status,
         payment_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
        """,
        (
            subscription_id,
            payment["user_id"],
            "ANNUAL",
            payment["currency"],
            payment["amount"],
            start.isoformat(),
            expires.isoformat(),
            payment_id,
            now_iso(),
        )
    )

    conn.commit()
    conn.close()

    audit(
        owner_id,
        "PAYMENT_VERIFIED",
        "payment",
        payment_id
    )

    return {
        "status": "verified",
        "subscription_id": subscription_id,
        "expires_at": expires.isoformat()
    }


# ============================================================
# SUBSCRIPTION
# ============================================================

@app.get("/subscriptions/{user_id}")
def subscription(user_id: str):
    require_user(user_id)

    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM subscriptions
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not row:
        return {
            "status": "none"
        }

    result = dict(row)

    expires = datetime.fromisoformat(
        result["expires_at"]
    )

    result["server_time"] = now_iso()
    result["expired"] = (
        datetime.now(timezone.utc) >= expires
    )

    return result


# ============================================================
# ACTIVATION CODES
# ============================================================

@app.post("/owner/activation-code")
def create_activation_code(
    owner_id: str,
    plan: str = "ANNUAL",
    duration_days: int = 365
):
    require_owner(owner_id)

    raw_code = (
        "ARYA-"
        + secrets.token_hex(4).upper()
        + "-"
        + secrets.token_hex(4).upper()
    )

    code_hash = sha256(raw_code)

    conn = db()

    conn.execute(
        """
        INSERT INTO activation_codes
        (id, code_hash, plan, duration_days,
         status, created_at)
        VALUES (?, ?, ?, ?, 'unused', ?)
        """,
        (
            uid(),
            code_hash,
            plan,
            duration_days,
            now_iso(),
        )
    )

    conn.commit()
    conn.close()

    audit(
        owner_id,
        "ACTIVATION_CODE_CREATED"
    )

    return {
        "activation_code": raw_code,
        "plan": plan,
        "duration_days": duration_days
    }


@app.post("/activation/use")
def use_activation(data: ActivationRequest):
    require_user(data.user_id)

    code_hash = sha256(data.code)

    conn = db()

    code = conn.execute(
        """
        SELECT *
        FROM activation_codes
        WHERE code_hash = ?
        """,
        (code_hash,)
    ).fetchone()

    if not code:
        conn.close()
        raise HTTPException(404, "کد فعال‌سازی معتبر نیست")

    if code["status"] != "unused":
        conn.close()
        raise HTTPException(
            409,
            "این کد قبلاً استفاده شده است"
        )

    start = datetime.now(timezone.utc)
    expires = start + timedelta(
        days=code["duration_days"]
    )

    subscription_id = uid()

    conn.execute(
        """
        INSERT INTO subscriptions
        (id, user_id, plan, currency, amount,
         started_at, expires_at, status,
         payment_id, created_at)
        VALUES (?, ?, ?, 'ACTIVATION', 0, ?, ?, 'active', NULL, ?)
        """,
        (
            subscription_id,
            data.user_id,
            code["plan"],
            start.isoformat(),
            expires.isoformat(),
            now_iso(),
        )
    )

    conn.execute(
        """
        UPDATE activation_codes
        SET status = 'used',
            user_id = ?,
            used_at = ?
        WHERE id = ?
        """,
        (
            data.user_id,
            now_iso(),
            code["id"],
        )
    )

    conn.commit()
    conn.close()

    return {
        "status": "activated",
        "subscription_id": subscription_id,
        "expires_at": expires.isoformat()
    }


# ============================================================
# DEVICES
# ============================================================

@app.post("/devices")
def register_device(data: DeviceCreate):
    require_user(data.user_id)

    conn = db()

    count = conn.execute(
        """
        SELECT COUNT(*)
        FROM devices
        WHERE user_id = ?
        AND status = 'active'
        """,
        (data.user_id,)
    ).fetchone()[0]

    if count >= DEVICE_LIMIT:
        conn.close()
        raise HTTPException(
            403,
            "تعداد دستگاه‌های مجاز تکمیل شده است"
        )

    device_id = uid()

    conn.execute(
        """
        INSERT INTO devices
        (id, user_id, device_hash,
         device_name, platform,
         status, created_at, last_seen)
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
        """,
        (
            device_id,
            data.user_id,
            sha256(data.device_hash),
            data.device_name,
            data.platform,
            now_iso(),
            now_iso(),
        )
    )

    conn.commit()
    conn.close()

    return {
        "device_id": device_id,
        "status": "active"
    }


# ============================================================
# FEEDBACK
# ============================================================

@app.post("/feedback")
def create_feedback(data: FeedbackCreate):
    if data.user_id:
        require_user(data.user_id)

    feedback_id = uid()

    conn = db()

    conn.execute(
        """
        INSERT INTO feedback
        (id, user_id, category,
         original_language, original_text,
         persian_translation, status, created_at)
        VALUES (?, ?, ?, ?, ?, NULL, 'new', ?)
        """,
        (
            feedback_id,
            data.user_id,
            data.category,
            data.language,
            data.text,
            now_iso(),
        )
    )

    conn.commit()
    conn.close()

    return {
        "feedback_id": feedback_id,
        "status": "new",
        "translation_status": "pending"
    }


@app.get("/owner/feedback")
def owner_feedback(owner_id: str):
    require_owner(owner_id)

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM feedback
        ORDER BY created_at DESC
        """
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


# ============================================================
# AI MAINTENANCE PROPOSALS
# ============================================================

@app.post("/owner/ai/proposals")
def create_ai_proposal(data: ProposalCreate):
    require_owner(data.owner_id)

    proposal_id = uid()

    conn = db()

    conn.execute(
        """
        INSERT INTO ai_change_proposals
        (id, title, description,
         proposed_change, status,
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
        )
    )

    conn.commit()
    conn.close()

    audit(
        data.owner_id,
        "AI_CHANGE_PROPOSAL_CREATED",
        "ai_change_proposal",
        proposal_id
    )

    return {
        "proposal_id": proposal_id,
        "status": "pending",
        "message": "نیازمند بررسی و تأیید OWNER است."
    }


@app.post("/owner/ai/proposals/{proposal_id}/decision")
def decide_ai_proposal(
    proposal_id: str,
    data: ProposalApproval
):
    require_owner(data.owner_id)

    conn = db()

    proposal = conn.execute(
        """
        SELECT *
        FROM ai_change_proposals
        WHERE id = ?
        """,
        (proposal_id,)
    ).fetchone()

    if not proposal:
        conn.close()
        raise HTTPException(
            404,
            "پیشنهاد پیدا نشد"
        )

    status = "approved" if data.approve else "rejected"

    conn.execute(
        """
        UPDATE ai_change_proposals
        SET status = ?,
            approved_by = ?,
            approved_at = ?
        WHERE id = ?
        """,
        (
            status,
            data.owner_id,
            now_iso(),
            proposal_id,
        )
    )

    conn.commit()
    conn.close()

    audit(
        data.owner_id,
        "AI_CHANGE_PROPOSAL_DECISION",
        "ai_change_proposal",
        proposal_id,
        {"decision": status}
    )

    return {
        "proposal_id": proposal_id,
        "status": status
    }


# ============================================================
# KNOWLEDGE VERSIONING
# ============================================================

@app.post("/owner/knowledge")
def create_knowledge_version(
    owner_id: str,
    title: str,
    content: str,
    version: str
):
    require_owner(owner_id)

    knowledge_id = uid()

    conn = db()

    conn.execute(
        """
        INSERT INTO knowledge_versions
        (id, version, title, content,
         status, created_by, created_at)
        VALUES (?, ?, ?, ?, 'draft', ?, ?)
        """,
        (
            knowledge_id,
            version,
            title,
            content,
            owner_id,
            now_iso(),
        )
    )

    conn.commit()
    conn.close()

    return {
        "knowledge_id": knowledge_id,
        "status": "draft"
    }


# ============================================================
# AUDIT
# ============================================================

@app.get("/owner/audit")
def audit_logs(
    owner_id: str,
    limit: int = 100
):
    require_owner(owner_id)

    limit = min(max(limit, 1), 500)

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM audit_logs
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


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
    payload: dict
):
    require_user(user_id)

    conn = db()

    existing = conn.execute(
        """
        SELECT *
        FROM sync_queue
        WHERE operation_id = ?
        """,
        (operation_id,)
    ).fetchone()

    if existing:
        conn.close()
        return {
            "status": "already_received",
            "operation_id": operation_id
        }

    conn.execute(
        """
        INSERT INTO sync_queue
        (id, user_id, operation_id,
         entity_type, entity_id,
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
        )
    )

    conn.commit()
    conn.close()

    return {
        "status": "queued",
        "operation_id": operation_id
    }


# ============================================================
# SERVER TIME
# ============================================================

@app.get("/server-time")
def server_time():
    return {
        "utc": now_iso(),
        "unix": int(
            datetime.now(timezone.utc).timestamp()
        )
    }


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=False
    )
# ============================================================
# ARYA AgriDoctor - Dynamic Wallet & Payment API
# ============================================================

from fastapi import APIRouter, Header, HTTPException
from typing import Optional

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

initialize_wallet_tables()

wallet_router = APIRouter(
    prefix="/wallets",
    tags=["Dynamic Wallets"],
)


def _check_owner_secret(
    owner_secret: Optional[str],
) -> None:
    expected = os.getenv("ARYA_MASTER_SECRET", "").strip()

    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Owner security is not configured.",
        )

    if not owner_secret or not secure_compare(
        owner_secret,
        expected,
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
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


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
        raise HTTPException(
            status_code=404,
            detail="Wallet not found.",
        )

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

        return {
            "ok": True,
            "payment": payment,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@wallet_router.get("/payment-intent/{payment_id}")
def get_wallet_payment_intent(
    payment_id: int,
):
    payment = get_payment_intent(payment_id)

    if payment is None:
        raise HTTPException(
            status_code=404,
            detail="Payment intent not found.",
        )

    return {
        "ok": True,
        "payment": payment,
    }


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
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    if not success:
        raise HTTPException(
            status_code=404,
            detail="Payment intent not found.",
        )

    return {
        "ok": True,
        "payment_id": payment_id,
        "status": "verified",
    }


app.include_router(wallet_router)
