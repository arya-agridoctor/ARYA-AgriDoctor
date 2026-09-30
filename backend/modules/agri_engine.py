"""
ARYA AgriDoctor
AGRI ENGINE
Version: 1.0.0

Independent agricultural intelligence engine.

IMPORTANT:
- This module does NOT modify main.py.
- This module does NOT modify vision.py.
- This module does NOT modify voice_language.py.
- Sensitive agricultural recommendations must be source-backed.
- No pesticide/fertilizer dosage is invented by this module.
- External data providers are modular and replaceable.
- Knowledge has provenance, freshness and confidence metadata.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "ARYA Agri Engine"
APP_VERSION = "1.0.0"

HOST = os.getenv("ARYA_AGRI_HOST", "0.0.0.0")
PORT = int(os.getenv("ARYA_AGRI_PORT", "8002"))

BASE_DIR = Path(__file__).resolve().parent

DB_PATH = os.getenv(
    "ARYA_AGRI_DB",
    str(BASE_DIR / "agri_engine.db"),
)

REQUEST_TIMEOUT = int(
    os.getenv("ARYA_AGRI_TIMEOUT", "30")
)

MAX_SOURCE_SIZE_MB = float(
    os.getenv("ARYA_AGRI_MAX_SOURCE_MB", "5")
)

ALLOW_EXTERNAL_SOURCES = (
    os.getenv(
        "ARYA_AGRI_ALLOW_EXTERNAL_SOURCES",
        "false",
    ).lower()
    in {"1", "true", "yes", "on"}
)

AUTO_UPDATE = (
    os.getenv(
        "ARYA_AGRI_AUTO_UPDATE",
        "false",
    ).lower()
    in {"1", "true", "yes", "on"}
)

OPENAI_API_KEY = os.getenv(
    "OPENAI_API_KEY",
    "",
).strip()

OPENAI_BASE_URL = os.getenv(
    "ARYA_AGRI_OPENAI_URL",
    "https://api.openai.com/v1",
).rstrip("/")

AI_MODEL = os.getenv(
    "ARYA_AGRI_MODEL",
    "gpt-5.6-luna",
)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=os.getenv(
        "ARYA_LOG_LEVEL",
        "INFO",
    ),
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(name)s | "
        "%(message)s"
    ),
)

logger = logging.getLogger(
    "arya.agri_engine"
)


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Specialized agricultural reasoning and "
        "knowledge engine for ARYA AgriDoctor."
    ),
)


# ============================================================
# DATABASE
# ============================================================

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
    )
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db()

    conn.executescript(
        """
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS crops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            crop_key TEXT UNIQUE NOT NULL,
            common_name TEXT NOT NULL,
            scientific_name TEXT,
            aliases_json TEXT,
            metadata_json TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS diseases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            disease_key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            scientific_name TEXT,
            aliases_json TEXT,
            metadata_json TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pest_key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            scientific_name TEXT,
            aliases_json TEXT,
            metadata_json TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS knowledge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            knowledge_key TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            source_url TEXT,
            source_name TEXT,
            source_version TEXT,
            source_checksum TEXT,
            region TEXT,
            language TEXT,
            confidence REAL,
            valid_from REAL,
            valid_until REAL,
            updated_at REAL NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_key TEXT UNIQUE NOT NULL,
            provider_type TEXT NOT NULL,
            endpoint TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 100,
            config_json TEXT,
            last_success_at REAL,
            last_error_at REAL,
            last_error TEXT,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS update_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT UNIQUE NOT NULL,
            provider_key TEXT,
            status TEXT NOT NULL,
            items_received INTEGER DEFAULT 0,
            items_updated INTEGER DEFAULT 0,
            error TEXT,
            started_at REAL NOT NULL,
            finished_at REAL
        );

        CREATE TABLE IF NOT EXISTS recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recommendation_id TEXT UNIQUE NOT NULL,
            request_hash TEXT,
            category TEXT,
            crop TEXT,
            region TEXT,
            result_json TEXT NOT NULL,
            confidence REAL,
            source_count INTEGER DEFAULT 0,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL,
            payload_json TEXT,
            created_at REAL NOT NULL
        );
        """
    )

    now = time.time()

    default_providers = [
        (
            "internal_knowledge",
            "knowledge",
            None,
            1,
            10,
            "{}",
        ),
        (
            "weather",
            "weather_api",
            None,
            0,
            50,
            "{}",
        ),
        (
            "soil",
            "soil_api",
            None,
            0,
            60,
            "{}",
        ),
        (
            "maps",
            "mapping_api",
            None,
            0,
            70,
            "{}",
        ),
        (
            "satellite",
            "satellite_api",
            None,
            0,
            80,
            "{}",
        ),
    ]

    for item in default_providers:
        conn.execute(
            """
            INSERT OR IGNORE INTO providers
            (
                provider_key,
                provider_type,
                endpoint,
                enabled,
                priority,
                config_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item[0],
                item[1],
                item[2],
                item[3],
                item[4],
                item[5],
                now,
                now,
            ),
        )

    conn.commit()
    conn.close()


# ============================================================
# GENERAL HELPERS
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def make_id(prefix: str) -> str:
    return (
        f"{prefix}_"
        f"{uuid.uuid4().hex}"
    )


def sha256(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def safe_float(
    value: Any,
    default: Optional[float] = None,
) -> Optional[float]:

    try:
        return float(value)
    except (
        TypeError,
        ValueError,
    ):
        return default


def clamp(
    value: float,
    minimum: float,
    maximum: float,
) -> float:

    return max(
        minimum,
        min(maximum, value),
    )


def normalize_text(
    value: Optional[str],
) -> str:

    if value is None:
        return ""

    return re.sub(
        r"\s+",
        " ",
        value.strip(),
    )


def normalize_language(
    value: Optional[str],
) -> Optional[str]:

    if not value:
        return None

    value = value.strip().lower()

    aliases = {
        "persian": "fa",
        "farsi": "fa",
        "فارسی": "fa",
        "english": "en",
        "انگلیسی": "en",
        "german": "de",
        "deutsch": "de",
        "آلمانی": "de",
        "arabic": "ar",
        "عربی": "ar",
        "turkish": "tr",
        "ترکی": "tr",
        "azerbaijani": "az",
        "azeri": "az",
        "kurdish": "ku",
        "کردی": "ku",
        "russian": "ru",
        "روسی": "ru",
    }

    return aliases.get(
        value,
        value,
    )


# ============================================================
# SSRF / EXTERNAL SOURCE SECURITY
# ============================================================

def validate_external_url(
    url: str,
) -> None:

    if not ALLOW_EXTERNAL_SOURCES:
        raise HTTPException(
            status_code=403,
            detail=(
                "External agricultural sources "
                "are currently disabled."
            ),
        )

    parsed = urlparse(url)

    if parsed.scheme not in {
        "https",
        "http",
    }:
        raise HTTPException(
            status_code=400,
            detail="Only HTTP/HTTPS URLs are allowed.",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="Invalid URL.",
        )

    hostname = parsed.hostname.lower()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
    }

    if hostname in blocked_names:
        raise HTTPException(
            status_code=403,
            detail="Blocked destination.",
        )

    try:
        address = ipaddress.ip_address(
            hostname
        )

        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        ):
            raise HTTPException(
                status_code=403,
                detail="Private network destinations are blocked.",
            )

    except ValueError:
        pass


# ============================================================
# MODELS
# ============================================================

class FarmContext(BaseModel):
    country: Optional[str] = None
    region: Optional[str] = None
    province: Optional[str] = None
    district: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    elevation_m: Optional[float] = None
    soil_type: Optional[str] = None
    soil_ph: Optional[float] = None
    organic_matter: Optional[float] = None

    irrigation_type: Optional[str] = None
    water_source: Optional[str] = None

    season: Optional[str] = None
    planting_date: Optional[str] = None

    temperature_c: Optional[float] = None
    rainfall_mm: Optional[float] = None

    crop: Optional[str] = None
    crop_stage: Optional[str] = None


class AnalyzeRequest(BaseModel):
    context: FarmContext
    question: str = Field(
        ...,
        min_length=3,
        max_length=10000,
    )
    language: str = "fa"


class CropSuitabilityRequest(BaseModel):
    context: FarmContext
    crops: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
    )
    language: str = "fa"


class DiagnosisRequest(BaseModel):
    context: FarmContext
    symptoms: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
    )
    language: str = "fa"


class RecommendationRequest(BaseModel):
    context: FarmContext
    category: str
    objective: str
    language: str = "fa"


class KnowledgeItemRequest(BaseModel):
    knowledge_key: str
    category: str
    title: str
    content: str
    source_url: Optional[str] = None
    source_name: Optional[str] = None
    source_version: Optional[str] = None
    region: Optional[str] = None
    language: Optional[str] = None
    confidence: float = 0.5
    valid_until: Optional[float] = None


class ProviderRequest(BaseModel):
    provider_key: str
    provider_type: str
    endpoint: Optional[str] = None
    priority: int = 100
    enabled: bool = True
    config: Dict[str, Any] = {}


class SourceFetchRequest(BaseModel):
    url: str
    source_name: Optional[str] = None


# ============================================================
# KNOWLEDGE ENGINE
# ============================================================

@dataclass
class KnowledgeMatch:
    title: str
    content: str
    category: str
    source_name: Optional[str]
    source_url: Optional[str]
    confidence: float
    freshness: float


def knowledge_freshness(
    updated_at: float,
    valid_until: Optional[float],
) -> float:

    current = time.time()

    if valid_until is not None:
        if current > valid_until:
            return 0.0

    age_days = (
        current - updated_at
    ) / 86400

    if age_days <= 7:
        return 1.0

    if age_days <= 30:
        return 0.9

    if age_days <= 90:
        return 0.75

    if age_days <= 180:
        return 0.55

    if age_days <= 365:
        return 0.35

    return 0.15


def search_knowledge(
    query: str,
    category: Optional[str] = None,
    region: Optional[str] = None,
    limit: int = 10,
) -> List[KnowledgeMatch]:

    query = normalize_text(query)

    if not query:
        return []

    tokens = [
        token.lower()
        for token in re.findall(
            r"[\w\u0600-\u06FF]+",
            query,
        )
        if len(token) > 2
    ]

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM knowledge
        WHERE enabled = 1
        ORDER BY updated_at DESC
        LIMIT 500
        """
    ).fetchall()

    conn.close()

    matches: List[KnowledgeMatch] = []

    for row in rows:

        if category and row["category"] != category:
            continue

        if (
            region
            and row["region"]
            and region.lower()
            not in row["region"].lower()
        ):
            continue

        haystack = (
            f"{row['title']} "
            f"{row['content']} "
            f"{row['category']} "
            f"{row['region'] or ''}"
        ).lower()

        score = 0

        for token in tokens:
            if token in haystack:
                score += 1

        if score <= 0:
            continue

        freshness = knowledge_freshness(
            row["updated_at"],
            row["valid_until"],
        )

        confidence = safe_float(
            row["confidence"],
            0.5,
        ) or 0.5

        final_score = (
            min(
                1.0,
                score / max(
                    1,
                    len(tokens),
                ),
            )
            * 0.6
            + confidence * 0.25
            + freshness * 0.15
        )

        matches.append(
            KnowledgeMatch(
                title=row["title"],
                content=row["content"],
                category=row["category"],
                source_name=row["source_name"],
                source_url=row["source_url"],
                confidence=final_score,
                freshness=freshness,
            )
        )

    matches.sort(
        key=lambda item: item.confidence,
        reverse=True,
    )

    return matches[:limit]


# ============================================================
# KNOWLEDGE WRITE
# ============================================================

def upsert_knowledge(
    item: KnowledgeItemRequest,
) -> Dict[str, Any]:

    checksum = sha256(
        json.dumps(
            {
                "title": item.title,
                "content": item.content,
                "source": item.source_url,
                "version": item.source_version,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
    )

    conn = db()

    conn.execute(
        """
        INSERT INTO knowledge
        (
            knowledge_key,
            category,
            title,
            content,
            source_url,
            source_name,
            source_version,
            source_checksum,
            region,
            language,
            confidence,
            valid_from,
            valid_until,
            updated_at,
            enabled
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(knowledge_key)
        DO UPDATE SET
            category = excluded.category,
            title = excluded.title,
            content = excluded.content,
            source_url = excluded.source_url,
            source_name = excluded.source_name,
            source_version = excluded.source_version,
            source_checksum = excluded.source_checksum,
            region = excluded.region,
            language = excluded.language,
            confidence = excluded.confidence,
            valid_until = excluded.valid_until,
            updated_at = excluded.updated_at,
            enabled = 1
        """,
        (
            item.knowledge_key,
            item.category,
            item.title,
            item.content,
            item.source_url,
            item.source_name,
            item.source_version,
            checksum,
            item.region,
            normalize_language(
                item.language
            ),
            clamp(
                item.confidence,
                0.0,
                1.0,
            ),
            time.time(),
            item.valid_until,
            time.time(),
        ),
    )

    conn.commit()
    conn.close()

    return {
        "status": "success",
        "knowledge_key": item.knowledge_key,
        "checksum": checksum,
    }


# ============================================================
# BUILT-IN AGRICULTURAL LOGIC
# ============================================================

def assess_data_completeness(
    context: FarmContext,
) -> Dict[str, Any]:

    fields = {
        "location": bool(
            context.latitude is not None
            and context.longitude is not None
        ),
        "crop": bool(context.crop),
        "soil": bool(
            context.soil_type
            or context.soil_ph is not None
            or context.organic_matter is not None
        ),
        "water": bool(
            context.water_source
            or context.irrigation_type
        ),
        "weather": bool(
            context.temperature_c is not None
            or context.rainfall_mm is not None
        ),
        "season": bool(context.season),
        "crop_stage": bool(
            context.crop_stage
        ),
    }

    complete = sum(
        1 for value in fields.values()
        if value
    )

    score = complete / len(fields)

    missing = [
        key
        for key, value in fields.items()
        if not value
    ]

    return {
        "score": round(score, 3),
        "fields": fields,
        "missing": missing,
    }


def basic_soil_flags(
    context: FarmContext,
) -> List[Dict[str, Any]]:

    flags = []

    if context.soil_ph is not None:

        if context.soil_ph < 5.0:
            flags.append(
                {
                    "type": "soil_ph",
                    "status": "low",
                    "value": context.soil_ph,
                    "message": (
                        "Soil pH is strongly acidic "
                        "and crop-specific evaluation "
                        "is required."
                    ),
                }
            )

        elif context.soil_ph > 8.5:
            flags.append(
                {
                    "type": "soil_ph",
                    "status": "high",
                    "value": context.soil_ph,
                    "message": (
                        "Soil pH is strongly alkaline "
                        "and crop-specific evaluation "
                        "is required."
                    ),
                }
            )

    return flags


def basic_water_flags(
    context: FarmContext,
) -> List[Dict[str, Any]]:

    flags = []

    if not context.water_source:
        flags.append(
            {
                "type": "missing_water_data",
                "message": (
                    "Water source is unknown. "
                    "Water quality data may be required."
                ),
            }
        )

    return flags


# ============================================================
# OPENAI REASONING
# ============================================================

def openai_headers() -> Dict[str, str]:

    if not OPENAI_API_KEY:
        raise RuntimeError(
            "OPENAI_API_KEY is not configured."
        )

    return {
        "Authorization": (
            f"Bearer {OPENAI_API_KEY}"
        ),
        "Content-Type": "application/json",
    }


def extract_output_text(
    data: Dict[str, Any],
) -> str:

    if isinstance(
        data.get("output_text"),
        str,
    ):
        return data[
            "output_text"
        ].strip()

    output = data.get(
        "output",
        [],
    )

    parts = []

    if isinstance(output, list):

        for item in output:

            content = item.get(
                "content",
                [],
            )

            if not isinstance(
                content,
                list,
            ):
                continue

            for part in content:

                text = part.get("text")

                if isinstance(
                    text,
                    str,
                ):
                    parts.append(text)

    return "\n".join(
        parts
    ).strip()


def ai_reason(
    system_instruction: str,
    user_input: str,
) -> str:

    if not OPENAI_API_KEY:
        raise RuntimeError(
            "AI provider is not configured."
        )

    payload = {
        "model": AI_MODEL,
        "input": [
            {
                "role": "system",
                "content": [
                    {
                        "type": "input_text",
                        "text": system_instruction,
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": user_input,
                    }
                ],
            },
        ],
    }

    response = requests.post(
        f"{OPENAI_BASE_URL}/responses",
        headers=openai_headers(),
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"AI provider error "
            f"{response.status_code}: "
            f"{response.text[:2000]}"
        )

    data = response.json()

    output = extract_output_text(
        data
    )

    if not output:
        raise RuntimeError(
            "AI provider returned empty output."
        )

    return output


# ============================================================
# SPECIALIZED AGRICULTURAL PROMPTS
# ============================================================

AGRI_SYSTEM = """
You are ARYA AgriDoctor's specialist agricultural reasoning engine.

Your job is agricultural analysis, not generic conversation.

Rules:

1. Separate:
   - observed/input facts
   - sourced facts
   - inference
   - uncertainty

2. Never invent:
   - pesticide doses
   - fertilizer doses
   - legal restrictions
   - product registrations
   - weather observations
   - soil laboratory values
   - disease diagnoses

3. For pesticide or fertilizer recommendations:
   - prefer active ingredient
   - identify crop and target
   - require region and current authoritative source
   - do not fabricate dose or legal approval
   - clearly state when verification is required

4. When evidence is insufficient:
   ask for the missing data or provide
   multiple plausible explanations.

5. Never present an inference as a confirmed diagnosis.

6. Consider:
   - crop
   - cultivar when available
   - growth stage
   - soil
   - water
   - climate
   - season
   - geography
   - recent weather
   - management history
   - pests
   - diseases
   - nutrition
   - irrigation

7. Agricultural recommendations must be
   practical but conservative.

8. For yield estimates:
   provide a range and list assumptions.

9. Use metric units unless the user requests otherwise.

10. Never hide uncertainty.

Return structured JSON whenever requested.
"""


# ============================================================
# GENERAL ANALYSIS
# ============================================================

def analyze_farm(
    request: AnalyzeRequest,
) -> Dict[str, Any]:

    context = request.context

    completeness = (
        assess_data_completeness(
            context
        )
    )

    knowledge = search_knowledge(
        query=request.question,
        region=context.region
        or context.province,
        limit=8,
    )

    knowledge_context = "\n\n".join(
        [
            (
                f"TITLE: {item.title}\n"
                f"CATEGORY: {item.category}\n"
                f"CONTENT: {item.content}\n"
                f"SOURCE: "
                f"{item.source_name or 'unknown'}\n"
                f"URL: "
                f"{item.source_url or 'none'}\n"
                f"CONFIDENCE: "
                f"{item.confidence:.3f}\n"
                f"FRESHNESS: "
                f"{item.freshness:.3f}"
            )
            for item in knowledge
        ]
    )

    user_payload = {
        "language": normalize_language(
            request.language
        ) or "fa",
        "farm_context": (
            context.model_dump()
        ),
        "data_completeness": completeness,
        "soil_flags": (
            basic_soil_flags(context)
        ),
        "water_flags": (
            basic_water_flags(context)
        ),
        "knowledge": knowledge_context,
        "question": request.question,
    }

    output = ai_reason(
        AGRI_SYSTEM
        + """
Answer in the requested language.

Return JSON with:
{
  "summary": "...",
  "facts": [],
  "analysis": [],
  "possible_causes": [],
  "recommendations": [],
  "missing_data": [],
  "risk_flags": [],
  "confidence": 0.0,
  "sources": []
}
""",
        json.dumps(
            user_payload,
            ensure_ascii=False,
            indent=2,
        ),
    )

    try:
        result = json.loads(
            output
        )
    except json.JSONDecodeError:
        result = {
            "summary": output,
            "facts": [],
            "analysis": [],
            "possible_causes": [],
            "recommendations": [],
            "missing_data": [],
            "risk_flags": [],
            "confidence": 0.4,
            "sources": [],
        }

    save_recommendation(
        category="general_analysis",
        crop=context.crop,
        region=context.region
        or context.province,
        request_data=user_payload,
        result=result,
    )

    return {
        "status": "success",
        "data_completeness": completeness,
        "knowledge_matches": len(
            knowledge
        ),
        "result": result,
    }


# ============================================================
# CROP SUITABILITY
# ============================================================

def crop_suitability(
    request: CropSuitabilityRequest,
) -> Dict[str, Any]:

    context = request.context

    knowledge = search_knowledge(
        query=(
            "crop suitability "
            + " ".join(request.crops)
        ),
        region=(
            context.region
            or context.province
        ),
        limit=20,
    )

    payload = {
        "context": context.model_dump(),
        "candidate_crops": request.crops,
        "knowledge": [
            {
                "title": item.title,
                "content": item.content,
                "source": item.source_name,
                "url": item.source_url,
                "confidence": item.confidence,
            }
            for item in knowledge
        ],
    }

    output = ai_reason(
        AGRI_SYSTEM
        + """
Evaluate candidate crops.

For every crop return:
- suitability status
- reasons
- limiting factors
- missing data
- confidence
- evidence sources

Do not rank crops unless the user explicitly
provided a decision criterion.

Do not claim exact yield without reliable
regional evidence.
""",
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ),
    )

    try:
        result = json.loads(
            output
        )
    except json.JSONDecodeError:
        result = {
            "analysis": output
        }

    return {
        "status": "success",
        "result": result,
    }


# ============================================================
# DIAGNOSIS
# ============================================================

def diagnose(
    request: DiagnosisRequest,
) -> Dict[str, Any]:

    context = request.context

    query = (
        " ".join(request.symptoms)
    )

    knowledge = search_knowledge(
        query=query,
        category=None,
        region=(
            context.region
            or context.province
        ),
        limit=15,
    )

    payload = {
        "context": context.model_dump(),
        "symptoms": request.symptoms,
        "knowledge": [
            {
                "title": item.title,
                "content": item.content,
                "source": item.source_name,
                "url": item.source_url,
                "confidence": item.confidence,
            }
            for item in knowledge
        ],
    }

    output = ai_reason(
        AGRI_SYSTEM
        + """
Analyze symptoms.

Return JSON:
{
  "assessment": "...",
  "differential_diagnoses": [
    {
      "condition": "...",
      "evidence_for": [],
      "evidence_against": [],
      "confidence": 0.0
    }
  ],
  "next_observations": [],
  "safe_next_steps": [],
  "urgent_flags": [],
  "sources": []
}

Do not present a differential diagnosis
as a confirmed diagnosis.
""",
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ),
    )

    try:
        result = json.loads(
            output
        )
    except json.JSONDecodeError:
        result = {
            "assessment": output,
            "differential_diagnoses": [],
            "next_observations": [],
            "safe_next_steps": [],
            "urgent_flags": [],
            "sources": [],
        }

    return {
        "status": "success",
        "result": result,
    }


# ============================================================
# RECOMMENDATION ENGINE
# ============================================================

def recommendation(
    request: RecommendationRequest,
) -> Dict[str, Any]:

    context = request.context

    knowledge = search_knowledge(
        query=(
            f"{request.category} "
            f"{request.objective} "
            f"{context.crop or ''}"
        ),
        region=(
            context.region
            or context.province
        ),
        limit=15,
    )

    payload = {
        "category": request.category,
        "objective": request.objective,
        "context": context.model_dump(),
        "knowledge": [
            {
                "title": item.title,
                "content": item.content,
                "source": item.source_name,
                "url": item.source_url,
                "confidence": item.confidence,
            }
            for item in knowledge
        ],
    }

    output = ai_reason(
        AGRI_SYSTEM
        + """
Generate a practical agricultural decision-support
response.

Return:
{
  "summary": "...",
  "recommended_actions": [],
  "alternatives": [],
  "conditions": [],
  "warnings": [],
  "missing_data": [],
  "verification_required": [],
  "confidence": 0.0,
  "sources": []
}

If the requested recommendation involves
regulated pesticides, fertilizers, legal use,
or exact dosage, do not invent values.
State what authoritative information is required.
""",
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ),
    )

    try:
        result = json.loads(
            output
        )
    except json.JSONDecodeError:
        result = {
            "summary": output,
            "recommended_actions": [],
            "alternatives": [],
            "conditions": [],
            "warnings": [],
            "missing_data": [],
            "verification_required": [],
            "confidence": 0.4,
            "sources": [],
        }

    save_recommendation(
        category=request.category,
        crop=context.crop,
        region=(
            context.region
            or context.province
        ),
        request_data=payload,
        result=result,
    )

    return {
        "status": "success",
        "result": result,
    }


# ============================================================
# RECOMMENDATION STORAGE
# ============================================================

def save_recommendation(
    category: str,
    crop: Optional[str],
    region: Optional[str],
    request_data: Dict[str, Any],
    result: Dict[str, Any],
) -> None:

    request_hash = sha256(
        json.dumps(
            request_data,
            sort_keys=True,
            ensure_ascii=False,
        )
    )

    recommendation_id = make_id(
        "rec"
    )

    confidence = safe_float(
        result.get("confidence"),
        0.0,
    ) or 0.0

    sources = result.get(
        "sources",
        [],
    )

    if not isinstance(
        sources,
        list,
    ):
        sources = []

    conn = db()

    conn.execute(
        """
        INSERT INTO recommendations
        (
            recommendation_id,
            request_hash,
            category,
            crop,
            region,
            result_json,
            confidence,
            source_count,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            recommendation_id,
            request_hash,
            category,
            crop,
            region,
            json.dumps(
                result,
                ensure_ascii=False,
            ),
            clamp(
                confidence,
                0.0,
                1.0,
            ),
            len(sources),
            time.time(),
        ),
    )

    conn.commit()
    conn.close()


# ============================================================
# EXTERNAL SOURCE FETCH
# ============================================================

def fetch_external_source(
    url: str,
) -> Dict[str, Any]:

    validate_external_url(url)

    response = requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent":
                "ARYA-AgriDoctor/"
                + APP_VERSION,
        },
        allow_redirects=False,
        stream=True,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"Source returned HTTP "
            f"{response.status_code}"
        )

    content_length = safe_float(
        response.headers.get(
            "content-length"
        ),
        0,
    ) or 0

    if (
        content_length
        > MAX_SOURCE_SIZE_MB
        * 1024
        * 1024
    ):
        raise RuntimeError(
            "External source is too large."
        )

    chunks = []
    total = 0

    for chunk in response.iter_content(
        chunk_size=64 * 1024
    ):

        if not chunk:
            continue

        total += len(chunk)

        if (
            total
            > MAX_SOURCE_SIZE_MB
            * 1024
            * 1024
        ):
            raise RuntimeError(
                "External source exceeded size limit."
            )

        chunks.append(chunk)

    raw = b"".join(chunks)

    content_type = (
        response.headers.get(
            "content-type",
            "",
        )
    )

    try:
        text = raw.decode(
            response.encoding
            or "utf-8",
            errors="replace",
        )
    except Exception:
        text = ""

    parsed_json = None

    if "json" in content_type.lower():
        try:
            parsed_json = json.loads(
                text
            )
        except Exception:
            parsed_json = None

    return {
        "url": url,
        "status_code": response.status_code,
        "content_type": content_type,
        "text": text,
        "json": parsed_json,
        "checksum": hashlib.sha256(
            raw
        ).hexdigest(),
        "retrieved_at": utc_now_iso(),
    }


# ============================================================
# UPDATE SYSTEM
# ============================================================

def create_update_run(
    provider_key: Optional[str],
) -> str:

    run_id = make_id("upd")

    conn = db()

    conn.execute(
        """
        INSERT INTO update_runs
        (
            run_id,
            provider_key,
            status,
            started_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            run_id,
            provider_key,
            "running",
            time.time(),
        ),
    )

    conn.commit()
    conn.close()

    return run_id


def finish_update_run(
    run_id: str,
    status: str,
    received: int = 0,
    updated: int = 0,
    error: Optional[str] = None,
) -> None:

    conn = db()

    conn.execute(
        """
        UPDATE update_runs
        SET
            status = ?,
            items_received = ?,
            items_updated = ?,
            error = ?,
            finished_at = ?
        WHERE run_id = ?
        """,
        (
            status,
            received,
            updated,
            error,
            time.time(),
            run_id,
        ),
    )

    conn.commit()
    conn.close()


# ============================================================
# API ROUTES
# ============================================================

@app.get("/")
def root() -> Dict[str, Any]:

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "ready",
        "main_py_modified": False,
        "vision_py_modified": False,
        "voice_language_modified": False,
        "auto_update": AUTO_UPDATE,
        "external_sources": (
            ALLOW_EXTERNAL_SOURCES
        ),
    }


@app.get("/health")
def health() -> Dict[str, Any]:

    conn = db()

    knowledge_count = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM knowledge
        WHERE enabled = 1
        """
    ).fetchone()["count"]

    provider_count = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM providers
        WHERE enabled = 1
        """
    ).fetchone()["count"]

    conn.close()

    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "knowledge_items": knowledge_count,
        "enabled_providers": provider_count,
        "ai_configured": bool(
            OPENAI_API_KEY
        ),
        "auto_update": AUTO_UPDATE,
    }


@app.post("/agri/analyze")
def analyze(
    request: AnalyzeRequest,
) -> Dict[str, Any]:

    try:
        return analyze_farm(
            request
        )
    except HTTPException:
        raise
    except Exception as exc:

        logger.exception(
            "Agricultural analysis failed."
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Agricultural analysis failed."
            ),
        ) from exc


@app.post("/agri/crop-suitability")
def crop_suitability_route(
    request: CropSuitabilityRequest,
) -> Dict[str, Any]:

    try:
        return crop_suitability(
            request
        )
    except Exception as exc:

        logger.exception(
            "Crop suitability failed."
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Crop suitability analysis failed."
            ),
        ) from exc


@app.post("/agri/diagnose")
def diagnosis_route(
    request: DiagnosisRequest,
) -> Dict[str, Any]:

    try:
        return diagnose(
            request
        )
    except Exception as exc:

        logger.exception(
            "Diagnosis failed."
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Agricultural diagnosis failed."
            ),
        ) from exc


@app.post("/agri/recommend")
def recommendation_route(
    request: RecommendationRequest,
) -> Dict[str, Any]:

    try:
        return recommendation(
            request
        )
    except Exception as exc:

        logger.exception(
            "Recommendation failed."
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Agricultural recommendation failed."
            ),
        ) from exc


@app.post("/agri/knowledge")
def add_knowledge(
    request: KnowledgeItemRequest,
) -> Dict[str, Any]:

    if request.source_url:
        validate_external_url(
            request.source_url
        )

    return upsert_knowledge(
        request
    )


@app.get("/agri/knowledge/search")
def knowledge_search(
    q: str,
    category: Optional[str] = None,
    region: Optional[str] = None,
    limit: int = 10,
) -> Dict[str, Any]:

    limit = max(
        1,
        min(limit, 50),
    )

    results = search_knowledge(
        query=q,
        category=category,
        region=region,
        limit=limit,
    )

    return {
        "query": q,
        "count": len(results),
        "results": [
            {
                "title": item.title,
                "content": item.content,
                "category": item.category,
                "source_name": item.source_name,
                "source_url": item.source_url,
                "confidence": item.confidence,
                "freshness": item.freshness,
            }
            for item in results
        ],
    }


@app.post("/agri/providers")
def register_provider(
    request: ProviderRequest,
) -> Dict[str, Any]:

    if not re.match(
        r"^[A-Za-z0-9_.-]{2,80}$",
        request.provider_key,
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid provider key.",
        )

    conn = db()

    conn.execute(
        """
        INSERT INTO providers
        (
            provider_key,
            provider_type,
            endpoint,
            enabled,
            priority,
            config_json,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(provider_key)
        DO UPDATE SET
            provider_type = excluded.provider_type,
            endpoint = excluded.endpoint,
            enabled = excluded.enabled,
            priority = excluded.priority,
            config_json = excluded.config_json,
            updated_at = excluded.updated_at
        """,
        (
            request.provider_key,
            request.provider_type,
            request.endpoint,
            int(request.enabled),
            request.priority,
            json.dumps(
                request.config,
                ensure_ascii=False,
            ),
            time.time(),
            time.time(),
        ),
    )

    conn.commit()
    conn.close()

    return {
        "status": "success",
        "provider_key": request.provider_key,
    }


@app.get("/agri/providers")
def providers() -> Dict[str, Any]:

    conn = db()

    rows = conn.execute(
        """
        SELECT
            provider_key,
            provider_type,
            endpoint,
            enabled,
            priority,
            last_success_at,
            last_error_at,
            last_error
        FROM providers
        ORDER BY priority ASC, id ASC
        """
    ).fetchall()

    conn.close()

    return {
        "providers": [
            dict(row)
            for row in rows
        ]
    }


@app.post("/agri/source/fetch")
def source_fetch(
    request: SourceFetchRequest,
) -> Dict[str, Any]:

    try:
        result = fetch_external_source(
            request.url
        )

        return {
            "status": "success",
            "source_name": (
                request.source_name
            ),
            "result": result,
        }

    except HTTPException:
        raise

    except Exception as exc:

        logger.exception(
            "External source fetch failed."
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "External source could not "
                "be retrieved."
            ),
        ) from exc


@app.get("/agri/updates/status")
def updates_status() -> Dict[str, Any]:

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM update_runs
        ORDER BY started_at DESC
        LIMIT 20
        """
    ).fetchall()

    conn.close()

    return {
        "runs": [
            dict(row)
            for row in rows
        ]
    }


@app.get("/agri/recommendations")
def recommendation_history(
    limit: int = 20,
) -> Dict[str, Any]:

    limit = max(
        1,
        min(limit, 100),
    )

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM recommendations
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    conn.close()

    return {
        "count": len(rows),
        "items": [
            {
                "recommendation_id":
                    row["recommendation_id"],
                "category":
                    row["category"],
                "crop":
                    row["crop"],
                "region":
                    row["region"],
                "confidence":
                    row["confidence"],
                "source_count":
                    row["source_count"],
                "created_at":
                    row["created_at"],
            }
            for row in rows
        ],
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup() -> None:

    init_db()

    logger.info(
        "%s v%s started.",
        APP_NAME,
        APP_VERSION,
    )


# ============================================================
# LOCAL EXECUTION
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "agri_engine:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
