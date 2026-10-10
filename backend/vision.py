"""
================================================================
                         ARYA VISION
                    ARYA AgriDoctor
                         Version 2.1.0
================================================================

Independent agricultural vision service.

Features:
- Multiple image uploads
- Image format, size and quality validation
- EXIF orientation correction and image normalization
- Plant, disease, pest, nutrient and environmental stress analysis
- Differential diagnosis and uncertainty reporting
- Replaceable AI providers
- Provider health checks
- Versioned agricultural knowledge sources
- Source timestamps, checksums and expiration handling
- Owner-registered external knowledge sources
- Scheduled knowledge refresh
- SQLite persistence
- No dependency on backend/main.py

IMPORTANT:
- AI output is advisory, not a guaranteed diagnosis.
- Unsupported certainty and invented treatment dosages are prohibited.
- External URLs are validated before requests.
- This module does not itself verify pesticide registrations.
================================================================
"""

from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import logging
import math
import os
import re
import socket
import sqlite3
import threading
import time
import uuid

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import requests

from fastapi import (
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    UploadFile,
)

from fastapi.middleware.cors import CORSMiddleware

from PIL import (
    Image,
    ImageOps,
    UnidentifiedImageError,
)

from pydantic import BaseModel, Field, ConfigDict


# ================================================================
# LOGGING
# ================================================================

logging.basicConfig(
    level=os.getenv("ARYA_VISION_LOG_LEVEL", "INFO").upper(),
)

logger = logging.getLogger("arya.vision")


# ================================================================
# CONFIGURATION
# ================================================================

APP_NAME = "ARYA Vision"
VERSION = "2.1.0"

HOST = os.getenv(
    "ARYA_VISION_HOST",
    "0.0.0.0",
).strip()

def bounded_int(
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name, str(default))

    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid integer setting %s; using default.",
            name,
        )
        return default

    if not minimum <= value <= maximum:
        logger.warning(
            "Out-of-range setting %s; using default.",
            name,
        )
        return default

    return value


def bounded_float(
    name: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    raw = os.getenv(name, str(default))

    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid numeric setting %s; using default.",
            name,
        )
        return default

    if not math.isfinite(value) or not minimum <= value <= maximum:
        logger.warning(
            "Out-of-range setting %s; using default.",
            name,
        )
        return default

    return value


def env_bool(
    name: str,
    default: bool,
) -> bool:
    raw = os.getenv(name)

    if raw is None:
        return default

    value = raw.strip().lower()

    if value in {"1", "true", "yes", "on"}:
        return True

    if value in {"0", "false", "no", "off"}:
        return False

    logger.warning(
        "Invalid boolean setting %s; using default.",
        name,
    )

    return default


PORT = bounded_int(
    "ARYA_VISION_PORT",
    8001,
    1,
    65535,
)

MEDIA_DIR = Path(
    os.getenv(
        "ARYA_VISION_MEDIA_DIR",
        "./vision_media",
    )
).expanduser()

DB_PATH = Path(
    os.getenv(
        "ARYA_VISION_DB",
        "./vision.db",
    )
).expanduser()

MAX_UPLOAD_MB = bounded_int(
    "ARYA_VISION_MAX_UPLOAD_MB",
    12,
    1,
    100,
)

MAX_IMAGES_PER_REQUEST = bounded_int(
    "ARYA_VISION_MAX_IMAGES",
    4,
    1,
    12,
)

REQUEST_TIMEOUT = bounded_int(
    "ARYA_VISION_TIMEOUT",
    120,
    5,
    300,
)

MAX_PROVIDER_TIMEOUT = bounded_int(
    "ARYA_VISION_PROVIDER_TIMEOUT",
    60,
    3,
    120,
)

MAX_IMAGE_PIXELS = bounded_int(
    "ARYA_VISION_MAX_PIXELS",
    25_000_000,
    100_000,
    100_000_000,
)

VISION_PROVIDER = os.getenv(
    "ARYA_VISION_PROVIDER",
    "openai",
).strip().lower()

VISION_MODEL = os.getenv(
    "ARYA_VISION_MODEL",
    "gpt-5.6-luna",
).strip()

OPENAI_API_KEY = os.getenv(
    "OPENAI_API_KEY",
    "",
).strip()

OPENAI_RESPONSES_URL = os.getenv(
    "ARYA_VISION_OPENAI_URL",
    "https://api.openai.com/v1/responses",
).strip()

AUTO_UPDATE_ENABLED = env_bool(
    "ARYA_VISION_AUTO_UPDATE",
    True,
)

UPDATE_INTERVAL_SECONDS = bounded_int(
    "ARYA_VISION_UPDATE_INTERVAL",
    21600,
    60,
    31_536_000,
)

ALLOW_EXTERNAL_PROVIDERS = env_bool(
    "ARYA_VISION_ALLOW_EXTERNAL_PROVIDERS",
    False,
)

ALLOW_PRIVATE_PROVIDER_NETWORKS = env_bool(
    "ARYA_VISION_ALLOW_PRIVATE_PROVIDER_NETWORKS",
    False,
)

ADMIN_API_KEY = os.getenv(
    "ARYA_VISION_ADMIN_API_KEY",
    "",
).strip()

VISION_API_KEY = os.getenv(
    "ARYA_VISION_API_KEY",
    "",
).strip()

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ARYA_VISION_CORS",
        "",
    ).split(",")
    if origin.strip()
]

ALLOWED_IMAGE_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
}

ALLOWED_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
}

MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


# ================================================================
# APP
# ================================================================

app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    description=(
        "Independent agricultural computer vision, "
        "diagnosis support and versioned knowledge service."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-ARYA-Vision-Key",
        "X-ARYA-Admin-Key",
    ],
)


# ================================================================
# TIME AND IDENTIFIERS
# ================================================================

def utc_now() -> str:
    return datetime.now(
        timezone.utc,
    ).replace(
        microsecond=0,
    ).isoformat()


def unix_now() -> int:
    return int(time.time())


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def make_request_id() -> str:
    return new_id("VIS").upper()


# ================================================================
# JSON HELPERS
# ================================================================

def json_dumps(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def json_loads(
    value: Any,
    default: Any = None,
) -> Any:
    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return value

    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ================================================================
# AUTHENTICATION
# ================================================================

def require_client_key(
    x_arya_vision_key: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Vision-Key",
    ),
) -> None:
    if not VISION_API_KEY:
        # Health and analysis remain available only if deployment
        # explicitly configures a key or accepts the deployment risk.
        if env_bool(
            "ARYA_VISION_ALLOW_UNAUTHENTICATED",
            False,
        ):
            return

        raise HTTPException(
            status_code=503,
            detail="Vision API authentication is not configured.",
        )

    import hmac

    if not x_arya_vision_key or not hmac.compare_digest(
        x_arya_vision_key,
        VISION_API_KEY,
    ):
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )


def require_admin(
    x_arya_admin_key: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Admin-Key",
    ),
) -> None:
    import hmac

    if not ADMIN_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Vision administration is not configured.",
        )

    if not x_arya_admin_key or not hmac.compare_digest(
        x_arya_admin_key,
        ADMIN_API_KEY,
    ):
        raise HTTPException(
            status_code=401,
            detail="Administrator authentication required.",
        )


# ================================================================
# STORAGE INITIALIZATION
# ================================================================

def initialize_storage() -> None:
    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    MEDIA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


initialize_storage()


# ================================================================
# DATABASE
# ================================================================

def db() -> sqlite3.Connection:
    connection = sqlite3.connect(
        str(DB_PATH),
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys=ON",
    )

    connection.execute(
        "PRAGMA busy_timeout=30000",
    )

    return connection


def init_db() -> None:
    connection = db()

    try:
        connection.execute(
            "PRAGMA journal_mode=WAL",
        )

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                base_url TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                timeout_seconds INTEGER NOT NULL DEFAULT 60,
                config_json TEXT NOT NULL DEFAULT '{}',
                last_health TEXT,
                last_health_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                source_type TEXT NOT NULL,
                url TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                update_interval_seconds INTEGER NOT NULL DEFAULT 21600,
                last_update_at TEXT,
                last_success_at TEXT,
                last_error TEXT,
                version TEXT,
                checksum TEXT,
                item_count INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_key TEXT NOT NULL,
                item_key TEXT NOT NULL,
                title TEXT,
                category TEXT,
                content_json TEXT NOT NULL,
                version TEXT,
                checksum TEXT,
                source_url TEXT,
                observed_at TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(source_key, item_key),
                FOREIGN KEY(source_key)
                    REFERENCES knowledge_sources(source_key)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_knowledge_category
                ON knowledge_items(category);

            CREATE INDEX IF NOT EXISTS idx_knowledge_expiry
                ON knowledge_items(expires_at);

            CREATE INDEX IF NOT EXISTS idx_knowledge_source
                ON knowledge_items(source_key);

            CREATE TABLE IF NOT EXISTS vision_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT UNIQUE NOT NULL,
                provider_key TEXT,
                model TEXT,
                image_count INTEGER NOT NULL,
                input_hashes_json TEXT NOT NULL,
                context_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS update_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_key TEXT NOT NULL,
                status TEXT NOT NULL,
                version TEXT,
                checksum TEXT,
                item_count INTEGER NOT NULL DEFAULT 0,
                message TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL
            );
            """
        )

        connection.commit()

    finally:
        connection.close()


init_db()


# ================================================================
# URL VALIDATION
# ================================================================

def validate_external_url(url: str) -> str:
    if not ALLOW_EXTERNAL_PROVIDERS:
        raise ValueError(
            "External providers are disabled by configuration."
        )

    if not url or len(url) > 2048:
        raise ValueError("Invalid external URL.")

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() != "https":
            raise ValueError(
                "External provider URLs must use HTTPS."
            )

        if not parsed.hostname:
            raise ValueError("URL hostname is missing.")

        if parsed.username or parsed.password:
            raise ValueError(
                "Credentials in provider URLs are prohibited."
            )

        if parsed.fragment:
            raise ValueError(
                "URL fragments are not permitted."
            )

        host = parsed.hostname.lower()

        if host in {"localhost", "localhost.localdomain"}:
            raise ValueError(
                "Loopback destinations are prohibited."
            )

        try:
            ip = ipaddress.ip_address(host)

            if not ALLOW_PRIVATE_PROVIDER_NETWORKS and (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise ValueError(
                    "Private or non-public IP destinations are prohibited."
                )

        except ValueError as exc:
            # Distinguish a valid domain from a rejected IP address.
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise exc

        else:
            pass

        # Reject literal IP destinations unless the administrator
        # explicitly permits private provider networks.
        if not ALLOW_PRIVATE_PROVIDER_NETWORKS:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise ValueError(
                    "IP-literal provider URLs are disabled."
                )

        return url

    except ValueError:
        raise

    except Exception as exc:
        raise ValueError("Invalid provider URL.") from exc


# ================================================================
# IMAGE NORMALIZATION
# ================================================================

def normalize_image(
    raw: bytes,
) -> Dict[str, Any]:
    if not raw:
        raise ValueError("The uploaded image is empty.")

    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"Image exceeds the {MAX_UPLOAD_MB} MB limit."
        )

    try:
        with Image.open(
            io.BytesIO(raw),
        ) as image:
            detected_format = (
                image.format or ""
            ).upper()

            if detected_format not in {
                "JPEG",
                "PNG",
                "WEBP",
            }:
                raise ValueError(
                    "Unsupported image format."
                )

            image.verify()

        with Image.open(
            io.BytesIO(raw),
        ) as image:
            image = ImageOps.exif_transpose(image)

            if image.width <= 0 or image.height <= 0:
                raise ValueError(
                    "Invalid image dimensions."
                )

            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise ValueError(
                    "Image pixel count exceeds the configured limit."
                )

            image.load()

            image = image.convert("RGB")

            # Resize extremely large images while preserving aspect ratio.
            max_side = 2048

            if max(image.size) > max_side:
                image.thumbnail(
                    (max_side, max_side),
                    Image.Resampling.LANCZOS,
                )

            output = io.BytesIO()

            image.save(
                output,
                format="JPEG",
                quality=88,
                optimize=True,
            )

            normalized = output.getvalue()

            if not normalized:
                raise ValueError(
                    "Image normalization failed."
                )

            return {
                "bytes": normalized,
                "width": image.width,
                "height": image.height,
                "format": "JPEG",
                "sha256": sha256_bytes(normalized),
                "original_sha256": sha256_bytes(raw),
            }

    except (
        UnidentifiedImageError,
        OSError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as exc:
        raise ValueError(
            "The file is not a valid or safely readable image."
        ) from exc


def image_quality(
    image_data: Dict[str, Any],
) -> Dict[str, Any]:
    width = int(image_data["width"])
    height = int(image_data["height"])

    warnings: List[str] = []

    if min(width, height) < 256:
        warnings.append(
            "Image resolution may be insufficient for reliable diagnosis."
        )

    if min(width, height) < 96:
        score = 0.2
    elif min(width, height) < 256:
        score = 0.5
    else:
        score = 0.8

    return {
        "width": width,
        "height": height,
        "estimated_quality": score,
        "warnings": warnings,
    }


# ================================================================
# IMAGE DATA URL
# ================================================================

def image_data_url(
    image_bytes: bytes,
) -> str:
    encoded = base64.b64encode(
        image_bytes,
    ).decode("ascii")

    return "data:image/jpeg;base64," + encoded


# ================================================================
# PROVIDER BASE CLASS
# ================================================================

class VisionProvider:
    key = "base"

    def analyze(
        self,
        images: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        raise NotImplementedError

    def health(self) -> Dict[str, Any]:
        return {
            "provider": self.key,
            "status": "unknown",
            "checked_at": utc_now(),
        }


# ================================================================
# OPENAI PROVIDER
# ================================================================

class OpenAIVisionProvider(VisionProvider):
    key = "openai"

    def __init__(self) -> None:
        self.api_key = OPENAI_API_KEY
        self.model = VISION_MODEL
        self.endpoint = OPENAI_RESPONSES_URL

    def _validate_endpoint(self) -> None:
        parsed = urlsplit(self.endpoint)

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise RuntimeError(
                "The configured AI endpoint is invalid."
            )

    def health(self) -> Dict[str, Any]:
        return {
            "provider": self.key,
            "status": (
                "configured"
                if self.api_key and self.model and self.endpoint
                else "missing_configuration"
            ),
            "model": self.model,
            "checked_at": utc_now(),
            "note": "Configuration check only; no live API request was made.",
        }

    def analyze(
        self,
        images: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not self.api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not configured."
            )

        if not self.model:
            raise RuntimeError(
                "ARYA_VISION_MODEL is not configured."
            )

        self._validate_endpoint()

        system_prompt = """
You are ARYA AgriDoctor Vision, an agricultural image-analysis assistant.

Analyze only what can reasonably be inferred from the provided images
and user context.

Requirements:
- Identify the plant only when visual evidence supports it.
- Evaluate possible disease, pest, nutrient deficiency, water stress,
  heat stress, cold injury, physical damage, and other plausible causes.
- Give a differential diagnosis rather than pretending certainty.
- Distinguish visible observations from hypotheses.
- State limitations and missing information.
- Never invent laboratory results, field measurements, sources,
  product registrations, or pesticide/fertilizer dosages.
- Do not prescribe a chemical treatment when identification is uncertain.
- If evidence is insufficient, say so and request specific additional
  photographs, laboratory tests, or field observations.
- Recommend low-risk observation and management steps where appropriate.
- Any confidence value must represent a cautious qualitative estimate,
  not a scientifically calibrated probability.
- Return a valid JSON object only.

Required JSON shape:
{
  "plant_identification": {
    "name": null,
    "scientific_name": null,
    "confidence": "low"
  },
  "observations": [],
  "possible_causes": [
    {
      "name": "",
      "category": "disease|pest|nutrient|water|temperature|other",
      "confidence": "low|medium|high",
      "supporting_evidence": [],
      "contradicting_evidence": [],
      "additional_checks": []
    }
  ],
  "severity": {
    "level": "unknown",
    "basis": ""
  },
  "recommended_next_steps": [],
  "chemical_treatment": {
    "recommended": false,
    "reason": ""
  },
  "missing_information": [],
  "limitations": [],
  "diagnosis_status": "preliminary|insufficient_evidence",
  "summary": ""
}
""".strip()

        user_content: List[Dict[str, Any]] = [
            {
                "type": "input_text",
                "text": (
                    "Agricultural context:\n"
                    + json_dumps(context)
                    + "\nAnalyze the attached images according to "
                    "the required JSON schema."
                ),
            }
        ]

        for item in images:
            user_content.append(
                {
                    "type": "input_image",
                    "image_url": image_data_url(
                        item["bytes"],
                    ),
                    "detail": "high",
                }
            )

        payload = {
            "model": self.model,
            "instructions": system_prompt,
            "input": [
                {
                    "role": "user",
                    "content": user_content,
                }
            ],
        }

        timeout = min(
            REQUEST_TIMEOUT,
            MAX_PROVIDER_TIMEOUT,
        )

        response = requests.post(
            self.endpoint,
            headers={
                "Authorization": "Bearer " + self.api_key,
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=(
                min(10, timeout),
                timeout,
            ),
            allow_redirects=False,
        )

        if response.status_code >= 300:
            logger.warning(
                "Vision provider returned HTTP %s.",
                response.status_code,
            )

            raise RuntimeError(
                "The configured vision provider returned an error."
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise RuntimeError(
                "The vision provider returned invalid JSON."
            ) from exc

        text_output = body.get(
            "output_text",
        )

        if not text_output:
            output_items = body.get(
                "output",
                [],
            )

            collected: List[str] = []

            for output_item in output_items:
                for content_item in output_item.get(
                    "content",
                    [],
                ):
                    if content_item.get("type") == "output_text":
                        collected.append(
                            content_item.get("text", "")
                        )

            text_output = "\n".join(collected)

        if not isinstance(text_output, str) or not text_output.strip():
            raise RuntimeError(
                "The vision provider returned no analysis text."
            )

        try:
            result = json.loads(text_output)
        except ValueError:
            logger.warning(
                "Vision provider response was not valid JSON."
            )

            return {
                "diagnosis_status": "insufficient_evidence",
                "summary": text_output[:12000],
                "observations": [],
                "possible_causes": [],
                "recommended_next_steps": [
                    "Request a structured re-analysis before acting."
                ],
                "limitations": [
                    "The provider response did not match the required JSON format."
                ],
                "chemical_treatment": {
                    "recommended": False,
                    "reason": "No validated structured diagnosis was produced.",
                },
            }

        if not isinstance(result, dict):
            raise RuntimeError(
                "The vision provider returned an invalid result structure."
            )

        return result


# ================================================================
# PROVIDER REGISTRY
# ================================================================

_PROVIDER_REGISTRY: Dict[str, VisionProvider] = {}
_PROVIDER_LOCK = threading.RLock()


def register_provider(
    provider: VisionProvider,
    *,
    replace: bool = False,
) -> None:
    key = provider.key.strip().lower()

    if not key:
        raise ValueError(
            "Provider key cannot be empty."
        )

    with _PROVIDER_LOCK:
        if key in _PROVIDER_REGISTRY and not replace:
            raise ValueError(
                "Provider already registered."
            )

        _PROVIDER_REGISTRY[key] = provider


def get_provider(
    key: Optional[str] = None,
) -> VisionProvider:
    provider_key = (
        key or VISION_PROVIDER
    ).strip().lower()

    with _PROVIDER_LOCK:
        provider = _PROVIDER_REGISTRY.get(
            provider_key,
        )

    if provider is None:
        raise HTTPException(
            status_code=503,
            detail="Requested vision provider is not registered.",
        )

    return provider


register_provider(
    OpenAIVisionProvider(),
)


# ================================================================
# RESULT NORMALIZATION
# ================================================================

ALLOWED_CONFIDENCE = {
    "low",
    "medium",
    "high",
    "unknown",
}

ALLOWED_SEVERITY = {
    "unknown",
    "low",
    "mild",
    "moderate",
    "high",
    "severe",
}


def normalize_analysis_result(
    result: Dict[str, Any],
) -> Dict[str, Any]:
    normalized = dict(result)

    causes = normalized.get(
        "possible_causes",
        [],
    )

    if not isinstance(causes, list):
        causes = []

    cleaned_causes: List[Dict[str, Any]] = []

    for cause in causes[:20]:
        if not isinstance(cause, dict):
            continue

        confidence = str(
            cause.get(
                "confidence",
                "unknown",
            )
        ).lower()

        if confidence not in ALLOWED_CONFIDENCE:
            confidence = "unknown"

        cleaned_causes.append(
            {
                "name": str(
                    cause.get("name", "")
                )[:300],

                "category": str(
                    cause.get("category", "other")
                )[:80],

                "confidence": confidence,

                "supporting_evidence": (
                    cause.get("supporting_evidence", [])
                    if isinstance(
                        cause.get("supporting_evidence", []),
                        list,
                    )
                    else []
                )[:20],

                "contradicting_evidence": (
                    cause.get("contradicting_evidence", [])
                    if isinstance(
                        cause.get("contradicting_evidence", []),
                        list,
                    )
                    else []
                )[:20],

                "additional_checks": (
                    cause.get("additional_checks", [])
                    if isinstance(
                        cause.get("additional_checks", []),
                        list,
                    )
                    else []
                )[:20],
            }
        )

    plant = normalized.get(
        "plant_identification",
        {},
    )

    if not isinstance(plant, dict):
        plant = {}

    plant_confidence = str(
        plant.get("confidence", "unknown")
    ).lower()

    if plant_confidence not in ALLOWED_CONFIDENCE:
        plant_confidence = "unknown"

    severity = normalized.get(
        "severity",
        {},
    )

    if not isinstance(severity, dict):
        severity = {}

    severity_level = str(
        severity.get("level", "unknown")
    ).lower()

    if severity_level not in ALLOWED_SEVERITY:
        severity_level = "unknown"

    next_steps = normalized.get(
        "recommended_next_steps",
        [],
    )

    if not isinstance(next_steps, list):
        next_steps = []

    missing = normalized.get(
        "missing_information",
        [],
    )

    if not isinstance(missing, list):
        missing = []

    limitations = normalized.get(
        "limitations",
        [],
    )

    if not isinstance(limitations, list):
        limitations = []

    chemical = normalized.get(
        "chemical_treatment",
        {},
    )

    if not isinstance(chemical, dict):
        chemical = {}

    status = str(
        normalized.get(
            "diagnosis_status",
            "insufficient_evidence",
        )
    ).lower()

    if status not in {
        "preliminary",
        "insufficient_evidence",
    }:
        status = "preliminary"

    return {
        "plant_identification": {
            "name": plant.get("name"),
            "scientific_name": plant.get("scientific_name"),
            "confidence": plant_confidence,
        },

        "observations": (
            normalized.get("observations", [])
            if isinstance(
                normalized.get("observations", []),
                list,
            )
            else []
        )[:50],

        "possible_causes": cleaned_causes,

        "severity": {
            "level": severity_level,
            "basis": str(
                severity.get("basis", "")
            )[:2000],
        },

        "recommended_next_steps": [
            str(item)[:2000]
            for item in next_steps[:30]
        ],

        "chemical_treatment": {
            "recommended": False,
            "reason": str(
                chemical.get(
                    "reason",
                    "Chemical treatments require verified diagnosis and local label compliance.",
                )
            )[:2000],
        },

        "missing_information": [
            str(item)[:1000]
            for item in missing[:30]
        ],

        "limitations": [
            str(item)[:1000]
            for item in limitations[:30]
        ],

        "diagnosis_status": status,

        "summary": str(
            normalized.get("summary", "")
        )[:10000],

        "advisory": (
            "This is preliminary decision support, not a confirmed "
            "field diagnosis. Verify uncertain cases with suitable "
            "field observations, laboratory tests or a qualified "
            "agricultural specialist."
        ),
    }


# ================================================================
# ANALYSIS PERSISTENCE
# ================================================================

def save_analysis(
    *,
    rid: str,
    provider_key: str,
    model: str,
    images: List[Dict[str, Any]],
    context: Dict[str, Any],
    result: Dict[str, Any],
) -> None:
    connection = db()

    try:
        connection.execute(
            """
            INSERT INTO vision_analyses (
                request_id,
                provider_key,
                model,
                image_count,
                input_hashes_json,
                context_json,
                result_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid,
                provider_key,
                model,
                len(images),
                json_dumps([
                    item["sha256"]
                    for item in images
                ]),
                json_dumps(context),
                json_dumps(result),
                utc_now(),
            ),
        )

        connection.commit()

    finally:
        connection.close()


# ================================================================
# KNOWLEDGE SOURCE MODELS
# ================================================================

class KnowledgeSourceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_key: str = Field(
        min_length=2,
        max_length=100,
        pattern=r"^[a-zA-Z0-9_.-]+$",
    )

    name: str = Field(
        min_length=2,
        max_length=200,
    )

    source_type: str = Field(
        default="json",
        min_length=2,
        max_length=40,
    )

    url: str = Field(
        min_length=8,
        max_length=2048,
    )

    enabled: bool = True

    update_interval_seconds: int = Field(
        default=21600,
        ge=60,
        le=31_536_000,
    )

    version: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
    )


class KnowledgeItemInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_key: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_.:-]+$",
    )

    title: str = Field(
        min_length=1,
        max_length=500,
    )

    category: str = Field(
        min_length=1,
        max_length=100,
    )

    content: Dict[str, Any]

    version: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    source_url: Optional[str] = Field(
        default=None,
        max_length=2048,
    )

    observed_at: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    ttl_seconds: int = Field(
        default=86_400,
        ge=60,
        le=31_536_000,
    )


# ================================================================
# KNOWLEDGE SOURCE MANAGEMENT
# ================================================================

def register_knowledge_source(
    data: KnowledgeSourceInput,
) -> Dict[str, Any]:
    if data.source_type.lower() not in {
        "json",
    }:
        raise ValueError(
            "Only JSON knowledge sources are currently supported."
        )

    url = validate_external_url(
        data.url,
    )

    now = utc_now()

    connection = db()

    try:
        connection.execute(
            """
            INSERT INTO knowledge_sources (
                source_key,
                name,
                source_type,
                url,
                enabled,
                update_interval_seconds,
                version,
                metadata_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_key) DO UPDATE SET
                name = excluded.name,
                source_type = excluded.source_type,
                url = excluded.url,
                enabled = excluded.enabled,
                update_interval_seconds =
                    excluded.update_interval_seconds,
                version = excluded.version,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            """,
            (
                data.source_key,
                data.name,
                data.source_type.lower(),
                url,
                int(data.enabled),
                data.update_interval_seconds,
                data.version,
                json_dumps(data.metadata),
                now,
                now,
            ),
        )

        connection.commit()

        return {
            "source_key": data.source_key,
            "registered": True,
            "enabled": data.enabled,
            "updated_at": now,
        }

    finally:
        connection.close()


def add_knowledge_item(
    source_key: str,
    item: KnowledgeItemInput,
) -> Dict[str, Any]:
    connection = db()

    now = utc_now()

    expires = (
        datetime.now(timezone.utc)
        + timedelta(seconds=item.ttl_seconds)
    ).replace(
        microsecond=0,
    ).isoformat()

    content_json = json_dumps(
        item.content,
    )

    checksum = sha256_bytes(
        content_json.encode("utf-8"),
    )

    try:
        source = connection.execute(
            """
            SELECT source_key
            FROM knowledge_sources
            WHERE source_key = ?
            """,
            (source_key,),
        ).fetchone()

        if not source:
            raise HTTPException(
                status_code=404,
                detail="Knowledge source not found.",
            )

        source_url = item.source_url

        if source_url:
            source_url = validate_external_url(
                source_url,
            )

        connection.execute(
            """
            INSERT INTO knowledge_items (
                source_key,
                item_key,
                title,
                category,
                content_json,
                version,
                checksum,
                source_url,
                observed_at,
                expires_at,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_key, item_key) DO UPDATE SET
                title = excluded.title,
                category = excluded.category,
                content_json = excluded.content_json,
                version = excluded.version,
                checksum = excluded.checksum,
                source_url = excluded.source_url,
                observed_at = excluded.observed_at,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at
            """,
            (
                source_key,
                item.item_key,
                item.title,
                item.category,
                content_json,
                item.version,
                checksum,
                source_url,
                item.observed_at or now,
                expires,
                now,
                now,
            ),
        )

        connection.commit()

        return {
            "source_key": source_key,
            "item_key": item.item_key,
            "checksum": checksum,
            "expires_at": expires,
            "saved": True,
        }

    finally:
        connection.close()


# ================================================================
# KNOWLEDGE RETRIEVAL
# ================================================================

def get_knowledge(
    *,
    category: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    limit = max(
        1,
        min(int(limit), 100),
    )

    sql = """
        SELECT
            ki.source_key,
            ki.item_key,
            ki.title,
            ki.category,
            ki.content_json,
            ki.version,
            ki.checksum,
            ki.source_url,
            ki.observed_at,
            ki.expires_at,
            ks.name AS source_name,
            ks.last_success_at AS source_last_success_at
        FROM knowledge_items ki
        JOIN knowledge_sources ks
            ON ks.source_key = ki.source_key
        WHERE ks.enabled = 1
          AND (
              ki.expires_at IS NULL
              OR ki.expires_at > ?
          )
    """

    params: List[Any] = [
        utc_now(),
    ]

    if category:
        sql += " AND LOWER(ki.category) = LOWER(?)"
        params.append(category)

    if query:
        sql += (
            " AND (LOWER(ki.title) LIKE LOWER(?) "
            "OR LOWER(ki.content_json) LIKE LOWER(?))"
        )

        term = "%" + query[:200] + "%"

        params.extend([
            term,
            term,
        ])

    sql += " ORDER BY ki.updated_at DESC LIMIT ?"

    params.append(limit)

    connection = db()

    try:
        rows = connection.execute(
            sql,
            params,
        ).fetchall()

        results: List[Dict[str, Any]] = []

        for row in rows:
            results.append(
                {
                    "source_key": row["source_key"],
                    "source_name": row["source_name"],
                    "item_key": row["item_key"],
                    "title": row["title"],
                    "category": row["category"],
                    "content": json_loads(
                        row["content_json"],
                        {},
                    ),
                    "version": row["version"],
                    "checksum": row["checksum"],
                    "source_url": row["source_url"],
                    "observed_at": row["observed_at"],
                    "expires_at": row["expires_at"],
                    "source_last_success_at": (
                        row["source_last_success_at"]
                    ),
                }
            )

        return results

    finally:
        connection.close()


# ================================================================
# EXTERNAL KNOWLEDGE UPDATE
# ================================================================

def update_knowledge_source(
    source_key: str,
) -> Dict[str, Any]:
    connection = db()

    started = utc_now()

    try:
        source = connection.execute(
            """
            SELECT *
            FROM knowledge_sources
            WHERE source_key = ?
              AND enabled = 1
            """,
            (source_key,),
        ).fetchone()

        if not source:
            raise ValueError(
                "Knowledge source is missing or disabled."
            )

        source_url = validate_external_url(
            source["url"] or "",
        )

        response = requests.get(
            source_url,
            timeout=(
                5,
                min(MAX_PROVIDER_TIMEOUT, 30),
            ),
            headers={
                "User-Agent": "ARYA-Vision-Knowledge-Updater/2.1",
                "Accept": "application/json",
            },
            allow_redirects=False,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Source returned HTTP {response.status_code}."
            )

        if len(response.content) > 5 * 1024 * 1024:
            raise RuntimeError(
                "Knowledge source response exceeds 5 MB."
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                "Knowledge source did not return valid JSON."
            ) from exc

        if not isinstance(payload, dict):
            raise RuntimeError(
                "Knowledge source root must be a JSON object."
            )

        items = payload.get("items")

        if not isinstance(items, list):
            raise RuntimeError(
                "Knowledge source must provide an items array."
            )

        if len(items) > 10000:
            raise RuntimeError(
                "Knowledge source contains too many items."
            )

        version = str(
            payload.get("version", "")
        )[:100]

        checksum = sha256_bytes(
            response.content,
        )

        count = 0

        for raw_item in items:
            if not isinstance(raw_item, dict):
                continue

            item_key = str(
                raw_item.get("item_key", "")
            ).strip()

            title = str(
                raw_item.get("title", "")
            ).strip()

            category = str(
                raw_item.get("category", "general")
            ).strip()

            content = raw_item.get(
                "content",
                {},
            )

            if (
                not item_key
                or not title
                or not isinstance(content, dict)
            ):
                continue

            try:
                item_input = KnowledgeItemInput(
                    item_key=item_key,
                    title=title,
                    category=category or "general",
                    content=content,
                    version=str(
                        raw_item.get("version", version)
                    )[:100],
                    source_url=source_url,
                    observed_at=str(
                        raw_item.get("observed_at", utc_now())
                    )[:100],
                    ttl_seconds=bounded_int(
                        "ARYA_VISION_KNOWLEDGE_TTL",
                        86400,
                        60,
                        31_536_000,
                    ),
                )

                add_knowledge_item(
                    source_key,
                    item_input,
                )

                count += 1

            except (
                ValueError,
                HTTPException,
            ):
                logger.warning(
                    "Skipping invalid knowledge item from %s.",
                    source_key,
                )

        completed = utc_now()

        connection.execute(
            """
            UPDATE knowledge_sources
            SET last_update_at = ?,
                last_success_at = ?,
                last_error = NULL,
                version = ?,
                checksum = ?,
                item_count = ?,
                updated_at = ?
            WHERE source_key = ?
            """,
            (
                completed,
                completed,
                version,
                checksum,
                count,
                completed,
                source_key,
            ),
        )

        connection.execute(
            """
            INSERT INTO update_history (
                source_key,
                status,
                version,
                checksum,
                item_count,
                message,
                started_at,
                completed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_key,
                "success",
                version,
                checksum,
                count,
                "Source update completed.",
                started,
                completed,
            ),
        )

        connection.commit()

        return {
            "source_key": source_key,
            "status": "success",
            "version": version,
            "checksum": checksum,
            "item_count": count,
            "updated_at": completed,
        }

    except Exception as exc:
        completed = utc_now()

        message = str(exc)[:1000]

        try:
            connection.execute(
                """
                UPDATE knowledge_sources
                SET last_update_at = ?,
                    last_error = ?,
                    updated_at = ?
                WHERE source_key = ?
                """,
                (
                    completed,
                    message,
                    completed,
                    source_key,
                ),
            )

            connection.execute(
                """
                INSERT INTO update_history (
                    source_key,
                    status,
                    message,
                    started_at,
                    completed_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    source_key,
                    "error",
                    message,
                    started,
                    completed,
                ),
            )

            connection.commit()

        except sqlite3.Error:
            logger.exception(
                "Failed to persist knowledge update error."
            )

        logger.warning(
            "Knowledge source update failed for %s: %s",
            source_key,
            type(exc).__name__,
        )

        raise HTTPException(
            status_code=502,
            detail="Knowledge source update failed.",
        ) from exc

    finally:
        connection.close()


# ================================================================
# SCHEDULER
# ================================================================

_scheduler_started = False
_scheduler_lock = threading.Lock()


def scheduler_loop() -> None:
    while True:
        try:
            if AUTO_UPDATE_ENABLED and ALLOW_EXTERNAL_PROVIDERS:
                connection = db()

                try:
                    sources = connection.execute(
                        """
                        SELECT source_key, update_interval_seconds,
                               last_success_at
                        FROM knowledge_sources
                        WHERE enabled = 1
                        """
                    ).fetchall()

                finally:
                    connection.close()

                now = datetime.now(timezone.utc)

                for source in sources:
                    should_update = False

                    last_success = source["last_success_at"]

                    if not last_success:
                        should_update = True
                    else:
                        try:
                            last_time = datetime.fromisoformat(
                                last_success.replace(
                                    "Z",
                                    "+00:00",
                                )
                            )

                            if last_time.tzinfo is None:
                                last_time = last_time.replace(
                                    tzinfo=timezone.utc,
                                )

                            elapsed = (
                                now - last_time
                            ).total_seconds()

                            interval = max(
                                60,
                                int(
                                    source[
                                        "update_interval_seconds"
                                    ]
                                ),
                            )

                            should_update = elapsed >= interval

                        except (ValueError, TypeError):
                            should_update = True

                    if should_update:
                        try:
                            update_knowledge_source(
                                source["source_key"],
                            )
                        except Exception:
                            logger.warning(
                                "Scheduled source update failed."
                            )

        except Exception:
            logger.exception(
                "Vision knowledge scheduler encountered an error."
            )

        time.sleep(
            UPDATE_INTERVAL_SECONDS,
        )


def start_scheduler() -> None:
    global _scheduler_started

    with _scheduler_lock:
        if _scheduler_started:
            return

        thread = threading.Thread(
            target=scheduler_loop,
            name="arya-vision-knowledge-updater",
            daemon=True,
        )

        thread.start()

        _scheduler_started = True


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    start_scheduler()

    logger.info(
        "%s %s started on port %s",
        APP_NAME,
        VERSION,
        PORT,
    )


# ================================================================
# REQUEST MODELS
# ================================================================

class AnalysisContext(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )

    crop: Optional[str] = Field(
        default=None,
        max_length=200,
    )

    plant: Optional[str] = Field(
        default=None,
        max_length=200,
    )

    growth_stage: Optional[str] = Field(
        default=None,
        max_length=200,
    )

    location: Optional[Dict[str, Any]] = None

    weather: Optional[Dict[str, Any]] = None

    soil: Optional[Dict[str, Any]] = None

    water: Optional[Dict[str, Any]] = None

    lab: Optional[Dict[str, Any]] = None

    symptoms: Optional[str] = Field(
        default=None,
        max_length=10000,
    )

    user_question: Optional[str] = Field(
        default=None,
        max_length=10000,
    )


# ================================================================
# ROUTES: BASIC
# ================================================================

@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": VERSION,
        "status": "running",
        "independent": True,
        "main_py_dependency": False,
        "time": utc_now(),
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "version": VERSION,
        "database_configured": DB_PATH.exists(),
        "provider": VISION_PROVIDER,
        "time": utc_now(),
    }


@app.get("/info")
def info() -> Dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": VERSION,
        "capabilities": [
            "multi_image_upload",
            "image_validation",
            "image_quality_estimation",
            "exif_orientation_correction",
            "image_normalization",
            "plant_identification_support",
            "disease_analysis",
            "pest_analysis",
            "nutrient_deficiency_analysis",
            "water_and_temperature_stress_analysis",
            "differential_diagnosis",
            "severity_estimation",
            "replaceable_providers",
            "provider_health",
            "versioned_knowledge",
            "knowledge_expiration",
            "source_update_history",
        ],
        "external_updates_enabled": (
            AUTO_UPDATE_ENABLED
            and ALLOW_EXTERNAL_PROVIDERS
        ),
        "time": utc_now(),
    }


# ================================================================
# ROUTES: PROVIDERS
# ================================================================

@app.get("/providers")
def list_providers(
    _: None = Header(
        default=None,
        alias="X-ARYA-Vision-Key",
    ),
) -> Dict[str, Any]:
    results = []

    with _PROVIDER_LOCK:
        providers = list(
            _PROVIDER_REGISTRY.values(),
        )

    for provider in providers:
        try:
            results.append(
                provider.health(),
            )
        except Exception:
            results.append(
                {
                    "provider": provider.key,
                    "status": "health_check_failed",
                }
            )

    return {
        "active_provider": VISION_PROVIDER,
        "providers": results,
    }


@app.get("/providers/health")
def provider_health() -> Dict[str, Any]:
    provider = get_provider()

    try:
        return provider.health()
    except Exception:
        logger.exception(
            "Provider health check failed."
        )

        return {
            "provider": provider.key,
            "status": "health_check_failed",
            "checked_at": utc_now(),
        }


# ================================================================
# ROUTES: ANALYSIS
# ================================================================

@app.post("/analyze")
async def analyze_images(
    images: List[UploadFile] = File(...),
    crop: Optional[str] = Form(default=None),
    plant: Optional[str] = Form(default=None),
    growth_stage: Optional[str] = Form(default=None),
    symptoms: Optional[str] = Form(default=None),
    user_question: Optional[str] = Form(default=None),
    location_json: Optional[str] = Form(default=None),
    weather_json: Optional[str] = Form(default=None),
    soil_json: Optional[str] = Form(default=None),
    water_json: Optional[str] = Form(default=None),
    lab_json: Optional[str] = Form(default=None),
    x_arya_vision_key: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Vision-Key",
    ),
) -> Dict[str, Any]:
    require_client_key(
        x_arya_vision_key,
    )

    if not images:
        raise HTTPException(
            status_code=400,
            detail="At least one image is required.",
        )

    if len(images) > MAX_IMAGES_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Maximum {MAX_IMAGES_PER_REQUEST} images "
                "are allowed per request."
            ),
        )

    def parse_optional_json(
        raw: Optional[str],
        field_name: str,
    ) -> Optional[Dict[str, Any]]:
        if not raw:
            return None

        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid JSON in {field_name}.",
            ) from exc

        if not isinstance(parsed, dict):
            raise HTTPException(
                status_code=400,
                detail=f"{field_name} must be a JSON object.",
            )

        return parsed

    context = {
        "crop": crop,
        "plant": plant,
        "growth_stage": growth_stage,
        "symptoms": symptoms,
        "user_question": user_question,
        "location": parse_optional_json(
            location_json,
            "location_json",
        ),
        "weather": parse_optional_json(
            weather_json,
            "weather_json",
        ),
        "soil": parse_optional_json(
            soil_json,
            "soil_json",
        ),
        "water": parse_optional_json(
            water_json,
            "water_json",
        ),
        "lab": parse_optional_json(
            lab_json,
            "lab_json",
        ),
    }

    prepared_images: List[Dict[str, Any]] = []
    total_bytes = 0

    try:
        for upload in images:
            extension = Path(
                upload.filename or "",
            ).suffix.lower()

            content_type = (
                upload.content_type or ""
            ).lower()

            if extension not in ALLOWED_EXTENSIONS:
                raise HTTPException(
                    status_code=415,
                    detail="Unsupported image filename extension.",
                )

            if content_type not in ALLOWED_IMAGE_TYPES:
                raise HTTPException(
                    status_code=415,
                    detail="Unsupported image content type.",
                )

            raw = await upload.read(
                MAX_UPLOAD_BYTES + 1,
            )

            total_bytes += len(raw)

            if len(raw) > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="An image exceeds the upload size limit.",
                )

            if total_bytes > (
                MAX_UPLOAD_BYTES
                * MAX_IMAGES_PER_REQUEST
            ):
                raise HTTPException(
                    status_code=413,
                    detail="Total upload size exceeds the request limit.",
                )

            try:
                image_data = normalize_image(
                    raw,
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail=str(exc),
                ) from exc

            quality = image_quality(
                image_data,
            )

            image_data["quality"] = quality

            prepared_images.append(
                image_data,
            )

    finally:
        for upload in images:
            try:
                await upload.close()
            except Exception:
                pass

    provider = get_provider()

    rid = make_request_id()

    try:
        result = provider.analyze(
            prepared_images,
            context,
        )

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception(
            "Vision analysis failed; request_id=%s",
            rid,
        )

        raise HTTPException(
            status_code=502,
            detail={
                "message": "Vision analysis provider failed.",
                "request_id": rid,
            },
        ) from exc

    result = normalize_analysis_result(
        result,
    )

    result["request_id"] = rid

    result["provider"] = provider.key

    result["model"] = getattr(
        provider,
        "model",
        None,
    )

    result["created_at"] = utc_now()

    result["images"] = [
        {
            "sha256": item["sha256"],
            "width": item["width"],
            "height": item["height"],
            "quality": item["quality"],
        }
        for item in prepared_images
    ]

    try:
        save_analysis(
            rid=rid,
            provider_key=provider.key,
            model=str(
                getattr(
                    provider,
                    "model",
                    "",
                )
            ),
            images=prepared_images,
            context=context,
            result=result,
        )

    except sqlite3.Error:
        logger.exception(
            "Could not persist analysis record; request_id=%s",
            rid,
        )

        # A successful analysis is still returned, but the log
        # records that persistence failed.

    return result


# ================================================================
# ROUTES: KNOWLEDGE
# ================================================================

@app.get("/knowledge")
def knowledge_search(
    category: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    items = get_knowledge(
        category=category,
        query=query,
        limit=limit,
    )

    return {
        "items": items,
        "count": len(items),
        "generated_at": utc_now(),
        "expired_items_excluded": True,
    }


@app.post("/knowledge/sources")
def create_knowledge_source(
    data: KnowledgeSourceInput,
    x_arya_admin_key: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Admin-Key",
    ),
) -> Dict[str, Any]:
    require_admin(
        x_arya_admin_key,
    )

    try:
        return register_knowledge_source(
            data,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@app.get("/knowledge/sources")
def list_knowledge_sources(
    x_arya_admin_key: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Admin-Key",
    ),
) -> Dict[str, Any]:
    require_admin(
        x_arya_admin_key,
    )

    connection = db()

    try:
        rows = connection.execute(
            """
            SELECT source_key, name, source_type, url,
                   enabled, update_interval_seconds,
                   last_update_at, last_success_at,
                   last_error, version, checksum,
                   item_count, created_at, updated_at
            FROM knowledge_sources
            ORDER BY name
            """
        ).fetchall()

        return {
            "sources": [
                dict(row)
                for row in rows
            ],
            "count": len(rows),
        }

    finally:
        connection.close()


@app.post("/knowledge/sources/{source_key}/items")
def create_knowledge_item(
    source_key: str,
    item: KnowledgeItemInput,
    x_arya_admin_key: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Admin-Key",
    ),
) -> Dict[str, Any]:
    require_admin(
        x_arya_admin_key,
    )

    try:
        return add_knowledge_item(
            source_key,
            item,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@app.post("/knowledge/sources/{source_key}/update")
def update_source_route(
    source_key: str,
    x_arya_admin_key: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Admin-Key",
    ),
) -> Dict[str, Any]:
    require_admin(
        x_arya_admin_key,
    )

    if not ALLOW_EXTERNAL_PROVIDERS:
        raise HTTPException(
            status_code=403,
            detail="External knowledge updates are disabled.",
        )

    return update_knowledge_source(
        source_key,
    )


@app.get("/knowledge/updates")
def knowledge_update_history(
    limit: int = 50,
    x_arya_admin_key: Optional[str] = Header(
        default=None,
        alias="X-ARYA-Admin-Key",
    ),
) -> Dict[str, Any]:
    require_admin(
        x_arya_admin_key,
    )

    limit = max(
        1,
        min(limit, 200),
    )

    connection = db()

    try:
        rows = connection.execute(
            """
            SELECT id, source_key, status, version,
                   checksum, item_count, message,
                   started_at, completed_at
            FROM update_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return {
            "history
