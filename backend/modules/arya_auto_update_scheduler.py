"""
ARYA AgriDoctor
Automatic Update Scheduler
Version: 1.0.0

Purpose:
- Schedule automatic data-update jobs.
- Connect to ARYA data_update service.
- Keep update schedules persistent in SQLite.
- Prevent overlapping jobs.
- Support trusted-source update groups.
- Record execution history.
- Provide OWNER-oriented management endpoints.
- Fail safely when an external update service is unavailable.

This module is independent and does not modify backend/main.py
or any existing ARYA module.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field


# ============================================================
# Configuration
# ============================================================

APP_NAME = "ARYA Auto Update Scheduler"
APP_VERSION = "1.0.0"

HOST = os.getenv("ARYA_AUTO_UPDATE_HOST", "127.0.0.1")
PORT = int(os.getenv("ARYA_AUTO_UPDATE_PORT", "8025"))

DATABASE = os.getenv(
    "ARYA_AUTO_UPDATE_DATABASE",
    os.path.join(os.path.dirname(__file__), "arya_auto_update_scheduler.db"),
)

DATA_UPDATE_URL = os.getenv(
    "ARYA_DATA_UPDATE_URL",
    "http://127.0.0.1:8026",
).rstrip("/")

HTTP_TIMEOUT = float(os.getenv("ARYA_AUTO_UPDATE_HTTP_TIMEOUT", "30"))
MAX_RESPONSE_BYTES = int(
    os.getenv("ARYA_AUTO_UPDATE_MAX_RESPONSE_BYTES", str(5 * 1024 * 1024))
)

DEFAULT_INTERVAL_SECONDS = int(
    os.getenv("ARYA_AUTO_UPDATE_DEFAULT_INTERVAL", "21600")
)

MIN_INTERVAL_SECONDS = int(
    os.getenv("ARYA_AUTO_UPDATE_MIN_INTERVAL", "300")
)

MAX_INTERVAL_SECONDS = int(
    os.getenv("ARYA_AUTO_UPDATE_MAX_INTERVAL", "2592000")
)

SCHEDULER_ENABLED = os.getenv(
    "ARYA_AUTO_UPDATE_ENABLED",
    "true",
).lower() in {"1", "true", "yes", "on"}

LOG_LEVEL = os.getenv("ARYA_AUTO_UPDATE_LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
)

logger = logging.getLogger("arya.auto_update_scheduler")


# ============================================================
# Time helpers
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )


# ============================================================
# Database
# ============================================================

DB_LOCK = threading.RLock()


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(
        DATABASE,
        timeout=30,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    return connection


def init_database() -> None:
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

    with DB_LOCK:
        connection = get_connection()
        try:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;

                CREATE TABLE IF NOT EXISTS schedules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    interval_seconds INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    startup_run INTEGER NOT NULL DEFAULT 0,
                    next_run_at REAL,
                    last_run_at REAL,
                    last_status TEXT,
                    last_error TEXT,
                    run_count INTEGER NOT NULL DEFAULT 0,
                    success_count INTEGER NOT NULL DEFAULT 0,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS update_groups (
                    id TEXT PRIMARY KEY,
                    schedule_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    source_ids TEXT NOT NULL DEFAULT '[]',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(schedule_id, name),
                    FOREIGN KEY(schedule_id)
                        REFERENCES schedules(id)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS execution_runs (
                    id TEXT PRIMARY KEY,
                    schedule_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    duration_seconds REAL,
                    response_status INTEGER,
                    response_hash TEXT,
                    response_size INTEGER,
                    error TEXT,
                    details TEXT,
                    FOREIGN KEY(schedule_id)
                        REFERENCES schedules(id)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS scheduler_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    schedule_id TEXT,
                    run_id TEXT,
                    message TEXT,
                    details TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runtime_state (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_schedules_enabled
                    ON schedules(enabled);

                CREATE INDEX IF NOT EXISTS idx_schedules_next_run
                    ON schedules(next_run_at);

                CREATE INDEX IF NOT EXISTS idx_runs_schedule
                    ON execution_runs(schedule_id);

                CREATE INDEX IF NOT EXISTS idx_runs_started
                    ON execution_runs(started_at);

                CREATE INDEX IF NOT EXISTS idx_events_created
                    ON scheduler_events(created_at);
                """
            )
            connection.commit()
        finally:
            connection.close()


# ============================================================
# Database helpers
# ============================================================

def db_execute(
    query: str,
    parameters: tuple = (),
) -> None:
    with DB_LOCK:
        connection = get_connection()
        try:
            connection.execute(query, parameters)
            connection.commit()
        finally:
            connection.close()


def db_fetchone(
    query: str,
    parameters: tuple = (),
) -> Optional[sqlite3.Row]:
    with DB_LOCK:
        connection = get_connection()
        try:
            return connection.execute(
                query,
                parameters,
            ).fetchone()
        finally:
            connection.close()


def db_fetchall(
    query: str,
    parameters: tuple = (),
) -> List[sqlite3.Row]:
    with DB_LOCK:
        connection = get_connection()
        try:
            return connection.execute(
                query,
                parameters,
            ).fetchall()
        finally:
            connection.close()


def record_event(
    event_type: str,
    message: str,
    schedule_id: Optional[str] = None,
    run_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    db_execute(
        """
        INSERT INTO scheduler_events
        (
            event_type,
            schedule_id,
            run_id,
            message,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event_type,
            schedule_id,
            run_id,
            message,
            safe_json(details or {}),
            utc_now(),
        ),
    )


# ============================================================
# Models
# ============================================================

class ScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(
        default=None,
        max_length=1000,
    )
    interval_seconds: int = Field(
        default=DEFAULT_INTERVAL_SECONDS,
        ge=MIN_INTERVAL_SECONDS,
        le=MAX_INTERVAL_SECONDS,
    )
    enabled: bool = True
    startup_run: bool = False


class ScheduleUpdate(BaseModel):
    description: Optional[str] = Field(
        default=None,
        max_length=1000,
    )
    interval_seconds: Optional[int] = Field(
        default=None,
        ge=MIN_INTERVAL_SECONDS,
        le=MAX_INTERVAL_SECONDS,
    )
    enabled: Optional[bool] = None
    startup_run: Optional[bool] = None


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    source_ids: List[str] = Field(default_factory=list)
    enabled: bool = True


class SchedulerControl(BaseModel):
    enabled: bool


# ============================================================
# Runtime structures
# ============================================================

@dataclass
class RunningJob:
    schedule_id: str
    run_id: str
    task: asyncio.Task


RUNNING_JOBS: Dict[str, RunningJob] = {}
RUNNING_JOBS_LOCK = asyncio.Lock()


# ============================================================
# Data-update service client
# ============================================================

class DataUpdateClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def health(self) -> Dict[str, Any]:
        return await self._request(
            "GET",
            "/health",
        )

    async def sources(self) -> Dict[str, Any]:
        return await self._request(
            "GET",
            "/sources",
        )

    async def run_updates(
        self,
        source_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}

        if source_ids:
            payload["source_ids"] = source_ids

        return await self._request(
            "POST",
            "/updates/run",
            json_payload=payload,
        )

    async def fetch_source(
        self,
        source_id: str,
    ) -> Dict[str, Any]:
        return await self._request(
            "POST",
            f"/sources/{source_id}/fetch",
        )

    async def _request(
        self,
        method: str,
        path: str,
        json_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"

        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            follow_redirects=False,
        ) as client:
            response = await client.request(
                method=method,
                url=url,
                json=json_payload,
            )

            content_length = len(response.content)

            if content_length > MAX_RESPONSE_BYTES:
                raise RuntimeError(
                    "Data-update service response exceeded size limit."
                )

            if response.status_code >= 400:
                raise RuntimeError(
                    f"Data-update service returned HTTP "
                    f"{response.status_code}: "
                    f"{response.text[:1000]}"
                )

            try:
                return response.json()
            except Exception:
                return {
                    "status_code": response.status_code,
                    "text": response.text[:10000],
                }


data_update_client = DataUpdateClient(DATA_UPDATE_URL)


# ============================================================
# Scheduler core
# ============================================================

class AutoUpdateScheduler:
    def __init__(self):
        self.stop_event: Optional[asyncio.Event] = None
        self.task: Optional[asyncio.Task] = None
        self.started_at: Optional[str] = None

    async def start(self) -> None:
        if self.task and not self.task.done():
            return

        self.stop_event = asyncio.Event()
        self.started_at = utc_now()

        db_execute(
            """
            INSERT INTO runtime_state(key, value, updated_at)
            VALUES ('scheduler_started_at', ?, ?)
            ON CONFLICT(key)
            DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (
                self.started_at,
                utc_now(),
            ),
        )

        self.task = asyncio.create_task(
            self.loop(),
            name="arya-auto-update-scheduler",
        )

        record_event(
            "scheduler_started",
            "Automatic update scheduler started.",
        )

    async def stop(self) -> None:
        if not self.task:
            return

        if self.stop_event:
            self.stop_event.set()

        try:
            await asyncio.wait_for(
                self.task,
                timeout=10,
            )
        except asyncio.TimeoutError:
            self.task.cancel()
        except asyncio.CancelledError:
            pass

        self.task = None

        record_event(
            "scheduler_stopped",
            "Automatic update scheduler stopped.",
        )

    async def loop(self) -> None:
        while self.stop_event and not self.stop_event.is_set():
            try:
                if scheduler_enabled_from_db():
                    await self.process_due_schedules()
            except Exception as exc:
                logger.exception(
                    "Scheduler loop error: %s",
                    exc,
                )
                record_event(
                    "scheduler_error",
                    "Scheduler loop error.",
                    details={"error": str(exc)},
                )

            try:
                await asyncio.wait_for(
                    self.stop_event.wait(),
                    timeout=5,
                )
            except asyncio.TimeoutError:
                continue

    async def process_due_schedules(self) -> None:
        now = time.time()

        rows = db_fetchall(
            """
            SELECT *
            FROM schedules
            WHERE enabled = 1
              AND next_run_at IS NOT NULL
              AND next_run_at <= ?
            ORDER BY next_run_at ASC
            LIMIT 20
            """,
            (now,),
        )

        for row in rows:
            await self.launch_if_needed(row["id"])

    async def launch_if_needed(
        self,
        schedule_id: str,
    ) -> bool:
        async with RUNNING_JOBS_LOCK:
            if schedule_id in RUNNING_JOBS:
                return False

            row = db_fetchone(
                """
                SELECT *
                FROM schedules
                WHERE id = ?
                """,
                (schedule_id,),
            )

            if not row:
                return False

            if not row["enabled"]:
                return False

            run_id = str(uuid.uuid4())

            task = asyncio.create_task(
                self.execute_schedule(
                    schedule_id=schedule_id,
                    run_id=run_id,
                ),
                name=f"arya-update-{schedule_id}",
            )

            RUNNING_JOBS[schedule_id] = RunningJob(
                schedule_id=schedule_id,
                run_id=run_id,
                task=task,
            )

            return True

    async def execute_schedule(
        self,
        schedule_id: str,
        run_id: str,
    ) -> None:
        started_timestamp = time.time()
        started_at = utc_now()

        db_execute(
            """
            INSERT INTO execution_runs
            (
                id,
                schedule_id,
                started_at,
                status
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                run_id,
                schedule_id,
                started_at,
                "running",
            ),
        )

        db_execute(
            """
            UPDATE schedules
            SET
                last_run_at = ?,
                last_status = ?,
                last_error = NULL,
                run_count = run_count + 1,
                updated_at = ?
            WHERE id = ?
            """,
            (
                started_timestamp,
                "running",
                utc_now(),
                schedule_id,
            ),
        )

        record_event(
            "run_started",
            "Scheduled update run started.",
            schedule_id=schedule_id,
            run_id=run_id,
        )

        try:
            group_source_ids = self.get_enabled_group_sources(
                schedule_id
            )

            if group_source_ids:
                result = await data_update_client.run_updates(
                    source_ids=group_source_ids,
                )
            else:
                result = await data_update_client.run_updates()

            finished_timestamp = time.time()
            duration = finished_timestamp - started_timestamp
            finished_at = utc_now()

            serialized = safe_json(result)
            response_hash = hashlib.sha256(
                serialized.encode("utf-8")
            ).hexdigest()

            response_size = len(serialized.encode("utf-8"))

            db_execute(
                """
                UPDATE execution_runs
                SET
                    finished_at = ?,
                    status = ?,
                    duration_seconds = ?,
                    response_status = ?,
                    response_hash = ?,
                    response_size = ?,
                    details = ?
                WHERE id = ?
                """,
                (
                    finished_at,
                    "success",
                    duration,
                    200,
                    response_hash,
                    response_size,
                    serialized[:50000],
                    run_id,
                ),
            )

            db_execute(
                """
                UPDATE schedules
                SET
                    last_status = ?,
                    last_error = NULL,
                    success_count = success_count + 1,
                    next_run_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    "success",
                    finished_timestamp + self.get_interval(
                        schedule_id
                    ),
                    utc_now(),
                    schedule_id,
                ),
            )

            record_event(
                "run_success",
                "Scheduled update run completed successfully.",
                schedule_id=schedule_id,
                run_id=run_id,
                details={
                    "duration_seconds": duration,
                    "response_hash": response_hash,
                },
            )

        except Exception as exc:
            finished_timestamp = time.time()
            duration = finished_timestamp - started_timestamp

            db_execute(
                """
                UPDATE execution_runs
                SET
                    finished_at = ?,
                    status = ?,
                    duration_seconds = ?,
                    error = ?
                WHERE id = ?
                """,
                (
                    utc_now(),
                    "failed",
                    duration,
                    str(exc)[:10000],
                    run_id,
                ),
            )

            db_execute(
                """
                UPDATE schedules
                SET
                    last_status = ?,
                    last_error = ?,
                    failure_count = failure_count + 1,
                    next_run_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    "failed",
                    str(exc)[:10000],
                    finished_timestamp + self.get_interval(
                        schedule_id
                    ),
                    utc_now(),
                    schedule_id,
                ),
            )

            record_event(
                "run_failed",
                "Scheduled update run failed.",
                schedule_id=schedule_id,
                run_id=run_id,
                details={
                    "error": str(exc),
                    "duration_seconds": duration,
                },
            )

            logger.exception(
                "Scheduled update failed: %s",
                exc,
            )

        finally:
            async with RUNNING_JOBS_LOCK:
                RUNNING_JOBS.pop(
                    schedule_id,
                    None,
                )

    def get_interval(
        self,
        schedule_id: str,
    ) -> int:
        row = db_fetchone(
            """
            SELECT interval_seconds
            FROM schedules
            WHERE id = ?
            """,
            (schedule_id,),
        )

        if not row:
            return DEFAULT_INTERVAL_SECONDS

        return max(
            MIN_INTERVAL_SECONDS,
            min(
                MAX_INTERVAL_SECONDS,
                int(row["interval_seconds"]),
            ),
        )

    def get_enabled_group_sources(
        self,
        schedule_id: str,
    ) -> List[str]:
        rows = db_fetchall(
            """
            SELECT source_ids
            FROM update_groups
            WHERE schedule_id = ?
              AND enabled = 1
            """,
            (schedule_id,),
        )

        result: List[str] = []

        for row in rows:
            try:
                values = json.loads(row["source_ids"])
            except Exception:
                values = []

            if isinstance(values, list):
                for source_id in values:
                    if (
                        isinstance(source_id, str)
                        and source_id
                        and source_id not in result
                    ):
                        result.append(source_id)

        return result


scheduler = AutoUpdateScheduler()


# ============================================================
# Runtime state
# ============================================================

def scheduler_enabled_from_db() -> bool:
    row = db_fetchone(
        """
        SELECT value
        FROM runtime_state
        WHERE key = 'scheduler_enabled'
        """
    )

    if not row:
        return SCHEDULER_ENABLED

    return str(row["value"]).lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def set_scheduler_enabled(enabled: bool) -> None:
    db_execute(
        """
        INSERT INTO runtime_state(key, value, updated_at)
        VALUES ('scheduler_enabled', ?, ?)
        ON CONFLICT(key)
        DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        """,
        (
            "true" if enabled else "false",
            utc_now(),
        ),
    )


def initialize_default_schedule() -> None:
    existing = db_fetchone(
        """
        SELECT id
        FROM schedules
        WHERE name = ?
        """,
        ("global_data_update",),
    )

    if existing:
        return

    schedule_id = str(uuid.uuid4())
    now = time.time()
    timestamp = utc_now()

    db_execute(
        """
        INSERT INTO schedules
        (
            id,
            name,
            description,
            interval_seconds,
            enabled,
            startup_run,
            next_run_at,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            schedule_id,
            "global_data_update",
            "Global ARYA trusted-source data update.",
            DEFAULT_INTERVAL_SECONDS,
            1,
            0,
            now + DEFAULT_INTERVAL_SECONDS,
            timestamp,
            timestamp,
        ),
    )

    record_event(
        "default_schedule_created",
        "Default global data update schedule created.",
        schedule_id=schedule_id,
    )


# ============================================================
# FastAPI lifecycle
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    initialize_default_schedule()
    set_scheduler_enabled(
        scheduler_enabled_from_db()
    )

    if SCHEDULER_ENABLED:
        await scheduler.start()

    yield

    await scheduler.stop()


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Persistent automatic update scheduler for ARYA AgriDoctor."
    ),
    lifespan=lifespan,
)


# ============================================================
# Basic routes
# ============================================================

@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "scheduler_enabled": scheduler_enabled_from_db(),
        "data_update_url": DATA_UPDATE_URL,
    }


@app.get("/health")
async def health() -> Dict[str, Any]:
    running = len(RUNNING_JOBS)

    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "scheduler_enabled": scheduler_enabled_from_db(),
        "scheduler_task_running": bool(
            scheduler.task
            and not scheduler.task.done()
        ),
        "running_jobs": running,
        "timestamp": utc_now(),
    }


# ============================================================
# Scheduler control
# ============================================================

@app.get("/scheduler/status")
async def scheduler_status() -> Dict[str, Any]:
    rows = db_fetchall(
        """
        SELECT
            id,
            name,
            enabled,
            interval_seconds,
            next_run_at,
            last_run_at,
            last_status,
            run_count,
            success_count,
            failure_count
        FROM schedules
        ORDER BY name
        """
    )

    schedules = []

    for row in rows:
        schedules.append(
            {
                "id": row["id"],
                "name": row["name"],
                "enabled": bool(row["enabled"]),
                "interval_seconds": row["interval_seconds"],
                "next_run_at": row["next_run_at"],
                "last_run_at": row["last_run_at"],
                "last_status": row["last_status"],
                "run_count": row["run_count"],
                "success_count": row["success_count"],
                "failure_count": row["failure_count"],
                "running": row["id"] in RUNNING_JOBS,
            }
        )

    return {
        "enabled": scheduler_enabled_from_db(),
        "running_jobs": list(RUNNING_JOBS.keys()),
        "schedules": schedules,
    }


@app.post("/scheduler/enable")
async def enable_scheduler() -> Dict[str, Any]:
    set_scheduler_enabled(True)

    if not scheduler.task or scheduler.task.done():
        await scheduler.start()

    record_event(
        "scheduler_enabled",
        "Automatic update scheduler enabled.",
    )

    return {
        "success": True,
        "enabled": True,
    }


@app.post("/scheduler/disable")
async def disable_scheduler() -> Dict[str, Any]:
    set_scheduler_enabled(False)

    await scheduler.stop()

    record_event(
        "scheduler_disabled",
        "Automatic update scheduler disabled.",
    )

    return {
        "success": True,
        "enabled": False,
    }


@app.post("/scheduler/control")
async def scheduler_control(
    payload: SchedulerControl,
) -> Dict[str, Any]:
    if payload.enabled:
        return await enable_scheduler()

    return await disable_scheduler()


# ============================================================
# Schedule management
# ============================================================

@app.get("/schedules")
async def list_schedules() -> Dict[str, Any]:
    rows = db_fetchall(
        """
        SELECT *
        FROM schedules
        ORDER BY name
        """
    )

    return {
        "items": [
            {
                "id": row["id"],
                "name": row["name"],
                "description": row["description"],
                "interval_seconds": row["interval_seconds"],
                "enabled": bool(row["enabled"]),
                "startup_run": bool(row["startup_run"]),
                "next_run_at": row["next_run_at"],
                "last_run_at": row["last_run_at"],
                "last_status": row["last_status"],
                "last_error": row["last_error"],
                "run_count": row["run_count"],
                "success_count": row["success_count"],
                "failure_count": row["failure_count"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "running": row["id"] in RUNNING_JOBS,
            }
            for row in rows
        ]
    }


@app.post("/schedules")
async def create_schedule(
    payload: ScheduleCreate,
) -> Dict[str, Any]:
    existing = db_fetchone(
        """
        SELECT id
        FROM schedules
        WHERE name = ?
        """,
        (payload.name,),
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Schedule name already exists.",
        )

    schedule_id = str(uuid.uuid4())
    timestamp = utc_now()

    next_run = (
        time.time()
        if payload.startup_run
        else time.time() + payload.interval_seconds
    )

    db_execute(
        """
        INSERT INTO schedules
        (
            id,
            name,
            description,
            interval_seconds,
            enabled,
            startup_run,
            next_run_at,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            schedule_id,
            payload.name,
            payload.description,
            payload.interval_seconds,
            int(payload.enabled),
            int(payload.startup_run),
            next_run,
            timestamp,
            timestamp,
        ),
    )

    record_event(
        "schedule_created",
        "Schedule created.",
        schedule_id=schedule_id,
        details={
            "name": payload.name,
            "interval_seconds": payload.interval_seconds,
        },
    )

    return {
        "success": True,
        "schedule_id": schedule_id,
    }


@app.get("/schedules/{schedule_id}")
async def get_schedule(
    schedule_id: str,
) -> Dict[str, Any]:
    row = db_fetchone(
        """
        SELECT *
        FROM schedules
        WHERE id = ?
        """,
        (schedule_id,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Schedule not found.",
        )

    groups = db_fetchall(
        """
        SELECT *
        FROM update_groups
        WHERE schedule_id = ?
        ORDER BY name
        """,
        (schedule_id,),
    )

    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "interval_seconds": row["interval_seconds"],
        "enabled": bool(row["enabled"]),
        "startup_run": bool(row["startup_run"]),
        "next_run_at": row["next_run_at"],
        "last_run_at": row["last_run_at"],
        "last_status": row["last_status"],
        "last_error": row["last_error"],
        "run_count": row["run_count"],
        "success_count": row["success_count"],
        "failure_count": row["failure_count"],
        "groups": [
            {
                "id": group["id"],
                "name": group["name"],
                "source_ids": json.loads(
                    group["source_ids"]
                ),
                "enabled": bool(group["enabled"]),
            }
            for group in groups
        ],
    }


@app.patch("/schedules/{schedule_id}")
async def update_schedule(
    schedule_id: str,
    payload: ScheduleUpdate,
) -> Dict[str, Any]:
    existing = db_fetchone(
        """
        SELECT *
        FROM schedules
        WHERE id = ?
        """,
        (schedule_id,),
    )

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Schedule not found.",
        )

    description = (
        payload.description
        if payload.description is not None
        else existing["description"]
    )

    interval = (
        payload.interval_seconds
        if payload.interval_seconds is not None
        else existing["interval_seconds"]
    )

    enabled = (
        int(payload.enabled)
        if payload.enabled is not None
        else existing["enabled"]
    )

    startup_run = (
        int(payload.startup_run)
        if payload.startup_run is not None
        else existing["startup_run"]
    )

    next_run = existing["next_run_at"]

    if payload.interval_seconds is not None:
        next_run = time.time() + interval

    db_execute(
        """
        UPDATE schedules
        SET
            description = ?,
            interval_seconds = ?,
            enabled = ?,
            startup_run = ?,
            next_run_at = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            description,
            interval,
            enabled,
            startup_run,
            next_run,
            utc_now(),
            schedule_id,
        ),
    )

    record_event(
        "schedule_updated",
        "Schedule updated.",
        schedule_id=schedule_id,
    )

    return {
        "success": True,
        "schedule_id": schedule_id,
    }


@app.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
) -> Dict[str, Any]:
    existing = db_fetchone(
        """
        SELECT id
        FROM schedules
        WHERE id = ?
        """,
        (schedule_id,),
    )

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Schedule not found.",
        )

    async with RUNNING_JOBS_LOCK:
        running = RUNNING_JOBS.get(schedule_id)

        if running:
            running.task.cancel()
            RUNNING_JOBS.pop(
                schedule_id,
                None,
            )

    db_execute(
        """
        DELETE FROM schedules
        WHERE id = ?
        """,
        (schedule_id,),
    )

    record_event(
        "schedule_deleted",
        "Schedule deleted.",
        schedule_id=schedule_id,
    )

    return {
        "success": True,
        "schedule_id": schedule_id,
    }


# ============================================================
# Manual execution
# ============================================================

@app.post("/schedules/{schedule_id}/run")
async def run_schedule_now(
    schedule_id: str,
) -> Dict[str, Any]:
    existing = db_fetchone(
        """
        SELECT id
        FROM schedules
        WHERE id = ?
        """,
        (schedule_id,),
    )

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Schedule not found.",
        )

    launched = await scheduler.launch_if_needed(
        schedule_id
    )

    if not launched:
        raise HTTPException(
            status_code=409,
            detail="This schedule is already running.",
        )

    return {
        "success": True,
        "schedule_id": schedule_id,
        "message": "Update run started.",
    }


# ============================================================
# Update groups
# ============================================================

@app.post("/schedules/{schedule_id}/groups")
async def create_update_group(
    schedule_id: str,
    payload: GroupCreate,
) -> Dict[str, Any]:
    schedule = db_fetchone(
        """
        SELECT id
        FROM schedules
        WHERE id = ?
        """,
        (schedule_id,),
    )

    if not schedule:
        raise HTTPException(
            status_code=404,
            detail="Schedule not found.",
        )

    group_id = str(uuid.uuid4())

    try:
        db_execute(
            """
            INSERT INTO update_groups
            (
                id,
                schedule_id,
                name,
                source_ids,
                enabled,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                group_id,
                schedule_id,
                payload.name,
                safe_json(payload.source_ids),
                int(payload.enabled),
                utc_now(),
                utc_now(),
            ),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Update group already exists.",
        )

    record_event(
        "update_group_created",
        "Update group created.",
        schedule_id=schedule_id,
        details={
            "group_id": group_id,
            "name": payload.name,
        },
    )

    return {
        "success": True,
        "group_id": group_id,
    }


@app.get("/schedules/{schedule_id}/groups")
async def list_update_groups(
    schedule_id: str,
) -> Dict[str, Any]:
    rows = db_fetchall(
        """
        SELECT *
        FROM update_groups
        WHERE schedule_id = ?
        ORDER BY name
        """,
        (schedule_id,),
    )

    return {
        "items": [
            {
                "id": row["id"],
                "name": row["name"],
                "source_ids": json.loads(
                    row["source_ids"]
                ),
                "enabled": bool(row["enabled"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]
    }


@app.delete("/groups/{group_id}")
async def delete_update_group(
    group_id: str,
) -> Dict[str, Any]:
    existing = db_fetchone(
        """
        SELECT id, schedule_id
        FROM update_groups
        WHERE id = ?
        """,
        (group_id,),
    )

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Update group not found.",
        )

    db_execute(
        """
        DELETE FROM update_groups
        WHERE id = ?
        """,
        (group_id,),
    )

    record_event(
        "update_group_deleted",
        "Update group deleted.",
        schedule_id=existing["schedule_id"],
        details={
            "group_id": group_id,
        },
    )

    return {
        "success": True,
        "group_id": group_id,
    }


# ============================================================
# Execution history
# ============================================================

@app.get("/runs")
async def list_runs(
    schedule_id: Optional[str] = Query(
        default=None
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
    ),
) -> Dict[str, Any]:
    if schedule_id:
        rows = db_fetchall(
            """
            SELECT *
            FROM execution_runs
            WHERE schedule_id = ?
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (
                schedule_id,
                limit,
            ),
        )
    else:
        rows = db_fetchall(
            """
            SELECT *
            FROM execution_runs
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        )

    return {
        "items": [
            {
                "id": row["id"],
                "schedule_id": row["schedule_id"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "status": row["status"],
                "duration_seconds": row["duration_seconds"],
                "response_status": row["response_status"],
                "response_hash": row["response_hash"],
                "response_size": row["response_size"],
                "error": row["error"],
                "details": (
                    json.loads(row["details"])
                    if row["details"]
                    else None
                ),
            }
            for row in rows
        ]
    }


@app.get("/runs/{run_id}")
async def get_run(
    run_id: str,
) -> Dict[str, Any]:
    row = db_fetchone(
        """
        SELECT *
        FROM execution_runs
        WHERE id = ?
        """,
        (run_id,),
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Run not found.",
        )

    return {
        "id": row["id"],
        "schedule_id": row["schedule_id"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "status": row["status"],
        "duration_seconds": row["duration_seconds"],
        "response_status": row["response_status"],
        "response_hash": row["response_hash"],
        "response_size": row["response_size"],
        "error": row["error"],
        "details": (
            json.loads(row["details"])
            if row["details"]
            else None
        ),
    }


# ============================================================
# Events
# ============================================================

@app.get("/events")
async def list_events(
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
) -> Dict[str, Any]:
    rows = db_fetchall(
        """
        SELECT *
        FROM scheduler_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )

    return {
        "items": [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "schedule_id": row["schedule_id"],
                "run_id": row["run_id"],
                "message": row["message"],
                "details": (
                    json.loads(row["details"])
                    if row["details"]
                    else {}
                ),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }


# ============================================================
# Data-update service bridge
# ============================================================

@app.get("/data-update/health")
async def data_update_health() -> Dict[str, Any]:
    try:
        result = await data_update_client.health()

        return {
            "available": True,
            "service": DATA_UPDATE_URL,
            "result": result,
        }

    except Exception as exc:
        return {
            "available": False,
            "service": DATA_UPDATE_URL,
            "error": str(exc),
        }


@app.get("/data-update/sources")
async def data_update_sources() -> Dict[str, Any]:
    try:
        result = await data_update_client.sources()

        return {
            "success": True,
            "result": result,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


@app.post("/data-update/run")
async def data_update_run() -> Dict[str, Any]:
    try:
        result = await data_update_client.run_updates()

        record_event(
            "manual_global_update",
            "Manual global data update executed.",
        )

        return {
            "success": True,
            "result": result,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


# ============================================================
# Statistics
# ============================================================

@app.get("/stats")
async def statistics() -> Dict[str, Any]:
    schedule_count = db_fetchone(
        """
        SELECT COUNT(*) AS count
        FROM schedules
        """
    )

    enabled_schedule_count = db_fetchone(
        """
        SELECT COUNT(*) AS count
        FROM schedules
        WHERE enabled = 1
        """
    )

    run_count = db_fetchone(
        """
        SELECT COUNT(*) AS count
        FROM execution_runs
        """
    )

    success_count = db_fetchone(
        """
        SELECT COUNT(*) AS count
        FROM execution_runs
        WHERE status = 'success'
        """
    )

    failure_count = db_fetchone(
        """
        SELECT COUNT(*) AS count
        FROM execution_runs
        WHERE status = 'failed'
        """
    )

    return {
        "schedules": {
            "total": schedule_count["count"],
            "enabled": enabled_schedule_count["count"],
        },
        "runs": {
            "total": run_count["count"],
            "success": success_count["count"],
            "failed": failure_count["count"],
        },
        "currently_running": len(RUNNING_JOBS),
        "scheduler_enabled": scheduler_enabled_from_db(),
        "timestamp": utc_now(),
    }


# ============================================================
# Cleanup
# ============================================================

@app.post("/maintenance/cleanup")
async def cleanup_history(
    keep_runs: int = Query(
        default=1000,
        ge=100,
        le=100000,
    ),
    keep_events: int = Query(
        default=2000,
        ge=100,
        le=100000,
    ),
) -> Dict[str, Any]:
    with DB_LOCK:
        connection = get_connection()

        try:
            connection.execute(
                """
                DELETE FROM execution_runs
                WHERE id NOT IN (
                    SELECT id
                    FROM execution_runs
                    ORDER BY started_at DESC
                    LIMIT ?
                )
                """,
                (keep_runs,),
            )

            connection.execute(
                """
                DELETE FROM scheduler_events
                WHERE id NOT IN (
                    SELECT id
                    FROM scheduler_events
                    ORDER BY id DESC
                    LIMIT ?
                )
                """,
                (keep_events,),
            )

            connection.commit()

        finally:
            connection.close()

    record_event(
        "history_cleanup",
        "Scheduler history cleanup completed.",
        details={
            "keep_runs": keep_runs,
            "keep_events": keep_events,
        },
    )

    return {
        "success": True,
        "keep_runs": keep_runs,
        "keep_events": keep_events,
    }


# ============================================================
# Local execution
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "modules.arya_auto_update_scheduler:app",
        host=HOST,
        port=PORT,
        reload=False,
    )
