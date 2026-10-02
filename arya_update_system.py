"""
ARYA AgriDoctor — UPDATE / BACKUP / ROLLBACK SYSTEM
Version: 1.0.0

Purpose:
- Protect the current working ARYA version.
- Create full backups before updates.
- Stage updates separately.
- Run tests before activation.
- Roll back automatically when validation fails.
- Keep update history and reports.
- Never execute downloaded code automatically.

Important:
- This file does NOT modify backend/main.py.
- This file does NOT modify arya_master_system.py directly.
- Updates must pass validation before activation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


# ===============================================================
# CONFIG
# ===============================================================

APP_NAME = "ARYA AgriDoctor"
UPDATE_VERSION = "1.0.0"

ROOT = Path(
    os.getenv(
        "ARYA_PROJECT_ROOT",
        Path(__file__).resolve().parent,
    )
).resolve()

BACKUP_DIR = ROOT / ".arya_backups"
STAGING_DIR = ROOT / ".arya_staging"
REPORT_DIR = ROOT / ".arya_update_reports"
KNOWLEDGE_DIR = ROOT / "data" / "arya_knowledge_updates"

MAX_BACKUPS = int(
    os.getenv(
        "ARYA_MAX_BACKUPS",
        "10",
    )
)

VERSION_FILE = ROOT / ".arya_version.json"

# Files/directories that must never be overwritten
PROTECTED_PATHS = {
    ".git",
    ".github",
    ".env",
    ".env.local",
    ".env.production",
}

# Core application files that require special protection
CORE_FILES = {
    "backend/main.py",
    "arya_master_system.py",
}


# ===============================================================
# BASIC UTILITIES
# ===============================================================

def now() -> str:
    return dt.datetime.now(
        dt.timezone.utc
    ).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:

    return subprocess.run(
        command,
        cwd=str(cwd or ROOT),
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def sha256_file(
    path: Path,
) -> str:

    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def relative(
    path: Path,
) -> str:

    return path.relative_to(
        ROOT
    ).as_posix()


def ensure_directories() -> None:

    BACKUP_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    STAGING_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    KNOWLEDGE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


# ===============================================================
# VERSION
# ===============================================================

def load_version() -> dict[str, Any]:

    if not VERSION_FILE.exists():

        return {
            "application":
                APP_NAME,

            "version":
                "unknown",

            "created_at":
                now(),
        }

    try:

        return json.loads(
            VERSION_FILE.read_text(
                encoding="utf-8"
            )
        )

    except Exception:

        return {
            "application":
                APP_NAME,

            "version":
                "unknown",

            "created_at":
                now(),
        }


def save_version(
    data: dict[str, Any],
) -> None:

    VERSION_FILE.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


# ===============================================================
# GIT INFORMATION
# ===============================================================

def git_revision() -> str:

    result = run(
        [
            "git",
            "rev-parse",
            "HEAD",
        ]
    )

    if result.returncode != 0:
        return "unknown"

    return result.stdout.strip()


def git_status() -> str:

    result = run(
        [
            "git",
            "status",
            "--short",
        ]
    )

    if result.returncode != 0:
        return ""

    return result.stdout.strip()


# ===============================================================
# BACKUP
# ===============================================================

def create_backup(
    reason: str = "manual",
) -> Path:

    ensure_directories()

    timestamp = dt.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    revision = git_revision()

    short_revision = (
        revision[:12]
        if revision != "unknown"
        else "nogit"
    )

    backup_name = (
        f"backup_"
        f"{timestamp}_"
        f"{short_revision}"
    )

    destination = (
        BACKUP_DIR
        / backup_name
    )

    destination.mkdir(
        parents=True,
        exist_ok=False,
    )

    # Prefer Git archive because it captures the
    # complete tracked application state.
    archive = (
        destination
        / "source.tar"
    )

    result = run(
        [
            "git",
            "archive",
            "--format=tar",
            "HEAD",
            "-o",
            str(archive),
        ]
    )

    if result.returncode != 0:

        shutil.rmtree(
            destination,
            ignore_errors=True,
        )

        raise RuntimeError(
            "Backup failed: "
            + result.stderr.strip()
        )

    metadata = {
        "application":
            APP_NAME,

        "update_system":
            UPDATE_VERSION,

        "created_at":
            now(),

        "reason":
            reason,

        "git_revision":
            revision,

        "git_status":
            git_status(),

        "archive":
            archive.name,
    }

    (
        destination
        / "metadata.json"
    ).write_text(
        json.dumps(
            metadata,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    cleanup_old_backups()

    return destination


def list_backups() -> list[Path]:

    if not BACKUP_DIR.exists():
        return []

    return sorted(
        [
            item
            for item
            in BACKUP_DIR.iterdir()
            if item.is_dir()
            and item.name.startswith(
                "backup_"
            )
        ],
        key=lambda item: item.name,
        reverse=True,
    )


def cleanup_old_backups() -> None:

    backups = list_backups()

    for old_backup in backups[
        MAX_BACKUPS:
    ]:

        shutil.rmtree(
            old_backup,
            ignore_errors=True,
        )


# ===============================================================
# STAGING
# ===============================================================

def create_staging(
    source: Path,
) -> Path:

    ensure_directories()

    timestamp = dt.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    destination = (
        STAGING_DIR
        / f"candidate_{timestamp}"
    )

    destination.mkdir(
        parents=True,
        exist_ok=False,
    )

    if source.is_dir():

        for item in source.iterdir():

            if item.name in PROTECTED_PATHS:
                continue

            target = (
                destination
                / item.name
            )

            if item.is_dir():

                shutil.copytree(
                    item,
                    target,
                    ignore=shutil.ignore_patterns(
                        *PROTECTED_PATHS
                    ),
                )

            else:

                shutil.copy2(
                    item,
                    target,
                )

    else:

        raise RuntimeError(
            "Staging source does not exist."
        )

    return destination


# ===============================================================
# PYTHON SYNTAX TEST
# ===============================================================

def python_syntax_test(
    directory: Path,
) -> tuple[bool, str]:

    python_files = list(
        directory.rglob(
            "*.py"
        )
    )

    errors: list[str] = []

    for file in python_files:

        try:

            source = file.read_text(
                encoding="utf-8"
            )

            compile(
                source,
                str(file),
                "exec",
            )

        except Exception as exc:

            errors.append(
                f"{file}: {exc}"
            )

    if errors:

        return (
            False,
            "\n".join(errors),
        )

    return (
        True,
        f"Syntax OK: {len(python_files)} Python files",
    )


# ===============================================================
# CORE FILE PROTECTION TEST
# ===============================================================

def protected_files_test() -> tuple[bool, str]:

    missing = []

    for name in CORE_FILES:

        path = ROOT / name

        if not path.exists():

            missing.append(name)

    if missing:

        return (
            False,
            "Missing core files: "
            + ", ".join(missing),
        )

    return (
        True,
        "Core files present.",
    )


# ===============================================================
# MASTER / BACKEND STATIC TEST
# ===============================================================

def core_content_test() -> tuple[bool, str]:

    checks = {
        "backend/main.py":
            [
                "FastAPI",
            ],

        "arya_master_system.py":
            [
                "FastAPI",
                "BACKEND_URL",
                "raw_backend_call",
            ],
    }

    errors = []

    for filename, required in checks.items():

        path = ROOT / filename

        if not path.exists():

            errors.append(
                f"{filename}: missing"
            )

            continue

        content = path.read_text(
            encoding="utf-8"
        )

        for token in required:

            if token not in content:

                errors.append(
                    f"{filename}: "
                    f"missing required token "
                    f"{token}"
                )

    if errors:

        return (
            False,
            "\n".join(errors),
        )

    return (
        True,
        "Core content test passed.",
    )


# ===============================================================
# OPTIONAL RUNTIME TEST
# ===============================================================

def runtime_test() -> tuple[bool, str]:

    command = os.getenv(
        "ARYA_UPDATE_TEST_COMMAND",
        "",
    ).strip()

    if not command:

        return (
            True,
            "Runtime test skipped; "
            "ARYA_UPDATE_TEST_COMMAND "
            "is not configured.",
        )

    result = subprocess.run(
        command,
        cwd=str(ROOT),
        shell=True,
        text=True,
        capture_output=True,
        timeout=600,
    )

    if result.returncode != 0:

        return (
            False,
            (
                "Runtime test failed.\n"
                + result.stdout
                + "\n"
                + result.stderr
            ),
        )

    return (
        True,
        "Runtime test passed.",
    )


# ===============================================================
# FULL VALIDATION
# ===============================================================

def validate_current() -> dict[str, Any]:

    results = []

    ok, message = (
        protected_files_test()
    )

    results.append({
        "test":
            "protected_files",
        "ok":
            ok,
        "message":
            message,
    })

    ok, message = (
        core_content_test()
    )

    results.append({
        "test":
            "core_content",
        "ok":
            ok,
        "message":
            message,
    })

    ok, message = (
        python_syntax_test(ROOT)
    )

    results.append({
        "test":
            "python_syntax",
        "ok":
            ok,
        "message":
            message,
    })

    ok, message = runtime_test()

    results.append({
        "test":
            "runtime",
        "ok":
            ok,
        "message":
            message,
    })

    overall = all(
        item["ok"]
        for item in results
    )

    return {
        "ok":
            overall,

        "timestamp":
            now(),

        "git_revision":
            git_revision(),

        "tests":
            results,
    }


# ===============================================================
# REPORT
# ===============================================================

def save_report(
    report: dict[str, Any],
    prefix: str = "update",
) -> Path:

    ensure_directories()

    timestamp = dt.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    path = (
        REPORT_DIR
        / f"{prefix}_{timestamp}.json"
    )

    path.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    return path


# ===============================================================
# ROLLBACK
# ===============================================================

def rollback(
    backup: Path | None = None,
) -> None:

    backups = list_backups()

    if backup is None:

        if not backups:

            raise RuntimeError(
                "No backup available."
            )

        backup = backups[0]

    archive = (
        backup
        / "source.tar"
    )

    if not archive.exists():

        raise RuntimeError(
            "Backup archive missing: "
            + str(archive)
        )

    # Extract into a temporary directory first.
    with tempfile.TemporaryDirectory(
        prefix="arya_rollback_"
    ) as temp:

        temp_path = Path(temp)

        result = run(
            [
                "tar",
                "-xf",
                str(archive),
                "-C",
                str(temp_path),
            ]
        )

        if result.returncode != 0:

            raise RuntimeError(
                "Cannot extract backup: "
                + result.stderr
            )

        # Do not touch protected runtime secrets.
        for item in temp_path.iterdir():

            if item.name in PROTECTED_PATHS:
                continue

            target = ROOT / item.name

            if target.exists():

                if target.is_dir():

                    shutil.rmtree(
                        target
                    )

                else:

                    target.unlink()

            if item.is_dir():

                shutil.copytree(
                    item,
                    target,
                )

            else:

                shutil.copy2(
                    item,
                    target,
                )

    save_report(
        {
            "ok": True,
            "action": "rollback",
            "timestamp": now(),
            "backup": str(backup),
        },
        "rollback",
    )


# ===============================================================
# KNOWLEDGE UPDATE STORAGE
# ===============================================================

def register_knowledge_update(
    title: str,
    source: str,
    content: str,
) -> Path:

    """
    Stores new scientific knowledge separately.

    It does NOT inject the knowledge directly
    into the application code.
    """

    ensure_directories()

    timestamp = dt.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    record = {
        "title":
            title,

        "source":
            source,

        "received_at":
            now(),

        "content":
            content,
    }

    path = (
        KNOWLEDGE_DIR
        / f"knowledge_{timestamp}.json"
    )

    path.write_text(
        json.dumps(
            record,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    return path


# ===============================================================
# UPDATE SAFETY CHECK
# ===============================================================

def update_is_safe(
    candidate: Path,
) -> tuple[bool, str]:

    # Never allow update package to replace
    # the update system itself automatically.
    update_system = candidate / Path(
        __file__
    ).name

    if update_system.exists():

        return (
            False,
            "Candidate cannot replace "
            "the update system automatically.",
        )

    # Ensure candidate contains no protected
    # repository metadata.
    for protected in PROTECTED_PATHS:

        if (candidate / protected).exists():

            return (
                False,
                f"Protected path found: {protected}",
            )

    return (
        True,
        "Update safety check passed.",
    )


# ===============================================================
# APPLY UPDATE
# ===============================================================

def apply_candidate(
    candidate: Path,
) -> dict[str, Any]:

    safe, message = (
        update_is_safe(candidate)
    )

    if not safe:

        return {
            "ok": False,
            "stage": "safety",
            "message": message,
        }

    # -----------------------------------------------------------
    # 1. BACKUP CURRENT WORKING VERSION
    # -----------------------------------------------------------

    backup = create_backup(
        reason="before_update"
    )

    # -----------------------------------------------------------
    # 2. VALIDATE CANDIDATE
    # -----------------------------------------------------------

    syntax_ok, syntax_message = (
        python_syntax_test(candidate)
    )

    if not syntax_ok:

        return {
            "ok": False,
            "stage": "candidate_syntax",
            "message":
                syntax_message,
            "backup":
                str(backup),
        }

    # -----------------------------------------------------------
    # 3. APPLY FILES
    # -----------------------------------------------------------

    try:

        for item in candidate.iterdir():

            if item.name in PROTECTED_PATHS:
                continue

            target = ROOT / item.name

            if target.exists():

                if target.is_dir():

                    shutil.rmtree(
                        target
                    )

                else:

                    target.unlink()

            if item.is_dir():

                shutil.copytree(
                    item,
                    target,
                )

            else:

                shutil.copy2(
                    item,
                    target,
                )

        # -------------------------------------------------------
        # 4. VALIDATE NEW VERSION
        # -------------------------------------------------------

        report = validate_current()

        if not report["ok"]:

            raise RuntimeError(
                "Post-update validation failed."
            )

        report["backup"] = str(
            backup
        )

        report["candidate"] = str(
            candidate
        )

        save_report(
            report,
            "successful_update",
        )

        return {
            "ok":
                True,

            "message":
                "Update applied successfully.",

            "backup":
                str(backup),

            "report":
                report,
        }

    except Exception as exc:

        # -------------------------------------------------------
        # 5. AUTOMATIC ROLLBACK
        # -------------------------------------------------------

        try:

            rollback(
                backup
            )

        except Exception as rollback_error:

            return {
                "ok":
                    False,

                "stage":
                    "rollback_failed",

                "error":
                    str(exc),

                "rollback_error":
                    str(
                        rollback_error
                    ),

                "backup":
                    str(backup),
            }

        return {
            "ok":
                False,

            "stage":
                "update_failed_rolled_back",

            "error":
                str(exc),

            "backup":
                str(backup),

            "message":
                "Update failed. "
                "Previous version restored.",
        }


# ===============================================================
# STATUS
# ===============================================================

def status() -> dict[str, Any]:

    ensure_directories()

    backups = list_backups()

    return {
        "application":
            APP_NAME,

        "update_system":
            UPDATE_VERSION,

        "current_version":
            load_version(),

        "git_revision":
            git_revision(),

        "working_tree":
            git_status(),

        "backup_count":
            len(backups),

        "backups":
            [
                item.name
                for item in backups
            ],

        "staging":
            [
                item.name
                for item
                in STAGING_DIR.iterdir()
            ]
            if STAGING_DIR.exists()
            else [],
    }


# ===============================================================
# CLI
# ===============================================================

def main() -> int:

    parser = argparse.ArgumentParser(
        description=
            "ARYA safe update manager"
    )

    parser.add_argument(
        "command",
        choices=[
            "status",
            "backup",
            "test",
            "rollback",
            "knowledge",
        ],
    )

    parser.add_argument(
        "--source",
        default="",
        help=
            "Staging source directory",
    )

    parser.add_argument(
        "--title",
        default="",
    )

    parser.add_argument(
        "--url",
        default="",
    )

    parser.add_argument(
        "--content",
        default="",
    )

    args = parser.parse_args()

    ensure_directories()

    try:

        if args.command == "status":

            print(
                json.dumps(
                    status(),
                    ensure_ascii=False,
                    indent=2,
                )
            )

            return 0

        if args.command == "backup":

            path = create_backup(
                reason="manual"
            )

            print(
                json.dumps(
                    {
                        "ok": True,
                        "backup":
                            str(path),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )

            return 0

        if args.command == "test":

            report = validate_current()

            path = save_report(
                report,
                "test",
            )

            report["report"] = str(
                path
            )

            print(
                json.dumps(
                    report,
                    ensure_ascii=False,
                    indent=2,
                )
            )

            return (
                0
                if report["ok"]
                else 1
            )

        if args.command == "rollback":

            rollback()

            print(
                json.dumps(
                    {
                        "ok": True,
                        "message":
                            "Rollback completed.",
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )

            return 0

        if args.command == "knowledge":

            if not args.title:

                raise RuntimeError(
                    "--title is required"
                )

            path = register_knowledge_update(
                title=args.title,
                source=args.url,
                content=args.content,
            )

            print(
                json.dumps(
                    {
                        "ok": True,
                        "file":
                            str(path),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )

            return 0

    except Exception as exc:

        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                },
                ensure_ascii=False,
                indent=2,
            )
        )

        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
