"""
ARYA AgriDoctor - Secure Knowledge Update & Approval Gateway
Version: 3.0.0

Design:
- Scientific knowledge is separate from executable code.
- External sources are treated as untrusted DATA.
- Every proposed change creates a report first.
- Nothing is applied without explicit approval.
- Backups exclude secrets but include application/core files needed for recovery.
- Automatic rollback is limited to files changed by the current transaction.
- No downloaded source code is executed.
- Runtime tests are optional and must be explicitly configured.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VERSION = "3.0.0"

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

STATE_FILE = ROOT / ".arya_update_state.json"
LOCK_FILE = ROOT / ".arya_update_lock.json"

BACKUP_EXCLUDE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
}

BACKUP_EXCLUDE_DIRS = {
    ".git",
    ".arya_backups",
    ".arya_staging",
    ".arya_update_reports",
    ".pytest_cache",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".dart_tool",
    "build",
}

# These paths may be backed up and restored during explicit disaster recovery,
# but an automatic scientific knowledge update can NEVER replace them.
UPDATE_PROTECTED = {
    "backend/main.py",
    "arya_master_system.py",
    "arya_update_system.py",
    ".github",
    ".env",
    ".env.local",
    ".env.production",
}

# External sources are DATA sources only.
# New hosts must be manually reviewed before being added.
ALLOWED_SOURCE_HOSTS = {
    "fao.org",
    "www.fao.org",
    "who.int",
    "www.who.int",
    "usda.gov",
    "www.usda.gov",
    "aphis.usda.gov",
    "epa.gov",
    "www.epa.gov",
    "efsa.europa.eu",
    "www.efsa.europa.eu",
    "ippc.int",
    "www.ippc.int",
    "cgiar.org",
    "www.cgiar.org",
    "cabi.org",
    "www.cabi.org",
}

MAX_DOWNLOAD_BYTES = int(
    os.getenv("ARYA_MAX_SOURCE_BYTES", "2000000")
)

HTTP_TIMEOUT = int(
    os.getenv("ARYA_SOURCE_TIMEOUT", "20")
)

MAX_BACKUPS = int(
    os.getenv("ARYA_MAX_BACKUPS", "10")
)

# Runtime testing is opt-in.
# Never execute an arbitrary command received from an external source.
RUNTIME_TEST_COMMAND = os.getenv(
    "ARYA_UPDATE_TEST_COMMAND",
    "",
).strip()


@dataclass
class SourceRecord:
    url: str
    title: str
    retrieved_at: str
    sha256: str
    content_type: str
    bytes: int


@dataclass
class ChangeRecord:
    path: str
    action: str
    old_sha256: str | None
    new_sha256: str | None
    old_size: int
    new_size: int
    protected: bool


@dataclass
class UpdateReport:
    report_id: str
    created_at: str
    system_version: str
    status: str
    reason: str
    source_records: list[dict[str, Any]]
    knowledge_summary: dict[str, Any]
    changes: list[dict[str, Any]]
    tests: list[dict[str, Any]]
    security: list[str]
    approval_required: bool
    approval_token: str | None = None


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def safe_relative_path(value: str) -> Path:
    normalized = value.replace("\\", "/")
    p = Path(normalized)

    if p.is_absolute():
        raise ValueError(
            f"Unsafe absolute path: {value}"
        )

    if ".." in p.parts:
        raise ValueError(
            f"Unsafe traversal path: {value}"
        )

    return p


def is_excluded(path: Path) -> bool:
    r = path.resolve()

    try:
        rp = r.relative_to(ROOT)
    except ValueError:
        return True

    parts = set(rp.parts)

    if parts & BACKUP_EXCLUDE_DIRS:
        return True

    if r.name in BACKUP_EXCLUDE_NAMES:
        return True

    return False


def is_update_protected(path: Path) -> bool:
    try:
        rp = rel(path)
    except ValueError:
        return True

    for protected in UPDATE_PROTECTED:
        if (
            protected == rp
            or rp.startswith(
                protected.rstrip("/") + "/"
            )
        ):
            return True

    return False


def iter_files(base: Path = ROOT):
    for p in base.rglob("*"):
        if not p.is_file():
            continue

        if is_excluded(p):
            continue

        yield p


def json_dump(
    path: Path,
    data: Any,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    tmp = path.with_suffix(
        path.suffix + ".tmp"
    )

    tmp.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    os.replace(tmp, path)


def create_lock(
    kind: str,
    details: dict[str, Any],
) -> None:
    if LOCK_FILE.exists():
        raise RuntimeError(
            "An ARYA update transaction is already active. "
            "Do not start another transaction."
        )

    json_dump(
        LOCK_FILE,
        {
            "version": VERSION,
            "kind": kind,
            "started_at": now(),
            "details": details,
        },
    )


def clear_lock() -> None:
    try:
        LOCK_FILE.unlink()
    except FileNotFoundError:
        pass


def source_is_allowed(
    url: str,
) -> bool:
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme != "https":
        return False

    host = (
        parsed.hostname or ""
    ).lower().rstrip(".")

    return host in ALLOWED_SOURCE_HOSTS


def fetch_source(
    url: str,
    title: str = "",
) -> SourceRecord:
    if not source_is_allowed(url):
        raise ValueError(
            "Source is not on the ARYA trusted-host allow-list."
        )

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "ARYA-AgriDoctor-KnowledgeGateway/3.0",
            "Accept":
                "text/html,application/json,"
                "application/xml,text/plain",
        },
    )

    with urllib.request.urlopen(
        req,
        timeout=HTTP_TIMEOUT,
    ) as response:

        content_type = response.headers.get(
            "Content-Type",
            "",
        )

        length = response.headers.get(
            "Content-Length"
        )

        if length:
            if int(length) > MAX_DOWNLOAD_BYTES:
                raise ValueError(
                    "Source exceeds configured download limit."
                )

        data = bytearray()

        while True:
            chunk = response.read(64 * 1024)

            if not chunk:
                break

            data.extend(chunk)

            if len(data) > MAX_DOWNLOAD_BYTES:
                raise ValueError(
                    "Source exceeds configured download limit."
                )

    digest = hashlib.sha256(
        data
    ).hexdigest()

    source_dir = (
        KNOWLEDGE_DIR / "sources"
    )

    source_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    target = (
        source_dir
        / f"{digest}.source"
    )

    if not target.exists():
        target.write_bytes(
            bytes(data)
        )

    return SourceRecord(
        url=url,
        title=title or url,
        retrieved_at=now(),
        sha256=digest,
        content_type=content_type,
        bytes=len(data),
    )


def create_backup(
    reason: str,
) -> Path:

    BACKUP_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    stamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%dT%H%M%SZ"
    )

    unique = hashlib.sha256(
        os.urandom(16)
    ).hexdigest()[:8]

    backup = (
        BACKUP_DIR
        / f"backup_{stamp}_{unique}.zip"
    )

    manifest = {
        "version": VERSION,
        "created_at": now(),
        "reason": reason,
        "root": str(ROOT),
        "files": [],
    }

    with zipfile.ZipFile(
        backup,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as z:

        for path in iter_files():
            rp = rel(path)

            z.write(
                path,
                rp,
            )

            manifest["files"].append(
                {
                    "path": rp,
                    "sha256": sha256_file(path),
                    "size": path.stat().st_size,
                }
            )

        z.writestr(
            "ARYA_BACKUP_MANIFEST.json",
            json.dumps(
                manifest,
                ensure_ascii=False,
                indent=2,
            ),
        )

    # Verify backup readability.
    with zipfile.ZipFile(
        backup,
        "r",
    ) as z:

        if (
            "ARYA_BACKUP_MANIFEST.json"
            not in z.namelist()
        ):
            raise RuntimeError(
                "Backup manifest missing."
            )

    prune_backups()

    return backup


def prune_backups() -> None:
    backups = sorted(
        BACKUP_DIR.glob(
            "backup_*.zip"
        ),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    for old in backups[MAX_BACKUPS:]:
        try:
            old.unlink()
        except OSError:
            pass


def safe_extract_zip(
    archive: Path,
    destination: Path,
    members: list[str] | None = None,
) -> None:

    destination = destination.resolve()

    with zipfile.ZipFile(
        archive,
        "r",
    ) as z:

        names = (
            members
            if members is not None
            else z.namelist()
        )

        for name in names:

            if name.endswith("/"):
                continue

            candidate = safe_relative_path(
                name
            )

            target = (
                destination / candidate
            ).resolve()

            try:
                target.relative_to(
                    destination
                )
            except ValueError:
                raise RuntimeError(
                    f"Archive path escapes destination: {name}"
                )

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with z.open(
                name,
                "r",
            ) as src:

                with target.open(
                    "wb"
                ) as dst:

                    shutil.copyfileobj(
                        src,
                        dst,
                    )


def rollback_transaction(
    changed_files: list[dict[str, Any]],
    backup: Path,
) -> None:
    """
    Restore only files affected by the current transaction.

    This deliberately does NOT sweep/delete unrelated files.
    """

    with zipfile.ZipFile(
        backup,
        "r",
    ) as z:

        names = set(
            z.namelist()
        )

        for item in changed_files:

            path = safe_relative_path(
                item["path"]
            )

            live = (
                ROOT / path
            ).resolve()

            try:
                live.relative_to(ROOT)
            except ValueError:
                raise RuntimeError(
                    "Rollback target escaped project root."
                )

            action = item["action"]

            if action == "added":

                if (
                    live.exists()
                    and live.is_file()
                ):
                    live.unlink()

                continue

            if action in {
                "modified",
                "deleted",
            }:

                name = path.as_posix()

                if name not in names:
                    raise RuntimeError(
                        "Original file missing from backup: "
                        + name
                    )

                live.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                with z.open(
                    name,
                    "r",
                ) as src:

                    with live.open(
                        "wb"
                    ) as dst:

                        shutil.copyfileobj(
                            src,
                            dst,
                        )


def collect_tree(
    source: Path,
) -> dict[str, dict[str, Any]]:

    result: dict[
        str,
        dict[str, Any],
    ] = {}

    for p in iter_files(source):

        rp = (
            p.resolve()
            .relative_to(
                source.resolve()
            )
            .as_posix()
        )

        result[rp] = {
            "sha256": sha256_file(p),
            "size": p.stat().st_size,
        }

    return result


def validate_python_tree(
    base: Path,
) -> list[str]:

    errors: list[str] = []

    for p in base.rglob("*.py"):

        if is_excluded(p):
            continue

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "py_compile",
                str(p),
            ],
            cwd=str(base),
            capture_output=True,
            text=True,
            timeout=60,
        )

        if proc.returncode != 0:

            errors.append(
                f"{p}: "
                f"{proc.stderr.strip()}"
            )

    return errors


def validate_core_tokens(
    base: Path,
) -> list[str]:

    errors: list[str] = []

    required = {
        "backend/main.py": [
            "FastAPI",
        ],
        "arya_master_system.py": [
            "FastAPI",
        ],
        "arya_update_system.py": [
            "VERSION",
            "UpdateReport",
        ],
    }

    for filename, tokens in required.items():

        p = base / filename

        if not p.exists():

            errors.append(
                f"missing required file: {filename}"
            )

            continue

        text = p.read_text(
            encoding="utf-8",
            errors="replace",
        )

        for token in tokens:

            if token not in text:

                errors.append(
                    f"{filename}: "
                    f"missing required token "
                    f"{token!r}"
                )

    return errors


def run_configured_runtime_test(
    base: Path,
) -> dict[str, Any]:

    if not RUNTIME_TEST_COMMAND:

        return {
            "name":
                "configured_runtime_test",
            "status":
                "SKIPPED",
            "reason":
                "ARYA_UPDATE_TEST_COMMAND "
                "is not configured.",
        }

    import shlex

    args = shlex.split(
        RUNTIME_TEST_COMMAND,
        posix=(os.name != "nt"),
    )

    started = time.monotonic()

    proc = subprocess.run(
        args,
        cwd=str(base),
        capture_output=True,
        text=True,
        timeout=180,
        shell=False,
        env={
            **os.environ,
            "ARYA_UPDATE_TEST_MODE": "1",
        },
    )

    return {
        "name":
            "configured_runtime_test",
        "status":
            (
                "PASS"
                if proc.returncode == 0
                else "FAIL"
            ),
        "returncode":
            proc.returncode,
        "duration_seconds":
            round(
                time.monotonic() - started,
                3,
            ),
        "stdout_tail":
            proc.stdout[-4000:],
        "stderr_tail":
            proc.stderr[-4000:],
    }


def validate_tree(
    base: Path,
) -> list[dict[str, Any]]:

    results: list[
        dict[str, Any]
    ] = []

    py_errors = validate_python_tree(
        base
    )

    results.append(
        {
            "name":
                "python_syntax",
            "status":
                (
                    "PASS"
                    if not py_errors
                    else "FAIL"
                ),
            "errors":
                py_errors[:50],
        }
    )

    core_errors = validate_core_tokens(
        base
    )

    results.append(
        {
            "name":
                "core_integrity",
            "status":
                (
                    "PASS"
                    if not core_errors
                    else "FAIL"
                ),
            "errors":
                core_errors[:50],
        }
    )

    runtime = run_configured_runtime_test(
        base
    )

    results.append(runtime)

    return results


def tests_pass(
    results: list[dict[str, Any]],
) -> bool:

    return all(
        r.get("status")
        in {
            "PASS",
            "SKIPPED",
        }
        for r in results
    )


def compare_candidate(
    candidate: Path,
) -> list[ChangeRecord]:

    live = collect_tree(ROOT)
    cand = collect_tree(candidate)

    paths = sorted(
        set(live) | set(cand)
    )

    changes: list[
        ChangeRecord
    ] = []

    for rp in paths:

        old = live.get(rp)
        new = cand.get(rp)

        if (
            old
            and new
            and old["sha256"]
            == new["sha256"]
        ):
            continue

        if old and new:
            action = "modified"
        elif new:
            action = "added"
        else:
            action = "deleted"

        changes.append(
            ChangeRecord(
                path=rp,
                action=action,
                old_sha256=(
                    old["sha256"]
                    if old
                    else None
                ),
                new_sha256=(
                    new["sha256"]
                    if new
                    else None
                ),
                old_size=(
                    old["size"]
                    if old
                    else 0
                ),
                new_size=(
                    new["size"]
                    if new
                    else 0
                ),
                protected=is_update_protected(
                    ROOT / rp
                ),
            )
        )

    return changes


def security_check_changes(
    changes: list[ChangeRecord],
) -> list[str]:

    errors: list[str] = []

    for c in changes:

        if c.protected:

            errors.append(
                "Protected path cannot be "
                "changed automatically: "
                + c.path
            )

    return errors


def create_proposal(
    changes: list[ChangeRecord],
    source_records: list[SourceRecord],
    reason: str,
    knowledge_summary: dict[str, Any],
) -> Path:

    report_id = (
        datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-"
        + hashlib.sha256(
            os.urandom(16)
        ).hexdigest()[:10]
    )

    report = UpdateReport(
        report_id=report_id,
        created_at=now(),
        system_version=VERSION,
        status="PROPOSED",
        reason=reason,
        source_records=[
            asdict(s)
            for s in source_records
        ],
        knowledge_summary=(
            knowledge_summary
        ),
        changes=[
            asdict(c)
            for c in changes
        ],
        tests=[],
        security=[
            "External sources are treated "
            "as data, never executable code.",

            "Only HTTPS and an explicit "
            "trusted-host allow-list are accepted.",

            "Protected core files cannot "
            "be replaced by an automatic "
            "knowledge update.",

            "No change is applied without "
            "explicit approval.",

            "Backup is created before "
            "an approved transaction.",

            "Rollback restores only files "
            "changed by that transaction.",

            "Downloaded archives are "
            "path-validated before extraction.",
        ],
        approval_required=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        REPORT_DIR
        / f"{report_id}.json"
    )

    json_dump(
        path,
        asdict(report),
    )

    return path


def approve_report(
    report_path: Path,
) -> None:

    data = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    if data.get("status") != "PROPOSED":

        raise RuntimeError(
            "Only a PROPOSED report "
            "can be approved."
        )

    token = hashlib.sha256(
        (
            f"{data['report_id']}"
            f"|{VERSION}"
            f"|{data['created_at']}"
        ).encode()
    ).hexdigest()[:16]

    data["approval_token"] = token
    data["status"] = "APPROVED"
    data["approved_at"] = now()

    json_dump(
        report_path,
        data,
    )

    print(
        f"APPROVAL TOKEN: {token}"
    )

    print(
        "The report is approved, "
        "but no code is changed "
        "by this command."
    )


def apply_report(
    report_path: Path,
    candidate: Path,
) -> None:

    data = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    if data.get("status") != "APPROVED":

        raise RuntimeError(
            "Report must be explicitly "
            "approved first."
        )

    changes = [
        ChangeRecord(**c)
        for c in data.get(
            "changes",
            [],
        )
    ]

    security_errors = (
        security_check_changes(
            changes
        )
    )

    if security_errors:

        raise RuntimeError(
            "; ".join(
                security_errors
            )
        )

    if not candidate.resolve().is_dir():

        raise RuntimeError(
            "Candidate directory "
            "does not exist."
        )

    create_lock(
        "apply",
        {
            "report":
                str(report_path),
            "candidate":
                str(candidate),
        },
    )

    backup = None

    try:

        backup = create_backup(
            "before approved knowledge update"
        )

        results = validate_tree(
            candidate
        )

        if not tests_pass(results):

            raise RuntimeError(
                "Candidate validation "
                "failed; nothing was applied."
            )

        approved_paths = {
            c.path
            for c in changes
        }

        cand = collect_tree(
            candidate
        )

        for rp in sorted(
            approved_paths
        ):

            dst = (
                ROOT / rp
            )

            if rp not in cand:

                if (
                    dst.exists()
                    and dst.is_file()
                ):
                    dst.unlink()

                continue

            src = (
                candidate / rp
            )

            if is_update_protected(
                dst
            ):

                raise RuntimeError(
                    f"Protected file blocked: {rp}"
                )

            dst.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            # Atomic replacement.
            with src.open(
                "rb"
            ) as fsrc:

                fd, tmp_name = (
                    tempfile.mkstemp(
                        prefix=".arya-update-",
                        dir=str(
                            dst.parent
                        ),
                    )
                )

                try:

                    with os.fdopen(
                        fd,
                        "wb",
                    ) as fdst:

                        shutil.copyfileobj(
                            fsrc,
                            fdst,
                        )

                    os.replace(
                        tmp_name,
                        dst,
                    )

                finally:

                    try:
                        os.unlink(
                            tmp_name
                        )
                    except FileNotFoundError:
                        pass

        live_results = validate_tree(
            ROOT
        )

        if not tests_pass(
            live_results
        ):

            rollback_transaction(
                data["changes"],
                backup,
            )

            raise RuntimeError(
                "Post-apply tests failed. "
                "Automatic rollback completed."
            )

        data["status"] = "APPLIED"
        data["applied_at"] = now()
        data["backup"] = str(
            backup
        )
        data["post_apply_tests"] = (
            live_results
        )

        json_dump(
            report_path,
            data,
        )

    except Exception as exc:

        data["status"] = (
            "FAILED_OR_ROLLED_BACK"
        )

        data["failure"] = str(exc)

        if backup:

            data["backup"] = str(
                backup
            )

        json_dump(
            report_path,
            data,
        )

        raise

    finally:

        clear_lock()


def status() -> None:

    print(
        f"ARYA Update Gateway {VERSION}"
    )

    print(
        f"ROOT: {ROOT}"
    )

    print(
        f"BACKUPS: {BACKUP_DIR}"
    )

    print(
        f"REPORTS: {REPORT_DIR}"
    )

    print(
        f"KNOWLEDGE: {KNOWLEDGE_DIR}"
    )

    print(
        "LOCK ACTIVE: "
        + (
            "YES"
            if LOCK_FILE.exists()
            else "NO"
        )
    )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "ARYA secure knowledge "
            "update gateway"
        )
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    sub.add_parser("status")
    sub.add_parser("backup")
    sub.add_parser("test")

    p_fetch = sub.add_parser(
        "fetch"
    )

    p_fetch.add_argument(
        "url"
    )

    p_fetch.add_argument(
        "--title",
        default="",
    )

    p_report = sub.add_parser(
        "report"
    )

    p_report.add_argument(
        "--reason",
        required=True,
    )

    p_report.add_argument(
        "--candidate",
        required=True,
    )

    p_report.add_argument(
        "--source",
        action="append",
        default=[],
    )

    p_approve = sub.add_parser(
        "approve"
    )

    p_approve.add_argument(
        "--report",
        required=True,
    )

    p_apply = sub.add_parser(
        "apply"
    )

    p_apply.add_argument(
        "--report",
        required=True,
    )

    p_apply.add_argument(
        "--candidate",
        required=True,
    )

    args = parser.parse_args()

    try:

        if args.command == "status":

            status()
            return 0

        if args.command == "backup":

            create_lock(
                "backup",
                {},
            )

            try:

                print(
                    create_backup(
                        "manual backup"
                    )
                )

            finally:

                clear_lock()

            return 0

        if args.command == "test":

            results = validate_tree(
                ROOT
            )

            print(
                json.dumps(
                    results,
                    ensure_ascii=False,
                    indent=2,
                )
            )

            return (
                0
                if tests_pass(results)
                else 1
            )

        if args.command == "fetch":

            record = fetch_source(
                args.url,
                args.title,
            )

            print(
                json.dumps(
                    asdict(record),
                    ensure_ascii=False,
                    indent=2,
                )
            )

            return 0

        if args.command == "report":

            candidate = Path(
                args.candidate
            ).resolve()

            if not candidate.is_dir():

                raise RuntimeError(
                    "Candidate directory "
                    "does not exist."
                )

            sources = [
                fetch_source(u)
                for u in args.source
            ]

            changes = compare_candidate(
                candidate
            )

            errors = (
                security_check_changes(
                    changes
                )
            )

            summary = {
                "change_count":
                    len(changes),

                "added":
                    sum(
                        c.action == "added"
                        for c in changes
                    ),

                "modified":
                    sum(
                        c.action == "modified"
                        for c in changes
                    ),

                "deleted":
                    sum(
                        c.action == "deleted"
                        for c in changes
                    ),

                "protected_blocked":
                    len(errors),

                "changed_bytes":
                    sum(
                        abs(
                            c.new_size
                            - c.old_size
                        )
                        for c in changes
                    ),
            }

            path = create_proposal(
                changes,
                sources,
                args.reason,
                summary,
            )

            print(path)

            if errors:

                print(
                    json.dumps(
                        {
                            "SECURITY_BLOCK":
                                errors
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                )

                return 2

            return 0

        if args.command == "approve":

            approve_report(
                Path(
                    args.report
                ).resolve()
            )

            return 0

        if args.command == "apply":

            apply_report(
                Path(
                    args.report
                ).resolve(),
                Path(
                    args.candidate
                ).resolve(),
            )

            print(
                "UPDATE APPLIED AND VERIFIED."
            )

            return 0

    except Exception as exc:

        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
