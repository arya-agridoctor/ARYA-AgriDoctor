#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ARYA AgriDoctor - Secure Update / Backup / Validation System
Version: 3.1.0

Security goals:
- LIVE_ROOT is the only tree that Apply may modify.
- Candidate/Staging trees are evaluated relative to their own root.
- Protected core files cannot be automatically replaced.
- Secrets are excluded from backups and candidates.
- ZIP traversal, symlink and special-file attacks are rejected.
- Apply requires explicit approval bound to the exact candidate hash.
- Backup is created before Apply.
- Failed Apply triggers transaction rollback.
- No shell=True.
- External scientific sources are treated as DATA, never executable code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import py_compile
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# ============================================================
# VERSION / ROOT
# ============================================================

VERSION = "3.1.0"

ROOT = Path(__file__).resolve().parent
LIVE_ROOT = ROOT

INTERNAL_DIR = LIVE_ROOT / ".arya_update"

BACKUP_DIR = INTERNAL_DIR / "backups"
REPORT_DIR = INTERNAL_DIR / "reports"
CANDIDATE_DIR = INTERNAL_DIR / "candidates"
TRANSACTION_DIR = INTERNAL_DIR / "transactions"

LOCK_FILE = INTERNAL_DIR / ".update.lock"


# ============================================================
# LIMITS
# ============================================================

DEFAULT_MAX_FILE_SIZE = 25 * 1024 * 1024
DEFAULT_MAX_ZIP_FILES = 10000
DEFAULT_TIMEOUT = int(
    os.environ.get("ARYA_UPDATE_TEST_TIMEOUT", "180")
)

DEFAULT_RUNTIME_TEST_COMMAND = os.environ.get(
    "ARYA_UPDATE_TEST_COMMAND",
    ""
).strip()


# ============================================================
# PROTECTED FILES / DIRECTORIES
# ============================================================

PROTECTED_PATHS = {
    "backend/main.py",
    "arya_master_system.py",
    "arya_update_system.py",
}

PROTECTED_DIRS = {
    ".github",
}


# ============================================================
# SECRET FILES
# ============================================================

SECRET_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
}

SECRET_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
}


# ============================================================
# EXCLUDED DIRECTORIES
# ============================================================

EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    ".arya_update",
}


# ============================================================
# TRUSTED SCIENTIFIC SOURCES
# ============================================================

ALLOWED_SOURCE_HOSTS = {
    "fao.org",
    "who.int",
    "usda.gov",
    "aphis.usda.gov",
    "epa.gov",
    "efsa.europa.eu",
    "ippc.int",
    "cgiar.org",
    "cabi.org",
}


# ============================================================
# ERRORS
# ============================================================

class UpdateError(RuntimeError):
    pass


# ============================================================
# BASIC HELPERS
# ============================================================

def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )


def rel_posix(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def safe_resolve(path: Path, base: Path) -> Path:
    """
    Resolve a path and ensure it remains inside the specified base.

    IMPORTANT:
    The base is supplied explicitly. We do NOT compare candidate
    paths against LIVE_ROOT.
    """
    base_r = base.resolve()
    p = path.resolve()

    try:
        p.relative_to(base_r)
    except ValueError as exc:
        raise UpdateError(
            f"Path escapes allowed root: {path}"
        ) from exc

    return p


# ============================================================
# SECRET / PROTECTED PATH DETECTION
# ============================================================

def is_secret_rel(rel: str) -> bool:
    p = PurePosixPath(rel)
    name = p.name

    if name in SECRET_NAMES:
        return True

    if name.startswith(".env."):
        return True

    return any(
        name.lower().endswith(suffix)
        for suffix in SECRET_SUFFIXES
    )


def is_protected_rel(rel: str) -> bool:
    p = PurePosixPath(rel)

    if rel in PROTECTED_PATHS:
        return True

    return any(
        part in PROTECTED_DIRS
        for part in p.parts
    )


def is_excluded_rel(
    rel: str,
    *,
    include_internal: bool = False,
) -> bool:

    p = PurePosixPath(rel)

    if any(
        part in EXCLUDED_DIRS
        for part in p.parts
    ):
        if (
            include_internal
            and ".arya_update" in p.parts
        ):
            return False

        return True

    if is_secret_rel(rel):
        return True

    return False


# ============================================================
# FILE ENUMERATION
# ============================================================

def iter_files(
    base: Path,
    *,
    include_internal: bool = False,
) -> Iterable[Path]:
    """
    Enumerate regular files relative to 'base'.

    CRITICAL FIX:
    Exclusions are evaluated relative to the supplied base,
    NOT relative to LIVE_ROOT.

    This allows a Candidate outside LIVE_ROOT to be correctly
    inspected.
    """

    base = base.resolve()

    if not base.is_dir():
        raise UpdateError(
            f"Not a directory: {base}"
        )

    for root, dirs, files in os.walk(
        base,
        topdown=True,
        followlinks=False,
    ):

        root_p = Path(root)

        kept_dirs = []

        for d in dirs:

            p = root_p / d

            rel = (
                p.relative_to(base)
                .as_posix()
            )

            if is_excluded_rel(
                rel,
                include_internal=include_internal,
            ):
                continue

            if p.is_symlink():
                raise UpdateError(
                    f"Symlink directory rejected: {p}"
                )

            kept_dirs.append(d)

        dirs[:] = kept_dirs

        for name in files:

            p = root_p / name

            rel = (
                p.relative_to(base)
                .as_posix()
            )

            if is_excluded_rel(
                rel,
                include_internal=include_internal,
            ):
                continue

            if p.is_symlink():
                raise UpdateError(
                    f"Symlink file rejected: {p}"
                )

            st = p.stat()

            if not stat.S_ISREG(st.st_mode):
                raise UpdateError(
                    f"Non-regular file rejected: {p}"
                )

            yield p


# ============================================================
# HASHING
# ============================================================

def sha256_file(
    path: Path,
    chunk: int = 1024 * 1024,
) -> str:

    h = hashlib.sha256()

    with path.open("rb") as f:

        while True:

            data = f.read(chunk)

            if not data:
                break

            h.update(data)

    return h.hexdigest()


def tree_manifest(
    base: Path,
    *,
    include_internal: bool = False,
) -> Dict[str, str]:

    base = base.resolve()

    result: Dict[str, str] = {}

    for path in iter_files(
        base,
        include_internal=include_internal,
    ):

        rel = (
            path.relative_to(base)
            .as_posix()
        )

        result[rel] = sha256_file(path)

    return dict(
        sorted(result.items())
    )


def tree_digest(
    manifest: Dict[str, str]
) -> str:

    h = hashlib.sha256()

    for rel, digest in sorted(
        manifest.items()
    ):

        h.update(
            rel.encode("utf-8")
        )

        h.update(b"\0")

        h.update(
            digest.encode("ascii")
        )

        h.update(b"\n")

    return h.hexdigest()


# ============================================================
# JSON ATOMIC WRITE
# ============================================================

def atomic_write_json(
    path: Path,
    obj: object,
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, tmp = tempfile.mkstemp(
        prefix=".tmp-",
        suffix=".json",
        dir=str(path.parent),
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                obj,
                f,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )

            f.write("\n")

            f.flush()
            os.fsync(f.fileno())

        os.replace(
            tmp,
            path,
        )

    finally:

        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def load_json(path: Path) -> dict:

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        obj = json.load(f)

    if not isinstance(obj, dict):
        raise UpdateError(
            f"Invalid JSON object: {path}"
        )

    return obj


# ============================================================
# BACKUP
# ============================================================

def create_backup(
    label: str = "pre-update",
) -> Path:
    """
    Full project backup.

    Secrets and updater internal files are excluded.

    Protected core files ARE included in the backup because
    they are needed for disaster recovery.
    """

    BACKUP_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    stamp = dt.datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    output = (
        BACKUP_DIR
        / f"{stamp}-{label}-{uuid.uuid4().hex[:8]}.zip"
    )

    manifest = tree_manifest(
        LIVE_ROOT
    )

    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as z:

        for rel in manifest:

            path = (
                LIVE_ROOT
                / Path(rel)
            )

            info = zipfile.ZipInfo(rel)

            info.date_time = (
                time.localtime(
                    path.stat().st_mtime
                )[:6]
            )

            info.compress_type = (
                zipfile.ZIP_DEFLATED
            )

            with path.open("rb") as f:
                z.writestr(
                    info,
                    f.read(),
                )

        metadata = {
            "version": VERSION,
            "created_at": utc_now(),
            "root": str(LIVE_ROOT),
            "tree_digest": tree_digest(
                manifest
            ),
            "file_count": len(manifest),
            "purpose": label,
        }

        z.writestr(
            ".arya_backup_manifest.json",
            json.dumps(
                metadata,
                ensure_ascii=False,
                indent=2,
            ),
        )

    return output


# ============================================================
# ZIP SECURITY
# ============================================================

def validate_zip_member(
    name: str,
) -> None:

    if not name:
        raise UpdateError(
            "Invalid ZIP member name"
        )

    if "\x00" in name:
        raise UpdateError(
            "NUL byte in ZIP member"
        )

    p = PurePosixPath(name)

    if p.is_absolute():
        raise UpdateError(
            f"Absolute ZIP path rejected: {name}"
        )

    if any(
        part in ("", ".", "..")
        for part in p.parts
    ):
        raise UpdateError(
            f"Unsafe ZIP path rejected: {name}"
        )

    if len(p.parts) > 100:
        raise UpdateError(
            f"ZIP path too deep: {name}"
        )

    if len(name) > 4096:
        raise UpdateError(
            f"ZIP path too long: {name}"
        )


def extract_zip_candidate(
    zip_path: Path,
) -> Path:

    zip_path = zip_path.resolve()

    if not zip_path.is_file():
        raise UpdateError(
            f"Candidate ZIP not found: {zip_path}"
        )

    CANDIDATE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    candidate = (
        CANDIDATE_DIR
        / uuid.uuid4().hex
    )

    candidate.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:

        with zipfile.ZipFile(
            zip_path,
            "r",
        ) as z:

            infos = z.infolist()

            if len(infos) > DEFAULT_MAX_ZIP_FILES:
                raise UpdateError(
                    "ZIP contains too many entries"
                )

            for info in infos:

                validate_zip_member(
                    info.filename
                )

                # Unix mode check.
                mode = (
                    info.external_attr
                    >> 16
                ) & 0xFFFF

                if mode:

                    file_type = stat.S_IFMT(
                        mode
                    )

                    if (
                        file_type
                        and file_type != stat.S_IFREG
                        and not info.is_dir()
                    ):
                        raise UpdateError(
                            "ZIP special/symlink entry rejected: "
                            + info.filename
                        )

                if (
                    info.file_size
                    > DEFAULT_MAX_FILE_SIZE
                ):
                    raise UpdateError(
                        "Candidate file too large: "
                        + info.filename
                    )

                target = safe_resolve(
                    candidate
                    / Path(info.filename),
                    candidate,
                )

                if info.is_dir():

                    target.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    continue

                if is_secret_rel(
                    info.filename
                ):
                    raise UpdateError(
                        "Secret file cannot enter candidate: "
                        + info.filename
                    )

                target.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                with (
                    z.open(info, "r") as src,
                    target.open("xb") as dst
                ):
                    shutil.copyfileobj(
                        src,
                        dst,
                    )

        return candidate

    except Exception:

        shutil.rmtree(
            candidate,
            ignore_errors=True,
        )

        raise


# ============================================================
# PYTHON VALIDATION
# ============================================================

def validate_python_tree(
    base: Path,
) -> List[str]:

    errors: List[str] = []

    for path in iter_files(base):

        if path.suffix.lower() != ".py":
            continue

        try:

            py_compile.compile(
                str(path),
                doraise=True,
                quiet=1,
            )

        except Exception as exc:

            errors.append(
                f"{path.relative_to(base).as_posix()}: {exc}"
            )

    return errors


# ============================================================
# CANDIDATE VALIDATION
# ============================================================

def validate_candidate(
    candidate: Path,
    candidate_type: str = "application",
) -> dict:

    candidate = candidate.resolve()

    if not candidate.is_dir():
        raise UpdateError(
            "Candidate directory does not exist"
        )

    manifest = tree_manifest(
        candidate
    )

    if not manifest:
        raise UpdateError(
            "Candidate is empty"
        )

    errors: List[str] = []

    if candidate_type == "application":

        errors.extend(
            validate_python_tree(
                candidate
            )
        )

        required = {
            "backend",
            "arya_main",
        }

        top_dirs = {
            PurePosixPath(rel).parts[0]
            for rel in manifest
            if PurePosixPath(rel).parts
        }

        missing = sorted(
            required - top_dirs
        )

        if missing:

            errors.append(
                "Candidate is missing expected "
                "project areas: "
                + ", ".join(missing)
            )

    elif candidate_type == "knowledge":

        for rel in manifest:

            path = (
                candidate
                / Path(rel)
            )

            if (
                path.suffix.lower()
                not in {
                    ".json",
                    ".jsonl",
                    ".md",
                    ".txt",
                    ".csv",
                }
            ):

                errors.append(
                    "Knowledge candidate contains "
                    f"unsupported file type: {rel}"
                )

    else:

        raise UpdateError(
            f"Unknown candidate type: {candidate_type}"
        )

    return {
        "valid": not errors,
        "errors": errors,
        "file_count": len(manifest),
        "tree_digest": tree_digest(
            manifest
        ),
        "manifest": manifest,
        "candidate_type": candidate_type,
    }


# ============================================================
# CANDIDATE / LIVE COMPARISON
# ============================================================

def compare_candidate(
    candidate: Path,
) -> dict:
    """
    Compare Candidate against LIVE_ROOT.

    IMPORTANT:
    Candidate enumeration uses candidate as its root.
    Live enumeration uses LIVE_ROOT as its root.

    Candidate is NEVER interpreted relative to LIVE_ROOT.
    """

    candidate = candidate.resolve()

    live = tree_manifest(
        LIVE_ROOT
    )

    cand = tree_manifest(
        candidate
    )

    added = sorted(
        set(cand)
        - set(live)
    )

    removed = sorted(
        set(live)
        - set(cand)
    )

    changed = sorted(
        p
        for p in (
            set(live)
            & set(cand)
        )
        if live[p] != cand[p]
    )

    protected_changes = sorted(
        p
        for p in (
            set(changed)
            | set(added)
        )
        if is_protected_rel(p)
    )

    secret_changes = sorted(
        p
        for p in (
            set(changed)
            | set(added)
        )
        if is_secret_rel(p)
    )

    changed_bytes = 0
    added_bytes = 0
    removed_bytes = 0

    for rel in changed:

        changed_bytes += (
            candidate
            / Path(rel)
        ).stat().st_size

    for rel in added:

        added_bytes += (
            candidate
            / Path(rel)
        ).stat().st_size

    for rel in removed:

        removed_bytes += (
            LIVE_ROOT
            / Path(rel)
        ).stat().st_size

    total_candidate_bytes = sum(
        (
            candidate
            / Path(rel)
        ).stat().st_size
        for rel in cand
    )

    return {
        "live_tree_digest": tree_digest(
            live
        ),
        "candidate_tree_digest": tree_digest(
            cand
        ),
        "added": added,
        "removed": removed,
        "changed": changed,
        "protected_changes": protected_changes,
        "secret_changes": secret_changes,
        "added_bytes": added_bytes,
        "changed_bytes": changed_bytes,
        "removed_bytes": removed_bytes,
        "total_candidate_bytes": total_candidate_bytes,
    }


# ============================================================
# REPORT
# ============================================================

def make_report(
    candidate: Path,
    *,
    candidate_type: str,
    source_urls: Optional[
        Sequence[str]
    ] = None,
    source_notes: Optional[
        Sequence[str]
    ] = None,
) -> Path:

    validation = validate_candidate(
        candidate,
        candidate_type,
    )

    comparison = compare_candidate(
        candidate
    )

    report_id = uuid.uuid4().hex

    report = {
        "schema": 1,
        "report_id": report_id,
        "created_at": utc_now(),
        "updater_version": VERSION,
        "candidate_type": candidate_type,

        "candidate_tree_digest":
            validation[
                "tree_digest"
            ],

        "validation": validation,

        "comparison": comparison,

        "source_urls":
            list(source_urls or []),

        "source_notes":
            list(source_notes or []),

        "approval": {
            "approved": False,
            "approved_at": None,
            "candidate_tree_digest": None,
        },

        "policy": {
            "protected_files_are_never_auto_replaced":
                True,

            "secrets_are_never_imported":
                True,

            "scientific_source_is_data_only":
                True,
        },
    }

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        REPORT_DIR
        / f"{report_id}.json"
    )

    atomic_write_json(
        path,
        report,
    )

    return path


# ============================================================
# APPROVAL
# ============================================================

def approve_report(
    report_path: Path,
) -> dict:

    report = load_json(
        report_path
    )

    expected = report.get(
        "candidate_tree_digest"
    )

    comparison = report.get(
        "comparison",
        {},
    )

    if not expected:
        raise UpdateError(
            "Report has no candidate digest"
        )

    if (
        comparison.get(
            "candidate_tree_digest"
        )
        != expected
    ):
        raise UpdateError(
            "Report candidate digest is invalid"
        )

    report["approval"] = {
        "approved": True,
        "approved_at": utc_now(),
        "candidate_tree_digest": expected,
    }

    atomic_write_json(
        report_path,
        report,
    )

    return report


# ============================================================
# LOCK
# ============================================================

def acquire_lock() -> None:

    INTERNAL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    if LOCK_FILE.exists():

        try:
            info = load_json(
                LOCK_FILE
            )

        except Exception:

            info = {
                "raw":
                    LOCK_FILE.read_text(
                        encoding="utf-8",
                        errors="replace",
                    )
            }

        raise UpdateError(
            "Update lock exists: "
            + json.dumps(
                info,
                ensure_ascii=False,
            )
        )

    payload = {
        "pid": os.getpid(),
        "created_at": utc_now(),
        "version": VERSION,
    }

    fd = os.open(
        str(LOCK_FILE),
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL,
        0o600,
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                payload,
                f,
                indent=2,
            )

            f.flush()
            os.fsync(f.fileno())

    except Exception:

        try:
            LOCK_FILE.unlink()
        except OSError:
            pass

        raise


def release_lock() -> None:

    try:
        LOCK_FILE.unlink()

    except FileNotFoundError:
        pass


# ============================================================
# COPY CANDIDATE TO LIVE
# ============================================================

def copy_candidate_to_live(
    candidate: Path,
    *,
    changed_paths: Sequence[str],
    added_paths: Sequence[str],
) -> List[str]:

    touched: List[str] = []

    for rel in sorted(
        set(changed_paths)
        | set(added_paths)
    ):

        if is_protected_rel(rel):

            raise UpdateError(
                "Protected file change blocked: "
                + rel
            )

        if is_secret_rel(rel):

            raise UpdateError(
                "Secret file change blocked: "
                + rel
            )

        src = safe_resolve(
            candidate / Path(rel),
            candidate,
        )

        dst = safe_resolve(
            LIVE_ROOT / Path(rel),
            LIVE_ROOT,
        )

        if not src.is_file():

            raise UpdateError(
                "Candidate file missing: "
                + rel
            )

        dst.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        fd, tmp = tempfile.mkstemp(
            prefix=f".arya-{dst.name}-",
            dir=str(dst.parent),
        )

        try:

            with os.fdopen(
                fd,
                "wb",
            ) as out, src.open("rb") as inp:

                shutil.copyfileobj(
                    inp,
                    out,
                )

                out.flush()
                os.fsync(out.fileno())

            os.replace(
                tmp,
                dst,
            )

        finally:

            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

        touched.append(rel)

    return touched


# ============================================================
# REMOVE LIVE FILES
# ============================================================

def remove_live_files(
    rel_paths: Sequence[str],
) -> None:

    for rel in rel_paths:

        if is_protected_rel(rel):

            raise UpdateError(
                "Removal of protected file blocked: "
                + rel
            )

        if is_secret_rel(rel):

            raise UpdateError(
                "Removal of secret file blocked: "
                + rel
            )

        dst = safe_resolve(
            LIVE_ROOT / Path(rel),
            LIVE_ROOT,
        )

        if dst.exists():

            if not dst.is_file():

                raise UpdateError(
                    "Cannot remove non-file: "
                    + rel
                )

            dst.unlink()


# ============================================================
# RESTORE FROM BACKUP
# ============================================================

def restore_from_backup_for_paths(
    backup_zip: Path,
    paths: Sequence[str],
) -> None:

    if not backup_zip.is_file():

        raise UpdateError(
            f"Backup not found: {backup_zip}"
        )

    with zipfile.ZipFile(
        backup_zip,
        "r",
    ) as z:

        names = set(
            z.namelist()
        )

        for rel in paths:

            if rel not in names:
                continue

            validate_zip_member(rel)

            if is_secret_rel(rel):

                raise UpdateError(
                    "Refusing to restore secret file"
                )

            dst = safe_resolve(
                LIVE_ROOT / Path(rel),
                LIVE_ROOT,
            )

            dst.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            fd, tmp = tempfile.mkstemp(
                prefix=".arya-restore-",
                dir=str(dst.parent),
            )

            try:

                with os.fdopen(
                    fd,
                    "wb",
                ) as out, z.open(
                    rel,
                    "r",
                ) as src:

                    shutil.copyfileobj(
                        src,
                        out,
                    )

                    out.flush()
                    os.fsync(out.fileno())

                os.replace(
                    tmp,
                    dst,
                )

            finally:

                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass


# ============================================================
# RUNTIME TEST
# ============================================================

def run_runtime_test(
    command: str,
    cwd: Path,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[bool, str]:

    if not command:

        return (
            True,
            "SKIPPED: "
            "ARYA_UPDATE_TEST_COMMAND is not configured",
        )

    argv = command.split()

    if not argv:

        return (
            True,
            "SKIPPED: empty runtime command",
        )

    try:

        process = subprocess.run(
            argv,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            shell=False,
        )

        output = (
            process.stdout[-12000:]
            if process.stdout
            else ""
        )

        return (
            process.returncode == 0,
            output,
        )

    except Exception as exc:

        return (
            False,
            f"Runtime test exception: {exc}",
        )


# ============================================================
# APPLY
# ============================================================

def apply_report(
    report_path: Path,
    candidate: Path,
    *,
    runtime_command:
        str = DEFAULT_RUNTIME_TEST_COMMAND,
) -> dict:

    report = load_json(
        report_path
    )

    if not report.get(
        "approval",
        {},
    ).get(
        "approved"
    ):

        raise UpdateError(
            "Report has not been explicitly approved"
        )

    expected = report.get(
        "candidate_tree_digest"
    )

    candidate_type = report.get(
        "candidate_type",
        "application",
    )

    validation = validate_candidate(
        candidate,
        candidate_type,
    )

    if (
        validation["tree_digest"]
        != expected
    ):

        raise UpdateError(
            "Candidate changed after approval; "
            "approval is invalid"
        )

    comparison = compare_candidate(
        candidate
    )

    if (
        comparison[
            "candidate_tree_digest"
        ]
        != expected
    ):

        raise UpdateError(
            "Candidate digest changed during verification"
        )

    if comparison[
        "protected_changes"
    ]:

        raise UpdateError(
            "Protected file changes are blocked: "
            + ", ".join(
                comparison[
                    "protected_changes"
                ]
            )
        )

    if comparison[
        "secret_changes"
    ]:

        raise UpdateError(
            "Secret changes are blocked: "
            + ", ".join(
                comparison[
                    "secret_changes"
                ]
            )
        )

    if candidate_type != "application":

        raise UpdateError(
            "This Apply path installs application "
            "candidates only. Knowledge updates must "
            "be imported as data through a separate workflow."
        )

    acquire_lock()

    transaction_id = uuid.uuid4().hex

    transaction_path = (
        TRANSACTION_DIR
        / f"{transaction_id}.json"
    )

    touched = sorted(
        set(
            comparison["added"]
        )
        |
        set(
            comparison["changed"]
        )
        |
        set(
            comparison["removed"]
        )
    )

    backup = create_backup(
        f"transaction-{transaction_id}"
    )

    transaction = {
        "schema": 1,
        "transaction_id": transaction_id,
        "started_at": utc_now(),
        "status": "backup_created",
        "backup": str(backup),
        "candidate_tree_digest": expected,
        "touched": touched,
    }

    atomic_write_json(
        transaction_path,
        transaction,
    )

    try:

        transaction["status"] = (
            "applying"
        )

        atomic_write_json(
            transaction_path,
            transaction,
        )

        copy_candidate_to_live(
            candidate,
            changed_paths=
                comparison["changed"],
            added_paths=
                comparison["added"],
        )

        remove_live_files(
            comparison["removed"]
        )

        transaction[
            "status"
        ] = "post_apply_validation"

        atomic_write_json(
            transaction_path,
            transaction,
        )

        post = tree_manifest(
            LIVE_ROOT
        )

        for rel in (
            set(
                comparison["changed"]
            )
            |
            set(
                comparison["added"]
            )
        ):

            if is_protected_rel(rel):
                continue

            if rel not in post:

                raise UpdateError(
                    "Post-apply file missing: "
                    + rel
                )

            if (
                post[rel]
                != validation[
                    "manifest"
                ][rel]
            ):

                raise UpdateError(
                    "Post-apply hash mismatch: "
                    + rel
                )

        runtime_ok, runtime_output = (
            run_runtime_test(
                runtime_command,
                LIVE_ROOT,
            )
        )

        if not runtime_ok:

            raise UpdateError(
                "Runtime test failed:\n"
                + runtime_output
            )

        transaction[
            "status"
        ] = "completed"

        transaction[
            "completed_at"
        ] = utc_now()

        transaction[
            "runtime_test"
        ] = {
            "ok": runtime_ok,
            "output": runtime_output,
        }

        atomic_write_json(
            transaction_path,
            transaction,
        )

        return {
            "ok": True,
            "transaction_id":
                transaction_id,
            "backup":
                str(backup),
            "runtime_test":
                runtime_ok,
        }

    except Exception as exc:

        transaction[
            "status"
        ] = "rollback_started"

        transaction[
            "rollback_error"
        ] = None

        transaction[
            "failure"
        ] = str(exc)

        atomic_write_json(
            transaction_path,
            transaction,
        )

        try:

            # Restore ONLY paths touched by this transaction.
            restore_from_backup_for_paths(
                backup,
                touched,
            )

            # Files that did not exist in the original backup
            # were newly added by this transaction.
            with zipfile.ZipFile(
                backup,
                "r",
            ) as z:

                backup_names = {
                    name
                    for name in z.namelist()
                    if name
                    != ".arya_backup_manifest.json"
                }

            for rel in touched:

                if rel not in backup_names:

                    path = safe_resolve(
                        LIVE_ROOT / Path(rel),
                        LIVE_ROOT,
                    )

                    if (
                        path.exists()
                        and path.is_file()
                    ):

                        path.unlink()

            transaction[
                "status"
            ] = "rolled_back"

            transaction[
                "rolled_back_at"
            ] = utc_now()

            atomic_write_json(
                transaction_path,
                transaction,
            )

        except Exception as rollback_exc:

            transaction[
                "status"
            ] = "rollback_failed"

            transaction[
                "rollback_error"
            ] = str(
                rollback_exc
            )

            atomic_write_json(
                transaction_path,
                transaction,
            )

            raise UpdateError(
                "Update failed AND rollback failed: "
                + str(rollback_exc)
            ) from exc

        raise UpdateError(
            "Update failed; transaction rolled back: "
            + str(exc)
        ) from exc

    finally:

        release_lock()


# ============================================================
# SCIENTIFIC SOURCE SECURITY
# ============================================================

def source_allowed(
    url: str,
) -> bool:

    parsed = urllib.parse.urlparse(
        url
    )

    if (
        parsed.scheme.lower()
        != "https"
    ):
        return False

    host = (
        parsed.hostname
        or ""
    ).lower().rstrip(".")

    return any(
        host == allowed
        or host.endswith(
            "." + allowed
        )
        for allowed
        in ALLOWED_SOURCE_HOSTS
    )


def fetch_source(
    url: str,
    timeout: int = 20,
) -> dict:

    if not source_allowed(url):

        raise UpdateError(
            "Source host is not allow-listed: "
            + url
        )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "ARYA-AgriDoctor-Updater/3.1",
            "Accept":
                "text/html,application/json,text/plain,*/*",
        },
        method="GET",
    )

    with urllib.request.urlopen(
        request,
        timeout=timeout,
    ) as response:

        data = response.read(
            2 * 1024 * 1024 + 1
        )

        if len(data) > (
            2 * 1024 * 1024
        ):

            raise UpdateError(
                "Source response too large"
            )

        content_type = (
            response.headers.get(
                "Content-Type",
                "",
            )
        )

        return {
            "url": url,
            "fetched_at": utc_now(),
            "status": getattr(
                response,
                "status",
                200,
            ),
            "content_type":
                content_type,
            "sha256":
                hashlib.sha256(
                    data
                ).hexdigest(),
            "bytes":
                len(data),
            "content":
                data.decode(
                    "utf-8",
                    errors="replace",
                ),
        }


# ============================================================
# SCIENTIFIC KNOWLEDGE SCAN
# ============================================================

def knowledge_scan(
    urls: Sequence[str],
    notes: Sequence[str],
) -> Path:
    """
    Collect scientific sources and create a review report.

    IMPORTANT:
    This function DOES NOT decide that new information is valid
    scientific knowledge.

    It DOES NOT modify executable code.

    Human/AI review must determine:
    - whether knowledge is actually new
    - whether current knowledge already covers it
    - whether sources conflict
    - confidence
    - whether persistent storage is necessary
    - affected sections
    - affected files
    - estimated change size
    """

    sources = [
        fetch_source(url)
        for url in urls
    ]

    report_id = uuid.uuid4().hex

    report = {
        "schema": 1,

        "report_id":
            report_id,

        "created_at":
            utc_now(),

        "kind":
            "scientific_knowledge_review",

        "status":
            "REVIEW_REQUIRED",

        "sources": [
            {
                "url":
                    source["url"],

                "fetched_at":
                    source["fetched_at"],

                "status":
                    source["status"],

                "content_type":
                    source["content_type"],

                "sha256":
                    source["sha256"],

                "bytes":
                    source["bytes"],

                "content_preview":
                    source["content"][:4000],
            }

            for source in sources
        ],

        "review": {

            "new_knowledge":
                None,

            "current_knowledge_covers_it":
                None,

            "conflicts":
                None,

            "confidence":
                None,

            "persistent_update_needed":
                None,

            "affected_sections":
                [],

            "affected_files":
                [],

            "estimated_change_bytes":
                None,

            "recommended_action":
                "REVIEW_REQUIRED",
        },

        "notes":
            list(notes),

        "policy":
            (
                "External scientific content is DATA only "
                "and cannot directly modify or execute ARYA code."
            ),
    }

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        REPORT_DIR
        / f"knowledge-{report_id}.json"
    )

    atomic_write_json(
        path,
        report,
    )

    return path


# ============================================================
# SAFE OFFLINE SELF TEST
# ============================================================

def self_test() -> dict:
    """
    Offline tests.

    Does NOT modify LIVE_ROOT.
    """

    failures: List[str] = []

    with tempfile.TemporaryDirectory(
        prefix="arya-updater-test-"
    ) as temp_dir:

        sandbox = Path(temp_dir)

        live = (
            sandbox
            / "live"
        )

        candidate = (
            sandbox
            / "candidate"
        )

        live.mkdir()
        candidate.mkdir()

        # ----------------------------------------
        # LIVE PROJECT
        # ----------------------------------------

        (
            live
            / "backend"
        ).mkdir()

        (
            live
            / "backend"
            / "main.py"
        ).write_text(
            "print('protected')\n",
            encoding="utf-8",
        )

        (
            live
            / "app.py"
        ).write_text(
            "VALUE = 1\n",
            encoding="utf-8",
        )

        # ----------------------------------------
        # CANDIDATE
        # ----------------------------------------

        (
            candidate
            / "backend"
        ).mkdir()

        (
            candidate
            / "backend"
            / "main.py"
        ).write_text(
            "print('DO NOT TOUCH')\n",
            encoding="utf-8",
        )

        (
            candidate
            / "app.py"
        ).write_text(
            "VALUE = 2\n",
            encoding="utf-8",
        )

        (
            candidate
            / "new.txt"
        ).write_text(
            "new\n",
            encoding="utf-8",
        )

        # ----------------------------------------
        # MANIFEST TEST
        # ----------------------------------------

        live_manifest = tree_manifest(
            live
        )

        candidate_manifest = tree_manifest(
            candidate
        )

        if (
            "backend/main.py"
            not in live_manifest
        ):

            failures.append(
                "live manifest missed protected file"
            )

        if (
            "backend/main.py"
            not in candidate_manifest
        ):

            failures.append(
                "candidate manifest missed protected file"
            )

        if (
            "app.py"
            not in candidate_manifest
        ):

            failures.append(
                "candidate manifest missed app.py"
            )

        # ----------------------------------------
        # PROTECTED PATH TEST
        # ----------------------------------------

        if not is_protected_rel(
            "backend/main.py"
        ):

            failures.append(
                "protected path detector failed"
            )

        if is_protected_rel(
            "app.py"
        ):

            failures.append(
                "false protected path"
            )

        # ----------------------------------------
        # SOURCE TEST
        # ----------------------------------------

        if not source_allowed(
            "https://fao.org/example"
        ):

            failures.append(
                "allow-list failed"
            )

        if source_allowed(
            "http://fao.org/example"
        ):

            failures.append(
                "non-HTTPS source accepted"
            )

        if source_allowed(
            "https://evil.example/fao.org"
        ):

            failures.append(
                "untrusted source accepted"
            )

        # ----------------------------------------
        # ZIP TRAVERSAL TEST
        # ----------------------------------------

        bad_zip = (
            sandbox
            / "bad.zip"
        )

        with zipfile.ZipFile(
            bad_zip,
            "w",
        ) as z:

            z.writestr(
                "../escape.txt",
                "bad",
            )

        try:

            extract_zip_candidate(
                bad_zip
            )

            failures.append(
                "ZIP traversal was not rejected"
            )

        except UpdateError:
            pass

        # ----------------------------------------
        # CANDIDATE ROOT ISOLATION TEST
        # ----------------------------------------

        if (
            tree_digest(
                live_manifest
            )
            ==
            tree_digest(
                candidate_manifest
            )
        ):

            failures.append(
                "candidate/live digest unexpectedly identical"
            )

        # ----------------------------------------
        # SYMLINK TEST
        # ----------------------------------------

        symlink_supported = True

        try:

            symlink_path = (
                candidate
                / "bad_link"
            )

            symlink_path.symlink_to(
                live / "app.py"
            )

            try:

                list(
                    iter_files(candidate)
                )

                failures.append(
                    "candidate symlink was not rejected"
                )

            except UpdateError:
                pass

        except (
            OSError,
            NotImplementedError,
        ):

            symlink_supported = False

        # ----------------------------------------
        # PYTHON COMPILE TEST
        # ----------------------------------------

        (
            candidate
            / "valid.py"
        ).write_text(
            "VALUE = 123\n",
            encoding="utf-8",
        )

        compile_errors = (
            validate_python_tree(
                candidate
            )
        )

        if compile_errors:

            failures.append(
                "valid Python file failed compilation"
            )

    return {
        "ok":
            not failures,

        "version":
            VERSION,

        "failures":
            failures,
    }


# ============================================================
# CLI COMMANDS
# ============================================================

def cmd_backup(
    args: argparse.Namespace,
) -> None:

    print(
        create_backup(
            args.label
        )
    )


def cmd_validate(
    args: argparse.Namespace,
) -> None:

    print(
        json.dumps(
            validate_candidate(
                Path(args.candidate),
                args.type,
            ),
            ensure_ascii=False,
            indent=2,
        )
    )


def cmd_compare(
    args: argparse.Namespace,
) -> None:

    print(
        json.dumps(
            compare_candidate(
                Path(args.candidate)
            ),
            ensure_ascii=False,
            indent=2,
        )
    )


def cmd_report(
    args: argparse.Namespace,
) -> None:

    path = make_report(
        Path(args.candidate),
        candidate_type=args.type,
        source_urls=
            args.source_url or [],
        source_notes=
            args.note or [],
    )

    print(path)


def cmd_approve(
    args: argparse.Namespace,
) -> None:

    print(
        json.dumps(
            approve_report(
                Path(args.report)
            ),
            ensure_ascii=False,
            indent=2,
        )
    )


def cmd_apply(
    args: argparse.Namespace,
) -> None:

    result = apply_report(
        Path(args.report),
        Path(args.candidate),
        runtime_command=
            args.runtime_command,
    )

    print(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        )
    )


def cmd_knowledge_scan(
    args: argparse.Namespace,
) -> None:

    print(
        knowledge_scan(
            args.url,
            args.note or [],
        )
    )


def cmd_self_test(
    args: argparse.Namespace,
) -> None:

    print(
        json.dumps(
            self_test(),
            ensure_ascii=False,
            indent=2,
        )
    )


def cmd_version(
    args: argparse.Namespace,
) -> None:

    print(VERSION)


# ============================================================
# ARGUMENT PARSER
# ============================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=
            "ARYA secure backup/update/validation system"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=VERSION,
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ----------------------------------------
    # BACKUP
    # ----------------------------------------

    command = sub.add_parser(
        "backup"
    )

    command.add_argument(
        "--label",
        default="manual",
    )

    command.set_defaults(
        func=cmd_backup
    )

    # ----------------------------------------
    # VALIDATE
    # ----------------------------------------

    command = sub.add_parser(
        "validate"
    )

    command.add_argument(
        "candidate"
    )

    command.add_argument(
        "--type",
        choices=[
            "application",
            "knowledge",
        ],
        default="application",
    )

    command.set_defaults(
        func=cmd_validate
    )

    # ----------------------------------------
    # COMPARE
    # ----------------------------------------

    command = sub.add_parser(
        "compare"
    )

    command.add_argument(
        "candidate"
    )

    command.set_defaults(
        func=cmd_compare
    )

    # ----------------------------------------
    # REPORT
    # ----------------------------------------

    command = sub.add_parser(
        "report"
    )

    command.add_argument(
        "candidate"
    )

    command.add_argument(
        "--type",
        choices=[
            "application",
            "knowledge",
        ],
        default="application",
    )

    command.add_argument(
        "--source-url",
        action="append",
    )

    command.add_argument(
        "--note",
        action="append",
    )

    command.set_defaults(
        func=cmd_report
    )

    # ----------------------------------------
    # APPROVE
    # ----------------------------------------

    command = sub.add_parser(
        "approve"
    )

    command.add_argument(
        "report"
    )

    command.set_defaults(
        func=cmd_approve
    )

    # ----------------------------------------
    # APPLY
    # ----------------------------------------

    command = sub.add_parser(
        "apply"
    )

    command.add_argument(
        "report"
    )

    command.add_argument(
        "candidate"
    )

    command.add_argument(
        "--runtime-command",
        default=
            DEFAULT_RUNTIME_TEST_COMMAND,
    )

    command.set_defaults(
        func=cmd_apply
    )

    # ----------------------------------------
    # KNOWLEDGE SCAN
    # ----------------------------------------

    command = sub.add_parser(
        "knowledge-scan"
    )

    command.add_argument(
        "url",
        nargs="+",
    )

    command.add_argument(
        "--note",
        action="append",
    )

    command.set_defaults(
        func=cmd_knowledge_scan
    )

    # ----------------------------------------
    # SELF TEST
    # ----------------------------------------

    command = sub.add_parser(
        "self-test"
    )

    command.set_defaults(
        func=cmd_self_test
    )

    # ----------------------------------------
    # VERSION
    # ----------------------------------------

    command = sub.add_parser(
        "version"
    )

    command.set_defaults(
        func=cmd_version
    )

    return parser


# ============================================================
# MAIN
# ============================================================

def main(
    argv: Optional[
        Sequence[str]
    ] = None,
) -> int:

    parser = build_parser()

    args = parser.parse_args(
        argv
    )

    try:

        args.func(args)

        return 0

    except KeyboardInterrupt:

        print(
            "Interrupted.",
            file=sys.stderr,
        )

        return 130

    except UpdateError as exc:

        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return 2

    except Exception as exc:

        print(
            "UNEXPECTED ERROR: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

        return 3


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
