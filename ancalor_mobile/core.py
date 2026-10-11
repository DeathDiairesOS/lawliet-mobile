"""Case storage, evidence intake, provenance and integrity verification."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import uuid
import zipfile
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


class UserError(Exception):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def json_text(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(
 id TEXT PRIMARY KEY, label TEXT, platform TEXT, input_path TEXT, imported_at TEXT,
 container_sha256 TEXT, encrypted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS files(
 id INTEGER PRIMARY KEY, evidence_id TEXT REFERENCES evidence(id), path TEXT,
 logical_path TEXT, sha256 TEXT, size INTEGER, UNIQUE(evidence_id,path));
CREATE TABLE IF NOT EXISTS runs(
 id TEXT PRIMARY KEY, evidence_id TEXT REFERENCES evidence(id), engine TEXT,
 started_at TEXT, finished_at TEXT, status TEXT, records INTEGER DEFAULT 0,
 detail TEXT);
CREATE TABLE IF NOT EXISTS artifacts(
 id TEXT PRIMARY KEY, evidence_id TEXT REFERENCES evidence(id), file_id INTEGER REFERENCES files(id),
 category TEXT, timestamp TEXT, timestamp_raw TEXT, title TEXT, body TEXT,
 source_ref TEXT, parser TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS artifacts_time ON artifacts(timestamp);
CREATE INDEX IF NOT EXISTS artifacts_evidence ON artifacts(evidence_id);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, at TEXT, action TEXT, detail TEXT, previous_hash TEXT, hash TEXT);
"""


def case_dir(workspace, case):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", case):
        raise UserError("Case ID must contain 1–80 letters, digits, underscores or hyphens.")
    return Path(workspace).expanduser().resolve() / case


@contextmanager
def connect(workspace, case):
    root = case_dir(workspace, case)
    if not (root / "case.sqlite").is_file():
        raise UserError(f"Unknown case {case!r}. Create it with: ancalor case create {case}")
    db = sqlite3.connect(root / "case.sqlite")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        yield root, db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def audit(db, action, detail):
    previous = db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    previous = previous[0] if previous else "0" * 64
    at, detail = now(), json_text(detail)
    hashed = hashlib.sha256(json_text([at, action, detail, previous]).encode()).hexdigest()
    db.execute("INSERT INTO audit(at,action,detail,previous_hash,hash) VALUES(?,?,?,?,?)",
               (at, action, detail, previous, hashed))


def create_case(workspace, case, name=None, examiner=None):
    root = case_dir(workspace, case)
    root.parent.mkdir(parents=True, exist_ok=True)
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        raise UserError(f"Case directory already exists: {root}")
    db = sqlite3.connect(root / "case.sqlite")
    db.executescript(SCHEMA)
    db.executemany("INSERT INTO meta VALUES(?,?)", [
        ("case_id", case), ("name", name or case), ("examiner", examiner or ""),
        ("created_at", now()), ("schema_version", "1")])
    audit(db, "case.created", {"case_id": case, "name": name or case})
    db.commit()
    db.close()
    return root


def _safe_name(name):
    if "\\" in name or "\x00" in name:
        raise UserError(f"Unsafe archive path: {name!r}")
    parts = PurePosixPath(name)
    if parts.is_absolute() or ".." in parts.parts or (parts.parts and ":" in parts.parts[0]):
        raise UserError(f"Unsafe archive path: {name!r}")
    return Path(*parts.parts)


def extract_archive(source, target, max_bytes=20 * 1024**3, max_files=100000):
    """Reject links, special files, traversal, duplicate paths and oversized archives."""
    total, count, seen = 0, 0, set()

    def destination(name, size):
        nonlocal total, count
        relative = _safe_name(name)
        if not relative.parts:
            raise UserError("Archive contains an empty file name.")
        if relative.as_posix() in seen:
            raise UserError(f"Duplicate archive file: {name}")
        seen.add(relative.as_posix())
        total += size
        count += 1
        if total > max_bytes or count > max_files:
            raise UserError("Archive exceeds intake limits. Increase --max-gib or --max-files deliberately.")
        result = target / relative
        result.parent.mkdir(parents=True, exist_ok=True)
        return result

    def copy_bounded(reader, result, expected):
        nonlocal total
        written = 0
        with result.open("xb") as out:
            while chunk := reader.read(1024 * 1024):
                written += len(chunk)
                if written > expected:
                    raise UserError("Archive member exceeds its declared size.")
                out.write(chunk)
        if written != expected:
            raise UserError("Truncated archive member.")

    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            for item in archive.infolist():
                _safe_name(item.filename)
                mode = item.external_attr >> 16
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                    raise UserError("Archive links and special files are not accepted.")
                if item.is_dir():
                    continue
                result = destination(item.filename, item.file_size)
                with archive.open(item) as reader:
                    copy_bounded(reader, result, item.file_size)
    else:
        with tarfile.open(source, "r:*") as archive:
            for item in archive:
                _safe_name(item.name)
                if item.isdir():
                    continue
                if not item.isfile():
                    raise UserError("Archive links and special files are not accepted.")
                result = destination(item.name, item.size)
                with archive.extractfile(item) as reader:
                    copy_bounded(reader, result, item.size)


def _copy_tree(source, target, max_bytes, max_files):
    total, count = 0, 0
    if source.is_dir():
        for current, dirs, files in os.walk(source, followlinks=False):
            for name in dirs + files:
                if (Path(current) / name).is_symlink():
                    raise UserError("Evidence contains symlinks; supply a regular-file extraction.")
            for name in files:
                original = Path(current) / name
                if not original.is_file():
                    raise UserError(f"Evidence contains a special file: {original}")
                total += original.stat().st_size
                count += 1
                if total > max_bytes or count > max_files:
                    raise UserError("Evidence exceeds intake size/file limits.")
                copied = target / original.relative_to(source)
                copied.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, copied)
    else:
        if source.stat().st_size > max_bytes:
            raise UserError("Evidence exceeds intake size limit.")
        shutil.copyfile(source, target / source.name)


def import_evidence(root, db, source, platform="auto", label=None, max_bytes=20 * 1024**3, max_files=100000):
    original = Path(source).expanduser()
    if original.is_symlink():
        raise UserError("Evidence input must not be a symlink.")
    source = original.resolve()
    if not source.exists() or not (source.is_dir() or source.is_file()):
        raise UserError(f"Evidence not found or not a regular file/directory: {source}")
    if source.is_dir() and (source == root or source in root.parents):
        raise UserError("Evidence directory must not contain the case workspace.")
    evidence_id = uuid.uuid4().hex[:12]
    parent = root / "evidence"
    parent.mkdir(exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".intake-", dir=parent))
    moved = False
    try:
        container_hash = digest(source) if source.is_file() else None
        archive = source.is_file() and (zipfile.is_zipfile(source) or tarfile.is_tarfile(source))
        if archive:
            extract_archive(source, stage, max_bytes, max_files)
            if digest(source) != container_hash:
                raise UserError("Input archive changed during intake.")
        else:
            _copy_tree(source, stage, max_bytes, max_files)
        paths = sorted(p for p in stage.rglob("*") if p.is_file())
        if not paths:
            raise UserError("Evidence contains no regular files.")
        if len(paths) > max_files or sum(p.stat().st_size for p in paths) > max_bytes:
            raise UserError("Evidence exceeds intake size/file limits.")
        records = []
        for path in paths:
            relative = path.relative_to(stage).as_posix()
            hashed = digest(path)
            if not archive and digest(source / relative if source.is_dir() else source) != hashed:
                raise UserError(f"Input changed while copying: {relative}")
            records.append([relative, relative, hashed, path.stat().st_size])
        encrypted = False
        manifests = [p for p in paths if p.name == "Manifest.plist"]
        if manifests:
            import plistlib
            try:
                plist = plistlib.loads(manifests[0].read_bytes())
                encrypted = bool(plist.get("IsEncrypted")) if isinstance(plist, dict) else False
            except (ValueError, TypeError, plistlib.InvalidFileException):
                pass
        if platform == "auto":
            platform = "ios" if manifests or any(p.name in {"sms.db", "CallHistory.storedata", "AddressBook.sqlitedb"} for p in paths) else "android" if any("com.android." in p.as_posix() or p.name in {"mmssms.db", "contacts2.db"} for p in paths) else "unknown"
        # iTunes/Finder payload names are hashes; recover original logical paths.
        for manifest in (p for p in paths if p.name == "Manifest.db"):
            if encrypted:
                continue
            try:
                with closing(sqlite3.connect(manifest.as_uri() + "?mode=ro&immutable=1", uri=True)) as mdb:
                    mapping = {str(r[0]): f"{r[1]}/{r[2]}" for r in mdb.execute("SELECT fileID,domain,relativePath FROM Files")}
                for record in records:
                    record[1] = mapping.get(Path(record[0]).name, record[1])
            except sqlite3.DatabaseError:
                pass
        stage.rename(parent / evidence_id)
        moved = True
        db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?)", (evidence_id, label or source.name, platform, str(source), now(), container_hash, int(encrypted)))
        db.executemany("INSERT INTO files(evidence_id,path,logical_path,sha256,size) VALUES(?,?,?,?,?)", [(evidence_id, *r) for r in records])
        audit(db, "evidence.imported", {"evidence_id": evidence_id, "platform": platform, "files": len(records), "bytes": sum(r[3] for r in records), "container_sha256": container_hash, "encrypted": encrypted})
        db.commit()
        return evidence_id, len(records), sum(r[3] for r in records)
    finally:
        if not moved:
            shutil.rmtree(stage)


def add_artifact(db, evidence_id, file_id, category, timestamp, timestamp_raw, title, body, source_ref, parser, data):
    values = (evidence_id, file_id, category, timestamp, str(timestamp_raw) if timestamp_raw is not None else None, str(title), str(body), source_ref, parser, json_text(data))
    identifier = hashlib.sha256(json_text(values).encode()).hexdigest()[:24]
    cursor = db.execute("INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?)", (identifier, *values))
    return cursor.rowcount


def verify(root, db):
    failures, checked = [], 0
    expected = set()
    for row in db.execute("SELECT * FROM files"):
        path = root / "evidence" / row["evidence_id"] / row["path"]
        expected.add(path)
        checked += 1
        if not path.is_file() or path.is_symlink():
            failures.append({"path": str(path), "reason": "missing or unsafe"})
        elif digest(path) != row["sha256"]:
            failures.append({"path": str(path), "reason": "SHA-256 mismatch"})
    evidence_root = root / "evidence"
    if evidence_root.exists():
        for current, dirs, files in os.walk(evidence_root, followlinks=False):
            for name in dirs + files:
                path = Path(current) / name
                if path.is_symlink() or (path.is_file() and path not in expected):
                    failures.append({"path": str(path), "reason": "untracked or unsafe file"})
    previous = "0" * 64
    for row in db.execute("SELECT * FROM audit ORDER BY id"):
        hashed = hashlib.sha256(json_text([row["at"], row["action"], row["detail"], previous]).encode()).hexdigest()
        if row["previous_hash"] != previous or row["hash"] != hashed:
            failures.append({"audit_id": row["id"], "reason": "audit chain mismatch"})
        previous = row["hash"]
    return {"ok": not failures, "files_checked": checked, "audit_head": previous, "failures": failures}


def select_artifacts(db, query=None, category=None, evidence=None, since=None, until=None, limit=100):
    clauses, args = [], []
    if query:
        clauses.append("(instr(lower(a.title),lower(?))>0 OR instr(lower(a.body),lower(?))>0 OR instr(lower(a.data),lower(?))>0)")
        args.extend([query] * 3)
    for column, value, operator in [("a.category", category, "="), ("a.evidence_id", evidence, "="), ("a.timestamp", since, ">="), ("a.timestamp", until, "<=")]:
        if value:
            clauses.append(f"{column} {operator} ?")
            args.append(value)
    sql = "SELECT a.*,f.logical_path,f.sha256 AS source_sha256 FROM artifacts a LEFT JOIN files f ON f.id=a.file_id"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY a.timestamp IS NULL,a.timestamp,a.id LIMIT ?"
    args.append(limit)
    result = []
    for row in db.execute(sql, args):
        record = dict(row)
        record["data"] = json.loads(record["data"])
        result.append(record)
    return result
