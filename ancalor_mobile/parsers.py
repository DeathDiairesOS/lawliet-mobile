"""Conservative native artifact parsers; no inference of missing/deleted data."""
from __future__ import annotations

import json
import re
import shutil
import sqlite3
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from contextlib import closing
from pathlib import Path

from .core import UserError, add_artifact, audit, json_text, now, verify

VERSION = "native/0.1.0"


def timestamp(value, epoch="unix", unit="seconds"):
    if value is None or value == "":
        return None
    try:
        if isinstance(value, str):
            try:
                value = float(value)
            except ValueError:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                # A timestamp without timezone must not silently become UTC.
                return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z") if parsed.tzinfo else None
        seconds = float(value)
        if unit == "milliseconds":
            seconds /= 1000
        elif unit == "nanoseconds":
            seconds /= 1_000_000_000
        base = datetime(2001, 1, 1, tzinfo=timezone.utc) if epoch == "apple" else datetime(1970, 1, 1, tzinfo=timezone.utc)
        parsed = base + timedelta(seconds=seconds)
        if not 1990 <= parsed.year <= 2200:
            return None
        return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError):
        return None


def tables(db):
    return {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def columns(db, table):
    return {row[1] for row in db.execute(f'PRAGMA table_info("{table}")')}


def get(row, *names, default=""):
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return default


def records(db, table):
    try:
        cursor = db.execute(f'SELECT rowid AS __rowid__, * FROM "{table}"')
    except sqlite3.DatabaseError:
        cursor = db.execute(f'SELECT * FROM "{table}"')
    for row in cursor:
        # Preserve blob lengths rather than dumping private/bulky binary values.
        yield {k: ({"blob_bytes": len(v)} if isinstance(v, bytes) else v) for k, v in dict(row).items()}


def parse_database(input_db, logical_path):
    names = tables(input_db)
    path = logical_path.lower()
    if "message" in names and "handle" in names and "sms" in path:
        handle_cols = columns(input_db, "handle")
        handles = {r[0]: r[1] for r in input_db.execute('SELECT ROWID,id FROM handle')} if "id" in handle_cols else {}
        for row in records(input_db, "message"):
            raw = get(row, "date", default=None)
            # Modern iOS SMS uses Apple-epoch nanoseconds; older schemas use seconds.
            unit = "nanoseconds" if raw is not None and abs(float(raw)) > 100_000_000_000 else "seconds"
            contact = handles.get(get(row, "handle_id"), "unknown")
            direction = "outgoing" if get(row, "is_from_me", default=0) else "incoming"
            yield "messages", timestamp(raw, "apple", unit), raw, f"{get(row, 'service', default='SMS')} · {direction} · {contact}", get(row, "text"), f"message:rowid={get(row, '__rowid__', default='unknown')}", row
    if "sms" in names and "body" in columns(input_db, "sms"):
        for row in records(input_db, "sms"):
            raw = get(row, "date", default=None)
            kind = {1: "incoming", 2: "outgoing", 3: "draft", 4: "outbox", 5: "failed", 6: "queued"}.get(get(row, "type"), "unknown")
            yield "messages", timestamp(raw, unit="milliseconds"), raw, f"SMS · {kind} · {get(row, 'address')}", get(row, "body"), f"sms:_id={get(row, '_id', '__rowid__')}", row
    if "ZCALLRECORD" in names:
        for row in records(input_db, "ZCALLRECORD"):
            raw = get(row, "ZDATE", default=None)
            yield "calls", timestamp(raw, "apple"), raw, f"Call · {get(row, 'ZADDRESS')}", f"Duration: {get(row, 'ZDURATION', default='unknown')} seconds", f"ZCALLRECORD:Z_PK={get(row, 'Z_PK', '__rowid__')}", row
    if "calls" in names and "number" in columns(input_db, "calls"):
        for row in records(input_db, "calls"):
            raw = get(row, "date", default=None)
            yield "calls", timestamp(raw, unit="milliseconds"), raw, f"Call · {get(row, 'number')}", f"Duration: {get(row, 'duration', default='unknown')} seconds", f"calls:_id={get(row, '_id', '__rowid__')}", row
    if {"history_visits", "history_items"} <= names:
        items = {r[0]: r[1] for r in input_db.execute("SELECT id,url FROM history_items")}
        for row in records(input_db, "history_visits"):
            raw = get(row, "visit_time", default=None)
            yield "browser", timestamp(raw, "apple"), raw, get(row, "title", default="Safari visit"), items.get(get(row, "history_item"), ""), f"history_visits:id={get(row, 'id', '__rowid__')}", row
    if "urls" in names and "last_visit_time" in columns(input_db, "urls"):
        for row in records(input_db, "urls"):
            raw = get(row, "last_visit_time", default=None)
            when = None
            try:
                when = timestamp(float(raw) / 1_000_000 - 11644473600)
            except (TypeError, ValueError):
                pass
            yield "browser", when, raw, get(row, "title", default="Chrome URL"), get(row, "url"), f"urls:id={get(row, 'id', '__rowid__')} (last recorded visit, not full visit history)", row
    if "ABPerson" in names:
        for row in records(input_db, "ABPerson"):
            raw = get(row, "ModificationDate", default=None)
            name = " ".join(str(get(row, k)) for k in ("First", "Last")).strip()
            yield "contacts", timestamp(raw, "apple"), raw, name or "Unnamed contact", get(row, "Organization"), f"ABPerson:ROWID={get(row, '__rowid__')}", row
    if "data" in names and {"mimetype_id", "data1"} <= columns(input_db, "data"):
        mimetypes = {r[0]: r[1] for r in input_db.execute("SELECT _id,mimetype FROM mimetypes")} if "mimetypes" in names else {}
        for row in records(input_db, "data"):
            mime = mimetypes.get(get(row, "mimetype_id"), "unknown")
            yield "contacts", None, None, f"Contact {get(row, 'raw_contact_id')} · {mime.rsplit('/', 1)[-1]}", get(row, "data1"), f"data:_id={get(row, '_id', '__rowid__')}", row


def native_analyze(root, db, evidence_id):
    evidence = db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not evidence:
        raise UserError(f"Unknown evidence: {evidence_id}")
    if evidence["encrypted"]:
        raise UserError("Encrypted iOS backup detected. Import a decrypted working extraction; native parsing does not decrypt backups.")
    integrity = verify(root, db)
    if not integrity["ok"]:
        raise UserError("Evidence integrity check failed. Run verify for details.")
    run_id, started = uuid.uuid4().hex[:12], now()
    db.execute("INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES(?,?,?,?,?)", (run_id, evidence_id, VERSION, started, "running"))
    audit(db, "analysis.started", {"run_id": run_id, "evidence_id": evidence_id, "engine": VERSION})
    db.commit()
    count, supported, sqlite_files, errors = 0, 0, 0, []
    file_rows = list(db.execute("SELECT * FROM files WHERE evidence_id=? ORDER BY path", (evidence_id,)))
    lookup = {row["path"]: row for row in file_rows}
    logical_lookup = {row["logical_path"]: row for row in file_rows}
    try:
        with tempfile.TemporaryDirectory(prefix="ancalor-analysis-") as tmp:
            for source in file_rows:
                path = root / "evidence" / evidence_id / source["path"]
                with path.open("rb") as handle:
                    header = handle.read(16)
                if path.name in {"logcat.txt", "getprop.txt", "packages.txt"}:
                    try:
                        for category, when, raw, title, body, reference, data in parse_android_text(path):
                            count += add_artifact(db, evidence_id, source["id"], category, when, raw, title, body, reference, VERSION, data)
                    except (OSError, ValueError) as exc:
                        errors.append({"source": source["logical_path"], "error": str(exc)})
                    continue
                if header != b"SQLite format 3\x00" or path.name == "Manifest.db":
                    continue
                sqlite_files += 1
                work = Path(tmp) / f"{source['id']}.db"
                shutil.copyfile(path, work)
                sidecars = []
                # Find WAL/SHM through logical paths as well as physical paths (hashed backups).
                for suffix in ("-wal", "-shm"):
                    sidecar = lookup.get(source["path"] + suffix) or logical_lookup.get(source["logical_path"] + suffix)
                    if sidecar:
                        shutil.copyfile(root / "evidence" / evidence_id / sidecar["path"], Path(str(work) + suffix))
                        sidecars.append({"logical_path": sidecar["logical_path"], "sha256": sidecar["sha256"]})
                file_count = 0
                try:
                    with closing(sqlite3.connect(work.as_uri() + "?mode=ro", uri=True)) as input_db:
                        input_db.row_factory = sqlite3.Row
                        input_db.execute("PRAGMA query_only=ON")
                        # Bound work on malformed/hostile schemas and huge joins.
                        deadline = time.monotonic() + 60
                        input_db.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10000)
                        for category, when, raw, title, body, reference, data in parse_database(input_db, source["logical_path"]):
                            data["timestamp_semantics"] = "UTC normalization of source field; original value preserved"
                            if sidecars:
                                data["source_sidecars"] = sidecars
                            file_count += 1
                            count += add_artifact(db, evidence_id, source["id"], category, when, raw, title, body, reference, VERSION, data)
                    supported += int(file_count > 0)
                except (sqlite3.DatabaseError, ValueError, TypeError, OverflowError) as exc:
                    errors.append({"source": source["logical_path"], "error": str(exc)})
                finally:
                    for candidate in Path(tmp).glob(f"{source['id']}.db*"):
                        candidate.unlink()
        status = "partial" if errors else "complete"
        detail = {"sqlite_files_examined": sqlite_files, "databases_with_records": supported, "errors": errors,
                  "coverage": "Native baseline parsers only. Zero records does not prove absence of activity."}
    except BaseException as exc:
        status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
        detail = {"error": str(exc)}
        db.execute("UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?", (now(), status, count, json_text(detail), run_id))
        audit(db, "analysis.finished", {"run_id": run_id, "status": status, "records": count})
        db.commit()
        raise
    db.execute("UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?", (now(), status, count, json_text(detail), run_id))
    audit(db, "analysis.finished", {"run_id": run_id, "status": status, "new_records": count, **detail})
    db.commit()
    return {"run_id": run_id, "engine": VERSION, "status": status, "new_records": count, **detail}


def parse_android_text(path):
    if path.name == "logcat.txt":
        # Output of adb logcat -d -v epoch; no year/timezone guessing.
        pattern = re.compile(r"^\s*(\d{9,}(?:\.\d+)?)\s+(\d+)\s+(\d+)\s+([VDIWEFAS])\s+(.*?):\s?(.*)$")
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, 1):
                match = pattern.match(line)
                if not match:
                    continue
                raw, pid, tid, level, tag, message = match.groups()
                yield "logs", timestamp(raw), raw, f"{level} · {tag.strip()}", message, f"line={line_number}", {"pid": pid, "tid": tid, "level": level, "tag": tag.strip(), "raw_line": line.rstrip()}
    elif path.name == "packages.txt":
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.startswith("package:"):
                    continue
                value = line.strip()[8:]
                apk, separator, package = value.rpartition("=")
                package = package if separator else value
                yield "apps", None, None, package, apk if separator else "", f"line={line_number}", {"package": package, "apk_path": apk if separator else None}
    elif path.name == "getprop.txt":
        properties = {}
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = re.match(r"^\[(.*?)\]: \[(.*?)\]$", line.strip())
                if match:
                    properties[match[1]] = match[2]
        if properties:
            yield "device", None, None, "Android system properties", f"{properties.get('ro.product.manufacturer', '')} {properties.get('ro.product.model', '')} · Android {properties.get('ro.build.version.release', 'unknown')}", "getprop output", properties
