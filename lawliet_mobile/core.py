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
        raise UserError(f"Unknown case {case!r}. Create it with: lawliet case create {case}")
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


def import_evidence(root, db, source, platform="auto", label=None, max_bytes=20 * 1024**3, max_files=100000, expand_archives=True):
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
        archive = expand_archives and source.is_file() and (zipfile.is_zipfile(source) or tarfile.is_tarfile(source))
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
            platform = "ios" if manifests or any(p.name in {"sms.db", "CallHistory.storedata", "AddressBook.sqlitedb"} or p.as_posix().endswith("/Library/Safari/History.db") for p in paths) else "android" if any("com.android." in p.as_posix() or p.name in {"mmssms.db", "contacts2.db"} for p in paths) else "unknown"
        # iTunes/Finder payload names are hashes; recover original logical paths.
        for manifest in (p for p in paths if p.name == "Manifest.db"):
            if encrypted:
                continue
            try:
                # immutable=1 ignores WAL rows; mode=ro on intake files can
                # create SHM/WAL sidecars. Resolve through a disposable copy.
                with tempfile.TemporaryDirectory(prefix="lawliet-manifest-") as tmp:
                    working = Path(tmp) / "Manifest.db"
                    shutil.copyfile(manifest, working)
                    wal = Path(str(manifest) + "-wal")
                    if wal.is_file():
                        shutil.copyfile(wal, Path(str(working) + "-wal"))
                    with closing(sqlite3.connect(working.as_uri() + "?mode=ro", uri=True)) as mdb:
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


def begin_run_index(db, run_id):
    """Opt a new run into explicit membership without rewriting legacy records."""
    if not db.execute('SELECT 1 FROM runs WHERE id=?',(run_id,)).fetchone():
        raise UserError('Cannot index an unknown analysis run.')
    db.execute('CREATE TABLE IF NOT EXISTS run_artifact_indexes(run_id TEXT PRIMARY KEY REFERENCES runs(id), schema_version INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS artifact_runs(run_id TEXT REFERENCES runs(id), artifact_id TEXT REFERENCES artifacts(id), PRIMARY KEY(run_id,artifact_id))')
    db.execute('CREATE INDEX IF NOT EXISTS artifact_runs_artifact ON artifact_runs(artifact_id)')
    db.execute('INSERT INTO run_artifact_indexes VALUES(?,1)',(run_id,))


def has_run_index(db, run_id):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='run_artifact_indexes'").fetchone():return False
    row=db.execute('SELECT schema_version FROM run_artifact_indexes WHERE run_id=?',(run_id,)).fetchone()
    if row and row[0]!=1:raise UserError('Unsupported artifact/run index version.')
    return row is not None


def add_artifact(db, evidence_id, file_id, category, timestamp, timestamp_raw, title, body, source_ref, parser, data, *, run_id=None):
    if run_id is not None:
        run=db.execute('SELECT evidence_id FROM runs WHERE id=?',(run_id,)).fetchone()
        if not run or run['evidence_id']!=evidence_id or not has_run_index(db,run_id):
            raise UserError('Artifact requires an indexed run belonging to its evidence.')
    values = (evidence_id, file_id, category, timestamp, str(timestamp_raw) if timestamp_raw is not None else None, str(title), str(body), source_ref, parser, json_text(data))
    identifier = hashlib.sha256(json_text(values).encode()).hexdigest()[:24]
    cursor = db.execute("INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?)", (identifier, *values))
    inserted=cursor.rowcount
    if run_id is not None:
        db.execute('INSERT OR IGNORE INTO artifact_runs VALUES(?,?)',(run_id,identifier))
    return inserted


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
    from .findings import verify_findings
    findings_checked=0
    try:findings_checked=verify_findings(db)
    except (UserError, sqlite3.Error) as exc:
        failures.append({"component":"saved_findings","reason":str(exc)})
    from .investigation import verify_ledger
    investigations = None
    try: investigations = verify_ledger(db)
    except (UserError, sqlite3.Error) as exc:
        failures.append({"component":"investigations","reason":str(exc)})
    from .engine_integrity import verify_outputs
    engine_outputs_checked = 0
    try: engine_outputs_checked = verify_outputs(root, db)
    except (UserError, OSError, ValueError, KeyError, TypeError) as exc:
        failures.append({"component":"engine_outputs","reason":str(exc)})
    return {"ok": not failures, "files_checked": checked, "findings_checked":findings_checked,
            "investigation_ledger": investigations, "engine_outputs_checked": engine_outputs_checked,
            "audit_head": previous, "failures": failures}


def run_scope(db, run, alias=''):
    row = db.execute('SELECT * FROM runs WHERE id=?', (run,)).fetchone()
    if not row:
        raise UserError(f'Unknown analysis run: {run}')
    if has_run_index(db,run):
        return f'{alias}id IN (SELECT artifact_id FROM artifact_runs WHERE run_id=?)', [run]
    if row['engine'] not in {'ileapp', 'aleapp', 'sqlite-dissect'}:
        raise UserError('This legacy run has no explicit artifact membership. Select its evidence/parser, or reanalyze to create an indexed run.')
    prefix = f'runs/{run}/output/'
    return f'substr({alias}source_ref,1,?)=?', [len(prefix), prefix]


def media_group_key():
    """Presentation identity for byte-backed native/ExifTool observations only."""
    return """CASE WHEN a.category='media' AND f.sha256 IS NOT NULL AND f.size IS NOT NULL
        AND ((a.parser LIKE 'native/%' AND json_extract(a.data,'$.media.file_id')=a.file_id)
          OR (a.parser='exiftool' AND (json_extract(a.data,'$.MIMEType') LIKE 'image/%'
            OR json_extract(a.data,'$.MIMEType') LIKE 'video/%'
            OR json_extract(a.data,'$.MIMEType') LIKE 'audio/%')))
        THEN 'bytes:'||f.sha256||':'||f.size ELSE 'record:'||a.id END"""


def iter_artifacts(db, query=None, category=None, evidence=None, since=None, until=None, limit=100,
                   app=None, conversation=None, participant=None, offset=0, parser=None, run=None, report=None,
                   sort_field=None, sort_direction="asc", sort_mode="text", phone_query=None, media_items=False, media_state=None, view_group=None):
    db.create_function('casefold', 1, lambda value: str(value or '').casefold(), deterministic=True)
    clauses, args = [], []
    if view_group:
        if view_group != 'browser':
            raise UserError('Unsupported evidence view group.')
        from .review_groups import evidence_group
        db.create_function('evidence_group',2,evidence_group,deterministic=True)
        clauses.append("evidence_group(a.category,json_extract(a.data,'$._leapp_report_name'))=?")
        args.append(view_group)
    if run:
        clause, params = run_scope(db, run, 'a.')
        clauses.append(clause)
        args.extend(params)
    if phone_query:
        from .phone_search import phone_digits, has_phone
        digits = phone_digits(phone_query)
        if digits is None:
            raise UserError('Enter one phone number with 7–15 digits; spaces, parentheses, dots, hyphens and a leading + are accepted. Extensions are not inferred.')
        db.create_function('has_phone', 2, has_phone, deterministic=True)
        clauses.append('has_phone(a.data,?)')
        args.append(digits)
    if query:
        clauses.append("(instr(casefold(a.title),casefold(?))>0 OR instr(casefold(a.body),casefold(?))>0 OR instr(casefold(a.data),casefold(?))>0)")
        args.extend([query] * 3)
    for column, value, operator in [("a.parser", parser, "="), ("a.category", category, "="), ("a.evidence_id", evidence, "="), ("a.timestamp", since, ">="), ("a.timestamp", until, "<=")]:
        if value:
            clauses.append(f"{column} {operator} ?")
            args.append(value)
    for key, value in [("app", app), ("conversation_id", conversation)]:
        if value:
            clauses.append(f"json_extract(a.data,'$.message.{key}')=?")
            args.append(value)
    if report:
        clauses.append("json_extract(a.data,'$._leapp_report_name')=?")
        args.append(report)
    if participant:
        clauses.append("(instr(casefold(json_extract(a.data,'$.message.sender')),casefold(?))>0 OR instr(casefold(json_extract(a.data,'$.message.recipient')),casefold(?))>0 OR instr(casefold(json_extract(a.data,'$.message.conversation')),casefold(?))>0 OR instr(casefold(json_extract(a.data,'$.message.participants')),casefold(?))>0)")
        args.extend([participant] * 4)
    if media_state:
        if media_state != 'trash' or category != 'media' or not media_items:
            raise UserError('Trash selection requires the grouped media view.')
        from .media_sources import available
        clauses.append("a.file_id IN (SELECT file_id FROM media_acquisition_sources WHERE source_kind='trash')"
                       if available(db) else '0')
    base = "SELECT a.*,f.logical_path,f.sha256 AS source_sha256 FROM artifacts a LEFT JOIN files f ON f.id=a.file_id"
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    scope_args = list(args)
    if media_items:
        if category != 'media':
            raise UserError('Media item grouping requires the media category.')
        key = media_group_key()
        sql = ("WITH ranked AS (SELECT a.*,f.logical_path,f.sha256 AS source_sha256,"
               "f.size AS source_bytes,"+key+" AS _media_key,"
               "ROW_NUMBER() OVER (PARTITION BY "+key+" ORDER BY a.timestamp IS NULL,CASE WHEN a.parser LIKE 'native/%' THEN 0 ELSE 1 END,a.id) AS _media_rank,"
               "COUNT(*) OVER (PARTITION BY "+key+") AS _media_count "
               "FROM artifacts a LEFT JOIN files f ON f.id=a.file_id"+where+") "
               "SELECT * FROM ranked a WHERE _media_rank=1")
    else:
        sql = base + where
    if sort_mode not in {'text', 'number', 'timestamp'}:
        raise UserError('Sort mode must be text, number or timestamp.')
    if sort_direction not in {'asc', 'desc'}:
        raise UserError('Sort direction must be asc or desc.')
    if sort_field:
        if not isinstance(sort_field, str):
            raise UserError('Sort field must be a report column name.')
        from .report_sort import sort_value, compare_numbers
        def report_value(raw, key):
            data = json.loads(raw)
            fields = data.get('_leapp_fields', data)
            value = fields.get(key) if isinstance(fields, dict) and '_leapp_report_name' in data else None
            return sort_value(value, sort_mode)
        db.create_function('report_value', 2, report_value, deterministic=True)
        # Bound column names also support quotes and punctuation without JSON-path escaping.
        direction = 'DESC' if sort_direction == 'desc' else 'ASC'
        db.create_collation('report_number', compare_numbers)
        collation = ' COLLATE report_number' if sort_mode == 'number' else ''
        sql += f" ORDER BY report_value(a.data,?) IS NULL,report_value(a.data,?){collation} {direction},a.id LIMIT ? OFFSET ?"
        args.extend([sort_field, sort_field])
    else:
        sql += " ORDER BY a.timestamp IS NULL,a.timestamp,a.id LIMIT ? OFFSET ?"
    args.extend([-1 if limit is None else limit, offset])
    for row in db.execute(sql, args):
        record = dict(row)
        record["data"] = json.loads(record["data"])
        if media_items:
            identity = record.pop('_media_key')
            count = record.pop('_media_count')
            record.pop('_media_rank')
            size = record.pop('source_bytes')
            if identity.startswith('bytes:'):
                scoped = base + where + (' AND ' if where else ' WHERE ') + media_group_key() + "=?"
                scoped += " ORDER BY CASE WHEN a.parser='exiftool' THEN 0 ELSE 1 END,a.timestamp IS NULL,a.id LIMIT 21"
                observations = []
                for observation in db.execute(scoped, [*scope_args, identity]):
                    value = dict(observation)
                    value['data'] = json.loads(value['data'])
                    observations.append(value)
                record['media_item'] = {'content_sha256': record['source_sha256'], 'bytes': size,
                    'observation_count': count, 'observations': observations[:20],
                    'observations_truncated': count > 20,
                    'meaning': 'Same acquired file bytes; source occurrences and parser observations remain separate. Not proof of one capture event.'}
                from .media_sources import available
                source_contexts = []
                if available(db):
                    context_query = ('SELECT DISTINCT origin.* FROM artifacts a LEFT JOIN files f ON f.id=a.file_id '
                        'JOIN media_acquisition_sources origin ON origin.file_id=a.file_id' + where +
                        (' AND ' if where else ' WHERE ') + media_group_key() + '=? ORDER BY origin.file_id LIMIT 21')
                    source_contexts = [dict(value) for value in db.execute(context_query, [*scope_args, identity])]
                record['media_item']['source_contexts'] = source_contexts[:20]
                record['media_item']['source_contexts_truncated'] = len(source_contexts) > 20
                metadata = next((value for value in observations if value['parser']=='exiftool'), None)
                if metadata:
                    record['display_body'] = metadata['body']
        yield record


def select_artifacts(db, *args, **kwargs):
    return list(iter_artifacts(db, *args, **kwargs))
