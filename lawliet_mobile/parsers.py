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

from .core import begin_run_index, UserError, add_artifact, audit, json_text, now, verify
from .messages import metadata, scope_message, telephony_records, ios_event_markers

VERSION = "native/0.1.13"
MAX_SQLITE_VALUE_BYTES = 8 * 1024**2


def _integer_time(value):
    if type(value) is int:
        return value
    if isinstance(value, str) and re.fullmatch(r'[+-]?[0-9]+', value.strip()):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _rounded_microseconds(value, unit):
    if unit == "nanoseconds":
        whole, remainder = divmod(value, 1000)
        return whole + int(remainder > 500 or (remainder == 500 and whole % 2 != 0))
    return value * (1000 if unit == "milliseconds" else 1_000_000)


def timestamp(value, epoch="unix", unit="seconds"):
    if value is None or value == "":
        return None
    try:
        integer = _integer_time(value)
        if integer is not None:
            base = datetime(2001, 1, 1, tzinfo=timezone.utc) if epoch == "apple" else datetime(1970, 1, 1, tzinfo=timezone.utc)
            parsed = base + timedelta(microseconds=_rounded_microseconds(integer, unit))
            return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") if 1990 <= parsed.year <= 2200 else None
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


def chromium_timestamp(value):
    """Chromium integer microseconds since 1601; no float precision loss."""
    if value is None or type(value) is bool:
        return None
    try:
        if isinstance(value, float) or not re.fullmatch(r"[+-]?\d+", str(value)):
            return None
        when = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value))
        return when.isoformat(timespec="microseconds").replace('+00:00', 'Z') if 1990 <= when.year <= 2200 else None
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


def android_residual_coverage(input_db, logical_path):
    """Describe retained tables outside native SMS decoding, not message claims."""
    names = tables(input_db)
    android_telephony = ('sms' in names or 'mmssms' in logical_path.lower()
                         or {'pdu', 'part'} <= names)
    selected = {}
    if android_telephony:
        for name in ('pdu', 'part', 'addr'):
            if name in names:
                selected[name] = ('MMS attachment/part candidates' if name == 'part'
                                  else 'MMS message candidates' if name == 'pdu'
                                  else 'MMS address/link candidates')
    for name in names:
        if re.search(r'(^|_)rcs($|_)', name, re.IGNORECASE):
            selected[name] = 'RCS-named table candidates (meaning not established from table name)'
    for name, category in sorted(selected.items()):
        item = {'source': logical_path, 'table': name, 'state': 'unsupported',
                'category': category, 'rows_observed': None, 'count_state': 'unknown',
                'reason': f'Table {name}: {category} are not decoded by this native SMS parser. '
                          'SMS output does not establish MMS, attachment or RCS coverage. '
                          'Retained database bytes and raw SQLite query remain available; '
                          'table rows are not inferred messages or resolved attachments.'}
        try:
            quoted = name.replace('"', '""')
            item['rows_observed'] = input_db.execute(f'SELECT count(*) FROM "{quoted}"').fetchone()[0]
            item['count_state'] = 'observed_in_supplied_sqlite_view'
            item['reason'] += f" Observed table rows: {item['rows_observed']}; zero rows does not establish missing activity."
        except sqlite3.DatabaseError as exc:
            item['count_error'] = str(exc)
            item['reason'] += ' Table row count unavailable; no absence claim.'
        yield item


def browser_download_residual_coverage(input_db, logical_path):
    """Bounded presence observations, not decoding or download-history claims."""
    names = tables(input_db)
    if not ('urls' in names
            and {'id', 'url', 'last_visit_time'} <= columns(input_db, 'urls')):
        return
    for name in ('downloads', 'downloads_url_chains'):
        if name not in names:
            continue
        item = {'source': logical_path, 'table': name, 'state': 'unsupported',
                'category': 'browser', 'schema': 'chromium-url-download-omission/1',
                'rows_observed': None, 'count_state': 'unknown',
                'reason': f'Table {name} is retained but is not decoded by the native browser parser. '
                          'URL/visit output does not establish download coverage or local/synced/webview origin. '
                          'Table names and row presence do not establish a completed download, available file bytes, '
                          'deliberate user activity or device completeness.'}
        try:
            # Fixed known names, no column values or aggregate/table-sized scan.
            present = input_db.execute(f'SELECT 1 FROM "{name}" LIMIT 1').fetchone() is not None
            item['rows_observed'] = None if present else 0
            item['count_state'] = ('nonempty_in_supplied_sqlite_view' if present
                                   else 'empty_in_supplied_sqlite_view')
            item['reason'] += (' At least one table row observed; exact count not measured.' if present
                               else ' Zero rows observed in this supplied table; no device-absence conclusion.')
        except sqlite3.DatabaseError:
            # Do not copy schema/error prose or table cell contents into diagnostics.
            item['count_state'] = 'presence_probe_unavailable'
            item['reason'] += ' Table presence probe unavailable; no empty-table conclusion.'
        yield item


def parse_database(input_db, logical_path):
    names = tables(input_db)
    path = logical_path.lower()
    if {'message','recipient','thread'} <= names and {'body','date_sent','thread_id','type'} <= columns(input_db, 'message'):
        recipients = {get(r, '_id', '__rowid__'): r for r in records(input_db, 'recipient')}
        for row in records(input_db, 'message'):
            raw = get(row, 'date_sent', default=None)
            sender = recipients.get(get(row, 'from_recipient_id'), {})
            address = get(sender, 'e164', 'system_joined_name', 'profile_joined_name')
            try:
                base_type = int(get(row, 'type')) & 31
            except (ValueError, TypeError):
                base_type = -1
            direction = 'incoming' if base_type == 20 else 'outgoing' if base_type in {21,22,23,24,25,26,28} else 'draft' if base_type == 27 else 'unknown'
            row['message'] = metadata('signal', str(get(row, 'thread_id')), address, '', direction,
                label='Signal thread ' + str(get(row, 'thread_id')), timestamp_field='date_sent',
                attachment_status='not_assessed', schema_note='Plaintext Signal message/recipient/thread schema; event rows and unknown types retained.')
            yield 'messages', timestamp(raw, unit='milliseconds'), raw, 'Signal · ' + direction, get(row, 'body'), f"message:_id={get(row, '_id', '__rowid__')}", row
        return
    if "message" in names and "handle" in names and "sms" in path:
        handle_cols = columns(input_db, "handle")
        handles = {r[0]: r[1] for r in input_db.execute('SELECT ROWID,id FROM handle')} if "id" in handle_cols else {}
        chat_links = {}
        if 'chat_message_join' in names and {'chat_id', 'message_id'} <= columns(input_db, 'chat_message_join'):
            for chat_id, message_id in input_db.execute('SELECT chat_id,message_id FROM chat_message_join'):
                chat_links.setdefault(message_id, set()).add(str(chat_id))
        for row in records(input_db, "message"):
            raw = get(row, "date", default=None)
            # Modern iOS SMS uses Apple-epoch nanoseconds; older schemas use seconds.
            unit = "nanoseconds" if raw is not None and abs(float(raw)) > 100_000_000_000 else "seconds"
            integer = _integer_time(raw)
            normalized_time = timestamp(raw, 'apple', unit)
            row['timestamp_conversion'] = {
                'source_field': 'date', 'epoch': '2001-01-01T00:00:00Z',
                'selected_unit': unit, 'unit_selection': 'Existing magnitude heuristic; not a verified schema version.',
                'normalized_resolution': 'microsecond',
                'normalization_status': 'normalized' if normalized_time is not None else 'unavailable',
                'method': 'unavailable' if raw is None else 'exact_integer_nearest_microsecond_ties_even' if integer is not None else 'floating_point_approximation',
                'limitation': 'Stored time field, not independently verified sent, received, read or human activity time. Numeric unit does not establish measurement accuracy.'}
            if integer is not None and unit == 'nanoseconds':
                row['timestamp_conversion']['source_minus_normalized_nanoseconds'] = integer - _rounded_microseconds(integer, unit) * 1000
            contact = handles.get(get(row, "handle_id"), "unknown")
            # Only SQLite INTEGER 0/1 qualify. Do not coerce text, REAL,
            # NULL, absent fields or other integers into participant roles.
            from_me = row.get("is_from_me")
            direction = ({0: "incoming", 1: "outgoing"}.get(from_me, "unknown")
                         if type(from_me) is int else "unknown")
            chats = sorted(chat_links.get(get(row, '__rowid__', 'ROWID'), set()))
            conversation = 'chat:' + ','.join(chats) if chats else 'unlinked-handle:' + str(get(row, 'handle_id', default='unknown'))
            rich_event = ios_event_markers(row)
            row['message'] = metadata(str(get(row, 'service', default='SMS')).lower(), conversation,
                contact if direction == 'incoming' else '', contact if direction == 'outgoing' else '', direction,
                chat_ids=chats, conversation_kind='stored_chat_links' if chats else 'handle_fallback_not_a_confirmed_chat',
                body_status='plaintext' if get(row, 'text') else 'opaque_body_not_decoded' if rich_event['opaque_body_fields'] else 'no_plaintext_body',
                attachment_status='not_assessed', rich_event=rich_event)
            title = f"{get(row, 'service', default='SMS')} · {direction} · {contact}"
            if rich_event['state'] == 'not_decoded':
                title = 'Undecoded message event · ' + title
            yield "messages", normalized_time, raw, title, get(row, "text"), f"message:rowid={get(row, '__rowid__', default='unknown')}", row
    if "sms" in names and "body" in columns(input_db, "sms"):
        for row in records(input_db, "sms"):
            raw = get(row, "date", default=None)
            kind = {1: "incoming", 2: "outgoing", 3: "draft", 4: "outbox", 5: "failed", 6: "queued"}.get(get(row, "type"), "unknown")
            row["message"] = metadata("sms", get(row, "thread_id", "address"),
                                      get(row, "address") if kind == "incoming" else "",
                                      get(row, "address") if kind == "outgoing" else "", kind)
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
            when = chromium_timestamp(raw)
            row['browser'] = {'record_kind': 'url_summary', 'timestamp_field': 'last_visit_time',
                              'encoding': 'microseconds since 1601-01-01 UTC', 'precision': 'microsecond',
                              'limitation': 'Aggregate URL record; not an individual visit or proof of deliberate browsing.'}
            yield "browser", when, raw, get(row, "title", default="Chrome URL"), get(row, "url"), f"urls:id={get(row, 'id', '__rowid__')} (last recorded visit, not full visit history)", row
        if 'visits' in names and {'id', 'url', 'visit_time'} <= columns(input_db, 'visits') and 'id' in columns(input_db, 'urls'):
            url_rows = {r['id']: r for r in records(input_db, 'urls')}
            for row in records(input_db, 'visits'):
                url_row = url_rows.get(row.get('url'))
                raw = row.get('visit_time')
                row['browser'] = {'record_kind': 'visit', 'url_record': url_row,
                                  'timestamp_field': 'visit_time', 'encoding': 'microseconds since 1601-01-01 UTC',
                                  'precision': 'microsecond', 'url_link_state': 'linked' if url_row else 'missing',
                                  'limitation': 'Recorded navigation may be synced, automated or redirected; it does not alone prove deliberate human browsing.'}
                yield "browser", chromium_timestamp(raw), raw, (url_row.get('title') if url_row else None) or 'Chromium visit', (url_row.get('url') if url_row else None), f"visits:id={row.get('id')} -> urls:id={row.get('url')}", row
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
    from .runner_lease import lease
    with lease(root, db):
        from .native_container import configured,analyze
        cfg=configured(root)
        import os
        if os.environ.get('LAWLIET_MCP_PROFILE')=='native-container' and cfg is None:raise UserError('Native container endpoint requires isolation; no host fallback.')
        if cfg is not None:return analyze(root,db,evidence_id,cfg)
        return _native_analyze_owned(root, db, evidence_id)


def _native_preflight(root, db, evidence_id):
    evidence = db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not evidence:
        raise UserError(f"Unknown evidence: {evidence_id}")
    # Declared proprietary containers are not native SQLite/extraction inputs.
    # Check original intake name too: archive expansion can hide its suffix.
    proprietary={'.ufdr','.ufd','.ufdx'}
    declared=[evidence['input_path'] or '']
    for item in db.execute('SELECT path,logical_path FROM files WHERE evidence_id=?',(evidence_id,)):
        declared.extend((item['path'],item['logical_path']))
    if any(Path(name).suffix.lower() in proprietary for name in declared):
        raise UserError('Unsupported native input: proprietary UFDR/UFD/UFDX container declared. '
                        'The entire native request is refused, including mixed/nested sources; '
                        'retained imported bytes are unchanged. Supply a separately scoped supported extraction or report. '
                        'This filename guard does not identify or decode proprietary formats.')
    if evidence["encrypted"]:
        from .analysis_refusal import refuse_encrypted
        refuse_encrypted(db, evidence_id, VERSION,
                         "Encrypted iOS backup detected. Import a decrypted working extraction; native parsing does not decrypt backups.")
    integrity = verify(root, db)
    if not integrity["ok"]:
        raise UserError("Evidence integrity check failed. Run verify for details.")
    return evidence


def _native_analyze_owned(root, db, evidence_id):
    evidence=_native_preflight(root,db,evidence_id)
    from .runner_lease import ownership
    owner = ownership()
    run_id, started = uuid.uuid4().hex[:12], now()
    try:
        db.execute("INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)", (run_id, evidence_id, VERSION, started, "running", json_text({'runner_ownership': owner})))
        begin_run_index(db,run_id)
        audit(db, "analysis.started", {"run_id": run_id, "evidence_id": evidence_id, "engine": VERSION, "runner_ownership": owner})
        db.commit()
    except BaseException:
        db.rollback()
        raise
    count, supported, sqlite_files, errors = 0, 0, 0, []
    unparsed_candidates = []
    file_rows = list(db.execute("SELECT * FROM files WHERE evidence_id=? ORDER BY path", (evidence_id,)))
    lookup = {row["path"]: row for row in file_rows}
    logical_lookup = {row["logical_path"]: row for row in file_rows}
    try:
        with tempfile.TemporaryDirectory(prefix="lawliet-analysis-") as tmp:
            for source in file_rows:
                path = root / "evidence" / evidence_id / source["path"]
                with path.open("rb") as handle:
                    header = handle.read(16)
                    sqlite_format_versions = handle.read(4)[2:4] if header == b"SQLite format 3\x00" else b""
                if path.name.endswith(("_sms_backup", "_mms_backup")):
                    try:
                        for category, when, raw, title, body, reference, data in telephony_records(path):
                            scope_message(data, evidence_id, str(Path(source["logical_path"]).parent))
                            count += add_artifact(db, evidence_id, source["id"], category, when, raw, title, body, reference, VERSION, data, run_id=run_id)
                    except Exception as exc:
                        if (getattr(exc, 'sqlite_errorcode', 0) or 0) & 0xff == sqlite3.SQLITE_FULL:
                            raise
                        errors.append({"source": source["logical_path"], "error": str(exc)})
                    continue
                if path.name in {"ios-apps.plist", "ios-device.plist"}:
                    try:
                        from .ios_apps import inventory_records
                        # Validate the complete bounded inventory before indexing
                        # so a malformed later entry cannot imply a clean list.
                        parsed = list(inventory_records(path))
                        for category, when, raw, title, body, reference, data in parsed:
                            count += add_artifact(db, evidence_id, source['id'], category, when, raw,
                                title, body, reference, VERSION, data, run_id=run_id)
                    except (OSError, ValueError, UserError) as exc:
                        errors.append({'source': source['logical_path'], 'error': str(exc)})
                    continue
                if Path(source['logical_path']).suffix.lower()=='.xml':
                    try:
                        from .xml_backup import xml_backup_records, xml_coverage
                        parsed=xml_backup_records(path)
                        unparsed_candidates.extend(xml_coverage(parsed,source['logical_path']))
                        for category, when, raw, title, body, reference, data in parsed:
                            scope_message(data,evidence_id,source['logical_path'])
                            count += add_artifact(db,evidence_id,source['id'],category,when,raw,title,body,reference,VERSION,data,run_id=run_id)
                    except (OSError,ValueError) as exc:
                        errors.append({'source':source['logical_path'],'error':str(exc)})
                    continue
                if Path(source['logical_path']).suffix.lower()=='.vcf':
                    try:
                        from .contacts import vcard_records
                        # Parse before inserting so a malformed later card cannot leave partial contact rows.
                        parsed=list(vcard_records(path))
                        for category, when, raw, title, body, reference, data in parsed:
                            count += add_artifact(db,evidence_id,source['id'],category,when,raw,title,body,reference,VERSION,data,run_id=run_id)
                    except (OSError,ValueError) as exc:
                        errors.append({'source':source['logical_path'],'error':str(exc)})
                    continue
                if path.name in {"logcat.txt", "getprop.txt", "packages.txt"}:
                    try:
                        for category, when, raw, title, body, reference, data in parse_android_text(path):
                            count += add_artifact(db, evidence_id, source["id"], category, when, raw, title, body, reference, VERSION, data, run_id=run_id)
                    except (OSError, ValueError) as exc:
                        errors.append({"source": source["logical_path"], "error": str(exc)})
                    continue
                if header != b"SQLite format 3\x00" or path.name == "Manifest.db":
                    if (Path(source['logical_path']).name.lower() in {'signal.db', 'msgstore.db', 'mmssms.db', 'sms.db'} or '.crypt' in path.name
                            or path.suffix.lower() in {'.backup', '.ab'}):
                        unparsed_candidates.append({'source': source['logical_path'], 'state': 'unparsed',
                            'reason': 'Non-SQLite backup/container or encrypted/unsupported data. Use a validated format-specific decoder; retained bytes alone do not establish readable messages.'})
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
                # SQLite can silently ignore an absent/bad WAL or accept a readable
                # foreign WAL. Successful SELECTs do not establish pairing/provenance.
                wal_supplied = any(item['logical_path'].endswith('-wal') for item in sidecars)
                wal_header = sqlite_format_versions == b"\x02\x02"
                unusual_header = len(sqlite_format_versions) != 2 or sqlite_format_versions not in (b"\x01\x01",b"\x02\x02")
                wal_limit = None
                if wal_supplied or wal_header or unusual_header:
                    reason = ('SQLite WAL companion supplied; pairing/provenance is unverified even when rows are readable. '
                              'SQLite may ignore malformed or mismatched frames; committed-view completeness is not established.'
                              if wal_supplied else
                              'SQLite header declares WAL mode but no WAL companion was supplied. '
                              'Only the available main-database view is examined; missing committed WAL rows cannot be excluded.')
                    if unusual_header and not wal_supplied and not wal_header:
                        reason = 'SQLite journalling mode is not established from the observed header. '
                    if unusual_header:
                        reason += ' SQLite read/write format-version bytes are unexpected or incomplete; journalling mode is not established.'
                    wal_limit = {'state':'limited', 'wal_present':wal_supplied,
                                 'wal_mode_header':wal_header, 'format_version_bytes':list(sqlite_format_versions), 'pairing':'unverified' if wal_supplied else 'not_available',
                                 'source_sha256':source['sha256'], 'sidecars':sidecars, 'reason':reason}
                file_count = 0
                file_categories = set()
                try:
                    with closing(sqlite3.connect(work.as_uri() + "?mode=ro", uri=True)) as input_db:
                        input_db.row_factory = sqlite3.Row
                        input_db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,
                                          min(input_db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), MAX_SQLITE_VALUE_BYTES))
                        input_db.execute("PRAGMA query_only=ON")
                        # Bound work on malformed/hostile schemas and huge joins.
                        deadline = time.monotonic() + 60
                        input_db.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10000)
                        from .android_mms import decode as decode_android_mms
                        mms_rows, mms_limits, mms_supported = decode_android_mms(input_db, source['logical_path'], file_rows, evidence['platform'])
                        unparsed_candidates.extend(browser_download_residual_coverage(input_db, source['logical_path']))
                        residual = list(android_residual_coverage(input_db, source['logical_path']))
                        unparsed_candidates.extend(item for item in residual if not mms_supported or item.get('table') not in {'pdu','part','addr'})
                        if not mms_supported and residual and mms_limits:
                            for item in residual:
                                item['reason'] += ' ' + mms_limits[0]['reason']
                        else:
                            unparsed_candidates.extend(mms_limits)
                        from .media import attachment_rows, resolve_attachment
                        if source['logical_path'].endswith('sms.db'):
                            for attachment in attachment_rows(input_db):
                                resolved = resolve_attachment(attachment, file_rows)
                                attachment_data = {'attachment': resolved, 'source_database': source['logical_path']}
                                if sidecars:
                                    attachment_data['source_sidecars'] = sidecars
                                if wal_limit:
                                    attachment_data['sqlite_wal_coverage'] = wal_limit
                                file_categories.add('attachments')
                                file_count += 1
                                count += add_artifact(db, evidence_id, source['id'], 'attachments', None, None,
                                    (Path(attachment['filename']).name if isinstance(attachment['filename'], str) else '') or 'Unnamed attachment', resolved['status'],
                                    f"attachment:rowid={attachment['attachment_row_id']}", VERSION,
                                    attachment_data, run_id=run_id)
                        from itertools import chain
                        for category, when, raw, title, body, reference, data in chain(mms_rows, parse_database(input_db, source["logical_path"])):
                            file_categories.add(category)
                            scope_message(data, evidence_id, source["logical_path"])
                            data.setdefault("timestamp_semantics", "UTC normalization of source field; original value preserved")
                            if sidecars:
                                data["source_sidecars"] = sidecars
                            if wal_limit:
                                data["sqlite_wal_coverage"] = wal_limit
                            file_count += 1
                            count += add_artifact(db, evidence_id, source["id"], category, when, raw, title, body, reference, VERSION, data, run_id=run_id)
                        if not file_count:
                            from .empty_schema import no_record_diagnostic
                            unparsed_candidates.append(no_record_diagnostic(input_db, source['logical_path'], evidence['platform']))
                    supported += int(file_count > 0)
                except (sqlite3.DatabaseError, ValueError, TypeError, OverflowError) as exc:
                    if (getattr(exc, 'sqlite_errorcode', 0) or 0) & 0xff == sqlite3.SQLITE_FULL:
                        # SQLITE_FULL may have rolled back the entire artifact
                        # transaction. It is a job storage failure, not a bad
                        # input source that can safely be skipped.
                        raise
                    error = {"source": source["logical_path"], "error": str(exc)}
                    if (getattr(exc, 'sqlite_errorcode', 0) or 0) & 0xff == sqlite3.SQLITE_TOOBIG:
                        error.update(error=f'Native SQLite value or encoded row exceeds the {MAX_SQLITE_VALUE_BYTES}-byte processing limit; source coverage incomplete.',
                                     sqlite_error=str(exc), state='resource-limited',
                                     reason='Native SQLite value or encoded row exceeds the declared byte limit; source coverage incomplete.',
                                     max_value_or_encoded_row_bytes=MAX_SQLITE_VALUE_BYTES)
                    errors.append(error)
                finally:
                    if wal_limit:
                        for affected_category in sorted(file_categories or {'unknown'}):
                            unparsed_candidates.append({'source':source['logical_path'], 'state':'limited',
                                'category':affected_category, 'reason':wal_limit['reason'],
                                'sqlite_wal_coverage':wal_limit})
                    for candidate in Path(tmp).glob(f"{source['id']}.db*"):
                        candidate.unlink()
        from .media import index_media
        count += index_media(root, db, evidence_id, file_rows, VERSION, run_id=run_id)
        status = "partial" if errors else "complete"
        detail = {"runner_ownership": owner, "sqlite_files_examined": sqlite_files, "databases_with_records": supported, "errors": errors,
                  "sqlite_resource_policy": {"max_value_or_encoded_row_bytes": MAX_SQLITE_VALUE_BYTES,
                                             "scope": "Per-source SQLite text/BLOB/encoded-row limit; not a process memory or complete job time limit."},
                  "unparsed_candidates": unparsed_candidates,
                  "coverage": "Native baseline parsers only. Zero records does not prove absence of activity."}
    except BaseException as exc:
        discarded = count if not db.in_transaction else 0
        if discarded:
            count = 0
        status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
        detail = {"error": str(exc), "runner_ownership": owner}
        if discarded:
            detail['discarded_uncommitted_records'] = discarded
        if isinstance(exc, sqlite3.Error):
            detail['sqlite_errorcode'] = getattr(exc, 'sqlite_errorcode', None)
        try:
            db.execute("UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?", (now(), status, count, json_text(detail), run_id))
            audit(db, "analysis.finished", {"run_id": run_id, "status": status, "records": count})
            db.commit()
        except BaseException:
            db.rollback()
            raise
        raise
    try:
        db.execute("UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?", (now(), status, count, json_text(detail), run_id))
        audit(db, "analysis.finished", {"run_id": run_id, "status": status, "new_records": count, **detail})
        db.commit()
    except BaseException:
        db.rollback()
        raise
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
