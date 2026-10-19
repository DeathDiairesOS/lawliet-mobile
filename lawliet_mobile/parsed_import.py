"""Import derived parser reports while preserving report-level provenance."""
import csv
from .tsv import report_reader
import json
import math
import sqlite3
import uuid
from pathlib import Path

from .core import UserError, add_artifact, audit, begin_run_index, digest, import_evidence, json_text, now
from .messages import scope_message
from .leapp_reports import leapp_artifact
from .parsers import timestamp

MAX_REPORT = 512 * 1024**2
MAX_JSONL_LINE = 8 * 1024**2
MAX_JSON_DEPTH = 64


def _artifact_json(text):
    """Refuse ambiguous/nonfinite JSON and bound nesting before decoding."""
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise UserError('JSONL nesting exceeds the declared depth limit.')
        elif char in ']}':
            depth -= 1

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise UserError('Duplicate JSON object keys are unsupported; no value was selected.')
            result[key] = value
        return result

    def constant(_):
        raise UserError('Nonfinite JSON numbers are unsupported.')

    def floating(value):
        result = float(value)
        if not math.isfinite(result):
            raise UserError('JSON number exceeds the supported finite numeric range.')
        return result

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=floating)


def _start_import(db, eid, parser):
    from .runner_lease import ownership
    run = uuid.uuid4().hex[:12]
    owner = ownership()
    try:
        db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)',
                   (run, eid, parser, now(), 'running', json_text({'runner_ownership': owner})))
        begin_run_index(db, run)
        audit(db, 'parsed_import.started', {'run_id': run, 'evidence_id': eid,
                                          'engine': parser, 'runner_ownership': owner})
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return run, owner


def _fail_import(db, eid, run, owner, exc, plural=False):
    prefix = f"Import failed; original {'reports' if plural else 'report'} retained as {eid}."
    detail = {'error': str(exc), 'runner_ownership': owner}
    if isinstance(exc, sqlite3.Error):
        detail['sqlite_error_code'] = getattr(exc, 'sqlite_errorcode', None)
        detail['sqlite_error_name'] = getattr(exc, 'sqlite_errorname', None)
    try:
        # SQLITE_FULL can automatically abort the entire transaction/savepoint.
        # The durable started run precedes this transaction and stays retained.
        db.rollback()
        db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?',
                   ('failed', now(), 0, json_text(detail), run))
        audit(db, 'parsed_import.failed', {'evidence_id': eid, 'run_id': run,
                                          'error': str(exc), 'original_retained': True,
                                          'records': 0})
        db.commit()
    except sqlite3.Error as terminal:
        try:
            db.rollback()
        except sqlite3.Error:
            pass
        raise UserError(f'{prefix} The terminal state could not be recorded; the retained run remains unresolved. {exc}') from terminal
    raise UserError(f'{prefix} {exc}') from exc


def import_parsed(root, db, source, format_name, label=None, *, contained=False, origin_file_id=None):
    if type(contained) is not bool:raise UserError('contained must be a boolean.')
    if origin_file_id is not None and (not contained or type(origin_file_id) is not int or not 0<origin_file_id<2**63):raise UserError('origin_file_id requires contained mode and a positive integer file ID.')
    if contained and Path(source).is_dir():raise UserError('Contained report import supports one JSONL/TSV file; folders are not supported. No host fallback.')
    from .runner_lease import lease
    with lease(root, db):
        if contained:
            from .report_container import import_report
            return import_report(root, db, Path(source), format_name, label, origin_file_id=origin_file_id)
        return _import_parsed_owned(root, db, source, format_name, label)


def iter_report_records(path, format_name, eid, hashed, filename):
    """Shared report normalization; supplied IDs and report provenance remain unchanged."""
    path = Path(path)
    options = {} if format_name == 'jsonl' else {'encoding':'utf-8-sig', 'newline':''}
    with path.open('rb' if format_name == 'jsonl' else 'r', **options) as handle:
        if format_name == 'jsonl':
            def records():
                number = 0
                while line := handle.readline(MAX_JSONL_LINE + 1):
                    number += 1
                    if len(line) > MAX_JSONL_LINE:
                        raise UserError(f'JSONL line {number} exceeds the {MAX_JSONL_LINE}-byte limit.')
                    decoded = line.decode('utf-8-sig' if number == 1 else 'utf-8')
                    if not decoded.strip():
                        continue
                    row = _artifact_json(decoded)
                    if not isinstance(row, dict) or not {'category', 'body', 'data'} <= row.keys() or not isinstance(row['data'], dict) or not isinstance(row['body'], str):
                        raise UserError(f'Line {number} is not an Lawliet artifact record.')
                    data = dict(row['data'])
                    if 'message' in data:
                        m = data['message']
                        if not isinstance(m, dict) or not isinstance(m.get('app'), str) or not isinstance(m.get('conversation'), str):
                            raise UserError(f'Invalid message metadata on line {number}.')
                        scope_message(data, eid, str(row.get('evidence_id', '')) + ':' + str(m.get('conversation_id', '')))
                    data['_imported_record'] = {k: row.get(k) for k in ('id', 'evidence_id', 'parser', 'source_ref', 'source_sha256', 'logical_path')}
                    data['_import_note'] = 'Derived report import. Source claims are retained as supplied, not independently verified against the original device.'
                    yield number, (str(row['category']), timestamp(row.get('timestamp')), row.get('timestamp_raw'), str(row.get('title', 'Imported artifact')), row['body'], data)
        else:
            def records():
                reader = report_reader(handle)
                if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
                    raise UserError('TSV needs a nonempty header row with unique column names.')
                for number, row in enumerate(reader, 2):
                    if None in row or any(v is None for v in row.values()):
                        raise UserError(f'TSV row {number} does not match its headers.')
                    mapped = leapp_artifact(Path(filename).stem, row, eid)
                    yield number, mapped or ('external', None, None, Path(filename).stem, ' · '.join(f'{k}: {v}' for k,v in row.items() if v), row)
        for number, mapped in records():
            category, when, raw, title, body, data = mapped
            data['_import_report'] = {'sha256': hashed, 'record': number, 'filename': filename,
                                     'note': 'Hash identifies the imported report, not the application database.'}
            yield number, (category, when, raw, title, body, data)


def _import_parsed_owned(root, db, source, format_name, label=None):
    source = Path(source)
    if source.is_dir():
        return _import_leapp_folder_owned(root, db, source, label)
    if format_name not in {'jsonl', 'tsv'}:
        raise UserError('Choose Lawliet JSONL or LEAPP TSV.')
    parser = 'import/' + format_name
    hashed = digest(source)
    # A TSV filename selects its schema. Identical bytes under a different
    # report name must not silently reopen a differently categorized source.
    previous = db.execute('SELECT r.evidence_id FROM runs r JOIN files f ON r.evidence_id=f.evidence_id WHERE f.sha256=? AND r.engine=? AND r.status=\'complete\' AND (? != \'tsv\' OR f.path=?) LIMIT 1', (hashed, parser, format_name, source.name)).fetchone()
    if previous:
        return {'status': 'already_imported', 'evidence_id': previous[0], 'records': 0}
    eid, _, _ = import_evidence(root, db, source, 'auto', label or source.name, max_bytes=MAX_REPORT, expand_archives=False)
    file = db.execute('SELECT * FROM files WHERE evidence_id=?', (eid,)).fetchone()
    run, owner = _start_import(db, eid, parser)
    count = 0
    try:
        db.execute('SAVEPOINT parsed_rows')
        if hashed != file['sha256']:
            raise UserError('Source report changed between identity check and intake; no records imported. Retry with a stable source.')
        for number, mapped in iter_report_records(root / 'evidence' / eid / file['path'], format_name, eid, hashed, source.name):
            category, when, raw, title, body, data = mapped
            count += add_artifact(db, eid, file['id'], category, when, raw, title, body, f'report:record={number}', parser, data, run_id=run)
        if count == 0 and format_name != 'tsv':
            raise UserError('No records found in this report.')
        detail = {'format': format_name, 'report_sha256': hashed, 'runner_ownership': owner}
        if format_name == 'tsv':
            detail['reports'] = [{'name':source.stem,'path':file['path'],'records':count,'sha256':hashed}]
        db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?', ('complete', now(), count, json_text(detail), run))
        audit(db, 'parsed_import.complete', {'evidence_id': eid, 'run_id': run, 'records': count, 'report_sha256': hashed})
        db.execute('RELEASE parsed_rows')
        db.commit()
    except (ValueError, TypeError, KeyError, csv.Error, OSError, UserError, RecursionError, sqlite3.Error) as exc:
        _fail_import(db, eid, run, owner, exc)
    return {'status': 'complete', 'evidence_id': eid, 'records': count, 'run_id': run}


def import_leapp_folder(root, db, source, label=None):
    from .runner_lease import lease
    with lease(root, db):
        return _import_leapp_folder_owned(root, db, Path(source), label)


def _import_leapp_folder_owned(root, db, source, label=None):
    """Retain a complete report tree, index all TSVs together, never execute HTML."""
    eid, _, _ = import_evidence(root, db, source, 'auto', label or source.name,
                               max_bytes=20 * 1024**3, expand_archives=False)
    parser = 'import/leapp'
    run, owner = _start_import(db, eid, parser)
    count, reports = 0, []
    try:
        db.execute('SAVEPOINT parsed_folder')
        for file in db.execute('SELECT * FROM files WHERE evidence_id=? ORDER BY path', (eid,)).fetchall():
            path = root / 'evidence' / eid / file['path']
            if path.suffix.lower() != '.tsv':
                continue
            if file['size'] > MAX_REPORT:
                raise UserError('A TSV exceeds the 512 MiB report limit.')
            report_count = 0
            with path.open(encoding='utf-8-sig', newline='') as handle:
                reader = report_reader(handle)
                if not reader.fieldnames or len(set(reader.fieldnames))!=len(reader.fieldnames):
                    raise UserError(f'Invalid TSV headers: {file["path"]}')
                for number, row in enumerate(reader, 2):
                    if None in row or any(v is None for v in row.values()):
                        raise UserError(f'Invalid TSV record {number}: {file["path"]}')
                    category, when, raw, title, body, data = leapp_artifact(path.stem, row, eid)
                    # Separate identically named reports from different subfolders/accounts.
                    if 'message' in data:
                        scope_message(data, eid, file['path'])
                    data['_import_report'] = {'sha256': file['sha256'], 'record': number,
                        'filename': file['path'], 'note': 'Hash identifies the report, not the application database.'}
                    report_count += add_artifact(db, eid, file['id'], category, when, raw, title,
                        body, f'{file["path"]}:record={number}', parser, data, run_id=run)
            reports.append({'path': file['path'], 'records': report_count, 'sha256': file['sha256']})
            count += report_count
        if not reports:
            raise UserError('No TSV reports found. Select the full ALEAPP/iLEAPP output folder with TSV output enabled. HTML-only reports are not indexed.')
        detail = {'runner_ownership': owner, 'reports': reports, 'retained_files': db.execute('SELECT COUNT(*) FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]}
        db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?',
                   ('complete',now(),count,json_text(detail),run))
        audit(db,'parsed_import.complete',{'evidence_id':eid,'run_id':run,'records':count,**detail})
        db.execute('RELEASE parsed_folder')
        db.commit()
    except (ValueError, TypeError, KeyError, csv.Error, OSError, UserError, RecursionError, sqlite3.Error) as exc:
        _fail_import(db, eid, run, owner, exc, plural=True)
    return {'status':'complete','evidence_id':eid,'run_id':run,'records':count,**detail}
