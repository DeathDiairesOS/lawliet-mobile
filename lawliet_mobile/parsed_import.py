"""Import derived parser reports while preserving report-level provenance."""
import csv
from .tsv import report_reader
import json
import uuid
from pathlib import Path

from .core import UserError, add_artifact, audit, begin_run_index, digest, import_evidence, json_text, now
from .messages import scope_message
from .leapp_reports import leapp_artifact
from .parsers import timestamp

MAX_REPORT = 512 * 1024**2


def import_parsed(root, db, source, format_name, label=None):
    source = Path(source)
    if source.is_dir():
        return import_leapp_folder(root, db, source, label)
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
    run = uuid.uuid4().hex[:12]
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES(?,?,?,?,?)', (run, eid, parser, now(), 'running'))
    begin_run_index(db, run)
    db.commit()
    count = 0
    try:
        db.execute('SAVEPOINT parsed_rows')
        with (root / 'evidence' / eid / file['path']).open(encoding='utf-8-sig', newline='') as handle:
            if format_name == 'jsonl':
                def records():
                    number = 0
                    while line := handle.readline(8 * 1024**2 + 1):
                        number += 1
                        if len(line) > 8 * 1024**2:
                            raise UserError(f'JSONL line {number} exceeds 8 MiB.')
                        if not line.strip():
                            continue
                        row = json.loads(line)
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
                        mapped = leapp_artifact(source.stem, row, eid)
                        yield number, mapped or ('external', None, None, source.stem, ' · '.join(f'{k}: {v}' for k,v in row.items() if v), row)
            for number, mapped in records():
                category, when, raw, title, body, data = mapped
                data['_import_report'] = {'sha256': hashed, 'record': number, 'filename': source.name,
                                         'note': 'Hash identifies the imported report, not the application database.'}
                count += add_artifact(db, eid, file['id'], category, when, raw, title, body, f'report:record={number}', parser, data, run_id=run)
        if count == 0 and format_name != 'tsv':
            raise UserError('No records found in this report.')
        db.execute('RELEASE parsed_rows')
    except (ValueError, TypeError, KeyError, csv.Error, OSError, UserError) as exc:
        db.execute('ROLLBACK TO parsed_rows')
        db.execute('RELEASE parsed_rows')
        db.execute('UPDATE runs SET status=?,finished_at=?,detail=? WHERE id=?', ('failed', now(), json_text({'error': str(exc)}), run))
        audit(db, 'parsed_import.failed', {'evidence_id': eid, 'run_id': run, 'error': str(exc), 'original_retained': True})
        db.commit()
        raise UserError(f'Import failed; original report retained as {eid}. {exc}') from exc
    detail = {'format': format_name, 'report_sha256': hashed}
    if format_name == 'tsv':
        detail['reports'] = [{'name':source.stem,'path':file['path'],'records':count,'sha256':hashed}]
    db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?', ('complete', now(), count, json_text(detail), run))
    audit(db, 'parsed_import.complete', {'evidence_id': eid, 'run_id': run, 'records': count, 'report_sha256': hashed})
    db.commit()
    return {'status': 'complete', 'evidence_id': eid, 'records': count, 'run_id': run}


def import_leapp_folder(root, db, source, label=None):
    """Retain a complete report tree, index all TSVs together, never execute HTML."""
    eid, _, _ = import_evidence(root, db, source, 'auto', label or source.name,
                               max_bytes=20 * 1024**3, expand_archives=False)
    parser = 'import/leapp'
    run = uuid.uuid4().hex[:12]
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES(?,?,?,?,?)',
               (run, eid, parser, now(), 'running'))
    begin_run_index(db, run)
    db.commit()
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
        db.execute('RELEASE parsed_folder')
    except (ValueError, TypeError, KeyError, csv.Error, OSError, UserError) as exc:
        db.execute('ROLLBACK TO parsed_folder');db.execute('RELEASE parsed_folder')
        db.execute('UPDATE runs SET status=?,finished_at=?,detail=? WHERE id=?',
                   ('failed', now(), json_text({'error': str(exc)}), run))
        audit(db, 'parsed_import.failed', {'evidence_id':eid,'run_id':run,'error':str(exc),'original_retained':True})
        db.commit()
        raise UserError(f'Import failed; original reports retained as {eid}. {exc}') from exc
    detail = {'reports': reports, 'retained_files': db.execute('SELECT COUNT(*) FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]}
    db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?',
               ('complete',now(),count,json_text(detail),run))
    audit(db,'parsed_import.complete',{'evidence_id':eid,'run_id':run,'records':count,**detail});db.commit()
    return {'status':'complete','evidence_id':eid,'run_id':run,'records':count,**detail}
