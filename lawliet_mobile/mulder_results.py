"""Version-checked Mulder SQLite/audit ingestion; AI findings stay unreviewed."""
import json
import re
import shutil
import sqlite3
import tempfile
from pathlib import Path

from .core import UserError, add_artifact, begin_run_index, digest, now
from .mulder_engine import VERSION, atomic_json, job_path
from .parsers import timestamp

REQUIRED = {
    'case_metadata': {'case_id', 'evidence_root'},
    'findings': {'finding_id','case_id','title','description','severity','confidence','evidence_refs','sources','event_time_start','event_time_end'},
    'sources': {'source_id','case_id','source_name','source_path','source_hash','extractor'},
    'windows': {'window_id','source_id','line_start','line_end','event_time','raw_text'},
}


def objects(text):
    value = json.loads(text or '[]')
    if not isinstance(value, list) or len(value) > 10000:
        raise UserError('Unsupported Mulder list field.')
    return value


def output_case_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', value):
        raise UserError('Mulder output case ID must contain 1–128 letters, digits, underscores or hyphens.')
    return value


def ingest(root, db, jid, evidence_id, version, upstream_case_id=None):
    if version != VERSION:
        raise UserError('Unsupported Mulder output version.')
    upstream_case_id = output_case_id(upstream_case_id or jid)
    path = job_path(root, jid)
    outputs = path / 'outputs'
    if outputs.is_symlink() or not outputs.resolve().is_relative_to(path.resolve()):
        raise UserError('Unsafe Mulder output directory.')
    warnings, inventory = [], []
    for item in outputs.rglob('*'):
        if item.is_symlink():
            raise UserError('Mulder output contains an unsafe symbolic link; retained but not imported.')
        if item.is_file():
            inventory.append({'path': str(item.relative_to(path)), 'sha256': digest(item), 'size': item.stat().st_size})
    atomic_json(path / 'output-manifest.json', inventory)
    hashes = {entry['path']: entry['sha256'] for entry in inventory}
    report = outputs / (upstream_case_id + '.report.md')
    result = {'records': 0, 'findings': 0, 'windows': 0, 'warnings': warnings,
              'report_available': report.is_file(), 'manifest_sha256': digest(path / 'output-manifest.json'),
              'report_path': str(report) if report.is_file() else None, 'output_case_id': upstream_case_id}
    if not report.is_file():
        warnings.append('Mulder Markdown report is missing; report generation is not established.')
    database = outputs / (upstream_case_id + '.db')
    if not database.is_file():
        warnings.append('Mulder case database is missing; available output files remain preserved.')
        return result
    if db.execute('SELECT 1 FROM runs WHERE id=?', (jid,)).fetchone():
        raise UserError('This investigation output has already been imported.')
    db.execute('SAVEPOINT mulder_import')
    try:
        db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)',
                   (jid, evidence_id, 'mulder', now(), 'importing', '{}'))
        begin_run_index(db, jid)
        db.execute('''CREATE TABLE IF NOT EXISTS engine_audit_refs(
            run_id TEXT NOT NULL, tool_call_id TEXT NOT NULL, line INTEGER NOT NULL,
            tool_name TEXT NOT NULL, PRIMARY KEY(run_id,tool_call_id))''')
        auditfile = outputs / (upstream_case_id + '.audit.jsonl')
        if auditfile.is_file():
            with auditfile.open('rb') as stream:
                line = 0
                while True:
                    data = stream.readline(8*1024**2+1)
                    if not data: break
                    line += 1
                    if line > 1000000 or len(data) > 8*1024**2:
                        raise UserError('Mulder audit exceeds supported ingestion limits.')
                    try: entry = json.loads(data)
                    except (ValueError, UnicodeError):
                        warnings.append('Malformed audit record at line ' + str(line)); continue
                    if not isinstance(entry, dict):
                        warnings.append('Non-object audit record at line ' + str(line)); continue
                    if entry.get('type') == 'tool_call' and isinstance(entry.get('tool_call_id'), str):
                        if db.execute('SELECT 1 FROM engine_audit_refs WHERE run_id=? AND tool_call_id=?', (jid, entry['tool_call_id'])).fetchone():
                            db.execute('UPDATE engine_audit_refs SET line=-1 WHERE run_id=? AND tool_call_id=?', (jid, entry['tool_call_id']))
                            warnings.append('Duplicate tool-call ID in audit; citation is ambiguous.')
                        else:
                            db.execute('INSERT INTO engine_audit_refs VALUES(?,?,?,?)',
                                       (jid, entry['tool_call_id'], line, str(entry.get('tool_name', 'unknown'))))
        else:
            warnings.append('Mulder audit log missing; tool-call citations cannot be verified.')
        # Never open upstream database in place: even read-only SQLite can create sidecars.
        with tempfile.TemporaryDirectory(prefix='lawliet-mulder-read-') as temp:
            copy = Path(temp) / 'case.db'
            shutil.copyfile(database, copy)
            for suffix in ('-wal', '-shm', '-journal'):
                side = Path(str(database)+suffix)
                if side.is_file(): shutil.copyfile(side, Path(str(copy)+suffix))
            source = sqlite3.connect(copy)
            try:
                source.row_factory = sqlite3.Row
                source.execute('PRAGMA trusted_schema=OFF')
                source.execute('PRAGMA query_only=ON')
                source.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 8*1024**2)
                for table, columns in REQUIRED.items():
                    if not columns <= {r[1] for r in source.execute('PRAGMA table_info('+table+')')}:
                        raise UserError('Unsupported Mulder schema for ' + table + '; source outputs retained.')
                cases = [r[0] for r in source.execute('SELECT case_id FROM case_metadata LIMIT 2')]
                if cases != [upstream_case_id]:
                    raise UserError('Mulder output case identity does not match this investigation.')
                for row in source.execute('SELECT * FROM findings ORDER BY finding_id'):
                    if row['case_id'] != upstream_case_id: raise UserError('Cross-case finding rejected.')
                    original = dict(row)
                    refs = objects(row['evidence_refs'])
                    links = []
                    for ref in refs:
                        if not isinstance(ref, str): raise UserError('Unsupported Mulder evidence reference.')
                        match = db.execute('SELECT line,tool_name FROM engine_audit_refs WHERE run_id=? AND tool_call_id=?', (jid, ref)).fetchone()
                        links.append({'type': 'tool_invocation', 'tool_call_id': ref,
                                      'verified_in_audit': bool(match and match['line']>0), 'audit_line': match['line'] if match and match['line']>0 else None,
                                      'tool': match['tool_name'] if match else None})
                    if any(not r['verified_in_audit'] for r in links) or not links:
                        warnings.append('Finding ' + str(row['finding_id'])[:100] + ' has missing/unverified tool-call references.')
                    metadata = {'engine': 'mulder', 'engine_version': version, 'analysis_run_id': jid,
                                'upstream_case_id': upstream_case_id,
                                'review_status': 'unreviewed', 'interpretation': 'AI-generated finding, not an observed event',
                                'severity': row['severity'], 'confidence': row['confidence'], 'supporting_evidence': links,
                                'engine_declared_sources': objects(row['sources']),
                                'original': original, 'output_sha256': hashes['outputs/'+database.name],
                                'audit_sha256': hashes.get('outputs/'+auditfile.name),
                                'limitations': ['Tool-call citations do not necessarily locate an original file or record.',
                                                'Finding timestamps are engine assertions; excluded from the observed timeline.']}
                    add_artifact(db, evidence_id, None, 'agent_findings', None, row['event_time_start'],
                                 'AI finding · '+row['title'], row['description'],
                                 'engine-runs/'+jid+'/outputs/'+database.name+'#findings:'+str(row['finding_id']),
                                 'mulder/'+version, metadata, run_id=jid)
                    result['findings'] += 1
                    if result['findings'] > 100000: raise UserError('Finding ingestion limit exceeded.')
                sql = '''SELECT w.*,s.case_id,s.source_name,s.source_path,s.source_hash,s.extractor FROM windows w
                         JOIN sources s ON s.source_id=w.source_id ORDER BY w.window_id'''
                orphaned = source.execute('SELECT count(*) FROM windows w LEFT JOIN sources s ON s.source_id=w.source_id WHERE s.source_id IS NULL').fetchone()[0]
                if orphaned:
                    warnings.append(str(orphaned)+' indexed windows have no source record and could not be normalized; retained in the original database.')
                for row in source.execute(sql):
                    if row['case_id'] != upstream_case_id: raise UserError('Cross-case source rejected.')
                    data = dict(row)
                    data.update(engine='mulder', engine_version=version, analysis_run_id=jid,
                                upstream_case_id=upstream_case_id,
                                review_status='unreviewed', output_sha256=hashes['outputs/'+database.name],
                                provenance_type='indexed_tool_output_window')
                    # Extracted windows are preserved as tool output, not reinterpreted as messages.
                    add_artifact(db, evidence_id, None, 'external', timestamp(row['event_time']), row['event_time'],
                                 row['source_name'], row['raw_text'],
                                 'engine-runs/'+jid+'/outputs/'+database.name+'#windows:'+str(row['window_id']),
                                 'mulder/'+version, data, run_id=jid)
                    result['windows'] += 1
                    if result['windows'] > 100000: raise UserError('Window ingestion limit exceeded; outputs retained.')
            finally:
                source.close()
        result['records'] = result['findings'] + result['windows']
        db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?',
                   ('partial' if warnings else 'complete', now(), result['records'], json.dumps(result), jid))
        db.execute('RELEASE SAVEPOINT mulder_import')
        return result
    except BaseException:
        db.execute('ROLLBACK TO SAVEPOINT mulder_import');db.execute('RELEASE SAVEPOINT mulder_import')
        raise
