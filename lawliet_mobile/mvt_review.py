"""Retained MVT Android output -> existing case artifacts; never executes MVT."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import uuid

from .core import UserError, add_artifact, audit, begin_run_index, import_evidence, json_text, now
from .package_verification import _directory, _read
from .sqlite_container_worker import strict_json

VERSION = '2026.10.5'
PARSER = 'mvt/' + VERSION
ENGINE = 'mvt-review'
MANIFEST = 'mulder-retention-manifest.json'
RECEIPT = 'mulder-execution-receipt.txt'
MAX_TOTAL = 64 * 1024**2
MAX_JSON = 8 * 1024**2
MAX_RECORD = 64 * 1024
LIMITATIONS = [
    'These are retained MVT output observations, not confirmed compromise or examiner-approved findings.',
    'Empty output or no indicator match cannot exclude compromise. Module completion is not independently verified.',
    'Source hashes identify retained parser output, not original phone artifacts or authenticated authorship.',
    'Timestamp fields remain verbatim in original values; this adapter does not infer timeline timestamps.',
    'The upstream execution receipt precedes Mulder indexing. Its separate index-outcome bundle is not included here.',
]


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _path(value):
    if (not isinstance(value, str) or not value or len(value.encode()) > 4096 or '\\' in value
            or '\x00' in value or ':' in value or value.startswith('/')
            or any(p in ('', '.', '..') for p in value.split('/'))):
        raise UserError('Unsafe retained output path.')
    return PurePosixPath(value)


def _read_file(folder, relative, limit=MAX_JSON):
    relative = _path(relative)
    fd = None
    try:
        fd = _directory(Path(folder) / relative.parent)
        data, _ = _read(fd, relative.name)
        if len(data) > limit:
            raise UserError('Retained file exceeds its review byte limit: ' + str(relative))
        return data
    except (OSError, ValueError) as exc:
        raise UserError('Cannot safely read retained file: ' + str(relative)) from exc
    finally:
        if fd is not None:
            os.close(fd)


def _decode(raw):
    try:
        return strict_json(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise UserError('Malformed, duplicate-key or excessively nested JSON.') from exc


def _loaded(path):
    """Only manifested regular files are read; unlisted files cause refusal."""
    folder = Path(path).expanduser().absolute()
    manifest_raw = _read_file(folder, MANIFEST, 1024**2)
    manifest = _decode(manifest_raw)
    if (not isinstance(manifest, dict) or manifest.get('tool') != 'run_mvt_android'
            or not isinstance(manifest.get('tool_call_id'), str)
            or not re.fullmatch(r'tc_[0-9a-f]{8}', manifest['tool_call_id'])
            or not isinstance(manifest.get('files'), list) or not 1 <= len(manifest['files']) <= 1000):
        raise UserError('Unsupported retained MVT Android manifest.')
    blobs = {MANIFEST: manifest_raw}
    total = len(manifest_raw)
    for entry in manifest['files']:
        if not isinstance(entry, dict):
            raise UserError('Invalid retained manifest entry.')
        relative = str(_path(entry.get('path')))
        if (relative in blobs or type(entry.get('bytes')) is not int or entry['bytes'] < 0
                or not isinstance(entry.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])):
            raise UserError('Invalid, duplicate or self-referencing retained manifest entry.')
        if total + entry['bytes'] > MAX_TOTAL:
            raise UserError('MVT bundle exceeds 64 MiB review limit.')
        raw = _read_file(folder, relative, min(MAX_TOTAL-total, 32*1024**2))
        if len(raw) != entry['bytes'] or _sha(raw) != entry['sha256']:
            raise UserError('Retained output integrity mismatch: ' + relative)
        blobs[relative] = raw
        total += len(raw)
    # Enumeration is bounded; no content of an unlisted file is opened.
    pending, actual, count = [(folder, '')], set(), 0
    while pending:
        directory, prefix = pending.pop()
        fd = None
        try:
            fd = _directory(directory)
            with os.scandir(fd) as entries:
                for entry in entries:
                    count += 1
                    if count > 2000 or entry.is_symlink():
                        raise UserError('Unsafe or excessive MVT bundle entries.')
                    name = prefix + entry.name
                    if entry.is_dir(follow_symlinks=False):
                        pending.append((directory / entry.name, name + '/'))
                    elif entry.is_file(follow_symlinks=False):
                        actual.add(name)
                    else:
                        raise UserError('MVT bundle contains a special file.')
        except OSError as exc:
            raise UserError('MVT bundle cannot be enumerated safely.') from exc
        finally:
            if fd is not None: os.close(fd)
    if actual != set(blobs):
        raise UserError('MVT bundle has missing or unlisted files.')
    receipt = _decode(blobs.get(RECEIPT, b''))
    if (not isinstance(receipt, dict) or receipt.get('mvt_version') != VERSION
            or receipt.get('execution_state') not in ('limited', 'failed', 'empty')
            or type(receipt.get('source_unchanged')) is not bool
            or type(receipt.get('ioc_matching_requested')) is not bool
            or not isinstance(receipt.get('errors'), list) or len(receipt['errors']) > 100
            or any(not isinstance(e, dict) for e in receipt['errors'])
            or not isinstance(receipt.get('case_id'), str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', receipt['case_id'])
            or receipt.get('input_type') not in ('androidqf', 'backup', 'bugreport')
            or receipt.get('receipt_scope') != 'MVT execution and output parsing before indexing'):
        raise UserError('Unsupported MVT version or execution receipt schema.')
    if len(blobs[RECEIPT]) > 128*1024:
        raise UserError('MVT execution receipt exceeds review limit.')
    observations, modules, issues = [], [], []
    for name, raw in sorted(blobs.items()):
        if not name.endswith('.json') or Path(name).name == 'info.json' or Path(name).name.startswith('mulder-'):
            continue
        module = {'file': name, 'records': 0, 'imported': 0, 'issue': None}
        modules.append(module)
        try:
            if len(raw) > MAX_JSON: raise UserError('JSON module exceeds 8 MiB decoding limit; retained only.')
            value = _decode(raw)
            if not isinstance(value, (dict, list)): raise UserError('Module JSON must be an object or array.')
            rows = value if isinstance(value, list) else [value] if value else []
            module['records'] = len(rows)
            for index, row in enumerate(rows):
                encoded = json_text(row)
                if len(encoded.encode()) > MAX_RECORD:
                    raise UserError('A record exceeds 64 KiB review limit; remaining module records retained only.')
                if len(observations) >= 100000: raise UserError('100000-record review limit reached; remaining module retained only.')
                observations.append((name, index, row))
                module['imported'] += 1
        except UserError as exc:
            module['issue'] = str(exc)
            issues.append({'file': name, 'error': str(exc)})
    summary = {'schema_version': 1, 'upstream_case_id': receipt['case_id'],
               'tool_call_id': manifest['tool_call_id'], 'manifest_sha256': _sha(manifest_raw),
               'receipt_sha256': _sha(blobs[RECEIPT]), 'version': VERSION,
               'receipt': receipt, 'files': len(blobs), 'bytes': total,
               'records': len(observations), 'modules': modules, 'import_issues': issues,
               'limitations': LIMITATIONS}
    return summary, blobs, observations


def inspect_bundle(path):
    return _loaded(path)[0]


def _case(db):
    return db.execute("SELECT value FROM meta WHERE key='case_id'").fetchone()[0]


def import_bundle(root, db, path, expected_manifest_sha256, expected_upstream_case_id):
    summary, blobs, observations = _loaded(path)
    if (summary['manifest_sha256'] != expected_manifest_sha256
            or summary['upstream_case_id'] != expected_upstream_case_id):
        raise UserError('MVT source changed or source case does not match the reviewed preview. Preview it again.')
    # Idempotent only for this exact retained manifest in this LAWLIET case.
    previous = db.execute("SELECT id,evidence_id,status FROM runs WHERE engine=? AND json_extract(detail,'$.manifest_sha256')=?", (ENGINE, expected_manifest_sha256)).fetchone()
    if previous:
        if previous['status'] not in ('complete', 'partial'):
            raise UserError('A previous MVT import is failed or incomplete; inspect retained run ' + previous['id'] + ' before retrying. No new import was created.')
        _, stored = _run(db, previous['evidence_id'])
        retained, retained_blobs, _ = _loaded(Path(root) / 'evidence' / previous['evidence_id'])
        inventory = {r['path']: (r['size'], r['sha256']) for r in db.execute('SELECT path,size,sha256 FROM files WHERE evidence_id=?', (previous['evidence_id'],))}
        if inventory != {name: (len(raw), _sha(raw)) for name, raw in retained_blobs.items()}:
            raise UserError('Previously imported MVT file inventory differs from retained bytes.')
        if retained['manifest_sha256'] != expected_manifest_sha256 or retained['receipt'] != stored['receipt']:
            raise UserError('Previously imported MVT receipt differs from the verified retained bundle.')
        return {'schema_version': 1, 'case_id': _case(db), 'evidence_id': previous['evidence_id'], 'run_id': previous['id'], 'reused': True}
    with tempfile.TemporaryDirectory(prefix='lawliet-mvt-review-') as tmp:
        stage = Path(tmp)
        for name, raw in blobs.items():
            item = stage / name; item.parent.mkdir(parents=True, exist_ok=True); item.write_bytes(raw)
        evidence_id, _, _ = import_evidence(root, db, stage, 'android', 'MVT outputs · ' + summary['upstream_case_id'], MAX_TOTAL, 1001, expand_archives=False)
    db.execute('UPDATE evidence SET input_path=? WHERE id=?', (str(Path(path).expanduser().absolute()), evidence_id))
    run_id = uuid.uuid4().hex[:16]
    summary.update(case_id=_case(db), evidence_id=evidence_id, run_id=run_id)
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)',
               (run_id, evidence_id, ENGINE, now(), 'importing', json_text(summary)))
    db.commit()
    db.execute('SAVEPOINT mvt_import')
    try:
        begin_run_index(db, run_id)
        files = {r['path']: r for r in db.execute('SELECT * FROM files WHERE evidence_id=?', (evidence_id,))}
        for name, index, original in observations:
            provenance = {'schema_version': 1, 'analysis_run_id': run_id, 'tool_call_id': summary['tool_call_id'],
                          'upstream_case_id': summary['upstream_case_id'], 'source_record_index': index,
                          'source_file': name, 'source_output_sha256': files[name]['sha256'],
                          'receipt_file_id': files[RECEIPT]['id'], 'receipt_sha256': summary['receipt_sha256'],
                          'manifest_file_id': files[MANIFEST]['id'], 'manifest_sha256': summary['manifest_sha256'],
                          'interpretation': 'Unreviewed MVT output observation; not confirmed compromise', 'original': original}
            add_artifact(db, evidence_id, files[name]['id'], 'security_observations', None, None,
                         name + ' · record ' + str(index), json_text(original),
                         'evidence/' + evidence_id + '/' + name + '#json-record=' + str(index), PARSER,
                         {'mvt': provenance}, run_id=run_id)
        status = 'partial' if summary['import_issues'] or summary['receipt']['errors'] or summary['receipt']['execution_state'] == 'failed' or not summary['receipt']['source_unchanged'] else 'complete'
        db.execute('UPDATE runs SET status=?,finished_at=?,records=? WHERE id=?', (status, now(), len(observations), run_id))
        audit(db, 'mvt.review_imported', {'case_id': _case(db), 'evidence_id': evidence_id, 'run_id': run_id,
              'upstream_case_id': summary['upstream_case_id'], 'manifest_sha256': summary['manifest_sha256'], 'records': len(observations)})
        db.execute('RELEASE SAVEPOINT mvt_import'); db.commit()
    except BaseException:
        db.execute('ROLLBACK TO SAVEPOINT mvt_import'); db.execute('RELEASE SAVEPOINT mvt_import')
        db.execute("UPDATE runs SET status='failed',finished_at=? WHERE id=?", (now(), run_id))
        db.commit(); raise
    return {'schema_version': 1, 'case_id': _case(db), 'evidence_id': evidence_id, 'run_id': run_id, 'reused': False}


def list_bundles(root, db):
    values = []
    for row in db.execute('SELECT r.*,e.label FROM runs r JOIN evidence e ON e.id=r.evidence_id WHERE r.engine=? ORDER BY r.started_at DESC,r.id LIMIT 201', (ENGINE,)):
        detail = _decode(row['detail'])
        values.append({'evidence_id': row['evidence_id'], 'run_id': row['id'], 'status': row['status'], 'records': row['records'], 'label': row['label'], 'upstream_case_id': detail['upstream_case_id']})
    return {'schema_version': 1, 'case_id': _case(db), 'bundles': values[:200], 'truncated': len(values) > 200}


def _run(db, evidence_id):
    row = db.execute('SELECT * FROM runs WHERE evidence_id=? AND engine=?', (evidence_id, ENGINE)).fetchone()
    if not row: raise UserError('No imported MVT review run for this evidence in this case.')
    summary = _decode(row['detail'])
    if (not isinstance(summary, dict) or summary.get('schema_version') != 1
            or summary.get('case_id') != _case(db) or summary.get('evidence_id') != evidence_id
            or summary.get('run_id') != row['id'] or summary.get('version') != VERSION):
        raise UserError('Unsupported or mismatched MVT import run metadata.')
    receipts = [_decode(r['detail']) for r in db.execute(
        "SELECT detail FROM audit WHERE action='mvt.review_imported' AND json_extract(detail,'$.run_id')=?", (row['id'],))]
    expected = {'case_id': _case(db), 'evidence_id': evidence_id, 'run_id': row['id'],
                'upstream_case_id': summary['upstream_case_id'], 'manifest_sha256': summary['manifest_sha256'], 'records': summary['records']}
    if receipts != [expected]:
        raise UserError('MVT run has no matching import audit receipt.')
    return row, summary


def _verified(root, db, evidence_id, file_id, expected_hash):
    row = db.execute('SELECT * FROM files WHERE id=? AND evidence_id=?', (file_id, evidence_id)).fetchone()
    if not row or row['sha256'] != expected_hash: raise UserError('MVT source inventory mismatch.')
    raw = _read_file(Path(root) / 'evidence' / evidence_id, row['path'], 32*1024**2)
    if len(raw) != row['size'] or _sha(raw) != expected_hash: raise UserError('MVT retained source integrity mismatch.')
    return raw


def _display_fields(raw):
    """Bounded display projection; originals and upstream labels stay unchanged."""
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > MAX_RECORD:
        return {}
    try:
        original = _decode(raw.encode('utf-8'))
    except UserError:
        return {}
    if not isinstance(original, dict): return {}
    indicator = original.get('matched_indicator')
    indicator = indicator if isinstance(indicator, dict) else {}
    fields = [('message', original.get('message'), 600),
              ('upstream_level', original.get('level'), 32),
              ('module', original.get('module'), 100),
              ('indicator_value', indicator.get('value'), 256),
              ('indicator_type', indicator.get('type'), 64)]
    result, truncated = {}, []
    for key, value, limit in fields:
        if not isinstance(value, str) or not value: continue
        result[key] = value[:limit]
        if len(value) > limit: truncated.append(key)
    if truncated: result['truncated_fields'] = truncated
    return result


def review(root, db, evidence_id, query='', offset=0, limit=50):
    if not isinstance(query, str) or len(query) > 500 or type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise UserError('Invalid MVT search or page bounds.')
    run, summary = _run(db, evidence_id)
    for name, expected in ((RECEIPT, summary['receipt_sha256']), (MANIFEST, summary['manifest_sha256'])):
        row = db.execute('SELECT id FROM files WHERE evidence_id=? AND path=?', (evidence_id, name)).fetchone()
        if not row: raise UserError('MVT receipt inventory missing.')
        verified = _verified(root, db, evidence_id, row['id'], expected)
        if name == RECEIPT and _decode(verified) != summary['receipt']:
            raise UserError('MVT cached execution receipt differs from retained bytes.')
    where = "a.evidence_id=? AND a.parser=? AND (instr(lower(a.body),lower(?))>0 OR instr(lower(a.title),lower(?))>0)"
    args = (evidence_id, PARSER, query, query)
    total = db.execute('SELECT COUNT(*) FROM artifacts a WHERE ' + where, args).fetchone()[0]
    rows = [dict(r) for r in db.execute('SELECT a.id,a.evidence_id,a.title,substr(a.body,1,400) AS preview,substr(a.body,1,65537) AS display_json,a.source_ref,f.sha256 AS source_sha256 FROM artifacts a JOIN files f ON f.id=a.file_id WHERE ' + where + ' ORDER BY a.title,a.id LIMIT ? OFFSET ?', (*args, limit, offset))]
    for row in rows: row['display'] = _display_fields(row.pop('display_json'))
    return {'schema_version': 1, 'case_id': _case(db), 'evidence_id': evidence_id, 'run_id': run['id'],
            'import_status': run['status'], 'summary': summary, 'records': rows, 'total': total,
            'offset': offset, 'has_more': offset + len(rows) < total,
            'integrity': 'Execution receipt and manifest reverified; selected output is reverified when opened.'}


def record(root, db, evidence_id, artifact_id):
    run, summary = _run(db, evidence_id)
    row = db.execute('SELECT * FROM artifacts WHERE id=? AND evidence_id=? AND parser=?', (artifact_id, evidence_id, PARSER)).fetchone()
    if not row: raise UserError('Unknown MVT observation in this evidence.')
    decoded = _decode(row['data'])
    values_for_id = tuple(row[key] for key in ('evidence_id','file_id','category','timestamp','timestamp_raw','title','body','source_ref','parser')) + (json_text(decoded),)
    if _sha(json_text(values_for_id).encode())[:24] != row['id']:
        raise UserError('MVT indexed record integrity mismatch.')
    data = decoded['mvt']
    if data['analysis_run_id'] != run['id']: raise UserError('MVT record run association mismatch.')
    inventory = db.execute('SELECT path FROM files WHERE id=? AND evidence_id=?', (row['file_id'], evidence_id)).fetchone()
    if (not inventory or inventory['path'] != data['source_file']
            or row['source_ref'] != 'evidence/' + evidence_id + '/' + inventory['path'] + '#json-record=' + str(data['source_record_index'])):
        raise UserError('MVT source location does not match the retained file inventory.')
    raw = _verified(root, db, evidence_id, row['file_id'], data['source_output_sha256'])
    _verified(root, db, evidence_id, data['receipt_file_id'], data['receipt_sha256'])
    _verified(root, db, evidence_id, data['manifest_file_id'], data['manifest_sha256'])
    value = _decode(raw); values = value if isinstance(value, list) else [value] if isinstance(value, dict) and value else []
    index = data['source_record_index']
    if type(index) is not int or not 0 <= index < len(values) or values[index] != data['original'] or row['body'] != json_text(values[index]):
        raise UserError('MVT indexed record differs from its retained source.')
    return {'schema_version': 1, 'case_id': _case(db), 'evidence_id': evidence_id, 'run_id': run['id'],
            'artifact_id': artifact_id, 'source_ref': row['source_ref'], 'source_file': data['source_file'],
            'source_record_index': index, 'source_sha256': data['source_output_sha256'],
            'receipt_sha256': data['receipt_sha256'], 'receipt_source_ref': 'evidence/' + evidence_id + '/' + RECEIPT,
            'original': values[index], 'source_verified': True, 'limitations': LIMITATIONS}
