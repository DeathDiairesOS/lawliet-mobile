"""Scoped negative/inconclusive examination receipts, never device-clean verdicts."""
import hashlib
import json
import os
import stat
import time
import uuid
from pathlib import Path, PurePosixPath

from . import investigation as inv
from .core import UserError, audit, now
from .package_verification import _directory, PackageError

LABELS = {'no_matches': 'No indexed matches', 'inconclusive': 'Inconclusive examination'}
LIMITS = [
    'Searches are literal substrings of indexed titles and bodies in the selected evidence only.',
    'No indexed match does not establish absence from original, unparsed, encrypted or uncollected data.',
    'An inconclusive examination does not establish a clean device or the absence of compromise.',
    'Processing statuses are retained run observations, not acquisition or examination completeness.',
    'Source hashes bind retained bytes, not their authenticity or the completeness of a phone acquisition.',
]


def _text(value, label, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise UserError(f'{label} requires 1–{maximum} characters.')
    return value


def _source(root, row, deadline):
    """Stream a retained file through anchored no-follow descriptors."""
    eid, name = row['evidence_id'], row['path']
    if (not isinstance(eid, str) or PurePosixPath(eid).name != eid or eid in {'', '.', '..'}
            or not isinstance(name, str) or not name or '\\' in name
            or PurePosixPath(name).is_absolute() or any(x in {'', '.', '..'} for x in name.split('/'))):
        raise UserError('Unsafe examination source mapping.')
    path = Path(root)/'evidence'/eid/name
    if os.name == 'nt':
        from .windows_files import WindowsDirectory
        try:
            with WindowsDirectory(path.parent) as directory:
                result, _ = directory.fingerprint(path.name, maximum=row['size'], deadline=deadline)
                if result['bytes'] != row['size'] or result['sha256'] != row['sha256']:
                    raise UserError('Examination source integrity mismatch: retained bytes changed.')
            return
        except OSError as exc:
            raise UserError('Examination source is missing or unsafe; reconcile retained evidence.') from exc
    parent = leaf = None
    try:
        parent = _directory(path.parent)
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(leaf)
        if not stat.S_ISREG(before.st_mode) or before.st_size != row['size']:
            raise UserError('Examination source integrity mismatch: size/type changed.')
        h = hashlib.sha256()
        with os.fdopen(leaf, 'rb', closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024*1024), b''):
                if time.monotonic() > deadline:
                    raise UserError('Examination integrity check exceeded five minutes; narrow evidence scope.')
                h.update(chunk)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        after = os.fstat(leaf)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if identity(before) != identity(after) or identity(after) != identity(current) or h.hexdigest() != row['sha256']:
            raise UserError('Examination source integrity mismatch: retained bytes changed.')
        live_parent = _directory(path.parent)
        try:
            anchored, live = os.fstat(parent), os.fstat(live_parent)
            if (anchored.st_dev, anchored.st_ino) != (live.st_dev, live.st_ino):
                raise UserError('Examination source integrity mismatch: source directory changed.')
        finally:
            os.close(live_parent)
    except (OSError, PackageError) as exc:
        raise UserError('Examination source is missing or unsafe; reconcile retained evidence.') from exc
    finally:
        if leaf is not None: os.close(leaf)
        if parent is not None: os.close(parent)


def snapshot(root, db, evidence_ids):
    """Hash scoped rows incrementally; return only counts and controlled status summaries."""
    marks = ','.join('?' for _ in evidence_ids)
    digest = hashlib.sha256(); deadline = time.monotonic()+300
    counts = {}; statuses = {}; inventory = {eid: {'evidence_id': eid, 'files': 0, 'artifacts': 0, 'runs': 0} for eid in evidence_ids}
    tables = [
        ('evidence', f'SELECT * FROM evidence WHERE id IN ({marks}) ORDER BY id'),
        ('files', f'SELECT * FROM files WHERE evidence_id IN ({marks}) ORDER BY id'),
        ('artifacts', f'SELECT * FROM artifacts WHERE evidence_id IN ({marks}) ORDER BY id'),
        ('runs', f'SELECT * FROM runs WHERE evidence_id IN ({marks}) ORDER BY id'),
    ]
    existing = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    tables.append(('artifact_runs', f'SELECT ar.* FROM artifact_runs ar JOIN artifacts a ON a.id=ar.artifact_id WHERE a.evidence_id IN ({marks}) ORDER BY ar.run_id,ar.artifact_id' if 'artifact_runs' in existing else None))
    tables.append(('run_artifact_indexes', f'SELECT ri.* FROM run_artifact_indexes ri JOIN runs r ON r.id=ri.run_id WHERE r.evidence_id IN ({marks}) ORDER BY ri.run_id' if 'run_artifact_indexes' in existing else None))
    total_bytes = 0; rows = 0
    for table, sql in tables:
        digest.update(inv.encoded(['table', table]).encode()+b'\n'); counts[table] = 0
        for row in db.execute(sql, evidence_ids) if sql else ():
            rows += 1
            if rows > 2000000 or time.monotonic() > deadline:
                raise UserError('Examination snapshot exceeded its row/time bound; narrow evidence scope.')
            raw = inv.encoded(dict(row)).encode()
            if len(raw) > 4*1024*1024:
                raise UserError('Examination input row exceeds 4 MiB; narrow or reconcile indexed input.')
            digest.update(raw+b'\n'); counts[table] += 1
            if table in {'files', 'artifacts', 'runs'}:
                inventory[row['evidence_id']][table] += 1
            if table == 'files':
                _source(root, row, deadline); total_bytes += row['size']
            if table == 'runs':
                status = row['status'] if row['status'] in {'complete', 'completed', 'partial', 'failed', 'interrupted', 'cancelled', 'running', 'pending', 'importing'} else 'unknown'
                statuses[status] = statuses.get(status, 0)+1
    if counts['evidence'] != len(evidence_ids):
        raise UserError('Examination evidence scope is missing from this case.')
    return {'schema_version': 1, 'sha256': digest.hexdigest(), 'counts': counts,
            'source_bytes_verified': total_bytes, 'processing_status_counts': statuses,
            'evidence_inventory': list(inventory.values()),
            'identity': 'SHA-256 of ordered scoped evidence, file, artifact, run and available membership rows; retained file bytes freshly checked against inventory.',
            'limitations': 'No processing record or indexed artifact for a source means examination coverage is unknown; no successful extraction or parsing is inferred.'}


def prepare(root, db, objective, evidence_ids, outcome, examiner, examination_scope, limitations, queries):
    _text(objective, 'Investigation objective', 16000)
    _text(examiner, 'Examiner', 200); _text(examination_scope, 'Examination scope', 16000)
    _text(limitations, 'Examination limitations', 16000)
    if not isinstance(outcome, str) or outcome not in LABELS:
        raise UserError('Select no_matches or inconclusive explicitly.')
    if (not isinstance(evidence_ids, list) or not 1 <= len(evidence_ids) <= 100
            or any(not isinstance(x, str) or not x or len(x) > 128 for x in evidence_ids)
            or len(set(evidence_ids)) != len(evidence_ids)):
        raise UserError('Select 1–100 distinct evidence IDs explicitly.')
    if not isinstance(queries, list) or len(queries) > 20:
        raise UserError('Supply up to 20 literal search strings.')
    for text in queries: _text(text, 'Literal query', 1000)
    if len(set(queries)) != len(queries):
        raise UserError('Supply distinct literal queries.')
    if outcome == 'no_matches' and not queries:
        raise UserError('No indexed matches requires at least one executed query.')
    evidence_ids = sorted(evidence_ids)
    if not db.in_transaction: db.execute('BEGIN IMMEDIATE')
    else: db.execute('UPDATE audit SET id=id WHERE 0')
    db.execute('SAVEPOINT examination_prepare')
    try:
        inv.verify_ledger(db)
        before = snapshot(root, db, evidence_ids)
        if outcome == 'no_matches' and not before['counts']['artifacts']:
            raise UserError('No indexed matches requires nonempty indexed artifacts; use inconclusive for unparsed evidence.')
        state = inv.create(db, objective, evidence_ids); iid = state['id']; searches = []
        for text in queries:
            key = uuid.uuid4().hex
            result = inv.query(db, iid, key, text, limit=100)
            if outcome == 'no_matches' and (result['records'] or result['has_more']):
                raise UserError('A query returned indexed matches; no_matches was refused. Review matches or record an inconclusive examination.')
            event = db.execute('SELECT sequence FROM investigation_events WHERE investigation_id=? AND action_key=?', (iid, key)).fetchone()
            searches.append({'text': text, 'action_key': key, 'returned_records': len(result['records']),
                             'has_more': result['has_more'], 'limit': 100, 'event_sequence': event[0],
                             'event_sha256': inv.event_receipt(db, iid, key), 'tool': inv.QUERY_TOOL})
        after = snapshot(root, db, evidence_ids)
        if before != after:
            raise UserError('Examination inputs changed during query execution; retry after processing settles.')
        key = uuid.uuid4().hex
        summary = {'schema_version': 1, 'outcome': outcome, 'label': LABELS[outcome],
                   'examiner': examiner, 'examination_scope': examination_scope, 'limitations': limitations,
                   'queries': searches, 'snapshot': after, 'evidence_ids': evidence_ids,
                   'summary_action_key': key, 'review_status': 'unreviewed', 'method_limitations': LIMITS}
        request = {'outcome': outcome, 'evidence_ids': evidence_ids, 'queries': queries}
        db.execute('INSERT INTO investigation_events(investigation_id,action_key,at,kind,request,result) VALUES(?,?,?,?,?,?)',
                   (iid, key, now(), 'examination.summary', inv.encoded(request), inv.encoded(summary)))
        audit(db, 'investigation.examination', {'investigation_id': iid, 'action_key': key,
               'sha256': inv.checksum([request, summary]), 'record_sha256': inv.event_receipt(db, iid, key)})
        inv.verify_ledger(db)
        db.execute('RELEASE SAVEPOINT examination_prepare')
        return {'investigation_id': iid, 'review_status': 'unreviewed', 'scope': state['scope'], 'examination': summary}
    except BaseException:
        db.execute('ROLLBACK TO SAVEPOINT examination_prepare'); db.execute('RELEASE SAVEPOINT examination_prepare')
        raise


def checked(root, db, iid):
    """Rebind examination outcomes before export, approval and release; positives unchanged."""
    state = inv.get(db, iid)
    rows = db.execute("SELECT * FROM investigation_events WHERE investigation_id=? AND kind='examination.summary'", (iid,)).fetchall()
    if not rows: return None
    if len(rows) != 1: raise UserError('Unsupported duplicate examination summary.')
    summary = json.loads(rows[0]['result'])
    if summary.get('schema_version') != 1 or summary.get('outcome') not in LABELS or summary.get('evidence_ids') != state['scope']['evidence_ids']:
        raise UserError('Unsupported examination summary or evidence scope.')
    if snapshot(root, db, state['scope']['evidence_ids']) != summary.get('snapshot'):
        raise UserError('Examination input index or processing state changed; run a new examination and re-review.')
    return summary


def structural_identity(summary):
    """Literal derivatives may mask examiner prose/terms, never outcomes or receipts."""
    value = json.loads(inv.encoded(summary))
    for field in ('examiner', 'examination_scope', 'limitations'):
        value.pop(field, None)
    for query in value.get('queries', []):
        query.pop('text', None)
    return value
