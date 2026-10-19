"""Local investigation ledger and scoped retrieval. No model or autonomous loop.

Only the fixed artifact-query tool is executable here. Evidence text is data;
it cannot select tools, expand scope, execute SQL or initiate network requests.
"""
import hashlib
import json
import time
import uuid

from .core import UserError, audit, now

VERSION = 1
QUERY_TOOL = 'artifacts.query.v1'
ENTRY_KINDS = ('task', 'hypothesis', 'question', 'observation', 'interpretation')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def checksum(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def event_receipt(db, iid, key):
    row = db.execute('SELECT * FROM investigation_events WHERE investigation_id=? AND action_key=?',
                     (iid, key)).fetchone()
    return checksum(dict(row))


def schema(db):
    # Individual statements: executescript would implicitly commit caller work.
    db.execute('''CREATE TABLE IF NOT EXISTS investigations(
        id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL,
        created_at TEXT NOT NULL, objective TEXT NOT NULL, scope TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS investigation_events(
        sequence INTEGER PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations(id),
        action_key TEXT NOT NULL, at TEXT NOT NULL, kind TEXT NOT NULL,
        request TEXT NOT NULL, result TEXT NOT NULL,
        UNIQUE(investigation_id, action_key))''')


def create(db, objective, evidence_ids):
    if not isinstance(objective, str) or not objective.strip() or len(objective) > 16000:
        raise UserError('Supply an investigation objective of 1–16000 characters.')
    if not evidence_ids or len(evidence_ids) > 100 or any(not isinstance(x, str) for x in evidence_ids):
        raise UserError('Select 1–100 existing evidence IDs explicitly.')
    ids = sorted(set(evidence_ids))
    for eid in ids:
        if not db.execute('SELECT 1 FROM evidence WHERE id=?', (eid,)).fetchone():
            raise UserError('Investigation scope contains unknown evidence.')
    scope = {'evidence_ids': ids, 'allowed_tools': [QUERY_TOOL],
             'external_uploads': False, 'collection': False,
             'account_changes': False, 'report_release': False}
    schema(db)
    iid = uuid.uuid4().hex
    db.execute('INSERT INTO investigations VALUES(?,?,?,?,?)',
               (iid, VERSION, now(), objective, encoded(scope)))
    audit(db, 'investigation.created', {'investigation_id': iid, 'objective': objective, 'scope': scope,
                                        'record_sha256': checksum(get(db, iid))})
    return get(db, iid)


def get(db, iid):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='investigations'").fetchone():
        raise UserError('Unknown investigation.')
    row = db.execute('SELECT * FROM investigations WHERE id=?', (iid,)).fetchone()
    if not row:
        raise UserError('Unknown investigation.')
    value = dict(row)
    if value['schema_version'] != VERSION:
        raise UserError('Unsupported investigation schema version.')
    value['scope'] = json.loads(value['scope'])
    return value


def trace(db, iid, after=0, limit=100):
    get(db, iid)
    if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise UserError('Trace requires a nonnegative cursor and limit 1–100.')
    rows = db.execute('''SELECT * FROM investigation_events WHERE investigation_id=?
                         AND sequence>? ORDER BY sequence LIMIT ?''', (iid, after, limit + 1)).fetchall()
    entries = []
    for row in rows[:limit]:
        entry = dict(row)
        entry['request'] = json.loads(entry['request'])
        entry['result'] = json.loads(entry['result'])
        entries.append(entry)
    return {'events': entries, 'has_more': len(rows) > limit,
            'next_cursor': entries[-1]['sequence'] if entries else after}


def note(db, iid, kind, text, artifact_ids=()):
    """Append analyst reasoning separately from parsed evidence; citations aren't proof."""
    verify_ledger(db)
    state = get(db, iid)
    if kind not in ENTRY_KINDS:
        raise UserError('Unknown investigation entry kind.')
    if not isinstance(text, str) or not text.strip() or len(text) > 16000:
        raise UserError('Entry text must contain 1–16000 characters.')
    if len(artifact_ids) > 20 or any(not isinstance(x, str) for x in artifact_ids):
        raise UserError('An entry can cite up to 20 artifact IDs.')
    if kind in ('observation', 'interpretation') and not artifact_ids:
        raise UserError('Observations and interpretations require source artifacts.')
    citations = []
    for aid in sorted(set(artifact_ids)):
        row = db.execute('''SELECT a.*,f.logical_path,f.sha256 AS source_sha256 FROM artifacts a
                            LEFT JOIN files f ON f.id=a.file_id WHERE a.id=?''', (aid,)).fetchone()
        if not row or row['evidence_id'] not in state['scope']['evidence_ids']:
            raise UserError('Citation is missing or outside the investigation scope.')
        citation = dict(row)
        if len(encoded(citation).encode()) > 256 * 1024:
            raise UserError('Citation exceeds the current 256 KiB snapshot limit.')
        citations.append(citation)
    request = {'kind': kind, 'text': text, 'artifact_ids': sorted(set(artifact_ids))}
    result = {'citations': citations, 'review_status': 'unreviewed',
              'warning': 'Source linkage does not verify that the statement follows from the evidence.'}
    key = uuid.uuid4().hex
    db.execute('INSERT INTO investigation_events(investigation_id,action_key,at,kind,request,result) VALUES(?,?,?,?,?,?)',
               (iid, key, now(), 'analyst.' + kind, encoded(request), encoded(result)))
    audit(db, 'investigation.note', {'investigation_id': iid, 'entry_id': key,
                                   'sha256': checksum([request, result]),
                                   'record_sha256': event_receipt(db, iid, key)})
    return {'entry_id': key, **request, **result}


def query(db, iid, action_key, text, limit=20):
    """Atomic read-only query + receipt. Retry the same key to replay its snapshot.

    A killed process before commit leaves no completed action. Repeating this
    read-only query is safe; this contract does NOT cover external tool execution.
    """
    if not isinstance(action_key, str) or not action_key or len(action_key) > 128:
        raise UserError('Action key must contain 1–128 characters.')
    if not isinstance(text, str) or not text.strip() or len(text) > 1000:
        raise UserError('Query must contain 1–1000 characters.')
    if type(limit) is not int or not 1 <= limit <= 100:
        raise UserError('Query limit must be 1–100.')
    verify_ledger(db)
    state = get(db, iid)
    scope = state['scope']
    if QUERY_TOOL not in scope['allowed_tools']:
        raise UserError('Artifact queries are outside the approved toolset.')
    request = {'tool': QUERY_TOOL, 'text': text, 'limit': limit}
    previous = db.execute('''SELECT request,result FROM investigation_events
                             WHERE investigation_id=? AND action_key=?''', (iid, action_key)).fetchone()
    if previous:
        if previous['request'] != encoded(request):
            raise UserError('Action key already used for a different request.')
        return {'replayed': True, **json.loads(previous['result'])}
    ids = scope['evidence_ids']
    marks = ','.join('?' for _ in ids)
    # Literal substring, not SQL or wildcard syntax. Search indexed row text only.
    # Bound returned text and runtime; the underlying scan may still be expensive.
    deadline = time.monotonic() + 5
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    try:
        rows = db.execute(f'''SELECT a.id,a.evidence_id,a.file_id,a.category,a.timestamp,
            substr(a.title,1,2000) AS title,substr(a.body,1,4000) AS body_excerpt,
            length(a.body)>4000 AS body_truncated,substr(a.source_ref,1,2000) AS source_ref,
            a.parser,substr(f.logical_path,1,2000) AS logical_path,f.sha256 AS source_sha256
            FROM artifacts a LEFT JOIN files f ON f.id=a.file_id
            WHERE a.evidence_id IN ({marks})
            AND (instr(lower(coalesce(a.title,'')),lower(?))>0
                 OR instr(lower(coalesce(a.body,'')),lower(?))>0)
            ORDER BY a.id LIMIT ?''', (*ids, text, text, limit + 1)).fetchall()
    finally:
        db.set_progress_handler(None, 0)
    result = {'tool': QUERY_TOOL, 'records': [dict(row) for row in rows[:limit]],
              'has_more': len(rows) > limit,
              'limitations': ['Search covers indexed titles and bodies in approved evidence only.',
                              'No match does not establish absence from the original evidence.',
                              'Source hashes are stored inventory values, not a fresh integrity check.']}
    raw = encoded(result)
    db.execute('INSERT INTO investigation_events(investigation_id,action_key,at,kind,request,result) VALUES(?,?,?,?,?,?)',
               (iid, action_key, now(), 'tool.completed', encoded(request), raw))
    audit(db, 'investigation.action', {'investigation_id': iid, 'action_key': action_key,
                                     'tool': QUERY_TOOL, 'request_sha256': hashlib.sha256(encoded(request).encode()).hexdigest(),
                                     'result_sha256': hashlib.sha256(raw.encode()).hexdigest(),
                                     'record_sha256': event_receipt(db, iid, action_key)})
    return {'replayed': False, **result}


def verify_ledger(db):
    """Check inventories and receipts, not evidence bytes or external authenticity."""
    from .core import json_text
    states, events = {}, {}
    previous = '0' * 64
    for row in db.execute('SELECT * FROM audit ORDER BY id'):
        expected = hashlib.sha256(json_text([row['at'], row['action'], row['detail'], previous]).encode()).hexdigest()
        if row['previous_hash'] != previous or row['hash'] != expected:
            raise UserError('Investigation verification: audit chain mismatch.')
        previous = row['hash']
        if row['action'] not in ('investigation.created', 'investigation.note', 'investigation.action', 'investigation.examination'):
            continue
        try:
            receipt = json.loads(row['detail'])
            iid = receipt['investigation_id']
            if row['action'] == 'investigation.created':
                target, key = states, iid
            else:
                target, key = events, (iid, receipt['entry_id'] if row['action'] == 'investigation.note' else receipt['action_key'])
            if key in target:
                raise ValueError('duplicate receipt')
            target[key] = (row['action'], receipt)
        except (ValueError, KeyError, TypeError) as exc:
            raise UserError('Malformed investigation audit receipt.') from exc
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    actual_states = {r[0] for r in db.execute('SELECT id FROM investigations')} if 'investigations' in tables else set()
    actual_events = {(r[0], r[1]) for r in db.execute('SELECT investigation_id,action_key FROM investigation_events')} if 'investigation_events' in tables else set()
    if set(states) != actual_states or set(events) != actual_events:
        raise UserError('Investigation inventory mismatch: missing or unreceipted state/events.')
    legacy = 0
    try:
        for iid, (_, receipt) in states.items():
            state = get(db, iid)
            if receipt['objective'] != state['objective'] or receipt['scope'] != state['scope']:
                raise UserError('Investigation scope or objective integrity mismatch.')
            if 'record_sha256' in receipt:
                if receipt['record_sha256'] != checksum(state):
                    raise UserError('Investigation state integrity mismatch.')
            else:
                legacy += 1
        for row in db.execute('SELECT * FROM investigation_events') if 'investigation_events' in tables else ():
            action, receipt = events[(row['investigation_id'], row['action_key'])]
            request, result = json.loads(row['request']), json.loads(row['result'])
            if action == 'investigation.note':
                valid = (row['kind'] == 'analyst.' + request['kind'] and
                         receipt['sha256'] == checksum([request, result]))
            elif action == 'investigation.examination':
                valid = (row['kind'] == 'examination.summary' and
                         receipt['sha256'] == checksum([request, result]))
            else:
                valid = (row['kind'] == 'tool.completed' and receipt['tool'] == request['tool'] and
                         receipt['request_sha256'] == checksum(request) and receipt['result_sha256'] == checksum(result))
            if not valid:
                raise UserError('Investigation event integrity mismatch.')
            if 'record_sha256' in receipt:
                if receipt['record_sha256'] != checksum(dict(row)):
                    raise UserError('Investigation event metadata integrity mismatch.')
            else:
                legacy += 1
    except (ValueError, KeyError, TypeError) as exc:
        raise UserError('Malformed investigation ledger data.') from exc
    return {'investigations_checked': len(states), 'events_checked': len(events),
            'legacy_partial_receipts': legacy, 'audit_head': previous}
