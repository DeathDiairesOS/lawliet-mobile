"""Reversible examiner assertions over immutable, source-linked identifiers."""
import hashlib
import json
import re
import uuid
from .core import UserError, audit, json_text, now

ACTION = 'identity_association.recorded'
MAX_EVENTS = 10000
MAX_HISTORY_BYTES = 16 * 1024 * 1024
LIMITATIONS = [
    'Identifier types, examiner labels, rationale and associations are examiner assertions, not authenticated identity.',
    'Matching strings never create links automatically. Connected groups are transitive assertions, not proof of one person.',
    'Original artifact, conversation, identifier and contact-label records are never rewritten.',
    'Hash-linked local history is editable storage, not a signed or independently anchored identity ledger.',
]


def _history(db):
    previous = '0' * 64
    events = []
    history_bytes = 0
    for row in db.execute('SELECT * FROM audit ORDER BY id'):
        expected = hashlib.sha256(json_text([row['at'], row['action'], row['detail'], previous]).encode()).hexdigest()
        if row['previous_hash'] != previous or row['hash'] != expected:
            raise UserError('Identity associations unavailable: audit chain verification failed.')
        previous = row['hash']
        if row['action'] == ACTION:
            history_bytes += len(row['detail'].encode('utf-8'))
            if history_bytes > MAX_HISTORY_BYTES:
                raise UserError('Identity history exceeds the 16 MiB workspace bound.')
            events.append({'audit_id': row['id'], **json.loads(row['detail'])})
            if len(events) > MAX_EVENTS:
                raise UserError('Identity history exceeds the bounded 10000-event workspace.')
    return events


def _text(value, field):
    text = value.get(field)
    if not isinstance(text, str) or not text.strip() or len(text) > 4000:
        raise UserError('Identity field requires bounded nonempty text: ' + field)
    return text


def _pointer(record, pointer):
    if not pointer.startswith('/'):
        raise UserError('Identifier source_field must be an absolute JSON pointer.')
    value = record
    try:
        for token in pointer[1:].split('/'):
            # Reject non-RFC6901 escapes rather than ambiguously interpreting them.
            if '~' in token.replace('~0', '').replace('~1', ''):
                raise ValueError()
            key = token.replace('~1', '/').replace('~0', '~')
            if isinstance(value, list):
                if not re.fullmatch(r'0|[1-9][0-9]*', key):
                    raise ValueError()
                value = value[int(key)]
            else:
                value = value[key]
    except (TypeError, KeyError, IndexError, ValueError) as exc:
        raise UserError('Identifier source_field does not resolve in the artifact.') from exc
    if type(value) is not int and (not isinstance(value, str) or not value.strip() or len(value) > 4000):
        raise UserError('Identifier source_field must resolve to bounded source text or an exact integer; booleans/null/floats are unsupported.')
    return value


def _state(events):
    observations = {e['id']: e for e in events if e['kind'] == 'observe'}
    merges = {e['id']: e for e in events if e['kind'] == 'merge'}
    withdrawn = {e['association_id'] for e in events if e['kind'] == 'split'}
    return observations, merges, withdrawn


def record(db, value):
    """Append observe, merge, or split; merges/splits require confirmed=true."""
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    history = _history(db)
    if len(history) >= MAX_EVENTS:
        raise UserError('Identity history reached the bounded 10000-event limit.')
    if not isinstance(value, dict):
        raise UserError('An identity event object is required.')
    kind = value.get('kind')
    fields = {'observe': {'artifact_id', 'source_field', 'identifier_type', 'namespace'},
              'merge': {'observation_ids', 'confirmed'}, 'split': {'association_id', 'confirmed'}}
    if not isinstance(kind, str) or kind not in fields or set(value) - (fields[kind] | {'kind', 'examiner', 'rationale'}):
        raise UserError('Unsupported identity event fields or kind.')
    result = {'schema_version': 1, 'id': uuid.uuid4().hex, 'kind': kind, 'recorded_at': now(),
              'examiner': _text(value, 'examiner'), 'rationale': _text(value, 'rationale')}
    observations, merges, withdrawn = _state(history)
    if kind == 'observe':
        artifact_id = _text(value, 'artifact_id')
        field = _text(value, 'source_field')
        identifier_type = _text(value, 'identifier_type')
        if identifier_type not in {'phone', 'email', 'app-id', 'account'}:
            raise UserError('Identifier type must be phone, email, app-id or account.')
        row = db.execute('SELECT a.*,f.logical_path,f.sha256 AS source_sha256 FROM artifacts a LEFT JOIN files f ON f.id=a.file_id WHERE a.id=?', (artifact_id,)).fetchone()
        if row is None:
            raise UserError('Identifier artifact is not in this case.')
        artifact = dict(row)
        artifact['data'] = json.loads(artifact['data'])
        snapshot_text = json_text(artifact)
        if len(snapshot_text.encode('utf-8')) > 131072:
            raise UserError('Identifier artifact snapshot exceeds the 128 KiB bound.')
        raw = _pointer(artifact, field)
        if type(raw) is int and identifier_type not in {'app-id', 'account'}:
            raise UserError('Numeric source identifiers require app-id/account type; phone/email must retain source text.')
        provenance = {k: artifact[k] for k in ['id', 'evidence_id', 'file_id', 'source_ref', 'parser', 'logical_path', 'source_sha256']}
        result.update(artifact_id=artifact_id, source_field=field, raw_value=raw, identifier_type=identifier_type,
                      namespace=_text(value, 'namespace'), provenance=provenance, raw_value_type='json-integer' if type(raw) is int else 'json-string',
                      artifact_snapshot=artifact,
                      artifact_snapshot_sha256=hashlib.sha256(json_text(artifact).encode()).hexdigest())
    elif kind == 'merge':
        ids = value.get('observation_ids')
        if not isinstance(ids, list) or not 2 <= len(ids) <= 32 or any(not isinstance(i, str) for i in ids) or len(set(ids)) != len(ids):
            raise UserError('A merge requires 2–32 distinct observation IDs.')
        if any(i not in observations for i in ids):
            raise UserError('Merge observation is not in this case.')
        if value.get('confirmed') is not True:
            raise UserError('An examiner must explicitly confirm the association.')
        result.update(observation_ids=list(ids), confirmed=True)
    else:
        association_id = _text(value, 'association_id')
        if association_id not in merges or association_id in withdrawn:
            raise UserError('Split requires an active association in this case.')
        if value.get('confirmed') is not True:
            raise UserError('An examiner must explicitly confirm withdrawal.')
        result.update(association_id=association_id, confirmed=True,
                      scope='Withdraws only this merge assertion; other active links may still connect the observations.')
    if sum(len(json_text({k: v for k, v in e.items() if k != 'audit_id'}).encode('utf-8')) for e in history) + len(json_text(result).encode('utf-8')) > MAX_HISTORY_BYTES:
        raise UserError('Identity history would exceed the 16 MiB workspace bound.')
    audit(db, ACTION, result)
    return {**result, 'limitations': list(LIMITATIONS)}


def list_records(db, after=0, limit=100):
    if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise UserError('Use a nonnegative audit cursor and limit 1–100.')
    events = [e for e in _history(db) if e['audit_id'] > after]
    return {'records': events[:limit], 'has_more': len(events) > limit,
            'next_cursor': events[min(limit, len(events)) - 1]['audit_id'] if events else after,
            'limitations': list(LIMITATIONS)}


def groups(db):
    """Derived bounded view; each original observation remains separately addressable."""
    observations, merges, withdrawn = _state(_history(db))
    parent = {key: key for key in observations}
    def find(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key
    active = {key: e for key, e in merges.items() if key not in withdrawn}
    for event in active.values():
        ids = event['observation_ids']
        for identifier in ids[1:]:
            parent[find(identifier)] = find(ids[0])
    grouped = {}
    for key in observations:
        grouped.setdefault(find(key), []).append(key)
    return {'groups': [sorted(ids) for ids in grouped.values()], 'observations': list(observations.values()),
            'active_associations': list(active.values()), 'withdrawn_association_ids': sorted(withdrawn),
            'limitations': list(LIMITATIONS)}
