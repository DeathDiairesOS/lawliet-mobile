"""Append examiner device-state worksheets without querying or altering a device."""
import json
import uuid
from datetime import datetime
from .core import UserError, audit, now

VALUES = {
    'power': {'on', 'off', 'unknown'},
    'lock': {'locked', 'unlocked', 'unknown'},
    'network': {'connected', 'disconnected', 'airplane-mode', 'unknown'},
    'restart': {'observed', 'not-observed', 'unknown'},
    'boot_state': {'BFU', 'AFU', 'unknown'},
}


def record(db, value):
    allowed = {'device_reference', 'examiner', 'observed_at', 'states', 'evidence_id'}
    if not isinstance(value, dict) or set(value) - allowed:
        raise UserError('Unsupported device-state worksheet fields.')
    for field in ('device_reference', 'examiner', 'observed_at'):
        if not isinstance(value.get(field), str) or not value[field].strip() or len(value[field]) > 1000:
            raise UserError('Device reference, examiner and observed time are required.')
    try:
        at = datetime.fromisoformat(value['observed_at'].replace('Z', '+00:00'))
        if at.utcoffset() is None:
            raise ValueError()
    except ValueError as exc:
        raise UserError('Observed time must be ISO8601 with an explicit UTC offset.') from exc
    evidence_id = value.get('evidence_id')
    if evidence_id is not None and (not isinstance(evidence_id, str) or not db.execute(
            'SELECT 1 FROM evidence WHERE id=?', (evidence_id,)).fetchone()):
        raise UserError('Device-state evidence reference is not in this case.')
    states = value.get('states')
    if not isinstance(states, dict) or set(states) - VALUES.keys():
        raise UserError('States must use power, lock, network, restart or boot_state.')
    normalized = {}
    for field, choices in VALUES.items():
        entry = states.get(field, {'value': 'unknown', 'basis': 'unknown', 'reference': ''})
        if not isinstance(entry, dict) or set(entry) != {'value', 'basis', 'reference'}:
            raise UserError('Each state requires value, basis and reference.')
        if not isinstance(entry['value'], str) or entry['value'] not in choices:
            raise UserError('Unsupported device-state value: ' + field)
        if not isinstance(entry['basis'], str) or entry['basis'] not in {'observation', 'inference', 'unknown'}:
            raise UserError('State basis must distinguish observation, inference and unknown.')
        reference = entry['reference']
        if not isinstance(reference, str) or len(reference) > 4000:
            raise UserError('State reference must be text of at most 4000 characters.')
        if entry['value'] != 'unknown' and (entry['basis'] == 'unknown' or not reference.strip()):
            raise UserError('A known state needs an explicit basis and supporting reference.')
        normalized[field] = dict(entry)
    result = {**value, 'schema_version': 1, 'id': uuid.uuid4().hex,
              'recorded_at': now(), 'states': normalized,
              'verification': 'examiner-recorded; not independently verified',
              'limitations': ['No device was queried or changed by recording this worksheet.',
                              'Lock, power, network and restart observations do not automatically establish BFU or AFU.',
                              'References are examiner-supplied claims; this worksheet does not authenticate their contents.']}
    audit(db, 'device_state.recorded', result)
    return result


def list_records(db, after=0, limit=100):
    if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise UserError('Use a nonnegative audit cursor and limit 1–100.')
    rows = db.execute("SELECT id,detail FROM audit WHERE action='device_state.recorded' AND id>? ORDER BY id LIMIT ?",
                      (after, limit + 1)).fetchall()
    return {'records': [{'audit_id': r['id'], **json.loads(r['detail'])} for r in rows[:limit]],
            'has_more': len(rows) > limit, 'next_cursor': rows[min(limit, len(rows))-1]['id'] if rows else after}
