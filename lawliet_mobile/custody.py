"""Case-scoped, append-only custody claims in the existing hash-linked audit log.

This API does not authenticate handlers or make the editable case database immutable.
"""
import json
import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from .core import UserError, audit, digest, now, json_text

ACTION = 'custody.recorded'
KINDS = {'receipt', 'transfer', 'return', 'historical-gap'}
LIMITATIONS = [
    'Handlers, authority, event times and reference contents are examiner-supplied claims, not authenticated identities or permissions.',
    'The hash-linked audit log detects ordinary edits but is not immutable storage or a signed chain of custody.',
    'File hashes describe retained imported bytes at recording time; they do not establish pre-receipt authenticity.',
    'Missing historical custody is not reconstructed; this log does not establish current physical possession.',
]


def _verify_audit(db):
    previous = '0' * 64
    for row in db.execute('SELECT * FROM audit ORDER BY id'):
        expected = hashlib.sha256(json_text([row['at'], row['action'], row['detail'], previous]).encode()).hexdigest()
        if row['previous_hash'] != previous or row['hash'] != expected:
            raise UserError('Custody unavailable: case audit chain verification failed.')
        previous = row['hash']


def _text(value, field, required=True):
    result = value.get(field, '')
    if not isinstance(result, str) or len(result) > 4000 or (required and not result.strip()):
        raise UserError('Custody field must be bounded text: ' + field)
    return result


def _manifest(root, db, evidence_id):
    if evidence_id is None:
        return {'scope': 'no imported file evidence linked', 'files': [], 'status': 'not-checked'}
    if not isinstance(evidence_id, str) or not db.execute('SELECT 1 FROM evidence WHERE id=?', (evidence_id,)).fetchone():
        raise UserError('Custody evidence reference is not in this case.')
    root_path = Path(root).absolute()
    root_safe = not any(p.is_symlink() for p in (root_path, *root_path.parents))
    base = root_path / 'evidence' / evidence_id
    files = []
    for row in db.execute('SELECT path,logical_path,sha256,size FROM files WHERE evidence_id=? ORDER BY path', (evidence_id,)):
        path = base / row['path']
        entry = dict(row)
        entry.update(observed_sha256=None, observed_size=None, status='unavailable')
        # Refuse traversal and symlink components; never follow an evidence link.
        try:
            relative = path.relative_to(base)
            safe = root_safe and '..' not in relative.parts and not base.parent.is_symlink() and not base.is_symlink() and all(
                not (base.joinpath(*relative.parts[:n])).is_symlink() for n in range(1, len(relative.parts) + 1))
            if safe and path.is_file():
                entry['observed_sha256'] = digest(path)
                entry['observed_size'] = path.stat().st_size
                entry['status'] = 'matched' if (entry['sha256'], entry['size']) == (entry['observed_sha256'], entry['observed_size']) else 'changed'
        except (OSError, ValueError):
            pass
        files.append(entry)
    return {'scope': 'retained imported files; SHA256 over each complete file, not original device or archive',
            'files': files, 'status': 'matched' if files and all(f['status'] == 'matched' for f in files) else 'limited'}


def record(root, db, value):
    """Append one event. No update/delete operation; historical gaps remain visible."""
    # Serialize this append with other writers before verifying the predecessor.
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    _verify_audit(db)
    fields = {'kind', 'item_id', 'item_reference', 'evidence_id', 'occurred_at', 'recorded_by',
              'from_handler', 'to_handler', 'authority_reference', 'scope_reference',
              'seal_reference', 'photo_reference', 'note', 'prior_custody', 'gap_reason'}
    if not isinstance(value, dict) or set(value) - fields:
        raise UserError('Unsupported custody fields.')
    kind = value.get('kind')
    if not isinstance(kind, str) or kind not in KINDS:
        raise UserError('Custody kind must be receipt, transfer, return or historical-gap.')
    data = {f: _text(value, f) for f in ('occurred_at', 'recorded_by', 'authority_reference', 'scope_reference')}
    try:
        at = datetime.fromisoformat(data['occurred_at'].replace('Z', '+00:00'))
        if at.utcoffset() is None:
            raise ValueError()
    except ValueError as exc:
        raise UserError('Custody event time must include an explicit UTC offset.') from exc
    for field in ('from_handler', 'to_handler', 'seal_reference', 'photo_reference', 'note', 'gap_reason'):
        data[field] = _text(value, field, False)
    if kind != 'historical-gap' and not (data['from_handler'].strip() and data['to_handler'].strip()):
        raise UserError('Receipt, transfer and return require both claimed handlers.')
    if kind == 'historical-gap' and not data['gap_reason'].strip():
        raise UserError('A historical gap needs a reason describing the missing history.')
    previous = None
    if kind == 'receipt':
        if value.get('item_id') is not None:
            raise UserError('A receipt creates a new item ID; use transfer for an existing item.')
        item_id = uuid.uuid4().hex
        data['item_reference'] = _text(value, 'item_reference')
        prior = value.get('prior_custody', 'unknown')
        if not isinstance(prior, str) or prior not in {'unknown', 'documented-reference'}:
            raise UserError('Prior custody must be unknown or documented-reference.')
        if prior == 'documented-reference' and not data['note'].strip():
            raise UserError('Documented prior custody requires a reference in note.')
        data['prior_custody'] = prior
        evidence_id = value.get('evidence_id')
    else:
        item_id = _text(value, 'item_id')
        # Read case-local audit only; never borrow an item from another case.
        for row in db.execute('SELECT detail FROM audit WHERE action=? ORDER BY id DESC', (ACTION,)):
            candidate = json.loads(row['detail'])
            if candidate['item_id'] == item_id:
                previous = candidate
                break
        if previous is None:
            raise UserError('Custody item is not in this case.')
        if any(f in value for f in ('evidence_id', 'item_reference', 'prior_custody')):
            raise UserError('An existing custody item cannot be relinked by a later event.')
        evidence_id = previous['evidence_id']
        data['item_reference'] = previous['item_reference']
        data['prior_custody'] = previous['prior_custody']
    warnings = []
    if data['prior_custody'] == 'unknown':
        warnings.append('Pre-receipt custody is unknown.')
    if previous:
        if at < datetime.fromisoformat(previous['occurred_at'].replace('Z', '+00:00')):
            warnings.append('Event time precedes the previously recorded event; historical ordering requires review.')
        if previous['to_handler'] != data['from_handler']:
            warnings.append('Claimed handler continuity is unestablished; inspect prior events and historical gaps.')
    manifest = _manifest(root, db, evidence_id)
    if manifest['status'] != 'matched':
        warnings.append('File integrity is ' + manifest['status'] + '; inspect the manifest before relying on this event.')
    result = {**data, 'schema_version': 1, 'id': uuid.uuid4().hex, 'kind': kind,
              'item_id': item_id, 'evidence_id': evidence_id, 'recorded_at': now(),
              'previous_event_id': previous['id'] if previous else None,
              'manifest': manifest, 'warnings': warnings,
              'reference_status': {field: 'claimed-reference' if data[field].strip() else 'not-recorded'
                                   for field in ('seal_reference', 'photo_reference')},
              'limitations': list(LIMITATIONS)}
    audit(db, ACTION, result)
    return result


def list_records(db, after=0, limit=100, item_id=None):
    _verify_audit(db)
    if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise UserError('Use a nonnegative audit cursor and limit 1–100.')
    if item_id is not None and (not isinstance(item_id, str) or not item_id.strip() or len(item_id) > 4000):
        raise UserError('Invalid custody item ID.')
    records = []
    for row in db.execute('SELECT id,detail FROM audit WHERE action=? AND id>? ORDER BY id', (ACTION, after)):
        event = json.loads(row['detail'])
        if item_id is None or event['item_id'] == item_id:
            records.append({'audit_id': row['id'], **event})
            if len(records) > limit:
                break
    return {'records': records[:limit], 'has_more': len(records) > limit,
            'next_cursor': records[min(limit, len(records)) - 1]['audit_id'] if records else after}
