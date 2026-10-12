"""Recorded, receipt-bound media acquisition origins; never deletion inference."""
import json
from .core import UserError, audit, digest, now


def available(db):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='media_acquisition_sources'").fetchone() is not None


def record_trash(root, db, file_id, receipt_file_id):
    rows = []
    for identifier in (file_id, receipt_file_id):
        if type(identifier) is not int or identifier <= 0:
            raise UserError('Use positive case file IDs.')
        row = db.execute('SELECT * FROM files WHERE id=?', (identifier,)).fetchone()
        if row is None:
            raise UserError('Media and acquisition receipt must belong to this case.')
        path = root / 'evidence' / row['evidence_id'] / row['path']
        evidence_root = root / 'evidence' / row['evidence_id']
        if (not path.resolve().is_relative_to(evidence_root.resolve())
                or any(parent.is_symlink() for parent in [path, *path.parents] if parent != root.parent)
                or not path.is_file()
                or (identifier == receipt_file_id and path.stat().st_size > 64 * 1024)
                or digest(path) != row['sha256']):
            raise UserError('Media/acquisition receipt integrity check failed.')
        rows.append((row, path))
    media, _ = rows[0]
    receipt, path = rows[1]
    if path.stat().st_size > 64 * 1024:
        raise UserError('Media acquisition receipt exceeds 64 KiB.')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('format') != 'ancalor-android-trash-acquisition-v1':
        raise UserError('Unsupported media acquisition receipt format.')
    remote = data.get('remote_path', '')
    if (not isinstance(remote, str) or not remote.startswith('/sdcard/Android/.Trash/')
            or '..' in remote.split('/') or any(ord(c) < 32 for c in remote)):
        raise UserError('Receipt does not declare a supported shared-storage Trash path.')
    if (data.get('method') != 'read-only-adb-pull' or data.get('source_kind') != 'trash'
            or data.get('bytes') != media['size']
            or any(data.get(key) != media['sha256'] for key in ('source_sha256_before', 'source_sha256_after', 'acquired_sha256'))):
        raise UserError('Trash receipt does not match the acquired file bytes and method.')
    db.execute('''CREATE TABLE IF NOT EXISTS media_acquisition_sources(
        file_id INTEGER PRIMARY KEY REFERENCES files(id),
        receipt_file_id INTEGER NOT NULL REFERENCES files(id),
        source_kind TEXT NOT NULL, remote_path TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL, recorded_at TEXT NOT NULL)''')
    prior = db.execute('SELECT * FROM media_acquisition_sources WHERE file_id=?', (file_id,)).fetchone()
    if prior:
        if prior['receipt_file_id'] != receipt_file_id:
            raise UserError('This file already has a different recorded acquisition receipt.')
        return dict(prior)
    db.execute('INSERT INTO media_acquisition_sources VALUES(?,?,?,?,?,?)',
               (file_id, receipt_file_id, 'trash', remote, receipt['sha256'], now()))
    audit(db, 'media.trash_source.recorded', {'file_id': file_id, 'receipt_file_id': receipt_file_id,
          'receipt_sha256': receipt['sha256'], 'remote_path': remote,
          'scope': 'Recorded shared-storage Trash acquisition. Not independent authentication or permanent-deletion recovery.'})
    return dict(db.execute('SELECT * FROM media_acquisition_sources WHERE file_id=?', (file_id,)).fetchone())


def contexts(db, observations):
    if not available(db):
        return []
    ids = {row['file_id'] for row in observations if row.get('file_id') is not None}
    return [dict(row) for identifier in sorted(ids) for row in
            db.execute('SELECT * FROM media_acquisition_sources WHERE file_id=?', (identifier,))]
