"""Bounded, unencrypted Android Backup intake; originals remain evidence."""
import json
import tempfile
import zlib
from pathlib import Path

from .core import UserError, audit, digest, extract_archive, import_evidence


def inflate(reader, writer, limit):
    decoder, written = zlib.decompressobj(), 0
    while chunk := reader.read(65536):
        while chunk:
            block = decoder.decompress(chunk, min(65536, limit - written + 1))
            written += len(block)
            if written > limit:
                raise UserError("Decompressed data exceeds intake limit.")
            writer.write(block)
            chunk = decoder.unconsumed_tail
        if decoder.unused_data:
            raise UserError("Unexpected data after compressed stream.")
    if not decoder.eof:
        raise UserError("Truncated compressed stream.")
    return written


def unpack_backup(source, destination, max_bytes=20 * 1024**3, max_files=100000):
    """Expand only supported AB versions; reject encryption rather than guess."""
    with Path(source).open('rb') as reader:
        header = [reader.readline(128) for _ in range(4)]
        if header[0] != b'ANDROID BACKUP\n' or header[1] not in {b'1\n', b'2\n', b'3\n', b'4\n', b'5\n'}:
            raise UserError('Unsupported Android Backup header/version.')
        if header[3] != b'none\n':
            raise UserError('Encrypted Android backup: preserve the original and supply a separately decrypted extraction.')
        if header[2] not in {b'0\n', b'1\n'}:
            raise UserError('Invalid Android Backup compression flag.')
        with tempfile.TemporaryDirectory(prefix='lawliet-ab-') as tmp:
            tar = Path(tmp) / 'payload.tar'
            with tar.open('wb') as out:
                if header[2] == b'1\n':
                    inflate(reader, out, max_bytes)
                else:
                    size = 0
                    while block := reader.read(65536):
                        size += len(block)
                        if size > max_bytes:
                            raise UserError('Android Backup exceeds intake limit.')
                        out.write(block)
            extract_archive(tar, destination, max_bytes, max_files)
            return {'format': 'Android Backup', 'version': int(header[1]),
                    'compressed': header[2] == b'1\n', 'payload_sha256': digest(tar)}


def import_backup(root, db, source, label=None, max_bytes=20 * 1024**3, max_files=100000):
    # AB is not a TAR/ZIP, so ordinary intake preserves its original bytes.
    original_id, _, _ = import_evidence(root, db, source, 'android', label or 'Android backup original', max_bytes, max_files, expand_archives=False)
    original = root / 'evidence' / original_id / Path(source).name
    try:
        with tempfile.TemporaryDirectory(prefix='lawliet-ab-intake-') as tmp:
            output = Path(tmp)
            detail = unpack_backup(original, output, max_bytes, max_files)
            derived_id, files, size = import_evidence(root, db, output, 'android', label or 'Android backup extracted', max_bytes, max_files)
        audit(db, 'evidence.derived', {'original_evidence_id': original_id, 'evidence_id': derived_id,
                                     'original_sha256': digest(original), **detail})
        db.commit()
        return {'evidence_id': derived_id, 'original_evidence_id': original_id, 'files': files, 'bytes': size}
    except Exception as exc:
        audit(db, 'evidence.derivation_failed', {'original_evidence_id': original_id, 'error': str(exc)})
        db.commit()
        raise UserError(f'Original retained as {original_id}; extraction failed: {exc}') from exc


def backup_rows(path, limit=128 * 1024**2):
    import io
    output = io.BytesIO()
    with Path(path).open('rb') as reader:
        inflate(reader, output, limit)
    rows = json.loads(output.getvalue())
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise UserError('Telephony backup must contain a JSON list of records.')
    return rows
