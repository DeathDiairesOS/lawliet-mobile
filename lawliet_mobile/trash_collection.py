"""Bounded, explicit Samsung shared-storage Trash collection. No restore/delete."""
import json
import re
import shlex
import subprocess
import uuid
from pathlib import Path, PurePosixPath

from .core import UserError, audit, digest, import_evidence, json_text, now
from .media_sources import record_trash

TRASH_ROOT = '/sdcard/Android/.Trash'
MAX_FILES = 1000
MAX_LIST_BYTES = 1024 * 1024
PHOTO_SUFFIXES = {'.jpg', '.jpeg', '.png', '.heic', '.heif', '.webp', '.gif'}


def collect_trash(root, db, workspace, serial, timeout=900, max_bytes=1024**3):
    from .tools import command, execute, storage_guard
    if (not isinstance(serial, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]+', serial)
            or serial.startswith('-')):
        raise UserError('Supply the authorized device serial.')
    if type(max_bytes) is not int or max_bytes <= 0:
        raise UserError('Use a positive collection byte budget.')
    argv = command(workspace, 'adb') + ['-s', serial]
    identifier = uuid.uuid4().hex[:12]
    folder = root / 'collections' / identifier
    folder.mkdir(parents=True)
    started = now()
    commands, coverage, errors, matches = [], [], [], []
    status, eid = 'failed', None
    audit(db, 'collection.started', {'collection_id': identifier, 'serial': serial,
        'platform': 'android', 'profile': 'trash-photos', 'requested_paths': [TRASH_ROOT],
        'device_changes': 'Read-only ADB listing, hashing and copying; no restore or delete.'})
    db.commit()

    def run(args, name, ceiling=None):
        guard = storage_guard(folder, max_bytes)
        def bounded():
            guard()
            output = folder / name
            if ceiling is not None and output.exists() and output.stat().st_size > ceiling:
                raise UserError('Trash discovery output exceeds its bound.')
        try:
            result = execute(argv + args, folder / name, timeout, guard=bounded)
        except (OSError, subprocess.TimeoutExpired, UserError) as exc:
            result = getattr(exc, 'tool_result', {'argv': argv + args, 'returncode': None, 'error': str(exc)})
        commands.append(result)
        if result.get('returncode') != 0 or result.get('error'):
            raise UserError('Trash command failed; retained command logs describe the failure.')
        return folder / name

    def remote_hash(remote, name):
        output = run(['shell', 'sha256sum ' + shlex.quote(remote)], name, 4096)
        value = output.read_text(encoding='utf-8').strip()
        if not re.fullmatch(r'[0-9a-f]{64}\s+.+', value):
            raise UserError('Source SHA-256 could not be established.')
        return value[:64]

    try:
        state = run(['get-state'], 'device-state.txt', 4096).read_text().strip()
        if state != 'device':
            raise UserError('Selected device is unavailable or unauthorized.')
        run(['shell', 'getprop'], 'device-properties.txt', MAX_LIST_BYTES)
        run(['version'], 'adb-version.txt', 16384)
        clock_before = now()
        clock = run(['shell', 'date +%Y-%m-%dT%H:%M:%S%z'], 'device-time.txt', 4096)
        (folder / 'clock-observation.json').write_text(json_text({
            'host_before_utc': clock_before, 'host_after_utc': now(),
            'device_output': clock.read_text(encoding='utf-8'),
            'note': 'Clock observation only; no device clock correction or inferred deletion time.'}) + '\n', encoding='utf-8')
        listing = run(['shell', f'find {TRASH_ROOT} -type f -print0'], 'trash-paths.bin', MAX_LIST_BYTES).read_bytes()
        if listing and not listing.endswith(b'\0'):
            raise UserError('Incomplete Trash file listing; no files copied.')
        paths = listing.rstrip(b'\0').split(b'\0') if listing else []
        if len(paths) > MAX_FILES:
            raise UserError('Trash listing exceeds 1,000 files; narrow the acquisition manually.')
        decoded = [path.decode('utf-8', errors='strict') for path in paths]
        for remote in decoded:
            if (not remote.startswith(TRASH_ROOT + '/') or '..' in PurePosixPath(remote).parts
                    or any(ord(c) < 32 or ord(c) == 127 for c in remote)):
                raise UserError('Unsupported Trash filename; no files copied.')
        for index, remote in enumerate(dict.fromkeys(decoded)):
            if PurePosixPath(remote).suffix.lower() not in PHOTO_SUFFIXES:
                continue
            try:
                before = remote_hash(remote, f'{index}-hash-before.txt')
                output = folder / 'photos' / str(index) / PurePosixPath(remote).name
                output.parent.mkdir(parents=True)
                run(['pull', '-a', remote, str(output)], f'{index}-pull.txt')
                if output.is_symlink() or not output.is_file():
                    raise UserError('Pull did not return a regular file.')
                after = remote_hash(remote, f'{index}-hash-after.txt')
                acquired = digest(output)
                if before != after or acquired != before:
                    raise UserError('Source changed or copy hash mismatch; bytes retained without a verified Trash label.')
                from .media import media_type
                kind = media_type(output)
                if not kind or not kind[0].startswith('image/'):
                    raise UserError('File suffix was photo-like but acquired bytes are not a recognized image.')
                receipt = folder / 'receipts' / f'{index}.json'
                receipt.parent.mkdir(exist_ok=True)
                receipt.write_text(json_text({'format': 'ancalor-android-trash-acquisition-v1',
                    'source_kind': 'trash', 'method': 'read-only-adb-pull', 'remote_path': remote,
                    'bytes': output.stat().st_size, 'source_sha256_before': before,
                    'source_sha256_after': after, 'acquired_sha256': acquired,
                    'collected_at_host_utc': now()}) + '\n', encoding='utf-8')
                matches.append((output.relative_to(folder).as_posix(), receipt.relative_to(folder).as_posix()))
                coverage.append({'source': remote, 'state': 'collected', 'sha256': acquired,
                                 'detail': 'Accessible Trash copy; not permanent-deletion carving.'})
            except (UserError, OSError, UnicodeError) as exc:
                errors.append({'source': remote, 'error': str(exc)})
                coverage.append({'source': remote, 'state': 'failed', 'detail': str(exc)})
                # Budget failures must not trigger further pulls.
                if sum(p.stat().st_size for p in folder.rglob('*') if p.is_file()) >= max_bytes:
                    break
        if not coverage:
            coverage.append({'source': TRASH_ROOT, 'state': 'collected_empty',
                'detail': 'No matching files in this accessible path. Other apps/profiles and permanent deletion are not assessed.'})
        status = 'partial' if errors else 'complete'
    except (UserError, OSError, UnicodeError) as exc:
        errors.append({'error': str(exc)})
    finally:
        manifest = {'collection_id': identifier, 'platform': 'android', 'serial': serial,
            'profile': 'trash-photos', 'started_at_host_utc': started, 'finished_at_host_utc': now(),
            'status': status, 'coverage': coverage, 'commands': commands, 'errors': errors,
            'scope': 'Samsung shared-storage Trash path only; no private-app, MediaStore-wide or permanently deleted recovery claim.'}
        (folder / 'collection.json').write_text(json_text(manifest) + '\n', encoding='utf-8')
        try:
            eid, _, _ = import_evidence(root, db, folder, 'android', 'Android Gallery Trash collection', max_bytes)
            files = {r['path']: r['id'] for r in db.execute('SELECT id,path FROM files WHERE evidence_id=?', (eid,))}
            for media, receipt in matches:
                record_trash(root, db, files[media], files[receipt])
        except Exception as exc:
            status = 'failed'
            errors.append({'intake_error': str(exc), 'retained_path': str(folder)})
        audit(db, 'collection.finished', {'collection_id': identifier, 'status': status,
              'evidence_id': eid, 'errors': errors})
        db.commit()
    return {'collection_id': identifier, 'status': status, 'evidence_id': eid,
            'path': str(folder), 'coverage': coverage, 'errors': errors,
            'verified_trash_photos': len(matches) if eid and status != 'failed' else 0}
