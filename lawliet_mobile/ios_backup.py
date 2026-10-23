"""Database-only iPhone backup retention using a qualified external CLI.

This still runs Apple's backup protocol. Other payload bytes pass over USB but
are discarded by pymobiledevice3; this is not a restorable or complete backup.
"""
from contextlib import closing, contextmanager
import os
from pathlib import Path
import plistlib
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid

from .child_output import ChildOutputs
from .core import UserError, audit, digest, import_evidence, json_text, now
from .iphone_connection import UDID, require_local_usb_environment
from .provider_contacts import _create_collection
from .runner_lease import lease
from .tools import command, execute, storage_guard

VERSION = '11.41.2'
SCHEMA = 'lawliet.ios-selected/1'
RESERVE = 1024**3
MAX_FILES = 100000
BASE_PATHS = ('Library/SMS/sms.db', 'Library/AddressBook/AddressBook.sqlitedb')
SELECTED_PATHS = frozenset(p + suffix for p in BASE_PATHS for suffix in ('', '-wal', '-shm'))
DATABASE_REGEX = r'(?:^|/)(?:HomeDomain[-/])?Library/(?:SMS/sms\.db|AddressBook/AddressBook\.sqlitedb)(?:-(?:wal|shm))?$'
METADATA = frozenset(('Info.plist', 'Manifest.plist', 'Manifest.db', 'Manifest.db-wal', 'Manifest.db-shm', 'Status.plist'))


def _atomic_receipt(anchor, name, value):
    """Publish generated receipts without following child-created temp links."""
    if name not in ('collection.json', 'selection.json'):
        raise UserError('Unsupported selected-backup receipt name.')
    data = (json_text(value) + '\n').encode('utf-8')
    anchor.check_directory()
    temporary, fd, published = None, None, False
    try:
        if anchor.windows is not None:
            temporary, fd = anchor.windows.new_file()
        else:
            temporary = '.receipt-' + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=anchor.fd)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        anchor.check_directory()
        if anchor.windows is not None:
            anchor.windows.rename(fd, name, replace=True)
        else:
            os.replace(temporary, name, src_dir_fd=anchor.fd, dst_dir_fd=anchor.fd)
        published = True
        anchor.check_directory()
    finally:
        if fd is not None:
            try:
                if anchor.windows is not None and not published:
                    anchor.windows.delete(fd)
            finally:
                os.close(fd)
        if temporary is not None and anchor.windows is None and not published:
            try:
                os.unlink(temporary, dir_fd=anchor.fd)
            except FileNotFoundError:
                pass


def _files(folder):
    """Reject links/special output before reading or importing child files."""
    result = {}
    for current, directories, names in os.walk(folder, followlinks=False):
        for name in directories + names:
            path = Path(current) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise UserError('Linked iPhone collection output refused; raw attempt retained.')
            if name in directories:
                if not stat.S_ISDIR(info.st_mode):
                    raise UserError('Non-directory collection output refused.')
            else:
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise UserError('Collection output must be single-link regular files.')
                result[path.relative_to(folder).as_posix()] = info.st_size
                if len(result) > MAX_FILES:
                    raise UserError('iPhone collection exceeded its file-count limit.')
    return result


def _read(path, maximum=1024**2):
    with ChildOutputs(path.parent) as output:
        return output.read(path.name, maximum)


def _backup_failure(anchor, maximum):
    """Classify known tool diagnostics without reflecting evidence or log text.

    Oversized, missing or unsafe logs remain available for manual review, but
    never replace the original failure with a second diagnostic-read failure.
    """
    parts = []
    for name in ('backup.log', 'backup.log.stderr'):
        try:
            parts.append(anchor.read(name, min(maximum, 1024**2)).decode('utf-8', errors='replace'))
        except (OSError, UserError):
            continue
    diagnostics = '\n'.join(parts)
    if ('MBErrorDomain/208' in diagnostics or
            re.search(r"Device link error:[^\n]*['\"]ErrorCode['\"]:\s*208\b", diagnostics)):
        return ('iPhone backup was refused because the device is locked (backup error 208). '
                'Unlock the selected iPhone, approve any backup/passcode prompt on the phone, '
                'keep it unlocked and rerun collection. The failed attempt is retained; no automatic retry.')
    if any(value in diagnostics for value in ('NotEnoughDiskSpaceError', 'MBErrorDomain/105', 'No space left on device')):
        return ('iPhone backup reported insufficient storage. Check available space on the computer and iPhone '
                'before rerunning. Apple may require whole-backup free space even with database-only retention. '
                'The failed attempt is retained; no automatic retry.')
    if re.search(r'\b(?:ConnectionTerminatedError|StreamClosedError|DeviceNotFoundError|NoDeviceConnectedError|ConnectionResetError|BrokenPipeError)\b', diagnostics):
        return ('iPhone backup reported a lost or unavailable device connection. Check the USB connection, '
                'unlock the selected iPhone and confirm trust if prompted, then rerun collection. '
                'The failed attempt is retained; no automatic retry.')
    if 'Please enter the device passcode to continue the backup' in diagnostics:
        return ('iPhone backup requested passcode confirmation on the phone but did not complete. '
                'Unlock the selected iPhone and approve any backup/passcode prompt on the phone when rerunning. '
                'The failed attempt is retained; no automatic retry.')
    return None


@contextmanager
def _database_copy(path, folder, max_bytes):
    """SQLite may create sidecars, so inspect a disposable bounded copy."""
    companions = [p for p in (path, Path(str(path) + '-wal'), Path(str(path) + '-shm')) if p.exists()]
    needed = sum(p.stat().st_size for p in companions)
    existing = sum(_files(folder).values())
    if existing + needed > max_bytes or shutil.disk_usage(folder).free < needed + RESERVE:
        raise UserError('Insufficient collection budget for SQLite validation working copy.')
    with tempfile.TemporaryDirectory(prefix='.validate-', dir=folder) as temp:
        target = Path(temp) / path.name
        for source in companions:
            shutil.copyfile(source, Path(temp) / source.name)
        with closing(sqlite3.connect(target.as_uri() + '?mode=ro', uri=True)) as db:
            # Hostile/corrupt databases must not monopolize the worker.
            deadline = time.monotonic() + 15
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            yield db


def _inspect_backup(folder, serial, max_bytes):
    backup = folder / 'backup' / serial
    _files(folder)
    errors = []
    metadata_hashes = {}
    for name in ('Info.plist', 'Manifest.plist', 'Status.plist', 'Manifest.db'):
        path = backup / name
        if not path.is_file() or path.stat().st_size == 0:
            raise UserError('Missing or empty iPhone backup metadata: ' + name)
    for name in METADATA:
        path = backup / name
        if path.is_file():
            metadata_hashes[name] = digest(path)
    try:
        info = plistlib.loads(_read(backup / 'Info.plist', 16 * 1024**2))
        manifest = plistlib.loads(_read(backup / 'Manifest.plist', 16 * 1024**2))
        status = plistlib.loads(_read(backup / 'Status.plist'))
    except (ValueError, plistlib.InvalidFileException) as exc:
        raise UserError('Invalid backup metadata; received bytes retained.') from exc
    if not all(isinstance(p, dict) for p in (info, manifest, status)):
        raise UserError('Invalid backup metadata shape.')
    if manifest.get('IsEncrypted') is not False:
        raise UserError('Backup is encrypted or encryption state is unknown; selected encrypted parsing is unsupported. No password or encryption change attempted.')
    identifiers = [info[k] for k in ('Target Identifier', 'Unique Identifier') if k in info]
    if not identifiers or any(not isinstance(v, str) or v.lower() != serial.lower() for v in identifiers):
        raise UserError('Returned backup identity does not match the selected iPhone.')
    if status.get('SnapshotState') != 'finished':
        errors.append('Backup snapshot did not finish.')
    payloads, selected_seen, excluded = [], set(), 0
    removed_placeholders = []
    output = folder / 'omissions.jsonl'
    temporary = folder / 'omissions.tmp'
    produced = 0
    with _database_copy(backup / 'Manifest.db', folder, max_bytes) as db, temporary.open('x', encoding='utf-8') as omitted:
        base_bytes = sum(_files(folder).values())
        if db.execute('PRAGMA quick_check(1)').fetchone()[0] != 'ok':
            raise UserError('Backup Manifest.db failed SQLite integrity validation.')
        for number, row in enumerate(db.execute('SELECT fileID,domain,relativePath,flags FROM Files')):
            if number >= 1000000:
                raise UserError('Backup manifest exceeds review row limit.')
            file_id, domain, relative, flags = row
            if not all(isinstance(v, str) for v in (file_id, domain, relative)) or not re.fullmatch(r'[0-9a-fA-F]{40}', file_id):
                raise UserError('Invalid file identifier or path types in backup manifest.')
            selected = domain == 'HomeDomain' and relative in SELECTED_PATHS
            candidates = [p for p in (backup / file_id[:2] / file_id, backup / file_id) if p.is_file()]
            if len(candidates) > 1:
                raise UserError('Duplicate physical payload paths for one backup file identifier.')
            path = candidates[0] if candidates else None
            size = path.stat().st_size if path else 0
            if selected:
                if relative in selected_seen:
                    raise UserError('Duplicate selected path in backup manifest.')
                selected_seen.add(relative)
                if flags != 1 or not path or not size:
                    errors.append('Selected manifest payload missing or empty: HomeDomain/' + relative)
                else:
                    payloads.append({'file_id': file_id, 'domain': domain, 'relative_path': relative,
                                     'path': path.relative_to(folder).as_posix(), 'bytes': size, 'sha256': digest(path)})
            else:
                excluded += 1
                if size:
                    raise UserError('Unexpected nonselected backup payload retained; no evidence imported.')
            if path and not size:
                # These are transport placeholders, not acquired zero-byte SQL databases.
                removed_placeholders.append(path.relative_to(folder).as_posix())
                path.unlink()
            if not selected or not size:
                record = {'file_id': file_id, 'domain': domain, 'relative_path': relative, 'flags': flags,
                          'reason': 'selected_payload_missing' if selected else 'outside_selected_scope'}
                line = json_text(record) + '\n'
                produced += len(line.encode('utf-8'))
                if base_bytes + produced > max_bytes:
                    raise UserError('Omission inventory exceeds collection byte budget.')
                if number % 1024 == 0 and shutil.disk_usage(folder).free < RESERVE:
                    raise UserError('Free-space reserve reached while writing omission inventory.')
                omitted.write(line)
    os.replace(temporary, output)
    for relative in BASE_PATHS:
        if relative not in selected_seen:
            errors.append('Requested database not present in backup manifest: HomeDomain/' + relative)
    present = {p['relative_path']: p for p in payloads}
    for relative in BASE_PATHS:
        if relative not in present:
            continue
        payload = present[relative]
        path = folder / payload['path']
        # Restore logical filenames only in disposable validation workspace so WAL can be applied.
        with tempfile.TemporaryDirectory(prefix='.database-', dir=folder) as temp:
            temporary_db = Path(temp) / Path(relative).name
            needed = sum(present[p]['bytes'] for p in (relative, relative + '-wal', relative + '-shm') if p in present)
            if sum(_files(folder).values()) + needed > max_bytes or shutil.disk_usage(folder).free < needed + RESERVE:
                raise UserError('Insufficient collection budget for selected database validation.')
            for logical in (relative, relative + '-wal', relative + '-shm'):
                if logical in present:
                    shutil.copyfile(folder / present[logical]['path'], Path(temp) / Path(logical).name)
            try:
                with closing(sqlite3.connect(temporary_db.as_uri() + '?mode=ro', uri=True)) as source:
                    deadline = time.monotonic() + 15
                    source.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                    if source.execute('PRAGMA quick_check(1)').fetchone()[0] != 'ok':
                        raise sqlite3.DatabaseError('integrity check failed')
                    tables = {r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    expected = 'message' if relative.endswith('sms.db') else 'ABPerson'
                    if expected not in tables:
                        raise sqlite3.DatabaseError('expected table absent: ' + expected)
            except sqlite3.DatabaseError as exc:
                errors.append('Selected database validation failed: ' + relative + ': ' + str(exc))
    expected_paths = {(backup / name).relative_to(folder).as_posix() for name in METADATA}
    expected_paths.update(p['path'] for p in payloads)
    for path in _files(backup):
        if (backup / path).relative_to(folder).as_posix() not in expected_paths:
            raise UserError('Unrecognized backup output remains; no evidence imported.')
    if any(digest(backup / name) != value for name, value in metadata_hashes.items()):
        raise UserError('Original backup metadata changed during validation.')
    return {'schema': SCHEMA, 'selected_payloads': payloads, 'selected_manifest_files': len(selected_seen),
            'excluded_manifest_entries': excluded, 'metadata_sha256': metadata_hashes,
            'removed_zero_byte_placeholders': removed_placeholders,
            'requested_sidecars': sorted(p for p in SELECTED_PATHS if p not in BASE_PATHS),
            'received_sidecars': sorted(p for p in present if p not in BASE_PATHS),
            'omission_inventory': 'omissions.jsonl', 'omission_inventory_sha256': digest(output), 'errors': errors}


def collect_selected(root, db, workspace, serial, timeout=900, max_bytes=256 * 1024**2):
    if not isinstance(serial, str) or not UDID.fullmatch(serial):
        raise UserError('Select an explicit USB iPhone identifier.')
    if type(timeout) is not int or not 1 <= timeout <= 3600 or type(max_bytes) is not int or not 1024**2 <= max_bytes <= 2 * 1024**3:
        raise UserError('Invalid selected iPhone acquisition timeout or byte budget.')
    require_local_usb_environment()
    # Resolve dependencies before any phone command or attempt output.
    cmd = command(workspace, 'pymobiledevice3')
    info_tool = command(workspace, 'ideviceinfo')
    with lease(root, db):
        return _collect(root, db, cmd, info_tool, serial, timeout, max_bytes)


def _collect(root, db, cmd, info_tool, serial, timeout, max_bytes):
    identifier = uuid.uuid4().hex[:12]
    folder = _create_collection(root, identifier)
    # ChildOutputs pins Windows ancestry with WindowsDirectory and checks the
    # POSIX directory identity before each command/guard/publication.
    with ChildOutputs(folder) as anchor:
        return _collect_owned(root, db, cmd, info_tool, serial, timeout, max_bytes, identifier, folder, anchor)


def _collect_owned(root, db, cmd, info_tool, serial, timeout, max_bytes, identifier, folder, anchor):
    deadline = time.monotonic() + timeout
    commands, errors, coverage = [], [], []
    status, evidence_id, selection = 'failed', None, None
    started = now()
    byte_guard = storage_guard(folder, max_bytes, reserve=RESERVE)
    def guard():
        anchor.check_directory()
        byte_guard()
        _files(folder)
    tool_hashes = {str(Path(p).absolute()): digest(Path(p)) for p in cmd + info_tool if Path(p).is_file()}
    receipt = {'schema': SCHEMA, 'collection_id': identifier, 'platform': 'ios', 'profile': 'ios-selected',
               'serial': serial, 'started_at_host_utc': started, 'commands': commands, 'errors': errors,
               'coverage': coverage, 'max_bytes': max_bytes, 'tool_version_required': VERSION, 'tool_hashes': tool_hashes,
               'scope': 'SMS/iMessage and contacts databases with returned WAL/SHM only. Attachments, contact images and other payloads intentionally omitted. Not a restorable full backup.',
               'storage_policy': 'Periodic byte/free-space guard with intake-copy reserve; transient growth between checks is possible. Backup protocol may still demand whole-backup free space.',
               'device_changes': 'Apple backup service and sync lock; no restore, password change, encryption change, app installation or configuration changes requested.'}
    audit(db, 'collection.started', receipt)
    db.commit()

    def run(argv, name, limit):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UserError('Selected iPhone collection deadline exceeded.')
        guard()
        try:
            value = execute(argv, folder / name, min(limit, remaining), guard=guard)
        except BaseException as exc:
            if hasattr(exc, 'tool_result'):
                commands.append(exc.tool_result)
            if name == 'backup.log' and isinstance(exc, subprocess.TimeoutExpired):
                detail = _backup_failure(anchor, max_bytes)
                raise UserError(detail or 'iPhone backup timed out. Inspect the retained attempt before rerunning; no automatic retry.') from exc
            raise
        commands.append(value)
        if value.get('returncode') != 0 or value.get('error'):
            if name == 'backup.log':
                detail = _backup_failure(anchor, max_bytes)
                if detail:
                    raise UserError(detail)
            raise UserError('iPhone collection command failed; retained logs describe the attempt: ' + name)
        return _read(folder / name, min(max_bytes, 1024**2)).decode('utf-8', errors='replace')

    try:
        version = run(cmd + ['version'], 'version.log', 30).strip()
        if version != VERSION:
            raise UserError('Selected acquisition requires qualified pymobiledevice3 ' + VERSION + '; found ' + version[:100])
        help_text = run(cmd + ['backup2', 'backup', '--help'], 'help.log', 30)
        # Rich truncates the longer --no-patch-manifest cell at normal widths.
        # Its paired positive option plus the exact qualified version establish
        # this contract without mistaking display truncation for incompatibility.
        if not all(flag in help_text for flag in ('--only-regex', '--patch-manifest')):
            raise UserError('Installed pymobiledevice3 does not advertise the qualified selection contract.')
        encryption = run(info_tool + ['-u', serial, '-q', 'com.apple.mobile.backup', '-k', 'WillEncrypt'], 'encryption.log', 15).strip().lower()
        receipt['encryption_observed'] = encryption if encryption in ('true', 'false') else 'unknown'
        if encryption != 'false':
            raise UserError('Selected collection requires a known unencrypted backup for this adapter. Encrypted or unknown backup state is unsupported; no settings changed.')
        backup = folder / 'backup'
        backup.mkdir(mode=0o700)
        run(cmd + ['backup2', 'backup', '--udid', serial, '--only-regex', DATABASE_REGEX,
                   '--no-patch-manifest', str(backup)], 'backup.log', timeout)
        selection = _inspect_backup(folder, serial, max_bytes)
        errors.extend(selection['errors'])
        diagnostics = _read(folder / 'backup.log.stderr', min(max_bytes, 1024**2)).decode('utf-8', errors='replace')
        if 'Failed to fully upload:' in diagnostics or 'Traceback (most recent call last)' in diagnostics:
            errors.append('Backup emitted a file-transfer failure; inspect backup.log.stderr.')
        _atomic_receipt(anchor, 'selection.json', selection)
        for relative in BASE_PATHS:
            received = next((p for p in selection['selected_payloads'] if p['relative_path'] == relative), None)
            coverage.append({'source': 'HomeDomain/' + relative, 'state': 'collected' if received else 'not_returned',
                             'sha256': received['sha256'] if received else None,
                             'detail': 'Returned database only; device-wide completeness is not established.'})
        coverage.append({'source': 'attachments_and_other_payloads', 'state': 'intentionally_omitted',
                         'detail': 'Excluded to preserve storage. See omissions.jsonl; unavailable attachment bytes are not examined.'})
        status = 'partial' if errors else 'complete'
    except KeyboardInterrupt:
        status = 'interrupted'
        errors.append('Examiner interrupted collection; any partial bytes remain in the attempt directory.')
    except Exception as exc:
        errors.append(str(exc))
    finally:
        receipt.update(status=status, finished_at_host_utc=now(), selection=selection)
        receipt_written = False
        manifest_hash = None
        try:
            _atomic_receipt(anchor, 'collection.json', receipt)
            receipt_written = True
            manifest_hash = digest(folder / 'collection.json')
        except Exception as exc:
            status = 'failed'
            errors.append('Collection receipt could not be finalized; raw attempt retained: ' + str(exc))
        # Import only inspected output: failed/incomplete raw bytes are retained at the attempt path.
        if selection is not None and receipt_written:
            try:
                guard()
                total = sum(_files(folder).values())
                if shutil.disk_usage(folder).free < total + RESERVE:
                    raise UserError('Insufficient space for the preserved evidence copy.')
                evidence_id = import_evidence(root, db, folder, 'ios', 'iPhone selected messages and contacts',
                                              max_bytes=max_bytes, max_files=MAX_FILES, expand_archives=False)[0]
            except Exception as exc:
                status = 'failed'
                errors.append('Evidence intake failed; collection retained: ' + str(exc))
                receipt.update(status=status)
                try:
                    _atomic_receipt(anchor, 'collection.json', receipt)
                    manifest_hash = digest(folder / 'collection.json')
                except Exception as final_error:
                    manifest_hash = None
                    errors.append('Updated failure receipt could not be finalized: ' + str(final_error))
        audit(db, 'collection.finished', {'collection_id': identifier, 'status': status, 'evidence_id': evidence_id,
                                         'manifest_sha256': manifest_hash, 'errors': errors})
        db.commit()
    return {'collection_id': identifier, 'status': status, 'evidence_id': evidence_id, 'path': str(folder),
            'coverage': coverage, 'errors': errors, 'selection': selection}
