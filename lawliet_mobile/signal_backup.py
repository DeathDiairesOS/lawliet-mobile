"""Known-passphrase on-device Signal backup adapter; secrets never enter argv/logs."""
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from pathlib import Path
from .core import UserError, audit, digest, import_evidence, json_text, now
from .tools import command, storage_guard


LIMITATIONS = [
    'Supports legacy Android single-file .backup exports with a known 30-digit passphrase. New on-device backup folders (backup.db, attachments, manifest.json) and Signal Secure Backups are not supported.',
    'Only records and media present in the supplied backup can be examined; missing or deleted history is not established by a successful decode.',
    'Decoded files are retained as emitted by the tool. Message-to-attachment availability is assessed separately during artifact indexing.',
]


def signal_backup_preflight(source, workspace=None):
    """Describe intake without reading keys, importing evidence or executing a tool.

    A filename cannot authenticate an encrypted format. Eligible opaque files are
    candidates only; the configured decoder must subsequently validate them.
    """
    path = Path(source).expanduser()
    try:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise UserError('Signal backup input must not be a symlink.')
        if stat.S_ISDIR(mode):
            if (path / 'backup.db').exists() or (path / 'manifest.json').exists() or path.name.startswith('signal-backup-'):
                raise UserError('New Signal on-device backup folders are not supported by this legacy decoder. Preserve the complete folder, including backup.db, attachments and manifest.json, using Import evidence; decryption remains unavailable.')
            if (path / 'database.sqlite').is_file():
                raise UserError('This appears to be an already decoded Signal directory. Use Import evidence so its database and media are preserved together; no passphrase is needed.')
            raise UserError('Select the individual legacy Android Signal .backup file, not its containing folder. New on-device folder backups and Signal Secure Backups are not supported by this decoder.')
        if not stat.S_ISREG(mode):
            raise UserError('Signal backup input must be a regular file.')
        if path.name in {'backup.db', 'manifest.json'} and (path.parent / 'manifest.json').exists():
            raise UserError('This belongs to a new Signal on-device backup folder, which this legacy decoder does not support. Preserve the complete folder using Import evidence instead of selecting individual components.')
        size = path.stat().st_size
        if not size:
            raise UserError('Signal backup file is empty.')
        with path.open('rb') as handle:
            header = handle.read(16)
    except OSError as exc:
        raise UserError('Cannot read the selected Signal backup file.') from exc
    if header == b'SQLite format 3\x00':
        raise UserError('This is already a plaintext SQLite database. Use Import evidence with its companion files; do not decrypt it again.')
    if header.startswith((b'PK\x03\x04', b'PK\x05\x06', b'\x1f\x8b')):
        raise UserError('This is a compressed archive, not a supported Android on-device Signal backup file. Select the contained .backup file after preserving the original archive.')
    result = {'format': 'android_on_device_candidate', 'format_verified': False,
              'bytes': size, 'credential': 'known_30_digit_passphrase',
              'limitations': list(LIMITATIONS)}
    if workspace is not None:
        try:
            cmd = command(workspace, 'signalbackup-tools')
            result['tool'] = {'available': True, 'path': cmd[-1], 'compatibility_verified': False}
        except UserError:
            result['tool'] = {'available': False, 'compatibility_verified': False,
                              'setup': 'Configure an independently installed signalbackup-tools executable using lawliet tools configure signalbackup-tools /path/to/tool.'}
    return result


def _tool_contract(cmd):
    """Validate the installed CLI without sending it evidence or credentials."""
    try:
        help_result = subprocess.run(cmd + ['--help'], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UserError('Cannot inspect signalbackup-tools CLI support; verify the configured installation.') from exc
    help_text = help_result.stdout.decode('utf-8', errors='replace')
    if help_result.returncode or not all(flag in help_text for flag in ('--output', '--stoponerror')):
        raise UserError('Configured signalbackup-tools does not advertise the required --output and --stoponerror options. Install/configure a compatible version before decoding evidence.')
    version = re.search(r'source version\s+([A-Za-z0-9._+-]{1,80})', help_text)
    return {'version': version.group(1) if version else None,
            'version_status': 'reported_by_tool' if version else 'not_reported',
            'executable_sha256': digest(cmd[-1]), 'required_cli_verified': True}


def _check_output(output):
    """Reject links and special files before indexing decoder-generated output."""
    if output.is_symlink() or not output.is_dir():
        raise UserError('Signal decoder output directory is unsafe or missing.')
    count = 0
    for current, dirs, names in os.walk(output, followlinks=False):
        for name in dirs + names:
            mode = (Path(current) / name).lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise UserError('Signal decoder produced an unsafe link or special file; output was not imported.')
        count += len(names)
    database = output / 'database.sqlite'
    if not database.is_file():
        raise UserError('Decoder returned no database.sqlite. Partial output is retained but not indexed.')
    with database.open('rb') as handle:
        if handle.read(16) != b'SQLite format 3\x00':
            raise UserError('Decoder output is not a plaintext SQLite database.')
    return count


def decrypt_signal(root, db, workspace, source, passphrase, timeout=900, max_bytes=20*1024**3):
    from .runner_lease import lease
    with lease(root, db):
        return _decrypt_signal_owned(root, db, workspace, source, passphrase, timeout, max_bytes)


def _decrypt_signal_owned(root, db, workspace, source, passphrase, timeout, max_bytes):
    if not isinstance(passphrase, str):
        raise UserError('Provide the known Android on-device backup passphrase in the secure passphrase field.')
    secret = re.sub(r'[\s-]', '', passphrase)
    if len(secret) == 64:
        raise UserError('A 64-character recovery key is not supported here. This decoder accepts only a legacy Android single-file .backup and its known 30-digit passphrase; new on-device folders and Signal Secure Backups are unsupported.')
    if not re.fullmatch(r'[0-9]{30}', secret):
        raise UserError('Legacy Signal backups require the known 30-digit passphrase. New backup formats are not supported by this adapter.')
    if os.name != 'posix':
        raise UserError('Secure passphrase transport currently requires macOS/Linux.')
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 3600:
        raise UserError('Signal decoding timeout must be greater than zero and at most 3600 seconds.')
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise UserError('Signal decoding storage budget must be a positive byte count.')
    preflight = signal_backup_preflight(source)
    if preflight['bytes'] > max_bytes:
        raise UserError('Signal backup exceeds the decoding storage budget.')
    cmd = command(workspace, 'signalbackup-tools')
    tool = _tool_contract(cmd)
    original_eid, _, _ = import_evidence(root, db, source, 'android', 'Original encrypted Signal backup', max_bytes=max_bytes, expand_archives=False)
    original = db.execute('SELECT * FROM files WHERE evidence_id=?', (original_eid,)).fetchone()
    preserved = root / 'evidence' / original_eid / original['path']
    db.execute('UPDATE evidence SET encrypted=1 WHERE id=?', (original_eid,))
    run = uuid.uuid4().hex[:12]
    folder = root / 'runs' / run
    folder.mkdir(mode=0o700, parents=True)
    output = folder / 'decrypted'
    output.mkdir(mode=0o700)
    work = folder / 'input.backup'
    argv = cmd + [str(work), '--stoponerror', '--output', str(output)]
    from .runner_lease import ownership, spawn, stop
    owner = ownership()
    detail = {'runner_ownership': owner, 'argv': argv, 'original_evidence_id': original_eid,
              'original_sha256': original['sha256'], 'tool': tool,
              'executable_sha256': tool['executable_sha256'],
              'timeout_seconds': timeout, 'max_bytes': max_bytes,
              'format': 'android_on_device', 'limitations': list(LIMITATIONS),
              'note': 'Upstream stdout/stderr suppressed because it may print derived encryption keys. Passphrase sent through a non-echoing private terminal; never recorded. Strict stop-on-error mode prevents silently accepting recovered partial input.'}
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)', (run, original_eid, 'signalbackup-tools', now(), 'running', json_text(detail)))
    audit(db, 'analysis.started', {'run_id': run, 'evidence_id': original_eid, 'engine': 'signalbackup-tools', 'runner_ownership': owner})
    audit(db, 'signal.decrypt.started', {'run_id': run, 'original_evidence_id': original_eid})
    db.commit()
    status = 'failed'
    child = alive = master = slave = None
    try:
        if preserved.is_symlink() or digest(preserved) != original['sha256']:
            raise UserError('Preserved Signal backup failed its integrity check before decoding.')
        shutil.copyfile(preserved, work)
        os.chmod(work, 0o600)
        if digest(work) != original['sha256']:
            raise UserError('Signal working copy failed its integrity check.')
        import pty, termios
        master, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        guard = storage_guard(folder, max_bytes)
        guard()
        child, alive = spawn(argv, stdin_fd=slave, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=folder)
        os.write(master, (secret + '\n').encode())
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            guard()
            if time.monotonic() > deadline:
                raise UserError('Signal decryption timed out; partial output retained.')
            time.sleep(0.2)
        guard()
        detail['returncode'] = child.returncode
        detail['process_status_kind'] = 'guardian exit status; child signal exits mapped to 128+signal'
        if child.returncode:
            raise UserError('Signal decryption failed. Check backup format, tool compatibility and the supplied passphrase. Partial output is retained but not indexed.')
        if work.is_symlink() or digest(work) != original['sha256']:
            raise UserError('Signal decoder changed its input working copy; output was not imported.')
        if preserved.is_symlink() or digest(preserved) != original['sha256']:
            raise UserError('Preserved Signal backup failed its integrity check after decoding; output was not imported.')
        detail['input_integrity'] = 'passed_before_and_after'
        output_files = _check_output(output)
        derived_eid, files, size = import_evidence(root, db, output, 'android', 'Decrypted Signal backup · ' + original_eid, max_bytes=max_bytes, expand_archives=False)
        detail.update(derived_evidence_id=derived_eid, files=files, bytes=size,
                      non_database_files=max(0, output_files - 1))
        status = 'complete'
        return {'status': status, 'run_id': run, 'original_evidence_id': original_eid,
                'evidence_id': derived_eid, 'files': files, 'bytes': size,
                'original_sha256': original['sha256'], 'input_integrity': detail['input_integrity'],
                'tool': tool, 'non_database_files': detail['non_database_files'],
                'limitations': list(LIMITATIONS)}
    except BaseException as exc:
        detail['error'] = str(exc) if isinstance(exc, UserError) else 'Signal decoding interrupted or failed (' + type(exc).__name__ + '); partial output retained.'
        # Defensive redaction also covers paths accidentally containing a key.
        detail['error'] = detail['error'].replace(secret, '[redacted]')
        if isinstance(exc, (UserError, KeyboardInterrupt, SystemExit)):
            raise
        raise UserError(detail['error']) from exc
    finally:
        if child and child.poll() is None:
            stop(child, alive)
            alive = None
        if alive is not None:
            os.close(alive)
        for fd in (master, slave):
            if fd is not None:
                os.close(fd)
        try:
            detail['preserved_original_intact'] = not preserved.is_symlink() and digest(preserved) == original['sha256']
        except OSError:
            detail['preserved_original_intact'] = False
        db.execute('UPDATE runs SET status=?,finished_at=?,detail=? WHERE id=?', (status, now(), json_text(detail), run))
        audit(db, 'signal.decrypt.finished', {'run_id': run, 'status': status, 'original_evidence_id': original_eid, 'derived_evidence_id': detail.get('derived_evidence_id'), 'preserved_original_intact': detail['preserved_original_intact']})
        db.commit()
