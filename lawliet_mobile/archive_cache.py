"""Validate archive reuse against source bytes and the complete decoded tree."""
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from .core import UserError
from .provider_sms import _write_manifest

MARKER = '.mulder-extraction-complete.json'
FORMAT = 'ancalor-archive-completion-v1'
RECEIPT_MAX = 32 * 1024**2


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _check_deadline(deadline):
    if time.monotonic() > deadline:
        raise UserError('Archive verification exceeded its 600-second limit.')


def fingerprint(path, *, single_link=False, max_bytes=None, deadline=None, observed=None):
    deadline = time.monotonic() + 600 if deadline is None else deadline
    _check_deadline(deadline)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or (single_link and before.st_nlink != 1):
            raise UserError('Archive cache requires regular unlinked output files.')
        if max_bytes is not None and before.st_size > max_bytes:
            raise UserError('Archive cache exceeds declared output bytes.')
        h, consumed = hashlib.sha256(), 0
        while True:
            _check_deadline(deadline)
            chunk = stream.read(1024**2 if max_bytes is None else min(1024**2, max_bytes - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if max_bytes is not None and consumed > max_bytes:
                raise UserError('Archive cache exceeds declared output bytes.')
            h.update(chunk)
        after = os.fstat(stream.fileno())
        current = os.stat(path, follow_symlinks=False)
        if _identity(before) != _identity(after) or _identity(after) != _identity(current):
            raise UserError('Archive component changed during fingerprinting.')
    if observed is not None:
        observed['identity'] = _identity(after)
    return {'bytes': before.st_size, 'sha256': h.hexdigest()}


def inventory(destination, max_output_bytes, max_files, *, deadline=None):
    deadline = time.monotonic() + 600 if deadline is None else deadline
    destination = Path(destination)
    if destination.is_symlink() or not destination.is_dir():
        raise UserError('Archive cache directory is unavailable or linked.')
    entries, total, budget, file_count = [], 0, 0, 0
    identities = {destination: _identity(destination.stat(follow_symlinks=False))}
    pending = [destination]
    while pending:
        folder = pending.pop()
        with os.scandir(folder) as listing:
            for item in listing:
                _check_deadline(deadline)
                path = Path(item.path)
                if path == destination / MARKER:
                    continue
                relative = path.relative_to(destination).as_posix()
                # Include empty directories and implicit parents, not just files.
                budget += len(relative.encode('utf-8')) + 200
                if budget > RECEIPT_MAX // 2 or len(entries) >= min(1000000, max_files * 129):
                    raise UserError('Archive cache inventory exceeds its receipt bound.')
                original = item.stat(follow_symlinks=False)
                identities[path] = _identity(original)
                mode = original.st_mode
                if stat.S_ISDIR(mode):
                    entries.append({'path': relative, 'kind': 'directory'})
                    pending.append(path)
                elif stat.S_ISREG(mode):
                    file_count += 1
                    if file_count > max_files:
                        raise UserError('Archive cache exceeds declared file count.')
                    value = fingerprint(path, single_link=True, max_bytes=max_output_bytes-total, deadline=deadline)
                    total += value['bytes']
                    if total > max_output_bytes:
                        raise UserError('Archive cache exceeds declared output bytes.')
                    entries.append({'path': relative, 'kind': 'file', **value})
                else:
                    raise UserError('Archive cache contains a link or special file.')
    for path, identity in identities.items():
        _check_deadline(deadline)
        if _identity(os.stat(path, follow_symlinks=False)) != identity:
            raise UserError('Archive cache tree changed during verification.')
    return sorted(entries, key=lambda e: e['path'])


def write_completion(destination, archive, source_before, max_output_bytes, max_files):
    deadline = time.monotonic() + 600
    source_state = {}
    source_after = fingerprint(archive, deadline=deadline, observed=source_state)
    if source_after != source_before:
        raise UserError('Archive changed during extraction; reuse receipt refused.')
    tree = inventory(destination, max_output_bytes, max_files, deadline=deadline)
    if _identity(os.stat(archive, follow_symlinks=False)) != source_state['identity']:
        raise UserError('Archive source changed during receipt verification.')
    receipt = {'format': FORMAT, 'archive': str(archive), 'source': source_after,
               'decoder_policy': 'lawliet-bounded-archive-v1',
               'max_output_bytes': max_output_bytes, 'max_files': max_files,
               'file_count': sum(e['kind'] == 'file' for e in tree), 'inventory': tree}
    if len(json.dumps(receipt).encode()) > RECEIPT_MAX:
        raise UserError('Archive cache receipt exceeds its byte bound.')
    _write_manifest(Path(destination) / MARKER, receipt)


def is_complete(destination, archive, max_output_bytes, max_files):
    try:
        deadline = time.monotonic() + 600
        source_state = {}
        fd = os.open(Path(destination) / MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > RECEIPT_MAX:
                return False
            receipt = json.loads(stream.read(RECEIPT_MAX + 1))
        if (not isinstance(receipt, dict) or receipt.get('format') != FORMAT
                or receipt.get('archive') != str(archive)
                or receipt.get('decoder_policy') != 'lawliet-bounded-archive-v1'
                or receipt.get('max_output_bytes') != max_output_bytes
                or receipt.get('max_files') != max_files
                or receipt.get('source') != fingerprint(archive, deadline=deadline, observed=source_state)):
            return False
        tree = inventory(destination, max_output_bytes, max_files, deadline=deadline)
        if (_identity(os.stat(Path(destination)/MARKER, follow_symlinks=False)) != _identity(info)
                or _identity(os.stat(archive, follow_symlinks=False)) != source_state['identity']):
            return False
        return receipt.get('inventory') == tree and receipt.get('file_count') == sum(e['kind'] == 'file' for e in tree)
    except (OSError, ValueError, TypeError, UserError, RecursionError):
        return False
