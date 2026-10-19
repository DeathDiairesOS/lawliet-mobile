"""Bounded, staged decoding for Mulder's general archive tool."""
import bz2
import gzip
import os
import shutil
import stat
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

from .core import UserError, _safe_name


MAX_BYTES = 20 * 1024**3
MAX_FILES = 100000
RESERVE_BYTES = 1024**3


def extract_bounded(source, destination, *, password=None,
                    max_output_bytes=MAX_BYTES, max_files=MAX_FILES):
    """Publish only a complete ZIP/TAR/gzip/bzip2 decode, or raise visibly.

    Links, special files, duplicate paths and decoder fallback are refused.
    These are disk/file/time controls, not a claim of OS or memory isolation.
    """
    if (type(max_output_bytes) is not int or not 1 <= max_output_bytes <= MAX_BYTES
            or type(max_files) is not int or not 1 <= max_files <= MAX_FILES):
        raise UserError('Invalid archive limits: bytes 1..21474836480; files 1..100000.')
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not source.is_file():
        raise UserError('Archive must be a regular non-symlink file.')
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise UserError('Archive destination must be an empty non-symlink directory.')
    if password is not None and (not isinstance(password, str) or not 1 <= len(password) <= 1024):
        raise UserError('Invalid supplied ZIP password.')
    deadline = time.monotonic() + 600
    seen, files, total, members = set(), [], 0, 0

    def has_tar_member():
        # A zero-filled disk image can be mistaken for an empty tar by
        # is_tarfile. Inspect only the first member, not the entire stream.
        try:
            with tarfile.open(source, 'r|*') as archive:
                return archive.next() is not None
        except (tarfile.TarError, OSError, EOFError):
            return False

    def guard():
        if time.monotonic() > deadline:
            raise UserError('Archive decoding exceeded its 600-second limit.')
        if shutil.disk_usage(destination.parent).free < RESERVE_BYTES:
            raise UserError('Archive decoding reached its 1 GiB disk reserve.')

    with tempfile.TemporaryDirectory(prefix='.lawliet-archive-', dir=destination.parent) as temporary:
        stage = Path(temporary) / 'complete'
        stage.mkdir(mode=0o700)

        def member(name, size, directory=False):
            nonlocal members
            guard()
            if len(name.encode('utf-8', errors='surrogatepass')) > 4096:
                raise UserError('Archive path exceeds 4096 bytes.')
            relative = _safe_name(name)
            if not relative.parts or len(relative.parts) > 128:
                raise UserError('Archive path is empty or exceeds 128 components.')
            key = relative.as_posix()
            if key == '.mulder-extraction-complete.json':
                raise UserError('Archive path conflicts with extraction bookkeeping.')
            if key in seen:
                raise UserError('Duplicate archive path: ' + key)
            seen.add(key)
            members += 1
            if members > max_files or size < 0 or size + total > max_output_bytes:
                raise UserError('Archive exceeds declared byte/file limits.')
            if size + RESERVE_BYTES > shutil.disk_usage(destination.parent).free:
                raise UserError('Archive member exceeds available disk budget and reserve.')
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if directory:
                target.mkdir(exist_ok=True)
            return target

        def copy(reader, target, expected=None):
            nonlocal total
            written = 0
            with target.open('xb') as output:
                while True:
                    guard()
                    # Read one extra byte at the boundary so exact-cap inputs pass.
                    chunk = reader.read(min(1024**2, max_output_bytes - total + 1))
                    if not chunk:
                        break
                    written += len(chunk)
                    if total + len(chunk) > max_output_bytes:
                        raise UserError('Archive exceeds declared byte limit.')
                    if expected is not None and written > expected:
                        raise UserError('Archive member exceeds its declared size.')
                    if len(chunk) + RESERVE_BYTES > shutil.disk_usage(destination.parent).free:
                        raise UserError('Archive decoding reached its disk reserve.')
                    output.write(chunk)
                    total += len(chunk)
            if expected is not None and written != expected:
                raise UserError('Truncated archive member.')
            files.append(target.relative_to(stage).as_posix())

        suffix = source.suffix.lower()
        if suffix == '.zip':
            with zipfile.ZipFile(source) as archive:
                if password is not None:
                    archive.setpassword(password.encode('utf-8'))
                for item in archive.infolist():
                    mode = item.external_attr >> 16
                    if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                        raise UserError('Archive links and special files are not accepted.')
                    target = member(item.filename, item.file_size, item.is_dir())
                    if not item.is_dir():
                        with archive.open(item) as reader:
                            copy(reader, target, item.file_size)
        elif password is not None:
            raise UserError('Supplied passwords are supported for ZIP only.')
        elif (suffix in {'.tar', '.tgz'} or source.name.lower().endswith(('.tar.gz', '.tar.bz2'))
              or (suffix in {'.gz', '.bz2'} and has_tar_member())):
            with tarfile.open(source, 'r|*') as archive:
                for item in archive:
                    if not (item.isfile() or item.isdir()):
                        raise UserError('Archive links and special files are not accepted.')
                    target = member(item.name, item.size, item.isdir())
                    if item.isfile():
                        with archive.extractfile(item) as reader:
                            copy(reader, target, item.size)
        elif suffix in {'.gz', '.bz2'}:
            target = member(source.stem, 0)
            opener = gzip.open if suffix == '.gz' else bz2.open
            with opener(source, 'rb') as reader:
                copy(reader, target)
        else:
            raise UserError('Archive format has no qualified bounded decoder: ' + suffix)
        guard()
        os.replace(stage, destination)
    return sorted(files)
