"""Exclusive staged outputs anchored to one non-symlink parent directory."""
import hashlib
import os
from pathlib import Path
import secrets
import stat

from .core import UserError


class OutputFiles:
    """Protect output identity and clean only files created by this operation.

    A pair is published sequentially, not as an atomic filesystem transaction.
    Concurrent privileged modification is outside this local-process boundary.
    """
    def __init__(self, paths):
        self.paths = [Path(p).absolute() for p in paths]
        self.fd = None
        self.owned = {}
        self.stages = {}
        self.file_fds = []
        if not self.paths or len(set(self.paths)) != len(self.paths) or len({p.parent for p in self.paths}) != 1:
            raise UserError('Outputs require distinct files in one directory.')
        if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
            raise UserError('Safe export requires no-follow directory APIs on this platform.')

    def __enter__(self):
        parent = self.paths[0].parent
        if '..' in parent.parts:
            raise UserError('Export parent traversal is unsupported.')
        fd = os.open(parent.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parent.parts[1:]:
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            self.fd = fd
            for p in self.paths:
                try:
                    os.stat(p.name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise FileExistsError('Choose new export and companion filenames.')
            self.check_parent()
            return self
        except BaseException:
            os.close(fd)
            self.fd = None
            raise

    def check_parent(self):
        # Reopen the complete chain rather than following a replaced ancestor.
        parent = self.paths[0].parent
        fd = os.open(parent.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parent.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            current, original = os.fstat(fd), os.fstat(self.fd)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise UserError('Export directory changed during processing.')
        finally:
            os.close(fd)

    @staticmethod
    def identity(s):
        return s.st_dev, s.st_ino

    def open(self, path):
        path = Path(path)
        self.check_parent()
        name = '.lawliet-export-' + secrets.token_hex(16)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        # Hold the original descriptor until cleanup ends so unlink/recreate
        # cannot recycle its inode and impersonate an owned output.
        self.file_fds.append(fd)
        self.owned[name] = self.identity(os.fstat(fd))
        self.stages[path.name] = name
        return os.fdopen(os.dup(fd), 'w', encoding='utf-8')

    def digest(self, path):
        name = self.stages.get(Path(path).name, Path(path).name)
        self.check_parent()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or self.identity(before) != self.owned.get(name):
                raise UserError('Export output identity changed during processing.')
            value = hashlib.sha256()
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    value.update(block)
            after = os.fstat(fd)
            fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if fingerprint(before) != fingerprint(after) or fingerprint(after) != fingerprint(os.stat(name, dir_fd=self.fd, follow_symlinks=False)):
                raise UserError('Export output changed while hashing.')
            return value.hexdigest()
        finally:
            os.close(fd)

    def publish(self):
        self.check_parent()
        for path in self.paths:
            stage = self.stages[path.name]
            self.digest(path)
            # link refuses an existing file, including a symlink. No overwrite.
            os.link(stage, path.name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
            self.owned[path.name] = self.owned[stage]
            os.unlink(stage, dir_fd=self.fd)
            del self.owned[stage]
            del self.stages[path.name]
        self.check_parent()

    def __exit__(self, kind, value, trace):
        try:
            names = list(self.owned) if kind else list(self.stages.values())
            for name in names:
                try:
                    current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                    if self.identity(current) == self.owned[name]:
                        os.unlink(name, dir_fd=self.fd)
                except FileNotFoundError:
                    pass
        finally:
            for fd in self.file_fds:
                os.close(fd)
            os.close(self.fd)
