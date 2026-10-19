"""Bounded reads of child-created regular files in one anchored directory."""
import os
from pathlib import Path
import stat

from .core import UserError


class ChildOutputs:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        self.fd = None
        self.windows = None

    def _directory(self):
        if '..' in self.directory.parts:
            raise UserError('Unsafe child output directory.')
        fd = os.open(self.directory.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in self.directory.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def __enter__(self):
        if os.name == 'nt':
            from .windows_files import WindowsDirectory
            self.windows = WindowsDirectory(self.directory).__enter__()
            return self
        self.fd = self._directory()
        return self

    def check_directory(self):
        if self.windows is not None:
            self.windows.check()
            return
        fd = self._directory()
        try:
            current, original = os.fstat(fd), os.fstat(self.fd)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise UserError('Child output directory changed.')
        finally:
            os.close(fd)

    def read(self, name, maximum, *, prefix=False):
        if self.windows is not None:
            return self.windows.read(name, maximum, prefix=prefix)
        if not name or Path(name).name != name or name in ('.', '..'):
            raise UserError('Unsafe child output filename.')
        self.check_directory()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise UserError('Child output must be a regular file with one link.')
            if not prefix and before.st_size > maximum:
                raise UserError('Child output exceeds its byte limit.')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(maximum if prefix else maximum + 1)
            if not prefix and len(data) > maximum:
                raise UserError('Child output exceeds its byte limit.')
            fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if fingerprint(before) != fingerprint(after) or fingerprint(after) != fingerprint(current):
                raise UserError('Child output changed while reading.')
            self.check_directory()
            return data
        finally:
            os.close(fd)

    def __exit__(self, *args):
        if self.windows is not None:
            self.windows.close()
            self.windows = None
            return
        os.close(self.fd)
        self.fd = None
