"""Owned Windows directory publication for bounded archive decoding.

The original empty destination and staging directory stay open without delete
sharing. A concurrent replacement destination is never overwritten or removed.
"""
import os
from pathlib import Path
import secrets
import shutil
import tempfile

from .core import UserError
from .windows_files import WindowsDirectory


class ArchivePublication:
    def __init__(self, destination):
        self.destination = Path(destination).absolute()
        self.parent = None
        self.original = self.stage_fd = None
        self.stage = None
        self.retired = None
        self.published = False

    def _directory(self, path):
        handle = self.parent._open(path, 0x10081, 1, 3, 0x02000000)
        try:
            identity = self.parent.info(handle, directory=True)
            fd = self.parent.crt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            return fd, identity
        except BaseException:
            self.parent.api.CloseHandle(handle)
            raise

    def __enter__(self):
        try:
            self.parent = WindowsDirectory(self.destination.parent).__enter__()
            self.original, self.identity = self._directory(self.destination)
            if any(self.destination.iterdir()):
                raise UserError('Archive destination must remain empty.')
            self.stage = Path(tempfile.mkdtemp(prefix='.lawliet-archive-', dir=self.parent.path))
            self.stage_fd, self.stage_identity = self._directory(self.stage)
            return self.stage, self.publish
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def publish(self):
        self.parent.check()
        if (self.parent.info(self.parent.crt.get_osfhandle(self.original), directory=True) != self.identity
                or any(self.destination.iterdir())):
            raise UserError('Archive destination changed during decoding.')
        self.retired = self.parent.path / ('.lawliet-archive-empty-' + secrets.token_hex(16))
        self.parent.rename(self.original, self.retired.name, replace=False)
        try:
            if any(self.retired.iterdir()):
                raise UserError('Archive destination acquired content during publication.')
            # Both operations refer to retained source handles. Never opt in to
            # replacement, even when a competing destination happens to be empty.
            self.parent.rename(self.stage_fd, self.destination.name, replace=False)
            self.published = True
            self.parent.delete(self.original)  # Only this exact owned empty directory.
            os.close(self.original)
            self.original = None
            self.retired = None
        except BaseException as exc:
            if self.published:
                raise UserError('Complete archive output was published, but original destination cleanup failed; '
                                'the original directory is retained at ' + str(self.retired)) from exc
            if self.original is not None and not self.published:
                try:
                    self.parent.rename(self.original, self.destination.name, replace=False)
                    self.retired = None
                except OSError:
                    # A concurrent target belongs to someone else. Keep it.
                    # The retired original is deleted only if still empty.
                    if not any(self.retired.iterdir()):
                        self.parent.delete(self.original)
                    else:
                        raise UserError('Archive publication refused; changed original directory retained at '
                                        + str(self.retired)) from exc
            raise

    def __exit__(self, *args):
        try:
            if self.stage_fd is not None and not self.published:
                # The retained handle pins this exact directory throughout
                # cleanup; a vacated temporary pathname is never removed.
                for entry in self.stage.iterdir():
                    if entry.is_dir() and not entry.is_symlink():
                        shutil.rmtree(entry)
                    else:
                        entry.unlink()
                self.parent.delete(self.stage_fd)
        finally:
            for name in ('stage_fd', 'original'):
                fd = getattr(self, name)
                if fd is not None:
                    os.close(fd)
                    setattr(self, name, None)
            if self.parent is not None:
                self.parent.close()
