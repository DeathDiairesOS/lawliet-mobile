"""Local Windows file handles for bounded reads and exclusive derived outputs.

Directory handles reject reparse points and deny write/delete sharing while held.
Owned outputs are renamed or deleted by handle, never by a subsequently resolved
source path. Network shares and device paths are deliberately unsupported.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PureWindowsPath
import secrets

from .core import UserError


def component(name):
    reserved = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'}
    reserved.update(prefix + number for prefix in ('COM', 'LPT')
                    for number in '123456789¹²³')
    if (not isinstance(name, str) or not name or name in ('.', '..')
            or name[-1] in ' .' or any(ord(c) < 32 or c in '<>:"/\\|?*' for c in name)
            or name.split('.')[0].upper() in reserved):
        raise UserError('Unsupported Windows filename or device namespace.')
    return name


def local_path(path):
    value = PureWindowsPath(path)
    if not value.is_absolute() or len(value.drive) != 2 or value.drive[1] != ':' or not value.drive[0].isalpha():
        raise UserError('Safe Windows file access requires an absolute local drive path.')
    for part in value.parts[1:]:
        component(part)
    return value


def _api():
    if os.name != 'nt':
        raise UserError('Windows file handles are only available on Windows.')
    import ctypes as c
    from ctypes import wintypes as w
    import msvcrt
    dll = c.WinDLL('kernel32', use_last_error=True)
    dll.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    dll.CreateFileW.restype = w.HANDLE
    dll.CloseHandle.argtypes = [w.HANDLE]; dll.CloseHandle.restype = w.BOOL
    dll.GetFileType.argtypes = [w.HANDLE]; dll.GetFileType.restype = w.DWORD
    dll.GetFileInformationByHandle.argtypes = [w.HANDLE, w.LPVOID]
    dll.GetFileInformationByHandle.restype = w.BOOL
    dll.SetFileInformationByHandle.argtypes = [w.HANDLE, c.c_int, w.LPVOID, w.DWORD]
    dll.SetFileInformationByHandle.restype = w.BOOL

    class Information(c.Structure):
        _fields_ = [('attributes', w.DWORD), ('created', w.FILETIME),
                    ('accessed', w.FILETIME), ('written', w.FILETIME),
                    ('volume', w.DWORD), ('size_high', w.DWORD), ('size_low', w.DWORD),
                    ('links', w.DWORD), ('index_high', w.DWORD), ('index_low', w.DWORD)]

    class Rename(c.Structure):
        _fields_ = [('replace', w.BOOLEAN), ('root', w.HANDLE),
                    ('length', w.DWORD), ('name', w.WCHAR * 1)]

    return c, w, msvcrt, dll, Information, Rename


class WindowsDirectory:
    def __init__(self, path, *, create=False):
        self.path = Path(str(local_path(path)))
        self.create = create
        self.handles = []
        self.c, self.w, self.crt, self.api, self.Information, self.Rename = _api()

    def _error(self, path=None):
        error = self.c.WinError(self.c.get_last_error())
        if path is not None:
            error.filename = str(path)
        return error

    def _open(self, path, access, sharing, disposition, flags=0):
        handle = self.api.CreateFileW('\\\\?\\' + str(path), access, sharing, None,
                                      disposition, flags | 0x00200000, None)
        if handle == self.w.HANDLE(-1).value:
            raise self._error(path)
        return handle

    def info(self, handle, *, directory=False):
        info = self.Information()
        if not self.api.GetFileInformationByHandle(handle, self.c.byref(info)):
            raise self._error()
        if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory or self.api.GetFileType(handle) != 1:
            raise UserError('Windows evidence path is linked or is not a regular file/directory.')
        identity = (info.volume, info.index_high, info.index_low)
        if directory:
            return identity
        if info.links != 1:
            raise UserError('Child or export output must have exactly one link.')
        return identity + (info.links, (info.size_high << 32) | info.size_low,
                           info.written.dwHighDateTime, info.written.dwLowDateTime,
                           info.created.dwHighDateTime, info.created.dwLowDateTime)

    def __enter__(self):
        current = Path(self.path.anchor)
        try:
            for part in (None, *self.path.parts[1:]):
                if part is not None:
                    current /= part
                    if self.create:
                        try:
                            current.mkdir()
                        except FileExistsError:
                            pass
                # READ_ATTRIBUTES; share reads only. This excludes concurrent
                # directory replacement and adding a reparse point in place.
                handle = self._open(current, 0x80, 1, 3, 0x02000000)
                try:
                    identity = self.info(handle, directory=True)
                except BaseException:
                    self.api.CloseHandle(handle)
                    raise
                self.handles.append((handle, identity))
            return self
        except BaseException:
            self.close()
            raise

    def check(self):
        if not self.handles:
            raise UserError('Windows directory handle is closed.')
        for handle, identity in self.handles:
            if self.info(handle, directory=True) != identity:
                raise UserError('Windows output directory changed.')

    def read(self, name, maximum, *, prefix=False):
        component(name)
        if type(maximum) is not int or maximum < 0:
            raise UserError('Output byte limit must be a nonnegative integer.')
        self.check()
        handle = self._open(self.path / name, 0x80000000, 1, 3)
        fd = None
        try:
            before = self.info(handle)
            if not prefix and before[4] > maximum:
                raise UserError('Child output exceeds its byte limit.')
            fd = self.crt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(maximum if prefix else maximum + 1)
            if not prefix and len(data) > maximum:
                raise UserError('Child output exceeds its byte limit.')
            if before != self.info(handle):
                raise UserError('Child output changed while reading.')
            self.check()
            return data
        finally:
            if fd is not None:
                os.close(fd)
            else:
                self.api.CloseHandle(handle)

    def new_file(self):
        self.check()
        name = '.lawliet-export-' + secrets.token_hex(16)
        # READ | WRITE | DELETE; no other writer/deleter can open this file.
        handle = self._open(self.path / name, 0xc0010000, 1, 1)
        try:
            self.info(handle)
            return name, self.crt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        except BaseException:
            self.api.CloseHandle(handle)
            raise

    def digest(self, fd):
        self.check()
        handle = self.crt.get_osfhandle(fd)
        before = self.info(handle)
        value = hashlib.sha256()
        os.lseek(fd, 0, os.SEEK_SET)
        for block in iter(lambda: os.read(fd, 1024 * 1024), b''):
            value.update(block)
        if before != self.info(handle):
            raise UserError('Export output changed while hashing.')
        return value.hexdigest()

    def rename(self, fd, name):
        self.check(); component(name)
        encoded = str(self.path / name).encode('utf-16-le')
        size = self.Rename.name.offset + len(encoded)
        buffer = self.c.create_string_buffer(max(size, self.c.sizeof(self.Rename)))
        info = self.Rename.from_buffer(buffer)
        info.replace = False; info.root = None; info.length = len(encoded)
        self.c.memmove(self.c.addressof(buffer) + self.Rename.name.offset, encoded, len(encoded))
        if not self.api.SetFileInformationByHandle(self.crt.get_osfhandle(fd), 3, buffer, size):
            error = self.c.get_last_error()
            if error in (80, 183):
                raise FileExistsError('Choose new export and companion filenames.')
            raise self._error(self.path / name)

    def delete(self, fd):
        delete = self.w.BOOLEAN(True)
        if not self.api.SetFileInformationByHandle(self.crt.get_osfhandle(fd), 4,
                                                  self.c.byref(delete), self.c.sizeof(delete)):
            raise self._error()

    def close(self):
        for handle, _ in reversed(self.handles):
            self.api.CloseHandle(handle)
        self.handles = []

    def __exit__(self, *args):
        self.close()
