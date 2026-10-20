"""Windows host staging for optional Linux workers; no worker emulation.

Retained directory handles prevent parent replacement. Files are created under
random names, written and renamed without replacement by their original handles.
Windows read-only attributes seal staged inputs; container mounts remain read-only.
"""
from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

from .core import UserError
from .windows_files import WindowsDirectory, component


def _security_api(directory):
    c, w = directory.c, directory.w
    api = c.WinDLL("advapi32", use_last_error=True)
    api.GetSecurityInfo.argtypes = [w.HANDLE, c.c_int, w.DWORD, c.POINTER(w.LPVOID),
        c.POINTER(w.LPVOID), c.POINTER(w.LPVOID), c.POINTER(w.LPVOID), c.POINTER(w.LPVOID)]
    api.GetSecurityInfo.restype = w.DWORD
    api.SetSecurityInfo.argtypes = [w.HANDLE, c.c_int, w.DWORD,
                                   w.LPVOID, w.LPVOID, w.LPVOID, w.LPVOID]
    api.SetSecurityInfo.restype = w.DWORD
    api.ConvertSidToStringSidW.argtypes = [w.LPVOID, c.POINTER(w.LPWSTR)]
    api.ConvertSidToStringSidW.restype = w.BOOL
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        w.LPCWSTR, w.DWORD, c.POINTER(w.LPVOID), c.POINTER(w.DWORD)]
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    api.GetSecurityDescriptorDacl.argtypes = [
        w.LPVOID, c.POINTER(w.BOOL), c.POINTER(w.LPVOID), c.POINTER(w.BOOL)]
    api.GetSecurityDescriptorDacl.restype = w.BOOL
    api.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        w.LPVOID, w.DWORD, w.DWORD, c.POINTER(w.LPWSTR), c.POINTER(w.DWORD)]
    api.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = w.BOOL
    directory.api.LocalFree.argtypes = [w.LPVOID]
    directory.api.LocalFree.restype = w.LPVOID
    return api


def private_directory(directory):
    """Set/verify a protected owner+SYSTEM DACL on one newly created directory.

    Callers must never apply this to imported evidence or existing user folders.
    Ancestors and the directory remain pinned while the security handle is opened.
    """
    c, w = directory.c, directory.w
    api = _security_api(directory)
    directory.check()
    handle = directory._open(directory.path, 0x60000, 1, 3, 0x02000000)  # READ_CONTROL | WRITE_DAC
    allocated = []
    try:
        if directory.info(handle, directory=True) != directory.handles[-1][1]:
            raise UserError("New staging directory changed before privacy setup.")
        owner, old_sd = w.LPVOID(), w.LPVOID()
        code = api.GetSecurityInfo(handle, 1, 1, c.byref(owner), None, None, None, c.byref(old_sd))
        if code:
            raise c.WinError(code)
        allocated.append(old_sd)
        owner_string = w.LPWSTR()
        if not api.ConvertSidToStringSidW(owner, c.byref(owner_string)):
            raise directory._error()
        allocated.append(owner_string)
        owner_sid = owner_string.value
        if not owner_sid or not re.fullmatch(r"S-\d+(?:-\d+)+", owner_sid):
            raise UserError("New staging directory owner could not be established.")
        # Explicit inheritable allow entries; inherited entries are removed.
        descriptor = f"D:P(A;OICI;FA;;;{owner_sid})(A;OICI;FA;;;SY)"
        sd = w.LPVOID()
        if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor, 1, c.byref(sd), None):
            raise directory._error()
        allocated.append(sd)
        present, defaulted, dacl = w.BOOL(), w.BOOL(), w.LPVOID()
        if not api.GetSecurityDescriptorDacl(sd, c.byref(present), c.byref(dacl), c.byref(defaulted)):
            raise directory._error()
        if not present or not dacl:
            raise UserError("Private staging DACL is absent.")
        wanted_text = w.LPWSTR()
        if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, 1, 4, c.byref(wanted_text), None):
            raise directory._error()
        allocated.append(wanted_text)
        code = api.SetSecurityInfo(handle, 1, 4 | 0x80000000, None, None, dacl, None)
        if code:
            raise c.WinError(code)
        actual_sd, actual_text = w.LPVOID(), w.LPWSTR()
        code = api.GetSecurityInfo(handle, 1, 4, None, None, None, None, c.byref(actual_sd))
        if code:
            raise c.WinError(code)
        allocated.append(actual_sd)
        if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                actual_sd, 1, 4, c.byref(actual_text), None):
            raise directory._error()
        allocated.append(actual_text)
        actual = actual_text.value
        # Check the actual protected ACL, rather than treating chmod/stat mode
        # emulation as evidence of Windows confidentiality.
        if actual != wanted_text.value:
            raise UserError("Private staging DACL could not be verified exactly.")
        directory.check()
        return actual
    finally:
        for allocation in reversed(allocated):
            directory.api.LocalFree(c.cast(allocation, w.LPVOID))
        directory.api.CloseHandle(handle)


def directory_acl(directory):
    """Read the actual DACL without modifying it; used for boundary validation."""
    c, w = directory.c, directory.w
    api = _security_api(directory)
    directory.check()
    handle = directory._open(directory.path, 0x20000, 1, 3, 0x02000000)
    sd, text = w.LPVOID(), w.LPWSTR()
    try:
        if directory.info(handle, directory=True) != directory.handles[-1][1]:
            raise UserError("Staging directory changed before DACL inspection.")
        code = api.GetSecurityInfo(handle, 1, 4, None, None, None, None, c.byref(sd))
        if code:
            raise c.WinError(code)
        if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, 1, 4, c.byref(text), None):
            raise directory._error()
        return text.value
    finally:
        if text:
            directory.api.LocalFree(c.cast(text, w.LPVOID))
        if sd:
            directory.api.LocalFree(sd)
        directory.api.CloseHandle(handle)


class WindowsStaging:
    def __init__(self, folder):
        self.folder = Path(folder).absolute()
        self.directories = {}

    def __enter__(self):
        self.directories[""] = WindowsDirectory(self.folder).__enter__()
        return self

    def __exit__(self, *args):
        for directory in reversed(list(self.directories.values())):
            directory.close()
        self.directories.clear()

    @staticmethod
    def parts(relative):
        if not isinstance(relative, str):
            raise UserError("Container staging path must be text.")
        path = PurePosixPath(relative)
        if (not path.parts or path.is_absolute() or ".." in path.parts
                or path.as_posix() != relative or "\\" in relative):
            raise UserError("Container staging traversal refused.")
        for part in path.parts:
            component(part)
        return path.parts

    def check(self):
        if not self.directories:
            raise UserError("Container staging directory is closed.")
        for directory in self.directories.values():
            directory.check()

    def parent(self, relative, *, create=False):
        parts = self.parts(relative)
        self.check()
        current = self.directories[""]
        for index, name in enumerate(parts[:-1], 1):
            key = "/".join(parts[:index])
            if key not in self.directories:
                if create:
                    try:
                        (current.path / name).mkdir()
                        created = True
                    except FileExistsError:
                        created = False
                else:
                    created = False
                self.directories[key] = WindowsDirectory(current.path / name).__enter__()
                if created:
                    private_directory(self.directories[key])
            current = self.directories[key]
        return current, parts[-1]

    def mkdir(self, relative):
        parent, name = self.parent(relative)
        (parent.path / name).mkdir()
        self.directories[relative] = WindowsDirectory(parent.path / name).__enter__()
        private_directory(self.directories[relative])
        self.check()

    @staticmethod
    def _attributes(directory, fd, attributes):
        # FileBasicInfo updates the existing file handle, never a replaced name.
        c, w = directory.c, directory.w
        class BasicInformation(c.Structure):
            _fields_ = [("created", c.c_longlong), ("accessed", c.c_longlong),
                        ("written", c.c_longlong), ("changed", c.c_longlong),
                        ("attributes", w.DWORD)]
        value = BasicInformation(0, 0, 0, 0, attributes)
        if not directory.api.SetFileInformationByHandle(
                directory.crt.get_osfhandle(fd), 0, c.byref(value), c.sizeof(value)):
            raise directory._error()

    def write(self, relative, data):
        parent, name = self.parent(relative, create=True)
        _, fd = parent.new_file()
        try:
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("Container staged write made no progress.")
                view = view[count:]
            os.fsync(fd)
            parent.rename(fd, name)  # Existing regular files, links and ADS never overwritten.
            self._attributes(parent, fd, 1)  # FILE_ATTRIBUTE_READONLY
            self.check()
        except BaseException:
            try:
                self._attributes(parent, fd, 0x80)  # Clear read-only on our owned output only.
                parent.delete(fd)
            except OSError:
                pass
            raise
        finally:
            os.close(fd)

    def read(self, relative, limit):
        parent, name = self.parent(relative)
        raw = parent.read(name, limit)
        self.check()
        return raw
