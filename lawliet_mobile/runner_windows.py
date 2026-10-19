"""Windows ownership handles and job-contained trusted parser subprocesses.

The guardian reads its launch configuration only after the parent has assigned
it to a kill-on-close Job Object. No external tool can run in that interval.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import threading


def _api():
    if os.name != 'nt':
        raise RuntimeError('Windows runner primitives require Windows.')
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    signatures = {
        'CreateFileW': ([wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                         wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
        'CreateJobObjectW': ([wintypes.LPVOID, wintypes.LPCWSTR], wintypes.HANDLE),
        'SetInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD], wintypes.BOOL),
        'AssignProcessToJobObject': ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
        'TerminateJobObject': ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
        'CloseHandle': ([wintypes.HANDLE], wintypes.BOOL),
    }
    for name, (args, result) in signatures.items():
        function = getattr(api, name)
        function.argtypes, function.restype = args, result
    return api


def open_lease(path):
    """Deny new write/delete opens while any inherited owner handle remains."""
    import msvcrt
    api = _api()
    handle = api.CreateFileW(str(path), 0x80000000 | 0x40000000, 1, None,
                             4, 0x00200000, None)  # OPEN_ALWAYS, OPEN_REPARSE_POINT
    if handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        if error in (32, 33):
            raise BlockingIOError('A runner or its child still owns this case; retry refused.')
        raise ctypes.WinError(error)
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        api.CloseHandle(handle)
        raise


def process_running(pid):
    """Read process state without Windows' destructive os.kill(pid, 0)."""
    if type(pid) is not int or pid <= 0:
        raise ValueError('Process identifier must be a positive integer.')
    api = _api()
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    handle = api.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE only; no termination right
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: the PID no longer exists
            return False
        raise ctypes.WinError(error)
    try:
        state = api.WaitForSingleObject(handle, 0)
        if state == 0:
            return False
        if state == 258:  # WAIT_TIMEOUT: process handle is not signalled
            return True
        raise ctypes.WinError(ctypes.get_last_error())
    finally:
        api.CloseHandle(handle)


def _job():
    class BasicLimits(ctypes.Structure):
        _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong),
                    ('PerJobUserTimeLimit', ctypes.c_longlong),
                    ('LimitFlags', wintypes.DWORD),
                    ('MinimumWorkingSetSize', ctypes.c_size_t),
                    ('MaximumWorkingSetSize', ctypes.c_size_t),
                    ('ActiveProcessLimit', wintypes.DWORD),
                    ('Affinity', ctypes.c_size_t),
                    ('PriorityClass', wintypes.DWORD),
                    ('SchedulingClass', wintypes.DWORD)]

    class IOCounts(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
            'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [('BasicLimitInformation', BasicLimits), ('IoInfo', IOCounts),
                    ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                    ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]

    api = _api()
    handle = api.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE; no breakaway
    if not api.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        error = ctypes.get_last_error()
        api.CloseHandle(handle)
        raise ctypes.WinError(error)
    return api, handle


def _startup(handles):
    startup = subprocess.STARTUPINFO()
    startup.lpAttributeList = {'handle_list': handles}
    return startup


def _close_job_when_released(api, job, descriptor):
    try:
        # The caller receives the write descriptor, matching the POSIX API.
        while os.read(descriptor, 1):
            pass
    finally:
        os.close(descriptor)
        # Windows' implicit KILL_ON_JOB_CLOSE may report exit code zero. Give
        # explicit cancellation a failure code; closing remains the final guard.
        api.TerminateJobObject(job, 125)
        api.CloseHandle(job)


def spawn(argv, *, cwd, stdout, stderr, lease_fd=None, stdin_fd=None, env=None, hide_console=False):
    import msvcrt
    # Duplicate inherited handles rather than temporarily making the owner's
    # live descriptor inheritable across unrelated concurrent process launches.
    inherited = []
    config_read = config_write = alive_read = alive_write = None
    child = None
    api, job = _job()
    try:
        config_read, config_write = os.pipe()
        handles = {}
        for name, fd in (('configuration', config_read), ('lease', lease_fd), ('stdin', stdin_fd)):
            if fd is not None:
                duplicate = os.dup(fd)
                inherited.append(duplicate)
                os.set_handle_inheritable(msvcrt.get_osfhandle(duplicate), True)
                handles[name] = msvcrt.get_osfhandle(duplicate)
        config = json.dumps({'argv': argv, 'cwd': str(cwd) if cwd else None,
                             'hide_console': hide_console,
                             'lease_handle': handles.get('lease'), 'stdin_handle': handles.get('stdin')}).encode()
        if len(config) > 16384:
            raise ValueError('Guardian launch configuration exceeds bound.')
        interpreter = Path(sys.executable)
        if hide_console and interpreter.name.lower() == 'pythonw.exe':
            interpreter = interpreter.with_name('python.exe')
            if not interpreter.is_file():
                raise RuntimeError('The desktop environment is missing its Python worker interpreter.')
        child = subprocess.Popen(
            [str(interpreter), str(Path(__file__).resolve()), '--guardian', str(handles['configuration'])],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True,
            startupinfo=_startup(list(handles.values())), env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if hide_console else 0)
        # Popen retains the original process HANDLE: no PID lookup/reuse window.
        if not api.AssignProcessToJobObject(job, int(child._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        alive_read, alive_write = os.pipe()
        watcher = threading.Thread(target=_close_job_when_released,
            args=(api, job, alive_read), daemon=True, name='lawliet-owned-job')
        watcher.start()
        job = None
        alive_read = None
        for fd in inherited:
            os.close(fd)
        inherited.clear()
        os.close(config_read)
        config_read = None
        remaining = memoryview(config)
        while remaining:
            try:
                written = os.write(config_write, remaining)
            except InterruptedError:
                continue
            if written <= 0:
                raise BrokenPipeError('Guardian configuration pipe made no progress.')
            remaining = remaining[written:]
        os.close(config_write)
        config_write = None
        return child, alive_write
    except BaseException:
        if alive_write is not None:
            os.close(alive_write)
            alive_write = None
        if job is not None:
            api.CloseHandle(job)
            job = None
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait()
        raise
    finally:
        for fd in [*inherited, config_read, config_write, alive_read]:
            if fd is not None:
                os.close(fd)
        if job is not None:
            api.CloseHandle(job)


def guardian(configuration_handle):
    import msvcrt
    config_fd = msvcrt.open_osfhandle(configuration_handle, os.O_RDONLY | os.O_BINARY)
    with os.fdopen(config_fd, 'rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('Guardian configuration bound')
    config = json.loads(raw)
    lease_handle, stdin_handle = config.get('lease_handle'), config.get('stdin_handle')
    stdin_fd = msvcrt.open_osfhandle(stdin_handle, os.O_RDONLY | os.O_BINARY) if stdin_handle is not None else None
    try:
        child = subprocess.Popen(config['argv'], cwd=config['cwd'], close_fds=True,
            stdin=stdin_fd if stdin_fd is not None else subprocess.DEVNULL,
            startupinfo=_startup([lease_handle] if lease_handle is not None else []),
            creationflags=subprocess.CREATE_NO_WINDOW if config.get('hide_console') else 0)
        return child.wait()
    finally:
        if stdin_fd is not None:
            os.close(stdin_fd)
        if lease_handle is not None:
            _api().CloseHandle(lease_handle)


if __name__ == '__main__':
    sys.exit(guardian(int(sys.argv[2])))
