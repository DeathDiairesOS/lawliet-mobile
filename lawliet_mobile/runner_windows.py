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
import time


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
        'QueryInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID], wintypes.BOOL),
        'TerminateJobObject': ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
        'CreateIoCompletionPort': ([wintypes.HANDLE, wintypes.HANDLE, ctypes.c_size_t, wintypes.DWORD], wintypes.HANDLE),
        'GetQueuedCompletionStatus': ([wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(wintypes.LPVOID), wintypes.DWORD], wintypes.BOOL),
        'OpenProcess': ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
        'IsProcessInJob': ([wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
        'WaitForSingleObject': ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
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


def _completion_port(api, job):
    """Associate before assigning any process, so lifetime coverage is checkable."""
    class Association(ctypes.Structure):
        _fields_ = [('key', wintypes.LPVOID), ('port', wintypes.HANDLE)]
    port = api.CreateIoCompletionPort(wintypes.HANDLE(-1), None, 0, 1)
    if not port:
        raise ctypes.WinError(ctypes.get_last_error())
    association = Association(job, port)
    if not api.SetInformationJobObject(job, 7, ctypes.byref(association), ctypes.sizeof(association)):
        error = ctypes.get_last_error()
        api.CloseHandle(port)
        raise ctypes.WinError(error)
    return port


def _accounting(api, job):
    class Accounting(ctypes.Structure):
        _fields_ = [(name, ctypes.c_longlong) for name in (
            'user', 'kernel', 'period_user', 'period_kernel')] + [(name, wintypes.DWORD)
            for name in ('page_faults', 'total', 'active', 'terminated')]
    counts = Accounting()
    if not api.QueryInformationJobObject(job, 1, ctypes.byref(counts), ctypes.sizeof(counts), None):
        raise OSError(ctypes.get_last_error(), 'Cannot inspect owned Windows process accounting')
    return counts


def _terminate_and_wait(api, job, port, *, timeout=5):
    """Wait exact process objects, not merely the early ActiveProcesses counter.

    NEW_PROCESS notifications are not guaranteed. Their count must match the
    job's cumulative TotalProcesses; missing/excess coverage refuses outputs.
    https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port
    https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
    """
    deadline = time.monotonic() + timeout
    handles, seen, terminated = [], 0, False
    process_ids = set()

    def collect(wait_ms):
        nonlocal seen
        message, key, pid = wintypes.DWORD(), ctypes.c_size_t(), wintypes.LPVOID()
        if not api.GetQueuedCompletionStatus(port, ctypes.byref(message), ctypes.byref(key), ctypes.byref(pid), wait_ms):
            error = ctypes.get_last_error()
            if error == 258:  # WAIT_TIMEOUT, not an omitted successful packet.
                return False
            raise OSError(error, 'Cannot inspect owned Windows process notifications')
        if key.value != job:
            raise RuntimeError('Unexpected Windows job notification identity')
        if message.value != 6:  # JOB_OBJECT_MSG_NEW_PROCESS; exit packets are not a wait barrier.
            return True
        seen += 1
        if seen > 4096 or not pid.value or pid.value > 0xffffffff:
            raise RuntimeError('Owned Windows process lifetime ledger exceeds its bound')
        if pid.value in process_ids:
            # Refuse ambiguous reuse as well as duplicate packets: either could
            # otherwise conceal a different lifetime whose packet was omitted.
            raise RuntimeError('Owned Windows process lifetime ledger repeats an identity')
        process_ids.add(pid.value)
        handle = api.OpenProcess(0x00101000, False, pid.value)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:  # PID no longer identifies an extant process object.
                return True
            raise OSError(error, 'Cannot retain owned Windows process identity')
        try:
            state = api.WaitForSingleObject(handle, 0)
            if state == 0:
                return True  # This exact object has already terminated.
            if state != 258:
                raise OSError(ctypes.get_last_error(), 'Cannot inspect owned Windows process state')
            member = wintypes.BOOL()
            if not api.IsProcessInJob(handle, job, ctypes.byref(member)):
                raise OSError(ctypes.get_last_error(), 'Cannot verify owned Windows process membership')
            if not member.value:
                # Could be a recycled PID. Never wait for or signal an unrelated
                # live process, nor treat unknown identity as completed work.
                raise RuntimeError('Windows process identity no longer matches its owned job')
            handles.append(handle)
            handle = None
        finally:
            if handle is not None:
                api.CloseHandle(handle)
        return True

    try:
        # Retain available live identities before requesting asynchronous exit.
        while collect(0):
            if time.monotonic() >= deadline:
                raise TimeoutError('Owned Windows process ledger did not stabilize within its bound')
        if not api.TerminateJobObject(job, 125):
            raise OSError(ctypes.get_last_error(), 'Cannot terminate owned Windows process tree')
        terminated = True
        while True:
            counts = _accounting(api, job)
            if seen > counts.total:
                raise RuntimeError('Owned Windows process lifetime ledger has excess notifications')
            if counts.active == 0 and seen == counts.total:
                for handle in handles:
                    remaining = max(0, int((deadline - time.monotonic()) * 1000))
                    state = api.WaitForSingleObject(handle, remaining)
                    if state == 258:
                        raise TimeoutError('Owned Windows process did not finish terminating within its bound')
                    if state != 0:
                        raise OSError(ctypes.get_last_error(), 'Cannot wait for owned Windows process termination')
                final = _accounting(api, job)
                if final.active == 0 and seen == final.total:
                    return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Owned Windows process lifetime coverage could not be confirmed')
            collect(min(50, max(1, int(remaining * 1000))))
    finally:
        if not terminated:
            api.TerminateJobObject(job, 125)
        for handle in handles:
            api.CloseHandle(handle)


def _close_job_when_released(api, job, port, descriptor, completed, errors):
    try:
        while os.read(descriptor, 1):
            pass
    finally:
        os.close(descriptor)
        try:
            _terminate_and_wait(api, job, port)
        except BaseException as exc:
            errors.append(type(exc).__name__)
        finally:
            api.CloseHandle(job)
            api.CloseHandle(port)
            completed.set()


def wait_stopped(child):
    """Do not promote output until every owned process lifetime has completed."""
    state = getattr(child, '_lawliet_job_completion', None)
    if state is not None:
        completed, errors = state
        if not completed.wait(6) or errors:
            raise RuntimeError('Owned Windows process-tree termination could not be confirmed')


def spawn(argv, *, cwd, stdout, stderr, lease_fd=None, stdin_fd=None, env=None, hide_console=False):
    import msvcrt
    # Duplicate inherited handles rather than temporarily making the owner's
    # live descriptor inheritable across unrelated concurrent process launches.
    inherited = []
    config_read = config_write = alive_read = alive_write = None
    child = port = None
    api, job = _job()
    try:
        port = _completion_port(api, job)
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
        completed, errors = threading.Event(), []
        child._lawliet_job_completion = (completed, errors)
        watcher = threading.Thread(target=_close_job_when_released,
            args=(api, job, port, alive_read, completed, errors), daemon=True, name='lawliet-owned-job')
        watcher.start()
        job = port = None
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
        if port is not None:
            api.CloseHandle(port)
            port = None
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
        if port is not None:
            api.CloseHandle(port)


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
