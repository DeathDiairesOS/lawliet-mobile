"""Private Windows console transport for Signal's documented runtime prompt.

The upstream Windows getPassword() calls CRT _getch(), which reads a console,
not redirected stdin. This owned helper receives only the 30 digits through an
anonymous stdin pipe, allocates a separate console, hides it, and supplies input
only to that console. The runner's Windows Job Object owns helper and decoder.
No passphrase argument, environment variable, temporary file or log is used.

Protocol sources (reviewed 2026-10-20):
https://github.com/bepaald/signalbackup-tools/blob/master/main.h
https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/getch-getwch
https://learn.microsoft.com/en-us/windows/console/allocconsole
https://learn.microsoft.com/en-us/windows/console/writeconsoleinput
"""
from __future__ import annotations

import os
import subprocess
import sys


def run(argv):
    if os.name != 'nt' or not argv:
        return 120
    import ctypes as C
    from ctypes import wintypes as W
    import msvcrt

    class Character(C.Union):
        _fields_ = [('UnicodeChar', W.WCHAR), ('AsciiChar', C.c_char)]

    class KeyEvent(C.Structure):
        _fields_ = [('bKeyDown', W.BOOL), ('wRepeatCount', W.WORD),
                    ('wVirtualKeyCode', W.WORD), ('wVirtualScanCode', W.WORD),
                    ('uChar', Character), ('dwControlKeyState', W.DWORD)]

    class Event(C.Union):
        _fields_ = [('KeyEvent', KeyEvent), ('padding', C.c_byte * 16)]

    class InputRecord(C.Structure):
        _fields_ = [('EventType', W.WORD), ('Event', Event)]

    kernel = C.WinDLL('kernel32', use_last_error=True)
    user = C.WinDLL('user32', use_last_error=True)
    kernel.AllocConsole.argtypes = []; kernel.AllocConsole.restype = W.BOOL
    kernel.FreeConsole.argtypes = []; kernel.FreeConsole.restype = W.BOOL
    kernel.GetConsoleWindow.argtypes = []; kernel.GetConsoleWindow.restype = W.HWND
    kernel.GetConsoleProcessList.argtypes = [C.POINTER(W.DWORD), W.DWORD]
    kernel.GetConsoleProcessList.restype = W.DWORD
    kernel.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE]
    kernel.CreateFileW.restype = W.HANDLE
    kernel.GetConsoleMode.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]; kernel.GetConsoleMode.restype = W.BOOL
    kernel.SetConsoleMode.argtypes = [W.HANDLE, W.DWORD]; kernel.SetConsoleMode.restype = W.BOOL
    kernel.WriteConsoleInputW.argtypes = [W.HANDLE, C.POINTER(InputRecord), W.DWORD, C.POINTER(W.DWORD)]
    kernel.WriteConsoleInputW.restype = W.BOOL
    kernel.FlushConsoleInputBuffer.argtypes = [W.HANDLE]; kernel.FlushConsoleInputBuffer.restype = W.BOOL
    kernel.CloseHandle.argtypes = [W.HANDLE]; kernel.CloseHandle.restype = W.BOOL
    user.ShowWindow.argtypes = [W.HWND, C.c_int]; user.ShowWindow.restype = W.BOOL
    user.IsWindowVisible.argtypes = [W.HWND]; user.IsWindowVisible.restype = W.BOOL
    secret, events, handle, console_fd, child = bytearray(), None, None, None, None
    allocated = False
    try:
        # Read before AllocConsole resets the process standard handles. The
        # anonymous input is inherited only through the existing owned runner.
        secret = bytearray(sys.stdin.buffer.readline(32))
        if len(secret) != 31 or secret[-1] != 10 or any(c < 48 or c > 57 for c in secret[:-1]):
            return 120
        sys.stdin.close()
        kernel.FreeConsole()  # Detach this helper only; never target another PID.
        if not kernel.AllocConsole():
            return 121
        allocated = True
        window = kernel.GetConsoleWindow()
        if not window:
            return 121
        user.ShowWindow(window, 0)
        if user.IsWindowVisible(window):
            return 121
        processes = (W.DWORD * 2)()
        if kernel.GetConsoleProcessList(processes, 2) != 1 or processes[0] != os.getpid():
            return 121
        handle = kernel.CreateFileW('CONIN$', 0xC0000000, 3, None, 3, 0, None)
        if handle in (None, C.c_void_p(-1).value):
            handle = None
            return 121
        mode = W.DWORD()
        if not kernel.GetConsoleMode(handle, C.byref(mode)) or not kernel.SetConsoleMode(handle, mode.value & ~4):
            return 121
        events = (InputRecord * 31)()
        for index, code in enumerate(secret):
            code = 13 if index == 30 else code
            events[index].EventType = 1  # KEY_EVENT
            key = events[index].Event.KeyEvent
            key.bKeyDown, key.wRepeatCount, key.wVirtualKeyCode = True, 1, code
            key.uChar.UnicodeChar = chr(code)
        written = W.DWORD()
        if not kernel.WriteConsoleInputW(handle, events, len(events), C.byref(written)) or written.value != len(events):
            return 121
        C.memset(C.addressof(events), 0, C.sizeof(events))
        secret[:] = b'\0' * len(secret)
        # No CREATE_NEW_CONSOLE/DETACHED_PROCESS: the decoder must inherit this
        # helper's private console. Both remain descendants in the runner's Job.
        console_fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None  # Descriptor now owns the console handle.
        child = subprocess.Popen(argv, stdin=console_fd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
        return child.wait()
    except BaseException:
        # Exceptions may contain tool paths, but never need to be emitted here.
        return 122
    finally:
        secret[:] = b'\0' * len(secret)
        if events is not None:
            C.memset(C.addressof(events), 0, C.sizeof(events))
        if child is not None and child.poll() is None:
            child.kill(); child.wait()
        if console_fd is not None:
            kernel.FlushConsoleInputBuffer(msvcrt.get_osfhandle(console_fd))
            os.close(console_fd)
        if handle is not None:
            kernel.FlushConsoleInputBuffer(handle); kernel.CloseHandle(handle)
        if allocated:
            kernel.FreeConsole()


if __name__ == '__main__':
    raise SystemExit(run(sys.argv[1:]))
