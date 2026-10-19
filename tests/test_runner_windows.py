"""Windows ownership and actual process-tree teardown without forensic devices."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from lawliet_mobile import runner_lease
from lawliet_mobile.core import UserError, connect, create_case


def worker_code(ready):
    descendant = "import time; time.sleep(120)"
    return ("import json,os,pathlib,subprocess,sys,time; "
            f"p=subprocess.Popen([sys.executable,'-c',{descendant!r}]); "
            f"pathlib.Path({str(ready)!r}).write_text(json.dumps([os.getpid(),p.pid])); "
            "time.sleep(120)")


@unittest.skipUnless(os.name == 'nt', 'Windows ownership handles and Job Objects')
class WindowsRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base/'cases'
        self.root = create_case(self.workspace, 'A')
        self.ready = self.base/'ready.json'
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        self.api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.api.OpenProcess.restype = wintypes.HANDLE
        self.api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.api.WaitForSingleObject.restype = wintypes.DWORD
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]

    def process_handles(self, parent):
        deadline = time.monotonic()+15
        while not self.ready.exists() and parent.poll() is None and time.monotonic()<deadline:
            time.sleep(.02)
        self.assertTrue(self.ready.exists(), 'Synthetic worker did not start')
        while True:
            try:
                pids = json.loads(self.ready.read_text())
                break
            except (ValueError, OSError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.02)
        handles = []
        for pid in pids:
            handle = self.api.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
            self.assertTrue(handle, 'Could not inspect synthetic child')
            self.addCleanup(self.api.CloseHandle, handle)
            handles.append(handle)
        return handles

    def assert_stopped(self, handles):
        for handle in handles:
            self.assertEqual(self.api.WaitForSingleObject(handle, 10000), 0,
                             'Owned worker/descendant survived process cleanup')

    def test_stop_terminates_worker_and_descendant_with_and_without_case_lease(self):
        for owned in (False, True):
            with self.subTest(owned=owned):
                self.ready.unlink(missing_ok=True)
                with connect(self.workspace, 'A') as (root, db), open(os.devnull, 'wb') as log:
                    from contextlib import nullcontext
                    with runner_lease.lease(root, db) if owned else nullcontext():
                        child, alive = runner_lease.spawn([sys.executable, '-c', worker_code(self.ready)],
                            cwd=self.base, stdout=log, stderr=log)
                        try:
                            handles = self.process_handles(child)
                        finally:
                            runner_lease.stop(child, alive)
                        self.assert_stopped(handles)
                with connect(self.workspace, 'A') as (root, db), runner_lease.lease(root, db):
                    pass

    def test_parent_death_kills_job_and_releases_lease_after_last_child_exits(self):
        with (self.base/'parent.log').open('wb') as log:
            parent = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--parent',
                str(self.workspace), str(self.ready)], stdout=log, stderr=log,
                env={**os.environ, 'PYTHONPATH':str(Path(__file__).resolve().parents[1])})
            self.addCleanup(lambda: parent.poll() is None and (parent.kill(), parent.wait()))
            handles = self.process_handles(parent)
            with connect(self.workspace, 'A') as (root, db):
                with self.assertRaisesRegex(UserError, 'still owns'):
                    with runner_lease.lease(root, db):
                        pass
            parent.kill(); parent.wait(timeout=10)
            self.assert_stopped(handles)
        with connect(self.workspace, 'A') as (root, db), runner_lease.lease(root, db):
            pass

    def test_assignment_failure_never_executes_tool(self):
        from lawliet_mobile import runner_windows
        api, job = runner_windows._job()
        class RefuseAssignment:
            def AssignProcessToJobObject(self, *args):
                return False
            def CloseHandle(self, handle):
                return api.CloseHandle(handle)
        with open(os.devnull, 'wb') as log, patch.object(runner_windows, '_job', return_value=(RefuseAssignment(), job)):
            with self.assertRaises(OSError):
                runner_lease.spawn([sys.executable, '-c', worker_code(self.ready)],
                    cwd=self.base, stdout=log, stderr=log)
        self.assertFalse(self.ready.exists())

    def test_normal_return_and_job_release(self):
        with connect(self.workspace, 'A') as (root, db), runner_lease.lease(root, db), open(os.devnull, 'wb') as log:
            child, alive = runner_lease.spawn([sys.executable, '-c', 'raise SystemExit(7)'],
                cwd=self.base, stdout=log, stderr=log)
            try:
                self.assertEqual(child.wait(timeout=15), 7)
            finally:
                os.close(alive)

    def test_malformed_and_concurrent_lease_refused(self):
        with connect(self.workspace, 'A') as (root, db), runner_lease.lease(root, db):
            with self.assertRaisesRegex(UserError, 'still owns'):
                with runner_lease.lease(root, db):
                    pass
        (self.root/'.external-runner.lease').write_text('malformed')
        with connect(self.workspace, 'A') as (root, db), self.assertRaisesRegex(UserError, 'malformed'):
            with runner_lease.lease(root, db):
                pass


if __name__ == '__main__':
    if '--parent' in sys.argv:
        with connect(Path(sys.argv[-2]), 'A') as (root, db), runner_lease.lease(root, db), open(os.devnull, 'wb') as log:
            child, alive = runner_lease.spawn([sys.executable, '-c', worker_code(Path(sys.argv[-1]))],
                cwd=root, stdout=log, stderr=log)
            child.wait()
            os.close(alive)
    else:
        unittest.main()
