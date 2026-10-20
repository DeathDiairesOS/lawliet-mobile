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


class JobCompletionTests(unittest.TestCase):
    def test_completion_error_and_timeout_cannot_promote_output(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from lawliet_mobile.runner_windows import wait_stopped
        for finished, errors in ((False, []), (True, ['OSError'])):
            with self.subTest(finished=finished, errors=errors):
                completed = Mock()
                completed.wait.return_value = finished
                child = SimpleNamespace(_lawliet_job_completion=(completed, errors))
                with self.assertRaisesRegex(RuntimeError, 'termination could not be confirmed'):
                    wait_stopped(child)
                completed.wait.assert_called_once_with(6)
        completed = Mock()
        completed.wait.return_value = True
        wait_stopped(SimpleNamespace(_lawliet_job_completion=(completed, [])))


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

    def test_hidden_desktop_worker_from_pythonw_has_no_console(self):
        from lawliet_mobile import runner_windows
        console = Path(sys.executable)
        pythonw = console.with_name('pythonw.exe')
        self.assertTrue(pythonw.is_file(), 'Windows Python installation must include its GUI interpreter')
        output = self.base / 'hidden-worker.log'
        with output.open('wb') as stream, patch.object(sys, 'executable', str(pythonw)):
            child, alive = runner_windows.spawn([str(console), '-c',
                'import ctypes; print(int(bool(ctypes.windll.kernel32.GetConsoleWindow())))'],
                cwd=self.base, stdout=stream, stderr=stream, hide_console=True)
            try:
                self.assertEqual(child.wait(timeout=15), 0)
            finally:
                os.close(alive)
        self.assertEqual(output.read_text().strip(), '0')

    def test_status_probe_cannot_terminate_a_running_process(self):
        from lawliet_mobile.runner_windows import process_running
        from lawliet_mobile.mulder_engine import MulderEngine, atomic_json
        process = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(120)'])
        self.addCleanup(lambda: process.poll() is None and (process.kill(), process.wait()))
        self.assertTrue(process_running(process.pid))
        job = self.root/'engine-runs'/('a'*32)
        job.mkdir(parents=True)
        atomic_json(job/'status.json', {'status':'running', 'worker_pid':process.pid})
        with patch('os.kill', side_effect=AssertionError('Status must never signal a Windows PID')):
            state = MulderEngine(self.workspace, 'A').get_status('a'*32)
        self.assertEqual(state['status'], 'running')
        self.assertIsNone(process.poll())
        process.kill(); process.wait(timeout=10)
        self.assertFalse(process_running(process.pid))

    def test_malformed_and_concurrent_lease_refused(self):
        with connect(self.workspace, 'A') as (root, db), runner_lease.lease(root, db):
            with self.assertRaisesRegex(UserError, 'still owns'):
                with runner_lease.lease(root, db):
                    pass
        (self.root/'.external-runner.lease').write_text('malformed')
        with connect(self.workspace, 'A') as (root, db), self.assertRaisesRegex(UserError, 'malformed'):
            with runner_lease.lease(root, db):
                pass

    def test_workflow_lock_is_nonblocking_and_independent_of_runner_lease(self):
        from lawliet_mobile.agent_collection import _lock
        with connect(self.workspace, 'A') as (root, db), _lock(root) as acquired:
            self.assertTrue(acquired)
            with _lock(root) as duplicate:
                self.assertFalse(duplicate)
            with runner_lease.lease(root, db):
                pass
        with _lock(self.root) as acquired:
            self.assertTrue(acquired)

    def test_real_execution_preserves_log_identity_and_binary_output(self):
        from lawliet_mobile.tools import execute
        output = self.base/'nested'/'stdout'
        output.parent.mkdir()
        output.write_bytes(b'OLD LONG CONTENT')
        stderr = output.with_name(output.name+'.stderr')
        stderr.write_bytes(b'OLD ERROR CONTENT')
        identities = (output.stat().st_ino, stderr.stat().st_ino)
        result = execute([sys.executable, '-c',
            "import sys;sys.stdout.buffer.write(b'new\\x00');sys.stderr.write('err');raise SystemExit(7)"], output)
        self.assertEqual(result['returncode'], 7)
        self.assertEqual(output.read_bytes(), b'new\x00')
        self.assertEqual(stderr.read_bytes(), b'err')
        self.assertEqual((output.stat().st_ino, stderr.stat().st_ino), identities)

    def test_log_hardlink_refused_before_other_log_truncated(self):
        from lawliet_mobile.tools import execute
        output = self.base/'stdout'
        output.write_bytes(b'PRESERVE ORIGINAL LOG')
        canary = self.base/'foreign'
        canary.write_bytes(b'PRESERVE FOREIGN')
        os.link(canary, output.with_name(output.name+'.stderr'))
        with patch.object(runner_lease, 'spawn', side_effect=AssertionError('must not spawn')):
            with self.assertRaises((UserError, OSError)):
                execute([sys.executable, '-c', 'pass'], output)
        self.assertEqual(output.read_bytes(), b'PRESERVE ORIGINAL LOG')
        self.assertEqual(canary.read_bytes(), b'PRESERVE FOREIGN')

    def test_open_log_files_and_parent_cannot_be_replaced(self):
        from lawliet_mobile.tools import _command_logs
        folder = self.base/'logs'
        folder.mkdir()
        output = folder/'stdout'
        with _command_logs(output) as (stdout, stderr, check):
            with self.assertRaises(OSError):
                output.unlink()
            with self.assertRaises(OSError):
                folder.rename(self.base/'replaced')
            stdout.write(b'owned')
            stdout.flush()
            check()
        self.assertEqual(output.read_bytes(), b'owned')

    def test_timeout_retains_failure_receipt_and_reaps_guardian(self):
        from lawliet_mobile.tools import execute
        original = runner_lease.spawn
        children = []
        def capture(*args, **kwargs):
            result = original(*args, **kwargs)
            children.append(result[0])
            return result
        with patch.object(runner_lease, 'spawn', side_effect=capture):
            with self.assertRaises(subprocess.TimeoutExpired) as failure:
                execute([sys.executable, '-c', 'import time;time.sleep(120)'], self.base/'stdout', timeout=.5)
        self.assertEqual(failure.exception.tool_result['error'], 'timeout')
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())

    def test_engine_monitor_masks_split_credentials_and_retains_return_code(self):
        from lawliet_mobile.engine_worker import monitor
        secret = 'synthetic-secret-never-export'
        env = {**os.environ, 'ANTHROPIC_API_KEY':secret}
        code = ("import os,sys;sys.stdout.buffer.write(b'x'*65530+"
                "os.environ['ANTHROPIC_API_KEY'].encode()+b'END');raise SystemExit(6)")
        result, reason = monitor([sys.executable, '-c', code], self.base, env,
                                  self.base, 15, 1024**2)
        self.assertEqual((result, reason), (6, None))
        data = (self.base/'process.log').read_bytes()
        self.assertNotIn(secret.encode(), data)
        self.assertIn(b'[REDACTED]END', data)

    def test_engine_monitor_honors_timeout_and_cancel_with_retained_logs(self):
        from lawliet_mobile.engine_worker import monitor
        for mode in ('timeout', 'cancelled'):
            with self.subTest(mode=mode):
                marker = self.base/'cancel'
                if mode == 'cancelled':
                    marker.touch()
                code, reason = monitor([sys.executable, '-c', 'import time;time.sleep(120)'],
                    self.base, dict(os.environ), self.base, .5 if mode == 'timeout' else 15, 1024**2)
                self.assertNotEqual(code, 0)
                self.assertEqual(reason, mode)
                self.assertTrue((self.base/'process.log').is_file())

    def test_engine_workspace_lock_is_exclusive(self):
        from lawliet_mobile.engine_worker import _worker_lock
        path = self.workspace/'.engine-worker.lock'
        fd = _worker_lock(path)
        try:
            with self.assertRaisesRegex(UserError, 'already running'):
                _worker_lock(path)
        finally:
            os.close(fd)
        os.close(_worker_lock(path))


if __name__ == '__main__':
    if '--parent' in sys.argv:
        with connect(Path(sys.argv[-2]), 'A') as (root, db), runner_lease.lease(root, db), open(os.devnull, 'wb') as log:
            child, alive = runner_lease.spawn([sys.executable, '-c', worker_code(Path(sys.argv[-1]))],
                cwd=root, stdout=log, stderr=log)
            child.wait()
            os.close(alive)
    else:
        unittest.main()
