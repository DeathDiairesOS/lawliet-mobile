"""Real Windows request ownership, including unguarded probe descendants."""
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from lawliet_mobile.desktop_bridge import DesktopBridge


@unittest.skipUnless(os.name == 'nt', 'Requires real Windows Job Objects')
class DesktopBridgeWindowsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base/'cases'
        self.workspace.mkdir()
        self.marker = self.base/'child-pid.txt'
        self.script = self.base/'synthetic-probe.py'
        self.script.write_text('''import json, subprocess, sys, time
from pathlib import Path
request = json.load(sys.stdin)
child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'],
    stdin=subprocess.DEVNULL)
Path(sys.argv[1]).write_text(str(child.pid))
if sys.argv[2] == 'complete':
    print(json.dumps({'ok': True, 'result': {'action': request['action'],
        'query': request.get('query'), 'workspace': request['workspace']}}, ensure_ascii=False), flush=True)
else:
    time.sleep(60)
''', encoding='utf-8')
        self.bridge = DesktopBridge(self.workspace, timeout=10)
        self.addCleanup(self.bridge._close)

    def spawn_probe(self, mode):
        from lawliet_mobile.runner_windows import spawn
        def launch(argv, **kwargs):
            self.assertTrue(kwargs['hide_console'])
            self.assertIsInstance(kwargs['stdin_fd'], int)
            return spawn([sys.executable, str(self.script), str(self.marker), mode], **kwargs)
        return patch('lawliet_mobile.runner_windows.spawn', side_effect=launch)

    def wait_for_child(self):
        deadline = time.monotonic()+10
        while time.monotonic()<deadline:
            if self.marker.exists():
                try:
                    return int(self.marker.read_text())
                except ValueError:
                    pass
            time.sleep(.025)
        self.fail('Synthetic backend did not consume its request and start its child')

    def assert_child_stopped(self, pid):
        from lawliet_mobile.runner_windows import process_running
        deadline = time.monotonic()+5
        while time.monotonic()<deadline:
            if not process_running(pid):
                return
            time.sleep(.025)
        self.fail('Desktop request left a capability-probe descendant running')

    def test_close_terminates_backend_and_direct_probe_descendant(self):
        from lawliet_mobile.runner_windows import process_running
        responses = []
        with self.spawn_probe('wait'):
            thread = threading.Thread(target=lambda: responses.append(self.bridge.request({'action':'catalog'})))
            thread.start()
            try:
                pid = self.wait_for_child()
                self.assertTrue(process_running(pid))
                self.bridge._close()
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
                self.assert_child_stopped(pid)
                self.assertFalse(responses[0]['ok'])
                self.assertFalse(self.bridge._windows_alive)
            finally:
                self.bridge._close()
                thread.join(timeout=10)

    def test_normal_result_keeps_stdout_and_stops_leftover_descendant(self):
        with self.spawn_probe('complete'):
            response = self.bridge.request({'action':'catalog', 'query':'Synthetic é <script>text</script>'})
        self.assertEqual(response, {'ok':True, 'result':{
            'action':'catalog', 'query':'Synthetic é <script>text</script>',
            'workspace':str(self.workspace.resolve())}})
        self.assert_child_stopped(self.wait_for_child())
        self.assertFalse(self.bridge._windows_alive)
        self.assertFalse(self.bridge._processes)

    def test_timeout_terminates_probe_descendant(self):
        self.bridge._timeout = 2
        with self.spawn_probe('wait'):
            response = self.bridge.request({'action':'catalog'})
        self.assertFalse(response['ok'])
        self.assertIn('stopped or exceeded', response['error'])
        self.assert_child_stopped(self.wait_for_child())
        self.assertFalse(self.bridge._windows_alive)


if __name__ == '__main__':
    unittest.main()
