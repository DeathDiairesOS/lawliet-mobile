import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from lawliet_mobile.core import UserError
from lawliet_mobile.device_interaction import ADBManager, DeviceDiscovery, ForensicAuditLogger, InteractionService, ScrcpyManager, serial_id
from lawliet_mobile.scrcpy_adb import permitted


@unittest.skipUnless(os.name=='posix','Device interaction currently requires macOS/Linux')
class DeviceInteractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.audit = ForensicAuditLogger(self.root / 'audit.jsonl')

    def test_finder_launch_discovers_homebrew_tools_without_shell_path(self):
        from lawliet_mobile.tools import command
        tool=self.root/'adb';tool.write_text('#!/bin/sh\nexit 0\n');tool.chmod(0o700)
        with patch('lawliet_mobile.tools.shutil.which',return_value=None),patch('lawliet_mobile.tools.sys.platform','darwin'),patch('lawliet_mobile.tools.MACOS_TOOL_DIRECTORIES',(self.root,)):
            self.assertEqual(command(self.root,'adb'),[str(tool)])
            configured=self.root/'configured-adb';configured.write_text('#!/bin/sh\nexit 0\n');configured.chmod(0o700)
            (self.root/'tools.json').write_text(json.dumps({'adb':str(configured)}))
            self.assertEqual(command(self.root,'adb'),[str(configured)])

    def events(self):
        return [json.loads(line) for line in self.audit.path.read_text().splitlines()]

    def manager(self):
        manager = ScrcpyManager(self.root, Mock(), self.audit)
        manager.dependencies = lambda: {'adb': {'available': True}, 'scrcpy': {'available': True}}
        return manager

    def test_usb_multiple_offline_unauthorized_and_network_excluded(self):
        text = 'List of devices attached\nUSB1 device usb:1 model:Pixel_7\nUSB2 unauthorized\nUSB3 offline\n192.168.0.1:5555 device\nemulator-5554 device\n'
        devices = DeviceDiscovery.parse(text)
        self.assertEqual(set(devices), {'USB1', 'USB2', 'USB3'})
        self.assertEqual(devices['USB1']['model'], 'Pixel 7')
        self.assertEqual(devices['USB2']['authorization'], 'unauthorized')

    def test_serial_validation_blocks_shell_and_network(self):
        for serial in ('-s', 'x;reboot', 'x y', '../x', 'host:5555', '', None, 'emulator-5554'):
            with self.assertRaises(UserError):
                serial_id(serial)

    def test_discovery_metadata_and_disconnect_are_audited(self):
        adb = Mock()
        adb.run.side_effect = ['USB1 device model:Pixel\nUSB2 unauthorized\n', '[ro.product.manufacturer]: [Google]\n[ro.build.version.release]: [15]\n', 'USB2 offline\n']
        discovery = DeviceDiscovery(adb, self.audit)
        self.assertEqual(discovery.refresh()[0]['manufacturer'], 'Google')
        discovery.refresh()
        self.assertEqual([e['event'] for e in self.events()], ['device.connected', 'device.connected', 'device.status', 'device.disconnected'])
        self.assertEqual(adb.run.call_count, 3)  # unauthorized/offline never queried

    def test_failed_discovery_preserves_previous_observation(self):
        adb = Mock();adb.run.side_effect = ['USB1 unauthorized', UserError('failed')]
        discovery = DeviceDiscovery(adb, self.audit);discovery.refresh()
        with self.assertRaises(UserError):
            discovery.refresh()
        self.assertIn('USB1', discovery.devices)

    def test_adb_command_audit_and_timeout(self):
        runner = Mock(side_effect=subprocess.TimeoutExpired('adb', 8))
        with patch('lawliet_mobile.device_interaction.command', return_value=['/mock/adb']):
            with self.assertRaises(UserError):
                ADBManager(self.root, self.audit, runner).run(['devices', '-l'])
        self.assertEqual(self.events()[0]['argv'], ['/mock/adb', 'devices', '-l'])
        self.assertEqual(self.events()[1]['event'], 'adb.failed')

    def test_missing_dependencies_and_incompatible_scrcpy(self):
        manager = self.manager()
        with patch('lawliet_mobile.device_interaction.command', side_effect=UserError('missing')):
            deps = ScrcpyManager.dependencies(manager)
        self.assertFalse(deps['adb']['available']);self.assertFalse(deps['scrcpy']['available'])
        with patch('lawliet_mobile.device_interaction.command', return_value=['tool']), patch('lawliet_mobile.device_interaction.subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'scrcpy old', '')):
            self.assertFalse(ScrcpyManager.dependencies(manager)['scrcpy']['available'])

    def test_missing_scrcpy_blocks_start(self):
        manager = self.manager();manager.dependencies = lambda: {'scrcpy': {'available': False, 'error': 'missing'}}
        with self.assertRaises(UserError):
            manager.start('USB1')
        self.assertIsNone(manager.process)

    def test_readonly_start_stop_and_owned_process_cleanup(self):
        manager = self.manager()
        def launch(argv, **kwargs):
            self.argv = argv;self.env = kwargs['env']
            return subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
        manager.popen = launch
        with patch('lawliet_mobile.device_interaction.command', side_effect=lambda _, name: [name]):
            manager.start('USB1')
        pid = manager.process.pid
        self.assertIn('--no-control', self.argv)
        self.assertIn('--no-clipboard-autosync', self.argv)
        self.assertIn('--no-power-on', self.argv)
        self.assertEqual(self.env['ADB'], str(manager.wrapper))
        manager.stop();manager.stop()
        self.assertIsNone(manager.process)
        self.assertEqual(manager.session.status, 'stopped')
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertEqual(sum(e['event'] == 'mirror.stopped' for e in self.events()), 1)

    def test_child_failure_has_diagnostics_and_terminal_audit(self):
        manager = self.manager()
        manager.popen = lambda argv, **kw: subprocess.Popen([sys.executable, '-c', 'print("connection failed"); raise SystemExit(2)'], **kw)
        with patch('lawliet_mobile.device_interaction.command', side_effect=lambda _, name: [name]):
            manager.start('USB1', True)
        manager.process.wait(timeout=5)
        session = manager.poll()
        self.assertEqual(session['status'], 'failed')
        self.assertIn('connection failed', session['error'])
        self.assertFalse(session['control'])

    def test_failed_launch_is_audited(self):
        manager = self.manager();manager.popen = Mock(side_effect=OSError('no executable'))
        with patch('lawliet_mobile.device_interaction.command', side_effect=lambda _, name: [name]), self.assertRaises(UserError):
            manager.start('USB1')
        self.assertEqual(self.events()[-1]['event'], 'mirror.failed')

    def test_explicit_consent_and_control_required(self):
        service = InteractionService(self.root);self.addCleanup(service.close)
        service.discovery.refresh = lambda: []
        with self.assertRaises(UserError):
            service.handle({'action': 'start', 'serial': 'USB1'})
        with self.assertRaises(UserError):
            service.handle({'action': 'key', 'key': 'home'})
        self.assertIsNone(service.mirror.process)

    def test_disconnect_stops_session_without_restart(self):
        service = InteractionService(self.root);self.addCleanup(service.close)
        service.discovery.refresh = lambda: setattr(service.discovery, 'devices', {})
        service.mirror = Mock();service.mirror.process = object();service.mirror.session.serial = 'USB1'
        service.refresh()
        service.mirror.stop.assert_called_once_with('device_unavailable')
        service.mirror.start.assert_not_called()

    def test_scrcpy_adb_policy_blocks_install_upload_network_and_shell(self):
        for args in (['-s','USB1','install','-r','file.apk'], ['-s','USB1','push','secret.txt','/sdcard/Download/'], ['connect','host'], ['-s','USB1','shell','reboot'], ['-s','USB2','shell','getprop','ro.product.model']):
            self.assertFalse(permitted(args, 'USB1'))
        for args in (['devices','-l'], ['start-server'], ['-s','USB1','push','/local/scrcpy-server','/data/local/tmp/scrcpy-server.jar'], ['-s','USB1','forward','tcp:27183','localabstract:scrcpy_123abcd'], ['-s','USB1','reverse','--remove','localabstract:scrcpy_123abcd'], ['-s','USB1','shell','CLASSPATH=/data/local/tmp/scrcpy-server.jar','app_process','/','com.genymobile.scrcpy.Server','3.3','scid=123abcd','control=false']):
            self.assertTrue(permitted(args, 'USB1'), args)

    def test_utc_audit_and_private_permissions(self):
        self.audit.record('test', serial='synthetic')
        self.assertTrue(self.events()[0]['at'].endswith('+00:00'))
        self.assertEqual(self.audit.path.stat().st_mode & 0o777, 0o600)

    def test_cleanup_still_runs_when_audit_storage_fails(self):
        manager = self.manager()
        manager.popen = lambda argv, **kw: subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'], **kw)
        with patch('lawliet_mobile.device_interaction.command', side_effect=lambda _, name: [name]):
            manager.start('USB1')
        pid = manager.process.pid
        with patch.object(self.audit, 'record', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                manager.stop()
        self.assertIsNone(manager.process)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_unresponsive_child_is_killed_after_grace_period(self):
        manager = self.manager()
        manager.popen = lambda argv, **kw: subprocess.Popen([sys.executable, '-c', 'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(60)'], **kw)
        with patch('lawliet_mobile.device_interaction.command', side_effect=lambda _, name: [name]):
            manager.start('USB1')
        deadline = time.monotonic() + 3
        while 'ready' not in manager.diagnostics and time.monotonic() < deadline:
            time.sleep(0.01)
        pid = manager.process.pid
        manager.stop()
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertEqual(self.events()[-1]['exit_code'], -9)

    def test_mode_changes_and_navigation_remain_explicit(self):
        service = InteractionService(self.root)
        self.addCleanup(service.close)
        service.discovery.refresh = lambda: setattr(service.discovery, 'devices', {'USB1': {'serial': 'USB1', 'status': 'device'}})
        service.adb.key = Mock()
        service.mirror.dependencies = lambda: {'adb': {'available': True}, 'scrcpy': {'available': True}}
        service.mirror.popen = lambda argv, **kw: subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'], **kw)
        with patch('lawliet_mobile.device_interaction.command', side_effect=lambda _, name: [name]):
            request = {'action': 'start', 'serial': 'USB1', 'acknowledge_state_changes': True}
            self.assertFalse(service.handle(request)['session']['control'])
            with self.assertRaises(UserError):
                service.handle({'action': 'key', 'key': 'home'})
            service.handle({**request, 'action': 'control', 'control': True})
            service.handle({'action': 'key', 'key': 'home'})
            service.adb.key.assert_called_once_with('USB1', 'home')
            service.handle({**request, 'action': 'control', 'control': False})
            self.assertFalse(service.mirror.session.control)
            service.handle({'action': 'stop'})
        events = [json.loads(l)['event'] for l in service.audit.path.read_text().splitlines()]
        self.assertEqual(events.count('mirror.started'), 3)
        self.assertEqual(events.count('mirror.stopped'), 3)
        self.assertIn('investigator.navigation', events)

    def test_worker_running_session_eof_and_internal_adb_filter(self):
        adb = self.root / 'fake-adb'
        adb.write_text('#!' + sys.executable + '\nimport sys\na=sys.argv[1:]\nif a==["devices","-l"]: print("USB1 device model:Fixture")\nelif a[-1:]==["getprop"]: print("[ro.product.model]: [Fixture]")\nelif a==["version"]: print("Android Debug Bridge version 1.0.41")\n')
        adb.chmod(0o700)
        scrcpy = self.root / 'fake-scrcpy'
        scrcpy.write_text('#!' + sys.executable + '\nimport os,sys,subprocess,time\nif "--version" in sys.argv: print("scrcpy 3.3");sys.exit()\nif "--help" in sys.argv: print("--no-control --no-audio --no-clipboard-autosync --no-power-on --display-orientation");sys.exit()\nassert subprocess.run([os.environ["ADB"],"devices","-l"]).returncode==0\nassert subprocess.run([os.environ["ADB"],"-s","USB1","install","-r","forbidden.apk"]).returncode==1\nprint("Texture: fixture",flush=True)\ntime.sleep(60)\n')
        scrcpy.chmod(0o700)
        (self.root / 'tools.json').write_text(json.dumps({'adb': str(adb), 'scrcpy': str(scrcpy)}))
        worker = subprocess.Popen([sys.executable, '-m', 'lawliet_mobile.device_worker', str(self.root)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if worker.poll() is None:
                worker.terminate();worker.wait(timeout=10)
            for stream in (worker.stdin, worker.stdout, worker.stderr):
                if not stream.closed: stream.close()
        self.addCleanup(cleanup)
        worker.stdin.write(json.dumps({'action': 'start', 'serial': 'USB1', 'acknowledge_state_changes': True}) + '\n');worker.stdin.flush()
        reply = json.loads(worker.stdout.readline())
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(reply['result']['session']['status'], 'starting')
        audit = Path(reply['result']['audit_path'])
        deadline = time.monotonic() + 5
        while 'scrcpy.adb.blocked' not in audit.read_text() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIn('scrcpy.adb.command', audit.read_text())
        self.assertIn('scrcpy.adb.blocked', audit.read_text())
        worker.stdin.close();worker.wait(timeout=10)
        self.assertEqual(worker.returncode, 0, worker.stderr.read())
        events = [json.loads(l) for l in audit.read_text().splitlines()]
        self.assertEqual(events[-1]['event'], 'interaction.closed')
        self.assertEqual(events[-2]['event'], 'mirror.stopped')
        self.assertFalse(audit.with_suffix('.adb').exists())

    def test_worker_eof_writes_close_event(self):
        settings = self.root / 'tools.json';settings.write_text(json.dumps({'adb':'/missing/adb', 'scrcpy':'/missing/scrcpy'}))
        result = subprocess.run([sys.executable, '-m', 'lawliet_mobile.device_worker', str(self.root)], input='{"action":"status"}\n', text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])
        logs = list((self.root / '.device-interaction').glob('*.jsonl'))
        events = [json.loads(l)['event'] for l in logs[0].read_text().splitlines()]
        self.assertEqual(events[-1], 'interaction.closed')

    def test_adb_cannot_consume_worker_requests(self):
        # shell getprop forwards stdin: a child must never inherit the JSON channel.
        adb=self.root/'stdin-reading-adb'
        adb.write_text('#!' + sys.executable + '\nimport sys\nif "devices" in sys.argv: print("USB1 device model:Fixture")\nelif "getprop" in sys.argv: sys.stdin.read();print("[ro.product.model]: [Fixture]")\nelif "version" in sys.argv: sys.stdin.read();print("ADB fixture")\n')
        adb.chmod(0o700)
        (self.root/'tools.json').write_text(json.dumps({'adb':str(adb),'scrcpy':'/missing/scrcpy'}))
        requests='{"action":"dependencies"}\n{"action":"status"}\n'
        result=subprocess.run([sys.executable,'-m','lawliet_mobile.device_worker',str(self.root)],
            input=requests,text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        replies=[json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(replies),2,result.stdout)
        self.assertTrue(all(reply['ok'] for reply in replies),replies)
        self.assertTrue(replies[0]['result']['adb']['available'])
        self.assertEqual(replies[1]['result']['devices'][0]['serial'],'USB1')


if __name__ == '__main__':
    unittest.main()
