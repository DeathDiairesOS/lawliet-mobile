"""USB interaction service. scrcpy owns video/input; no streaming implementation."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
import uuid

from .core import UserError
from .tools import command


def utc():
    return datetime.now(timezone.utc).isoformat()


def serial_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value) or value.startswith('emulator-') or value.endswith('._tcp'):
        raise UserError('Select a physical USB Android serial from the device list.')
    return value


class ForensicAuditLogger:
    """Local append-only-by-convention JSONL; not an immutable custody ledger."""
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def record(self, event, **detail):
        import fcntl  # macOS/Linux; Windows adapter is deliberately not enabled.
        data = (json.dumps({'at': utc(), 'event': event, **detail}, ensure_ascii=True) + '\n').encode()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with os.fdopen(fd, 'ab', closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)


class ADBManager:
    def __init__(self, workspace, audit, runner=subprocess.run):
        self.workspace, self.audit, self.runner = workspace, audit, runner

    def run(self, args):
        argv = command(self.workspace, 'adb') + args
        self.audit.record('adb.command', argv=argv)
        try:
            env = os.environ.copy()
            for key in ('ADB_SERVER_SOCKET', 'ANDROID_ADB_SERVER_ADDRESS', 'ANDROID_ADB_SERVER_PORT', 'ANDROID_SERIAL'):
                env.pop(key, None)
            result = self.runner(argv, capture_output=True, text=True, timeout=8, env=env, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.audit.record('adb.failed', error=str(exc))
            raise UserError('ADB failed or timed out. Check USB connection and authorization.') from exc
        self.audit.record('adb.result', exit_code=result.returncode)
        if result.returncode:
            raise UserError('ADB: ' + result.stderr[-2000:].strip())
        return result.stdout[:65536]

    def key(self, serial, name):
        code = {'back': '4', 'home': '3', 'recent': '187'}.get(name)
        if code is None:
            raise UserError('Unsupported navigation action.')
        return self.run(['-s', serial_id(serial), 'shell', 'input', 'keyevent', code])


class DeviceDiscovery:
    def __init__(self, adb, audit):
        self.adb, self.audit, self.devices = adb, audit, {}

    @staticmethod
    def parse(text):
        devices = {}
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 2 or fields[0] == 'List' or fields[0].startswith('*'):
                continue
            try:
                serial = serial_id(fields[0])
            except UserError:
                continue  # Excludes network transports and emulators.
            attrs = dict(f.split(':', 1) for f in fields[2:] if ':' in f)
            devices[serial] = {'serial': serial, 'status': fields[1],
                               'manufacturer': '', 'model': attrs.get('model', '').replace('_', ' '),
                               'android_version': '', 'authorization': 'authorized' if fields[1] == 'device' else fields[1]}
        return devices

    def refresh(self):
        current = self.parse(self.adb.run(['devices', '-l']))
        for serial, device in current.items():
            previous = self.devices.get(serial)
            if previous is None:
                self.audit.record('device.connected', serial=serial, status=device['status'])
            elif previous['status'] != device['status']:
                self.audit.record('device.status', serial=serial, status=device['status'])
            if device['status'] == 'device':
                if previous and previous['status'] == 'device':
                    for key in ('manufacturer', 'model', 'android_version'):
                        device[key] = previous[key]
                else:
                    try:
                        props = self.adb.run(['-s', serial, 'shell', 'getprop'])
                        values = dict(re.findall(r'^\[([^\]]+)\]: \[([^\]]*)\]$', props, re.M))
                        for key, prop in [('manufacturer', 'ro.product.manufacturer'), ('model', 'ro.product.model'), ('android_version', 'ro.build.version.release')]:
                            device[key] = values.get(prop, device[key])[:200]
                    except UserError as exc:
                        device['metadata_error'] = str(exc)
        for serial in self.devices.keys() - current.keys():
            self.audit.record('device.disconnected', serial=serial)
        self.devices = current
        return list(current.values())


@dataclass
class DeviceSession:
    serial: str = ''
    status: str = 'stopped'
    started_at: str = ''
    stopped_at: str = ''
    control: bool = False
    rotation: int = 0
    error: str = ''


def _terminate_remaining_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        if sys.platform != 'darwin' or process.returncode is None:
            raise
        # XNU excludes zombies when signaling a group, so an existing group
        # with only exiting children can yield EPERM. A denied live group has
        # the same error: only observed disappearance (ESRCH) permits success.
        # Probe only on this failure path; do not repeat termination signals.
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                pass
            time.sleep(0.01)
        raise


class ScrcpyManager:
    def __init__(self, workspace, adb, audit, popen=subprocess.Popen):
        self.workspace, self.adb, self.audit, self.popen = workspace, adb, audit, popen
        self.process = None
        self.session = DeviceSession()
        self.diagnostics = ''
        self.reader = None
        self.wrapper = audit.path.with_suffix('.adb')
        # Executable adapter keeps scrcpy's internal ADB commands local and audited,
        # and blocks its built-in file-drop installation/upload feature.
        source = Path(__file__).with_name('scrcpy_adb.py')
        import shlex
        self.wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(source)) + ' "$@"\n')
        self.wrapper.chmod(0o700)

    def dependencies(self):
        result = {}
        for name in ('adb', 'scrcpy'):
            try:
                argv = command(self.workspace, name)
                check = subprocess.run(argv + (['version'] if name == 'adb' else ['--version']), capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
                if check.returncode:
                    raise UserError('Version check failed.')
                version = (check.stdout + check.stderr)[:2000]
                if name == 'scrcpy':
                    help_result = subprocess.run(argv + ['--help'], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
                    required = ['--no-control', '--no-audio', '--no-clipboard-autosync', '--no-power-on', '--display-orientation']
                    if help_result.returncode or any(flag not in help_result.stdout for flag in required):
                        raise UserError('Upgrade scrcpy: required safety/orientation options unavailable (use scrcpy 3.x).')
                result[name] = {'available': True, 'version': version}
            except (UserError, OSError, subprocess.TimeoutExpired) as exc:
                result[name] = {'available': False, 'error': str(exc)}
        return result

    def start(self, serial, control=False, rotation=0):
        serial_id(serial)
        if type(control) is not bool or rotation not in (0, 90, 180, 270):
            raise UserError('Invalid control mode or display orientation.')
        if self.process:
            raise UserError('Stop the current mirroring session first.')
        dependencies = self.dependencies()
        for name, info in dependencies.items():
            if not info['available']:
                raise UserError(name + ': ' + info['error'])
        argv = command(self.workspace, 'scrcpy') + ['--serial', serial, '--window-title', 'Lawliet · ' + ('CONTROL ENABLED' if control else 'VIEW ONLY'), '--no-audio', '--no-clipboard-autosync', '--no-power-on', '--display-orientation=' + str(rotation)]
        if not control:
            argv.append('--no-control')
        adb = command(self.workspace, 'adb')
        if len(adb) != 1:
            raise UserError('scrcpy requires a native ADB executable, not a Python entry point.')
        env = os.environ.copy()
        for key in ('ADB_SERVER_SOCKET', 'ANDROID_ADB_SERVER_ADDRESS', 'ANDROID_ADB_SERVER_PORT', 'ANDROID_SERIAL'):
            env.pop(key, None)
        env.update(ADB=str(self.wrapper), LAWLIET_REAL_ADB=adb[0], LAWLIET_DEVICE_SERIAL=serial, LAWLIET_DEVICE_AUDIT=str(self.audit.path))
        self.audit.record('mirror.start_requested', serial=serial, control=control, argv=argv)
        self.diagnostics = ''
        try:
            self.process = self.popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        except OSError as exc:
            self.audit.record('mirror.failed', serial=serial, error=str(exc))
            raise UserError('Cannot launch scrcpy: ' + str(exc)) from exc
        self.session = DeviceSession(serial, 'starting', utc(), control=control, rotation=rotation)
        try:
            self.audit.record('mirror.started', **asdict(self.session))
        except OSError:
            self.stop('audit_failed')
            raise
        def drain():
            while True:
                chunk = self.process_output.read1(1024)
                if not chunk:
                    break
                self.diagnostics = (self.diagnostics + chunk.decode('utf-8', errors='replace'))[-8192:]
        self.process_output = self.process.stdout
        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()

    def poll(self):
        if self.process and self.process.poll() is not None:
            code = self.process.returncode
            self.finish('closed' if code == 0 else 'failed', code)
        if self.process and 'Texture:' in self.diagnostics:
            self.session.status = 'running'
        return asdict(self.session)

    def finish(self, reason, code):
        if self.process:
            _terminate_remaining_group(self.process)
        if self.reader:
            self.reader.join(timeout=1)
        self.session.status = 'stopped' if reason != 'failed' else 'failed'
        self.session.stopped_at = utc()
        self.session.error = self.diagnostics if reason == 'failed' else ''
        try:
            self.audit.record('mirror.stopped', serial=self.session.serial, reason=reason, exit_code=code, control=self.session.control)
        finally:
            if self.process and self.process.stdout:
                self.process.stdout.close()
            self.process = None
            self.session.control = False

    def stop(self, reason='investigator'):
        if not self.process:
            return
        audit_error = None
        try:
            self.audit.record('mirror.stop_requested', serial=self.session.serial, reason=reason)
        except OSError as exc:
            audit_error = exc
        process = self.process
        if process.poll() is None:
            # SIGTERM scrcpy first so it can remove its device server/tunnels.
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        # finish removes surviving owned ADB children, never the shared daemon.
        self.finish(reason, process.returncode)
        if audit_error:
            raise audit_error


class InteractionService:
    def __init__(self, workspace):
        self.audit = ForensicAuditLogger(Path(workspace) / '.device-interaction' / (str(uuid.uuid4()) + '.jsonl'))
        self.adb = ADBManager(workspace, self.audit)
        self.discovery = DeviceDiscovery(self.adb, self.audit)
        self.mirror = ScrcpyManager(workspace, self.adb, self.audit)
        self.error = ''
        self.audit.record('interaction.opened')

    def refresh(self):
        self.mirror.poll()
        try:
            self.discovery.refresh()
            self.error = ''
            if self.mirror.process and self.discovery.devices.get(self.mirror.session.serial, {}).get('status') != 'device':
                self.mirror.stop('device_unavailable')
        except UserError as exc:
            self.error = str(exc)
            self.mirror.stop('discovery_failed')

    def handle(self, request):
        action = request.get('action', 'status')
        if action == 'dependencies':
            return self.mirror.dependencies()
        if action in ('start', 'control', 'rotate'):
            if request.get('acknowledge_state_changes') is not True:
                raise UserError('Acknowledge that ADB and scrcpy may modify device state.')
            self.refresh()
            serial = serial_id(request.get('serial'))
            if self.discovery.devices.get(serial, {}).get('status') != 'device':
                raise UserError('Device is disconnected, offline or unauthorized. Authorize it on the device.')
            control = request.get('control', False)
            rotation = request.get('rotation', 0)
            if type(control) is not bool or type(rotation) is not int or rotation not in (0, 90, 180, 270):
                raise UserError('Invalid control mode or display orientation.')
            self.audit.record('investigator.' + action, serial=serial, control=control, rotation=rotation)
            self.mirror.stop('mode_change')
            self.mirror.start(serial, control, rotation)
        elif action == 'key':
            self.refresh()
            session = self.mirror.session
            if not self.mirror.process or not session.control:
                raise UserError('Explicitly enable device control first.')
            self.audit.record('investigator.navigation', serial=session.serial, key=request.get('key'))
            self.adb.key(session.serial, request.get('key'))
        elif action == 'stop':
            self.mirror.stop()
        elif action != 'status':
            raise UserError('Unknown interaction operation.')
        return {'devices': list(self.discovery.devices.values()), 'session': self.mirror.poll(), 'error': self.error, 'audit_path': str(self.audit.path)}

    def close(self):
        try:
            self.mirror.stop('panel_closed')
        finally:
            try:
                self.audit.record('interaction.closed')
            finally:
                self.mirror.wrapper.unlink(missing_ok=True)
