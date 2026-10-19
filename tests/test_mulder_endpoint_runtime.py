"""Restricted endpoints validate the source they actually launch, without tools."""
import importlib
import os
import py_compile
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile.mulder_runtime import RuntimeQualificationError
from tools import mulder_endpoint_runtime as runtime_helper


@unittest.skipUnless(Path('/usr/bin/sandbox-exec').is_file(), 'macOS endpoint policies')
class EndpointRuntimeTests(unittest.TestCase):
    profiles = {
        'android_contacts': 'android-contacts', 'android_sms': 'android-sms',
        'parser_container': 'parser-container', 'native_container': 'native-container',
        'sqlite_container': 'sqlite-container', 'report_container': 'report-container',
    }
    markers = ('_LAWLIET_CONTACTS_TOOLS', '_LAWLIET_TOOL_PROFILE',
               '_LAWLIET_CONTAINER_TOOLS', '_LAWLIET_NATIVE_CONTAINER_TOOLS',
               '_LAWLIET_SQLITE_CONTAINER_TOOLS', '_LAWLIET_REPORT_CONTAINER_TOOLS')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.runtime = self.base/'runtime'; self.store = self.base/'cases'
        self.store.mkdir(); (self.store/'A.db').write_bytes(b'launcher preflight only')
        self.source = self.make_source(self.base/'selected build/src')
        self.old = self.runtime/'upstream/mulder-1.5.2-ancalor.1/src'
        self.launcher = self.runtime/'bin/mulder-lawliet-candidate'
        self.launcher.parent.mkdir(parents=True)
        self.write_launcher(self.source)
        self.socket = self.base/'daemon.sock'
        sock = socket.socket(socket.AF_UNIX); self.addCleanup(sock.close)
        sock.bind(str(self.socket))

    def make_source(self, source):
        for relative in ('__init__.py', 'cli.py', 'db.py', 'temporal.py',
                         'server/__init__.py', 'server/app.py', 'server/case_scope.py',
                         'server/jobs.py', 'server/tools/__init__.py', 'server/tools/core.py',
                         'server/tools/jobs.py', 'server/tools/phone.py', 'server/tools/mvt.py',
                         'server/tools/lawliet_sqlite_workspace.py', 'server/tools/lawliet_report_import.py',
                         'server/tools/lawliet_collection.py'):
            path = source/'mulder'/relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('')
        (source/'mulder/__init__.py').write_text('__version__ = "fixture"\n')
        (source/'mulder/server/app.py').write_text('\n'.join(x+' = ()' for x in self.markers))
        for file, profile in [('phone.py', 'native-container'),
                              ('lawliet_sqlite_workspace.py', 'sqlite-container'),
                              ('lawliet_report_import.py', 'report-container')]:
            (source/'mulder/server/tools'/file).write_text("# os.environ.get('LAWLIET_MCP_PROFILE') == '"+profile+"'\n")
        return source

    def write_launcher(self, source):
        self.launcher.write_text('#!/bin/sh\nset -eu\nexport PYTHONPATH='+shlex.quote(str(source))+
            '\nexec '+shlex.quote(sys.executable)+" -c 'from mulder.cli import cli; cli()' \"$@\"\n")
        self.launcher.chmod(0o755)

    def launch(self, name, **kwargs):
        module = importlib.import_module('tools.mulder_'+name)
        args = [self.runtime, self.store, 'A']
        if name.endswith('container'): args.append(self.socket)
        return module.launch(*args, **kwargs)

    def test_all_six_default_routes_probe_and_execute_same_interpreter_environment(self):
        dangerous = {'PYTHONHOME': '/wrong', 'PYTHONSTARTUP': '/wrong',
                     'DOCKER_HOST': 'tcp://remote', 'DOCKER_CONTEXT': 'remote',
                     'DOCKER_TLS_VERIFY': '1', 'DOCKER_CERT_PATH': '/wrong',
                     'ANDROID_SERIAL': 'unselected', 'ANDROID_ADB_SERVER_ADDRESS': 'remote',
                     'ANDROID_ADB_SERVER_PORT': '1', 'ADB_SERVER_SOCKET': 'tcp:remote:1'}
        original = runtime_helper.inspect_runtime
        for name, profile in self.profiles.items():
            with self.subTest(profile=profile), patch.dict(os.environ, dangerous), \
                    patch.object(runtime_helper, 'inspect_runtime', wraps=original) as probe:
                argv, env = self.launch(name)
                spec = probe.call_args.args[0]
                self.assertEqual(probe.call_count, 1)
                self.assertEqual(spec['environment'], env)
                self.assertEqual(env['LAWLIET_MCP_PROFILE'], profile)
                self.assertEqual(env['PYTHONPYCACHEPREFIX'], '/dev/null/lawliet-source-only')
                self.assertEqual(argv[argv.index('-B')-1], spec['python'])
                self.assertEqual(argv[argv.index('-B'):argv.index('serve')], ['-B', '-P', '-m', 'mulder.cli'])
                self.assertNotIn(str(self.launcher), argv)
                self.assertEqual(env['PYTHONPATH'].split(os.pathsep)[0], str(self.source))
                self.assertFalse(any(k in env for k in dangerous if k != 'ADB_SERVER_SOCKET'))
                if name.startswith('android_'):
                    self.assertEqual(env['ADB_SERVER_SOCKET'], 'tcp:127.0.0.1:5037')
                else:
                    self.assertNotIn('ADB_SERVER_SOCKET', env)
                    self.assertEqual(env['LAWLIET_CONTAINER_SOCKET'], str(self.socket))

    def test_stale_positive_marker_cannot_approve_launched_source(self):
        self.make_source(self.old)
        (self.source/'mulder/server/app.py').write_text('# no restricted profiles\n')
        for name in self.profiles:
            with self.subTest(name=name), self.assertRaises(ValueError): self.launch(name)

    def test_stale_missing_markers_cannot_reject_selected_source(self):
        self.make_source(self.old)
        (self.old/'mulder/server/app.py').write_text('# stale old version\n')
        for name in self.profiles:
            with self.subTest(name=name): self.launch(name)

    def test_three_explicit_source_overrides_work_without_candidate_launcher(self):
        alternate = self.make_source(self.base/'override/src')
        self.launcher.unlink()
        python = self.runtime/'mulder-1.5.2/bin/python'; python.parent.mkdir(parents=True)
        python.symlink_to(sys.executable)
        for name in ('native_container', 'sqlite_container', 'report_container'):
            with self.subTest(name=name):
                argv, env = self.launch(name, mulder_source=alternate)
                self.assertEqual(argv[argv.index('-B')-1], str(python))
                self.assertEqual(env['PYTHONPATH'].split(os.pathsep)[0], str(alternate))

    def test_explicit_backend_override_preserved_and_inspected(self):
        backend = self.base/'backend'
        self.make_source(backend)
        (backend/'mulder/server/app.py').write_text('raise AssertionError("backend must not shadow Mulder")\n')
        (backend/'lawliet_mobile').mkdir(parents=True)
        for name in ('native', 'sqlite', 'report'):
            (backend/'lawliet_mobile'/f'{name}_container.py').write_text('# explicit backend fixture\n')
            with self.subTest(name=name):
                _, env = self.launch(name+'_container', lawliet_source=backend)
                self.assertEqual(env['PYTHONPATH'].split(os.pathsep), [str(self.source), str(backend)])

    def test_failed_import_and_missing_identity_refused(self):
        (self.source/'mulder/server/app.py').write_text('import missing_forensic_dependency\n')
        with self.assertRaisesRegex(RuntimeQualificationError, 'cannot import'): self.launch('android_sms')
        with patch.object(runtime_helper, 'inspect_runtime', return_value={'modules': {}, 'errors': []}):
            with self.assertRaisesRegex(RuntimeQualificationError, 'did not identify'): self.launch('android_sms')

    def test_unknown_launcher_and_relative_pythonpath_fail_before_probe(self):
        self.launcher.write_text('#!/bin/sh\necho arbitrary\nexit 0\n')
        with patch.object(runtime_helper, 'inspect_runtime', side_effect=AssertionError('must not import')):
            with self.assertRaises(RuntimeQualificationError): self.launch('android_sms')
            self.write_launcher(Path('relative-source'))
            with self.assertRaisesRegex(RuntimeQualificationError, 'absolute'): self.launch('android_sms')

    def test_missing_candidate_does_not_silently_fall_back_to_old_checkout(self):
        self.make_source(self.old); self.launcher.unlink()
        for name in self.profiles:
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeQualificationError, 'unavailable'): self.launch(name)

    def test_setup_launcher_is_probed_when_candidate_is_absent(self):
        self.launcher.rename(self.runtime/'bin/mulder')
        original = runtime_helper.inspect_runtime
        for name, profile in self.profiles.items():
            with self.subTest(profile=profile), patch.object(runtime_helper, 'inspect_runtime', wraps=original) as probe:
                argv, env = self.launch(name)
                spec = probe.call_args.args[0]
                self.assertEqual(spec['launcher'], str(self.runtime/'bin/mulder'))
                self.assertEqual(env['PYTHONPATH'].split(os.pathsep)[0], str(self.source))
                self.assertEqual(env['LAWLIET_MCP_PROFILE'], profile)
                self.assertEqual(argv[argv.index('-B')-1], spec['python'])
                self.assertNotIn(str(self.runtime/'bin/mulder'), argv)

    def test_candidate_precedes_setup_launcher_and_broken_candidate_fails_closed(self):
        setup_source = self.make_source(self.base/'setup/src')
        candidate_script = self.launcher.read_text()
        self.write_launcher(setup_source)
        self.launcher.rename(self.runtime/'bin/mulder')
        self.launcher.write_text(candidate_script); self.launcher.chmod(0o755)
        _, env = self.launch('android_sms')
        self.assertEqual(env['PYTHONPATH'].split(os.pathsep)[0], str(self.source))
        for broken in ('invalid-script', 'not-executable', 'dangling-symlink'):
            with self.subTest(broken=broken):
                self.launcher.unlink()
                if broken == 'dangling-symlink':
                    self.launcher.symlink_to(self.base/'missing-launcher')
                else:
                    self.launcher.write_text(candidate_script if broken == 'not-executable' else '#!/bin/sh\nexit 0\n')
                    self.launcher.chmod(0o644 if broken == 'not-executable' else 0o755)
                with patch.object(runtime_helper, 'inspect_runtime', side_effect=AssertionError('must not import')):
                    with self.assertRaises(RuntimeQualificationError): self.launch('android_sms')

    def test_invalid_setup_launcher_is_refused(self):
        self.launcher.unlink()
        setup = self.runtime/'bin/mulder'
        setup.write_text('#!/bin/sh\necho arbitrary\nexit 0\n'); setup.chmod(0o755)
        with patch.object(runtime_helper, 'inspect_runtime', side_effect=AssertionError('must not import')):
            with self.assertRaises(RuntimeQualificationError): self.launch('android_sms')

    def test_actual_sandbox_command_ignores_valid_stale_bytecode(self):
        cli = self.source/'mulder/cli.py'
        old = 'VALUE = "STALE"\nif __name__ == "__main__": print(VALUE)\n'
        cli.write_text(old); stamp = cli.stat()
        py_compile.compile(str(cli), doraise=True)
        cli.write_text(old.replace('STALE', 'FRESH'))
        os.utime(cli, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        control = subprocess.run([sys.executable, '-B', '-P', '-m', 'mulder.cli'],
            env={'PATH':os.environ.get('PATH',''), 'PYTHONPATH':str(self.source)},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(control.stdout.strip(), 'STALE', control.stderr)
        argv, env = self.launch('android_sms')
        actual = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(actual.returncode, 0, actual.stderr)
        self.assertEqual(actual.stdout.strip(), 'FRESH')


class RuntimeDefaultsTests(unittest.TestCase):
    def test_portable_defaults_and_explicit_runtime_override(self):
        names = ('android_contacts', 'android_sms', 'parser_container')
        for name in names:
            module = importlib.import_module('tools.mulder_'+name)
            try:
                with self.subTest(name=name), patch.dict(os.environ, {}, clear=True), \
                        patch.object(Path, 'home', return_value=Path('/portable-home')):
                    importlib.reload(module)
                    self.assertEqual(module.RUNTIME, Path('/portable-home/Library/Application Support/LAWLIET/runtime'))
                with self.subTest(name=name), patch.dict(os.environ, {'LAWLIET_RUNTIME': '/custom/runtime'}):
                    importlib.reload(module)
                    self.assertEqual(module.RUNTIME, Path('/custom/runtime'))
            finally:
                importlib.reload(module)


if __name__ == '__main__': unittest.main()
