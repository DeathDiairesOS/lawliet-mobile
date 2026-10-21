"""Profile dispatch, native indexing and limits; collection transport is synthetic."""
import contextlib
import io
import json
from pathlib import Path
import plistlib
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.cli import main
from lawliet_mobile.core import UserError, create_case, digest, import_evidence
from lawliet_mobile.tools import IOS_PROFILE_LIMITS
from lawliet_mobile.validation import preflight


class IOSProfileRoutingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='lawliet-ios-routing-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.workspace = self.base / 'cases'; create_case(self.workspace, 'A')
        self.apps = self.base / 'apps'; self.apps.mkdir()
        (self.apps / 'ios-apps.plist').write_bytes(plistlib.dumps([
            {'CFBundleIdentifier': 'com.example.synthetic', 'CFBundleDisplayName': 'Synthetic App'}]))
        self.selected = self.base / 'selected'; self.selected.mkdir()
        with contextlib.closing(sqlite3.connect(self.selected / 'sms.db')) as db, db:
            db.executescript("CREATE TABLE handle(id TEXT); INSERT INTO handle VALUES('synthetic-contact');"
                "CREATE TABLE message(date INTEGER,text TEXT,handle_id INTEGER,is_from_me INTEGER,service TEXT);"
                "INSERT INTO message VALUES(813592800,'Synthetic selected message',1,0,'iMessage');")
        self.calls = []
        self.collection_status = 'complete'
        self.inventory = [{'tool': tool, 'available': True} for tool in
                          ('adb', 'idevice_id', 'ideviceinfo', 'ideviceinstaller', 'pymobiledevice3', 'idevicebackup2')]
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('lawliet_mobile.validation.doctor', return_value={'tools': self.inventory}))
        self.stack.enter_context(patch('lawliet_mobile.validation.shutil.disk_usage',
                                      return_value=SimpleNamespace(free=100*1024**3)))
        self.stack.enter_context(patch('lawliet_mobile.tools.execute', side_effect=AssertionError('No physical tool calls in routing tests')))
        self.legacy = self.stack.enter_context(patch('lawliet_mobile.tools._collect_into',
                                          side_effect=AssertionError('No implicit full backup')))
        self.stack.enter_context(patch('lawliet_mobile.ios_apps.collect_apps', side_effect=self.apps_collector))
        self.stack.enter_context(patch('lawliet_mobile.ios_backup.collect_selected', side_effect=self.selected_collector))

    def collect_fixture(self, profile, root, db, workspace, serial, timeout, max_bytes):
        self.calls.append({'profile': profile, 'timeout': timeout, 'max_bytes': max_bytes, 'serial': serial})
        self.assertLessEqual(max_bytes, IOS_PROFILE_LIMITS[profile])
        if profile == 'ios-apps': self.assertLessEqual(timeout, 900)
        if self.collection_status == 'failed':
            return {'status': 'failed', 'evidence_id': None}
        evidence = import_evidence(root, db, self.apps if profile == 'ios-apps' else self.selected, 'ios')[0]
        return {'status': self.collection_status, 'evidence_id': evidence}

    def apps_collector(self, *args):
        return self.collect_fixture('ios-apps', *args)

    def selected_collector(self, *args):
        return self.collect_fixture('ios-selected', *args)

    def gui(self, action='collect', **fields):
        return handle(self.workspace, {'action': action, 'case': 'A', 'platform': 'ios',
            'serial': '00000000-0000000000000001', 'max_gib': 20, **fields})

    def cli(self, *extra, platform='ios'):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            code = main(['--workspace', str(self.workspace), '--json', 'collect', platform,
                         '--case', 'A', '--serial', '00000000-0000000000000001', *extra])
        return code, json.loads(output.getvalue())

    def test_profile_preflight_uses_only_required_tools_and_capped_reserve(self):
        expected = {'ios-apps': ('ideviceinstaller', 16*1024**2),
                    'ios-selected': ('pymobiledevice3', 256*1024**2),
                    'ios-backup': ('idevicebackup2', 20*1024**3)}
        for profile, (missing, ceiling) in expected.items():
            with self.subTest(profile=profile):
                for tool in self.inventory:
                    tool['available'] = tool['tool'] in {'idevice_id', 'ideviceinfo'}
                report = preflight(self.workspace, 'ios', 20*1024**3, profile)
                self.assertEqual(report['missing_tools'], [missing])
                self.assertEqual(report['budget_bytes'], ceiling)
                self.assertEqual(report['required_bytes'], 2*ceiling + 1024**3)
                self.assertFalse(report['ready'])

    def test_preflight_rejects_malformed_profiles_and_byte_budgets(self):
        for profile in ('ios_apps', 'messages', '', 1, [], {}):
            with self.subTest(profile=profile), self.assertRaises(UserError):
                preflight(self.workspace, 'ios', 1024, profile)
        for budget in (0, -1, True, 1.5, None, '1024'):
            with self.subTest(budget=budget), self.assertRaises(UserError):
                preflight(self.workspace, 'ios', budget, 'ios-apps')
        with self.assertRaises(UserError):
            preflight(self.workspace, 'android', 1024, 'ios-apps')

    def test_omitted_ios_method_defaults_to_small_inventory_everywhere(self):
        report = preflight(self.workspace, 'ios', 20*1024**3)
        self.assertEqual(report['profile'], 'ios-apps')
        self.assertEqual(self.gui('preflight')['budget_bytes'], 16*1024**2)
        result = self.gui()
        self.assertEqual(result['analysis']['new_records'], 1)
        self.assertEqual(self.calls[-1]['profile'], 'ios-apps')
        self.assertEqual(self.calls[-1]['timeout'], 120)
        code, result = self.cli()
        self.assertEqual(code, 0, result)
        self.assertEqual(self.calls[-1]['profile'], 'ios-apps')
        self.legacy.assert_not_called()

    def test_gui_autoindexes_both_profiles_with_exact_source_and_bounded_timeout(self):
        expected = [('ios-apps', 120, 'apps', 'com.example.synthetic', 'ios-apps.plist'),
                    ('ios-selected', 900, 'messages', 'iMessage', 'sms.db')]
        for profile, timeout, category, title, name in expected:
            with self.subTest(profile=profile):
                source = (self.apps if profile == 'ios-apps' else self.selected) / name
                before = digest(source)
                result = self.gui(profile=profile)
                self.assertEqual((result['collection_status'], result['status']), ('complete', 'complete'))
                rows = self.gui('records', run=result['analysis']['run_id'])['records']
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['category'], category)
                self.assertIn(title, rows[0]['title'])
                self.assertEqual(rows[0]['source_sha256'], before)
                self.assertEqual(digest(source), before)
                self.assertEqual(self.calls[-1]['timeout'], timeout)
                self.assertEqual(self.calls[-1]['max_bytes'], IOS_PROFILE_LIMITS[profile])

    def test_cli_indexes_selected_data_and_caps_apps_timeout(self):
        for profile in ('ios-apps', 'ios-selected'):
            with self.subTest(profile=profile):
                code, result = self.cli('--profile', profile)
                self.assertEqual(code, 0, result)
                self.assertEqual(result['analysis']['new_records'], 1)
                self.assertEqual(self.calls[-1]['max_bytes'], IOS_PROFILE_LIMITS[profile])
        code, result = self.cli('--profile', 'ios-apps', '--timeout', '3600')
        self.assertEqual(code, 0, result)
        self.assertEqual(self.calls[-1]['timeout'], 900)

    def test_gui_malformed_or_android_profiles_never_fall_back_to_backup(self):
        for profile in ('ios_apps', 'apps', 'sms-provider', 'triage', 'ios-unknown', '', 42, [], {}):
            for action in ('preflight', 'collect'):
                with self.subTest(profile=profile, action=action), self.assertRaises(UserError):
                    self.gui(action, profile=profile)
        self.assertEqual(self.calls, [])
        self.legacy.assert_not_called()

    def test_cli_android_profiles_and_paths_are_refused_for_ios(self):
        for args in [('--profile', 'triage'), ('--profile', 'messages'),
                     ('--profile', 'ios-apps', '--pull', '/sdcard/DCIM'),
                     ('--profile', 'ios-selected', '--android-user', '0')]:
            with self.subTest(args=args):
                code, result = self.cli(*args)
                self.assertEqual(code, 1, result)
        self.assertEqual(self.calls, [])
        self.legacy.assert_not_called()

    def test_missing_profile_dependency_stops_before_any_collector(self):
        next(t for t in self.inventory if t['tool'] == 'ideviceinstaller')['available'] = False
        with self.assertRaisesRegex(UserError, 'preflight failed'):
            self.gui(profile='ios-apps')
        code, result = self.cli('--profile', 'ios-apps')
        self.assertEqual(code, 1, result)
        self.assertEqual(self.calls, [])

    def test_partial_collection_remains_partial_after_successful_native_parse(self):
        self.collection_status = 'partial'
        result = self.gui(profile='ios-selected')
        self.assertEqual(result['analysis']['status'], 'complete')
        self.assertEqual((result['collection_status'], result['status']), ('partial', 'partial'))
        code, result = self.cli('--profile', 'ios-selected')
        self.assertEqual(code, 1)
        self.assertEqual((result['collection_status'], result['status']), ('partial', 'partial'))

    def test_native_parse_errors_do_not_leave_collection_marked_complete(self):
        (self.selected / 'corrupt.db').write_bytes(b'SQLite format 3\x00' + b'broken' * 24)
        result = self.gui(profile='ios-selected')
        self.assertEqual(result['collection_status'], 'complete')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['analysis']['status'], 'partial')
        self.assertEqual(result['analysis']['new_records'], 1)
        code, result = self.cli('--profile', 'ios-selected')
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'partial')

    def test_full_backup_is_only_delegated_by_explicit_profile(self):
        with patch('lawliet_mobile.tools._collect_into',
                   return_value={'status': 'complete', 'evidence_id': None}) as backup:
            result = self.gui(profile='ios-backup')
            self.assertEqual(result['status'], 'complete')
            self.assertEqual(backup.call_args.args[3:7],
                ('ios', '00000000-0000000000000001', 3600, 20*1024**3))
            code, result = self.cli('--profile', 'ios-backup')
            self.assertEqual(code, 0, result)
        self.assertEqual(backup.call_count, 2)
        self.assertEqual(self.calls, [])

    def test_failed_collection_without_evidence_does_not_start_parser(self):
        self.collection_status = 'failed'
        for profile in ('ios-apps', 'ios-selected'):
            with self.subTest(profile=profile):
                result = self.gui(profile=profile)
                self.assertEqual(result['status'], 'failed')
                self.assertNotIn('analysis', result)
                code, result = self.cli('--profile', profile)
                self.assertEqual(code, 1)
                self.assertNotIn('analysis', result)

    def test_android_omitted_profile_still_uses_existing_triage(self):
        with patch('lawliet_mobile.cli.collect', return_value={'status': 'complete'}) as collector:
            code, result = self.cli(platform='android')
        self.assertEqual(code, 0, result)
        self.assertEqual(collector.call_args.args[3], 'android')
        self.assertEqual(collector.call_args.kwargs, {})


if __name__ == '__main__':
    unittest.main()
