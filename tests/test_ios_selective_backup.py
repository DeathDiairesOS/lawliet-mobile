import hashlib
import json
from contextlib import closing
from pathlib import Path
import plistlib
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile.core import UserError, connect, create_case, digest, verify
from lawliet_mobile.child_output import ChildOutputs
from lawliet_mobile.ios_backup import BASE_PATHS, DATABASE_REGEX, VERSION, _atomic_receipt, _backup_failure, collect_selected

SERIAL = '00008120-0012345678901234'


def fixture_backup(parent, *, missing=False, encrypted=False, duplicate=False, corrupt=False, wal=False):
    folder = parent / SERIAL
    folder.mkdir(parents=True)
    for name, value in [('Info.plist', {'Target Identifier': SERIAL}),
                        ('Manifest.plist', {'IsEncrypted': encrypted}),
                        ('Status.plist', {'SnapshotState': 'finished'})]:
        (folder / name).write_bytes(plistlib.dumps(value))
    with closing(sqlite3.connect(folder / 'Manifest.db')) as db, db:
        db.execute('CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER)')
        for relative, create in [(BASE_PATHS[0], 'CREATE TABLE message(text TEXT)'),
                                 (BASE_PATHS[1], 'CREATE TABLE ABPerson(First TEXT)'),
                                 ('Library/SMS/Attachments/video.mov', None),
                                 ('Library/AddressBook/AddressBookImages.sqlitedb', None)]:
            file_id = hashlib.sha1(('HomeDomain-' + relative).encode()).hexdigest()
            db.execute('INSERT INTO Files VALUES(?,?,?,1)', (file_id, 'HomeDomain', relative))
            payload = folder / file_id[:2] / file_id
            payload.parent.mkdir(exist_ok=True)
            if create:
                with closing(sqlite3.connect(payload)) as item, item:
                    item.execute(create)
                if corrupt and relative == BASE_PATHS[0]:
                    payload.write_bytes(b'not sqlite')
            else:
                payload.touch()  # pymobiledevice3 transport placeholder
            if wal and relative == BASE_PATHS[0]:
                with tempfile.TemporaryDirectory() as temp:
                    temporary = Path(temp) / 'sms.db'
                    shutil.copyfile(payload, temporary)
                    with closing(sqlite3.connect(temporary)) as item:
                        item.execute('PRAGMA journal_mode=WAL')
                        item.execute("INSERT INTO message VALUES('Fixture message only in WAL')")
                        item.commit()
                        wal_id = hashlib.sha1(('HomeDomain-' + relative + '-wal').encode()).hexdigest()
                        db.execute('INSERT INTO Files VALUES(?,?,?,1)', (wal_id, 'HomeDomain', relative + '-wal'))
                        wal_path = folder / wal_id[:2] / wal_id
                        wal_path.parent.mkdir(exist_ok=True)
                        shutil.copyfile(temporary, payload)
                        shutil.copyfile(Path(str(temporary) + '-wal'), wal_path)
        if missing:
            relative = BASE_PATHS[0] + '-wal'
            file_id = hashlib.sha1(('HomeDomain-' + relative).encode()).hexdigest()
            db.execute('INSERT INTO Files VALUES(?,?,?,1)', (file_id, 'HomeDomain', relative))
        if duplicate:
            db.execute('INSERT INTO Files SELECT * FROM Files WHERE relativePath=?', (BASE_PATHS[0],))
    return folder


class SelectedIPhoneTests(unittest.TestCase):
    def exercise(self, *, version=VERSION, encryption='false', missing=False, encrypted=False,
                 code=0, warning='', duplicate=False, corrupt=False, link=False, no_space=False, wal=False,
                 wrong_identity=False, receipt_error=False, receipt_link=False, timed_out=False):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve() / 'cases'
            create_case(workspace, 'selective')
            calls, source_hashes = [], {}
            outside = Path(tmp) / 'outside-receipt'
            outside.write_text('untouched')

            def receipt(anchor, name, value):
                if receipt_error and name == 'collection.json':
                    raise OSError('Synthetic no space left for receipt')
                return _atomic_receipt(anchor, name, value)

            def fake(argv, output, timeout, **kwargs):
                calls.append(argv)
                text = ''
                if argv[-1] == 'version':
                    text = version + '\n'
                    if receipt_link:
                        (output.parent / 'collection.tmp').symlink_to(outside)
                elif argv[-1] == '--help':
                    text = '--only-regex --patch-manifest --no-patch-mani…'
                elif argv[-1] == 'WillEncrypt':
                    text = encryption
                else:
                    self.assertIn('--only-regex', argv)
                    self.assertIn(DATABASE_REGEX, argv)
                    self.assertNotIn('--unback', argv)
                    self.assertNotIn('--password', argv)
                    self.assertNotIn('--only', argv)
                    self.assertEqual(argv[argv.index('--udid') + 1], SERIAL)
                    folder = fixture_backup(Path(argv[-1]), missing=missing, encrypted=encrypted,
                                            duplicate=duplicate, corrupt=corrupt, wal=wal)
                    if wrong_identity:
                        (folder / 'Info.plist').write_bytes(plistlib.dumps({'Target Identifier': '00008120-1111111111111111'}))
                    source_hashes.update({p.name: digest(p) for p in folder.iterdir() if p.is_file()})
                    if link:
                        (folder / 'unsafe').symlink_to(Path(tmp) / 'outside')
                output.write_text(text)
                stderr = Path(str(output) + '.stderr')
                stderr.write_text(warning if output.name == 'backup.log' else '')
                if timed_out and output.name == 'backup.log':
                    exc = subprocess.TimeoutExpired(argv, timeout)
                    exc.tool_result = {'argv': argv, 'returncode': -15, 'error': 'timeout'}
                    raise exc
                return {'argv': argv, 'returncode': code if output.name == 'backup.log' else 0,
                        'stdout': str(output), 'stderr': str(stderr)}

            with connect(workspace, 'selective') as (root, db), \
                    patch('lawliet_mobile.ios_backup.command', side_effect=lambda workspace, name: ['/configured/' + name]), \
                    patch('lawliet_mobile.ios_backup.execute', side_effect=fake), \
                    patch('lawliet_mobile.ios_backup._atomic_receipt', side_effect=receipt):
                if no_space:
                    with patch('lawliet_mobile.ios_backup.shutil.disk_usage', return_value=shutil._ntuple_diskusage(100, 99, 1)):
                        result = collect_selected(root, db, workspace, SERIAL)
                else:
                    result = collect_selected(root, db, workspace, SERIAL)
                self.assertTrue(verify(root, db)['ok'])
                finished = json.loads(db.execute("SELECT detail FROM audit WHERE action='collection.finished' ORDER BY id DESC LIMIT 1").fetchone()[0])
                self.assertEqual(finished['status'], result['status'])
                self.assertEqual(finished['evidence_id'], result['evidence_id'])
                if receipt_error:
                    self.assertIsNone(finished['manifest_sha256'])
                self.assertEqual(outside.read_text(), 'untouched')
                if result['evidence_id']:
                    names = [r[0] for r in db.execute('SELECT logical_path FROM files WHERE evidence_id=?', (result['evidence_id'],))]
                    self.assertIn('HomeDomain/' + BASE_PATHS[0], names)
                    self.assertIn('HomeDomain/' + BASE_PATHS[1], names)
                    self.assertFalse(any('/Attachments/' in p for p in names))
                    self.assertFalse(any('AddressBookImages' in p for p in names))
                    for name, expected in source_hashes.items():
                        self.assertEqual(digest(Path(result['path']) / 'backup' / SERIAL / name), expected)
                    self.assertEqual(result['selection']['excluded_manifest_entries'], 2)
                    self.assertEqual(result['selection']['received_sidecars'], [BASE_PATHS[0] + '-wal'] if wal else [])
                    self.assertEqual(len(result['selection']['removed_zero_byte_placeholders']), 2)
                return result, calls

    def test_complete_database_only_import_preserves_manifest_and_omissions(self):
        result, _ = self.exercise()
        self.assertEqual(result['status'], 'complete')
        self.assertIsNotNone(result['evidence_id'])

    def test_missing_declared_sidecar_is_partial_not_intentional_omission(self):
        result, _ = self.exercise(missing=True)
        self.assertEqual(result['status'], 'partial')
        self.assertIn('sms.db-wal', ' '.join(result['errors']))

    def test_no_sidecars_declared_is_valid(self):
        result, _ = self.exercise()
        self.assertEqual(result['selection']['selected_manifest_files'], 2)
        self.assertEqual(len(result['selection']['requested_sidecars']), 4)

    def test_received_wal_validates_using_working_copy(self):
        result, _ = self.exercise(wal=True)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['selection']['selected_manifest_files'], 3)

    def test_wrong_version_fails_before_phone_command(self):
        result, calls = self.exercise(version='10.0.0')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(len(calls), 1)

    def test_unknown_or_encrypted_preflight_never_starts_backup(self):
        for state in ('true', '', 'Error reading value'):
            with self.subTest(state=state):
                result, calls = self.exercise(encryption=state)
                self.assertEqual(result['status'], 'failed')
                self.assertFalse(any('--only-regex' in c for c in calls))

    def test_encryption_changed_during_backup_fails_without_import(self):
        result, _ = self.exercise(encrypted=True)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['evidence_id'])

    def test_nonzero_exit_not_success_despite_finished_status_file(self):
        result, _ = self.exercise(code=1)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['evidence_id'])

    def test_live_device_locked_diagnostic_is_actionable_without_log_reflection_or_retry(self):
        diagnostic = ("Please enter the device passcode to continue the backup\n"
                      "PRIVATE-FIXTURE-VALUE\n"
                      "PyMobileDevice3Exception: Device link error: {'ErrorCode': 208, "
                      "'ErrorDescription': 'Device locked (MBErrorDomain/208)', 'MessageName': 'Response'}")
        result, calls = self.exercise(code=1, warning=diagnostic)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['evidence_id'])
        error = ' '.join(result['errors'])
        self.assertIn('device is locked', error)
        self.assertIn('Unlock the selected iPhone', error)
        self.assertIn('on the phone', error)
        self.assertNotIn('PRIVATE-FIXTURE-VALUE', error)
        self.assertNotIn('ErrorDescription', error)
        self.assertEqual(sum('--only-regex' in call for call in calls), 1)

    def test_known_connection_and_storage_failures_are_separate_from_passcode_hint(self):
        for diagnostic, expected in (('NotEnoughDiskSpaceError: MBErrorDomain/105', 'insufficient storage'),
                                     ('ConnectionTerminatedError: transport closed', 'device connection')):
            with self.subTest(diagnostic=diagnostic):
                result, _ = self.exercise(code=1, warning='Please enter the device passcode to continue the backup\n' + diagnostic)
                self.assertEqual(result['status'], 'failed')
                self.assertIsNone(result['evidence_id'])
                self.assertIn(expected, ' '.join(result['errors']))

    def test_passcode_notification_with_timeout_does_not_claim_collection(self):
        result, calls = self.exercise(timed_out=True, warning='Please enter the device passcode to continue the backup\n')
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['evidence_id'])
        self.assertIn('requested passcode confirmation', ' '.join(result['errors']))
        self.assertEqual(sum('--only-regex' in call for call in calls), 1)

    def test_unrecognized_diagnostic_retains_generic_failure(self):
        result, _ = self.exercise(code=1, warning='PRIVATE-FIXTURE-VALUE: an unknown failure')
        self.assertIn('command failed', ' '.join(result['errors']))
        self.assertNotIn('PRIVATE-FIXTURE-VALUE', ' '.join(result['errors']))

    def test_failure_diagnostics_are_bounded_and_refuse_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary).resolve()
            (folder / 'backup.log').write_bytes(b'x' * (1024**2 + 1) + b'MBErrorDomain/208')
            with ChildOutputs(folder) as anchor:
                self.assertIsNone(_backup_failure(anchor, 2 * 1024**2))
            (folder / 'backup.log.stderr').symlink_to(folder / 'backup.log')
            with ChildOutputs(folder) as anchor:
                self.assertIsNone(_backup_failure(anchor, 2 * 1024**2))

    def test_reported_file_transfer_failure_is_partial(self):
        result, _ = self.exercise(warning='Failed to fully upload: selected file\n')
        self.assertEqual(result['status'], 'partial')

    def test_corrupt_database_is_partial(self):
        result, _ = self.exercise(corrupt=True)
        self.assertEqual(result['status'], 'partial')
        self.assertIn('validation failed', ' '.join(result['errors']))

    def test_duplicate_manifest_or_link_refused(self):
        for values in ({'duplicate': True}, {'link': True}):
            result, _ = self.exercise(**values)
            self.assertEqual(result['status'], 'failed')
            self.assertIsNone(result['evidence_id'])

    def test_storage_reserve_stops_before_tool(self):
        result, calls = self.exercise(no_space=True)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(calls, [])

    def test_missing_dependency_and_invalid_limits(self):
        with patch('lawliet_mobile.ios_backup.command', side_effect=UserError('not installed')):
            with self.assertRaisesRegex(UserError, 'not installed'):
                collect_selected(None, None, None, SERIAL)
        with self.assertRaises(UserError):
            collect_selected(None, None, None, '../bad')
        with self.assertRaises(UserError):
            collect_selected(None, None, None, SERIAL, max_bytes=True)

    def test_receipt_failure_is_audited_and_prevents_import(self):
        result, _ = self.exercise(receipt_error=True)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['evidence_id'])
        self.assertIn('could not be finalized', ' '.join(result['errors']))

    def test_failure_receipt_does_not_follow_child_temp_symlink(self):
        result, _ = self.exercise(version='10.0.0', receipt_link=True)
        self.assertEqual(result['status'], 'failed')

    def test_wrong_device_identity_refuses_import(self):
        result, _ = self.exercise(wrong_identity=True)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['evidence_id'])
        self.assertIn('identity', ' '.join(result['errors']))

    def test_timeout_retains_attempt_and_does_not_import(self):
        result, _ = self.exercise(timed_out=True)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['evidence_id'])

    def test_changed_attempt_directory_cannot_redirect_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp).resolve() / 'cases'
            outside = Path(temp).resolve() / 'outside'
            outside.mkdir()
            create_case(workspace, 'scope')
            def fake(argv, output, timeout, **kwargs):
                output.write_text(VERSION)
                Path(str(output) + '.stderr').write_text('')
                folder = output.parent
                folder.rename(folder.with_name(folder.name + '-original'))
                folder.symlink_to(outside, target_is_directory=True)
                return {'argv': argv, 'returncode': 0, 'stdout': str(output), 'stderr': str(output) + '.stderr'}
            with connect(workspace, 'scope') as (root, db), \
                    patch('lawliet_mobile.ios_backup.command', side_effect=lambda workspace, name: ['/configured/' + name]), \
                    patch('lawliet_mobile.ios_backup.execute', side_effect=fake):
                result = collect_selected(root, db, workspace, SERIAL)
                self.assertEqual(result['status'], 'failed')
                self.assertIsNone(result['evidence_id'])
                self.assertIn('receipt could not be finalized', ' '.join(result['errors']))
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
