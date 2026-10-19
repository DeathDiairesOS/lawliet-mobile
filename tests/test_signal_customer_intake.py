"""Signal customer intake qualification using controlled local decoder processes."""
import json
import os
import signal
import subprocess
import time
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, connect, create_case, digest, select_artifacts, verify
from lawliet_mobile.signal_backup import decrypt_signal, signal_backup_preflight
from lawliet_mobile.tools import configure
from lawliet_mobile.runner_lease import lease


KEY = '123456789012345678901234567890'


class SignalCustomerIntakeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'signal')
        self.backup = self.base / 'signal-test.backup'
        self.backup.write_bytes(b'controlled encrypted test fixture, not a real Signal backup')

    def decoder(self, operation=''):
        tool = self.base / 'decoder.py'
        tool.write_text("""import os, pathlib, sqlite3, sys, time
if '--help' in sys.argv:
    print('signalbackup-tools source version synthetic.20261017 --output --stoponerror')
    sys.exit(0)
secret = input()
assert secret not in sys.argv
assert '--stoponerror' in sys.argv
print('CIPHERKEY:' + secret)
print(secret, file=sys.stderr)
out = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
con = sqlite3.connect(out / 'database.sqlite')
con.executescript("CREATE TABLE recipient(_id INTEGER,e164 TEXT); CREATE TABLE thread(_id INTEGER); CREATE TABLE message(_id INTEGER,thread_id INTEGER,from_recipient_id INTEGER,body TEXT,date_sent INTEGER,type INTEGER); INSERT INTO recipient VALUES(1,'+12025550100'); INSERT INTO thread VALUES(7); INSERT INTO message VALUES(42,7,1,'Known Signal message',1700000000000,20);")
con.commit()
con.close()
(out / 'attachment_8.bin').write_bytes(b'known retained attachment bytes')
""" + operation + '\n')
        configure(self.workspace, 'signalbackup-tools', tool, sys.executable)

    def test_preflight_is_read_only_and_does_not_authenticate_opaque_file(self):
        with patch('lawliet_mobile.signal_backup.command', side_effect=UserError('missing')):
            result = signal_backup_preflight(self.backup, self.workspace)
        self.assertEqual(result['format'], 'android_on_device_candidate')
        self.assertFalse(result['format_verified'])
        self.assertFalse(result['tool']['available'])
        with connect(self.workspace, 'signal') as (_, db):
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)

    def test_rejects_wrong_intake_routes_without_case_writes(self):
        folder = self.base / 'decrypted'
        folder.mkdir()
        (folder / 'database.sqlite').write_bytes(b'SQLite format 3\x00')
        empty = self.base / 'empty.backup'; empty.touch()
        archive = self.base / 'archive.zip'; archive.write_bytes(b'PK\x03\x04payload')
        link = self.base / 'linked.backup'; link.symlink_to(self.backup)
        cases = [(folder, 'already decoded'), (folder / 'database.sqlite', 'plaintext'),
                 (empty, 'empty'), (archive, 'compressed archive'), (link, 'symlink')]
        for source, message in cases:
            with self.subTest(source=source), self.assertRaisesRegex(UserError, message):
                signal_backup_preflight(source)
        with connect(self.workspace, 'signal') as (root, db):
            with self.assertRaisesRegex(UserError, '64-character'):
                decrypt_signal(root, db, self.workspace, self.backup, 'A' * 64)
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)

    def test_new_on_device_backup_folder_is_not_misidentified_as_cloud_or_legacy(self):
        folder = self.base / 'signal-backup-2026-10-17-12-00-00'
        folder.mkdir()
        (folder / 'backup.db').write_bytes(b'encrypted')
        (folder / 'attachments').mkdir()
        (folder / 'manifest.json').write_text('{}')
        with self.assertRaisesRegex(UserError, 'New Signal on-device backup folders'):
            signal_backup_preflight(folder)
        with self.assertRaisesRegex(UserError, 'new Signal on-device backup folder'):
            signal_backup_preflight(folder / 'backup.db')

    def test_supported_decode_reaches_existing_backend_and_preserves_provenance(self):
        self.decoder()
        original_hash = digest(self.backup)
        result = handle(self.workspace, {'action': 'decrypt-signal', 'case': 'signal',
                                        'path': str(self.backup), 'passphrase': KEY})
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['non_database_files'], 1)
        self.assertEqual(result['tool']['version'], 'synthetic.20261017')
        self.assertEqual(result['original_sha256'], original_hash)
        self.assertEqual(digest(self.backup), original_hash)
        self.assertGreater(result['analysis']['new_records'], 0)
        with connect(self.workspace, 'signal') as (root, db):
            rows = select_artifacts(db, evidence=result['evidence_id'], app='signal')
            message = next(row for row in rows if row['category'] == 'messages')
            self.assertEqual(message['body'], 'Known Signal message')
            self.assertIn('42', message['source_ref'])
            self.assertEqual(datetime.fromisoformat(message['timestamp'].replace('Z', '+00:00')), datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc))
            self.assertTrue(verify(root, db)['ok'])
            original = db.execute('SELECT encrypted FROM evidence WHERE id=?', (result['original_evidence_id'],)).fetchone()
            self.assertEqual(original[0], 1)
            run = db.execute('SELECT detail FROM runs WHERE id=?', (result['run_id'],)).fetchone()
            detail = json.loads(run[0])
            self.assertTrue(detail['preserved_original_intact'])
            self.assertEqual(detail['input_integrity'], 'passed_before_and_after')
            for row in db.execute('SELECT detail FROM runs UNION ALL SELECT detail FROM audit'):
                self.assertNotIn(KEY, row[0] or '')
            self.assertFalse(list((root / 'runs' / result['run_id']).glob('*.log')))
            retained = db.execute('SELECT path FROM files WHERE evidence_id=? AND path LIKE ?', (result['evidence_id'], '%attachment_8.bin')).fetchone()
            self.assertEqual((root / 'evidence' / result['evidence_id'] / retained[0]).read_bytes(), b'known retained attachment bytes')

    def test_failed_decoder_retains_original_and_partial_files_but_imports_no_results(self):
        self.decoder('sys.exit(9)')
        with connect(self.workspace, 'signal') as (root, db):
            with self.assertRaisesRegex(UserError, 'Partial output is retained but not indexed'):
                decrypt_signal(root, db, self.workspace, self.backup, KEY, timeout=5)
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], 1)
            row = db.execute("SELECT status,detail,id FROM runs WHERE engine='signalbackup-tools'").fetchone()
            self.assertEqual(row['status'], 'failed')
            self.assertEqual(json.loads(row['detail'])['returncode'], 9)
            self.assertTrue((root / 'runs' / row['id'] / 'decrypted' / 'database.sqlite').is_file())
            self.assertTrue(verify(root, db)['ok'])
            self.assertNotIn(KEY, row['detail'])

    def test_decoder_input_mutation_fails_without_importing_derived_evidence(self):
        self.decoder("pathlib.Path(sys.argv[1]).write_bytes(b'changed')")
        with connect(self.workspace, 'signal') as (root, db):
            with self.assertRaisesRegex(UserError, 'changed its input working copy'):
                decrypt_signal(root, db, self.workspace, self.backup, KEY, timeout=5)
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], 1)
            self.assertTrue(verify(root, db)['ok'])

    def test_decoder_symlinks_are_rejected(self):
        self.decoder("(out / 'linked.bin').symlink_to(pathlib.Path(sys.argv[1]))")
        with connect(self.workspace, 'signal') as (root, db):
            with self.assertRaisesRegex(UserError, 'unsafe link'):
                decrypt_signal(root, db, self.workspace, self.backup, KEY, timeout=5)
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], 1)
            self.assertTrue(verify(root, db)['ok'])

    def test_timeout_records_failure_and_keeps_original(self):
        self.decoder('time.sleep(30)')
        with connect(self.workspace, 'signal') as (root, db):
            with self.assertRaisesRegex(UserError, 'timed out'):
                decrypt_signal(root, db, self.workspace, self.backup, KEY, timeout=.1)
            row = db.execute("SELECT status,detail FROM runs WHERE engine='signalbackup-tools'").fetchone()
            self.assertEqual(row['status'], 'failed')
            self.assertTrue(json.loads(row['detail'])['preserved_original_intact'])
            self.assertTrue(verify(root, db)['ok'])

    def test_incompatible_tool_is_rejected_before_evidence_import(self):
        tool = self.base / 'incompatible.py'
        tool.write_text("print('--output')\n")
        configure(self.workspace, 'signalbackup-tools', tool, sys.executable)
        with connect(self.workspace, 'signal') as (root, db):
            with self.assertRaisesRegex(UserError, 'does not advertise'):
                decrypt_signal(root, db, self.workspace, self.backup, KEY)
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)

    @unittest.skipUnless(os.name == 'posix', 'POSIX guardian ownership')
    def test_owner_death_reconciles_interrupted_decode_and_allows_retry(self):
        ready = self.base / 'ready'
        self.decoder("pathlib.Path(" + repr(str(ready)) + ").write_text(str(os.getpid()) + ',' + str(os.getppid()))\ntime.sleep(30)")
        script = """import sys
from pathlib import Path
from lawliet_mobile.core import connect
from lawliet_mobile.signal_backup import decrypt_signal
from tests.test_signal_customer_intake import KEY
workspace = Path(sys.argv[1])
with connect(workspace, 'signal') as (root, db):
    decrypt_signal(root, db, workspace, Path(sys.argv[2]), KEY, timeout=60)
"""
        parent = subprocess.Popen([sys.executable, '-c', script, str(self.workspace), str(self.backup)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1])})
        def cleanup():
            if parent.poll() is None:
                parent.kill()
            parent.communicate(timeout=5)
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 8
        while not ready.exists():
            if parent.poll() is not None:
                self.fail(parent.communicate()[1].decode())
            if time.monotonic() >= deadline:
                self.fail('Decoder did not reach controlled partial output')
            time.sleep(.02)
        child_pid, guardian_pid = map(int, ready.read_text().split(','))
        self.assertNotEqual(parent.pid, guardian_pid)
        with connect(self.workspace, 'signal') as (root, db):
            with self.assertRaisesRegex(UserError, 'still owns'):
                decrypt_signal(root, db, self.workspace, self.backup, KEY)
        parent.kill()
        parent.communicate(timeout=5)
        deadline = time.monotonic() + 8
        while True:
            try:
                with connect(self.workspace, 'signal') as (root, db):
                    with lease(root, db):
                        pass
                break
            except UserError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.05)
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)
        with connect(self.workspace, 'signal') as (root, db):
            rows = list(db.execute("SELECT status,detail,id FROM runs WHERE engine='signalbackup-tools'"))
            self.assertEqual([row['status'] for row in rows], ['interrupted'])
            self.assertEqual(json.loads(rows[0]['detail'])['recovery']['state'], 'abandoned_owner_reconciled')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)
            self.assertTrue((root / 'runs' / rows[0]['id'] / 'decrypted' / 'database.sqlite').is_file())
            self.assertTrue(verify(root, db)['ok'])
        self.decoder()
        with connect(self.workspace, 'signal') as (root, db):
            self.assertEqual(decrypt_signal(root, db, self.workspace, self.backup, KEY)['status'], 'complete')
            self.assertEqual([row[0] for row in db.execute("SELECT status FROM runs WHERE engine='signalbackup-tools' ORDER BY rowid")], ['interrupted', 'complete'])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='analysis.abandoned'").fetchone()[0], 1)
            self.assertTrue(verify(root, db)['ok'])
            for row in db.execute('SELECT detail FROM runs UNION ALL SELECT detail FROM audit'):
                self.assertNotIn(KEY, row[0] or '')

    def test_fast_decoder_cannot_skip_storage_limit_check(self):
        self.decoder("(out / 'large.bin').write_bytes(b'x' * 20000)")
        with connect(self.workspace, 'signal') as (root, db):
            with self.assertRaisesRegex(UserError, 'storage budget'):
                decrypt_signal(root, db, self.workspace, self.backup, KEY, max_bytes=2000)
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], 1)
            self.assertTrue(verify(root, db)['ok'])


if __name__ == '__main__':
    unittest.main()
