"""Small hashed-backup selections remain readable without implying completeness."""
import hashlib
import plistlib
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, connect, create_case, digest, import_evidence, verify
from lawliet_mobile.parsers import VERSION, native_analyze
from lawliet_mobile.validation import validate_case


class IOSSelectedEvidenceReviewTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='lawliet-ios-selected-review-')
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'IOS')
        self.source = self.base / 'selected'
        self.source.mkdir()
        self.main_logical = 'Library/SMS/sms.db'
        self.wal_logical = self.main_logical + '-wal'
        self.attachment_logical = 'Library/SMS/Attachments/uncollected.png'
        self.file_ids = {name: hashlib.sha1(('HomeDomain-' + name).encode()).hexdigest()
                         for name in (self.main_logical, self.wal_logical, self.attachment_logical)}
        live = self.base / 'live.db'
        with closing(sqlite3.connect(live)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA wal_autocheckpoint=0')
            db.executescript("""
                CREATE TABLE handle(id TEXT);
                INSERT INTO handle VALUES ('synthetic-contact');
                CREATE TABLE message(text TEXT, date INTEGER, is_from_me INTEGER, handle_id INTEGER);
                INSERT INTO message VALUES ('MAIN fixture message', 813592800, 0, 1);
                CREATE TABLE attachment(filename TEXT, total_bytes INTEGER);
                INSERT INTO attachment VALUES ('Library/SMS/Attachments/uncollected.png', 100);
                CREATE TABLE message_attachment_join(message_id INTEGER, attachment_id INTEGER);
                INSERT INTO message_attachment_join VALUES (1, 1);
            """)
            db.commit()
            db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            db.execute("INSERT INTO message VALUES ('WAL fixture message',813592801,1,1)")
            db.commit()
            for logical, suffix in ((self.main_logical, ''), (self.wal_logical, '-wal')):
                target = self.payload(logical)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(Path(str(live) + suffix), target)
        (self.source / 'Manifest.plist').write_bytes(plistlib.dumps({'IsEncrypted': False}))
        (self.source / 'Status.plist').write_bytes(plistlib.dumps({'SnapshotState': 'finished'}))
        with closing(sqlite3.connect(self.source / 'Manifest.db')) as db, db:
            db.execute('CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)')
            db.executemany('INSERT INTO Files VALUES (?, ?, ?, ?)',
                           [(fid, 'HomeDomain', logical, 1) for logical, fid in self.file_ids.items()])

    def payload(self, logical):
        fid = self.file_ids[logical]
        return self.source / fid[:2] / fid

    def examine(self):
        before = {str(p.relative_to(self.source)): digest(p) for p in self.source.rglob('*') if p.is_file()}
        with connect(self.workspace, 'IOS') as (root, db):
            evidence = import_evidence(root, db, self.source, 'ios')[0]
            run = native_analyze(root, db, evidence)
            report = validate_case(root, db, self.workspace, evidence, VERSION, run['run_id'])
            self.assertTrue(verify(root, db)['ok'])
        after = {str(p.relative_to(self.source)): digest(p) for p in self.source.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        rows = handle(self.workspace, {'action': 'records', 'case': 'IOS', 'run': run['run_id']})['records']
        return run, report, rows

    def test_retained_main_wal_rows_reach_gui_with_missing_attachment_explicit(self):
        run, report, rows = self.examine()
        self.assertEqual(run['status'], 'complete')
        messages = [row for row in rows if row['category'] == 'messages']
        self.assertEqual({row['body'] for row in messages}, {'MAIN fixture message', 'WAL fixture message'})
        self.assertEqual({row['timestamp'] for row in messages},
                         {'2026-10-13T14:00:00.000000Z', '2026-10-13T14:00:01.000000Z'})
        for row in messages:
            self.assertEqual(row['source_sha256'], digest(self.payload(self.main_logical)))
            self.assertEqual(row['logical_path'], 'HomeDomain/' + self.main_logical)
            self.assertEqual(row['data']['source_sidecars'], [{
                'logical_path': 'HomeDomain/' + self.wal_logical,
                'sha256': digest(self.payload(self.wal_logical))}])
            self.assertEqual(row['data']['sqlite_wal_coverage']['pairing'], 'unverified')
        attachments = [row for row in rows if row['category'] == 'attachments']
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]['data']['attachment']['status'], 'not_acquired')
        inventory = next(check for check in report['checks'] if check['check'] == 'ios_backup_inventory')
        self.assertEqual(inventory['status'], 'incomplete')
        self.assertEqual(inventory['missing_count'], 1)
        self.assertEqual(inventory['missing'][0]['logical_path'], 'HomeDomain/' + self.attachment_logical)
        self.assertEqual(report['status'], 'needs_review')

    def test_missing_declared_wal_is_not_hidden_by_readable_main_database(self):
        self.payload(self.wal_logical).unlink()
        run, report, rows = self.examine()
        self.assertEqual([row['body'] for row in rows if row['category'] == 'messages'], ['MAIN fixture message'])
        message = next(row for row in rows if row['category'] == 'messages')
        limit = message['data']['sqlite_wal_coverage']
        self.assertFalse(limit['wal_present'])
        self.assertIn('no WAL companion', limit['reason'])
        self.assertTrue(run['unparsed_candidates'])
        inventory = next(check for check in report['checks'] if check['check'] == 'ios_backup_inventory')
        self.assertEqual(inventory['missing_count'], 2)
        self.assertEqual(inventory['status'], 'incomplete')

    def test_encrypted_manifest_blocks_native_even_with_readable_fixture_payload(self):
        (self.source / 'Manifest.plist').write_bytes(plistlib.dumps({'IsEncrypted': True}))
        with connect(self.workspace, 'IOS') as (root, db):
            evidence = import_evidence(root, db, self.source, 'ios')[0]
            with self.assertRaisesRegex(UserError, 'Encrypted iOS'):
                native_analyze(root, db, evidence)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)
            self.assertTrue(verify(root, db)['ok'])


if __name__ == '__main__':
    unittest.main()
