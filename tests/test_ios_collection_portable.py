"""Synthetic iOS backup transport and host boundaries; no physical device."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile.core import UserError, connect, create_case, digest, select_artifacts, verify
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.tools import collect, command, configure, execute


FIXTURE = """import hashlib,pathlib,plistlib,sqlite3,sys,time
a=sys.argv[1:]
assert len(a)==5 and a[0]=='-u' and a[2:4]==['backup','--full']
serial=a[1]
if serial=='FAILUDID':
    sys.stdout.buffer.write('ErrorCode 17: synthetic refusal — café 東京\\n'.encode('utf-8'))
    sys.stderr.buffer.write(b'synthetic backup denied\\n')
    sys.exit(17)
if serial=='SLOWUDID':
    time.sleep(30)
    sys.exit(9)
if serial=='EMPTYUDID':
    sys.exit(0)
p=pathlib.Path(a[4])/serial;p.mkdir()
(p/'Manifest.plist').write_bytes(plistlib.dumps({'IsEncrypted':False}))
(p/'Status.plist').write_bytes(plistlib.dumps({'SnapshotState':'finished'}))
fid=hashlib.sha1(b'HomeDomain-Library/SMS/sms.db').hexdigest()
(p/fid[:2]).mkdir()
with sqlite3.connect(p/fid[:2]/fid) as d:
    d.executescript("CREATE TABLE handle(id TEXT);INSERT INTO handle VALUES('+12025550123');"
      "CREATE TABLE message(date INTEGER,text TEXT,handle_id INTEGER,is_from_me INTEGER,service TEXT);")
    d.execute("INSERT INTO message VALUES(813592800,?,1,0,'iMessage')",('Synthetic café 東京',))
d.close()
with sqlite3.connect(p/'Manifest.db') as m:
    m.execute('CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER)')
    m.execute('INSERT INTO Files VALUES(?,?,?,1)',(fid,'HomeDomain','Library/SMS/sms.db'))
m.close()
sys.stdout.buffer.write(b'synthetic backup completed\\n')
"""


class IOSCollectionPortableTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='lawliet-ios-portable-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.workspace = self.base / 'Case café 東京'
        self.root = create_case(self.workspace, 'IOS')
        self.fixture = self.base / 'backup café 東京.py'
        self.fixture.write_text(FIXTURE, encoding='utf-8')
        configure(self.workspace, 'idevicebackup2', self.fixture, python=sys.executable)

    def test_real_subprocess_hashed_backup_intake_and_exact_message(self):
        configured = json.loads((self.workspace / 'tools.json').read_bytes())
        self.assertEqual(configured['idevicebackup2']['path'], str(self.fixture))
        self.assertEqual(command(self.workspace, 'idevicebackup2'), [sys.executable, str(self.fixture)])
        tool_hash = digest(self.fixture)
        with connect(self.workspace, 'IOS') as (root, db):
            result = collect(root, db, self.workspace, 'ios', 'TESTUDID')
            self.assertEqual(result['status'], 'complete')
            folder = Path(result['path'])
            backup = folder / 'backup'
            before = {p.relative_to(backup).as_posix(): digest(p) for p in backup.rglob('*') if p.is_file()}
            self.assertEqual(len(before), 4)
            receipt = json.loads((folder / 'collection.json').read_bytes())
            self.assertEqual(receipt['commands'][0]['argv'],
                [sys.executable, str(self.fixture), '-u', 'TESTUDID', 'backup', '--full', str(backup)])
            self.assertEqual(receipt['commands'][0]['returncode'], 0)
            self.assertEqual(native_analyze(root, db, result['evidence_id'])['new_records'], 1)
            row = select_artifacts(db)[0]
            self.assertEqual(row['body'], 'Synthetic café 東京')
            self.assertEqual(row['timestamp'], '2026-10-13T14:00:00.000000Z')
            self.assertEqual(row['timestamp_raw'], '813592800')
            self.assertEqual(row['logical_path'], 'HomeDomain/Library/SMS/sms.db')
            self.assertEqual(row['source_ref'], 'message:rowid=1')
            fid = hashlib.sha1(b'HomeDomain-Library/SMS/sms.db').hexdigest()
            self.assertEqual(row['source_sha256'], before[f'TESTUDID/{fid[:2]}/{fid}'])
            self.assertEqual(before, {p.relative_to(backup).as_posix(): digest(p)
                                      for p in backup.rglob('*') if p.is_file()})
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(digest(self.fixture), tool_hash)

    def test_failed_unfinished_and_timed_out_backups_never_become_evidence(self):
        for serial, expected in [('FAILUDID', UserError), ('EMPTYUDID', UserError),
                                 ('SLOWUDID', subprocess.TimeoutExpired)]:
            with self.subTest(serial=serial), connect(self.workspace, 'IOS') as (root, db):
                previous = set((root / 'collections').glob('*')) if (root / 'collections').exists() else set()
                with self.assertRaises(expected):
                    collect(root, db, self.workspace, 'ios', serial,
                            timeout=0.5 if serial == 'SLOWUDID' else 30)
                folder, = set((root / 'collections').glob('*')) - previous
                receipt = json.loads((folder / 'collection.json').read_bytes())
                self.assertEqual(receipt['status'], 'failed')
                self.assertIsNone(receipt['evidence_id'])
                self.assertEqual(len(receipt['commands']), 1)
                self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)
                self.assertTrue((folder / 'backup.log').is_file())
                self.assertTrue((folder / 'backup.log.stderr').is_file())
                if serial == 'FAILUDID':
                    self.assertEqual(receipt['commands'][0]['returncode'], 17)
                    self.assertIn('café 東京', receipt['errors'][0]['error'])
                    self.assertEqual((folder / 'backup.log.stderr').read_bytes(), b'synthetic backup denied\n')
                elif serial == 'SLOWUDID':
                    self.assertEqual(receipt['commands'][0]['error'], 'timeout')
                    self.assertNotEqual(receipt['commands'][0]['returncode'], 0)

    def test_linked_collections_parent_refused_before_foreign_writes_or_device_command(self):
        foreign = self.base / 'foreign'
        foreign.mkdir()
        sentinel = foreign / 'sentinel'
        sentinel.write_bytes(b'UNCHANGED')
        link = self.root / 'collections'
        if os.name == 'nt':
            result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(foreign)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.addCleanup(link.rmdir)
        else:
            link.symlink_to(foreign, target_is_directory=True)
        with connect(self.workspace, 'IOS') as (root, db), patch('lawliet_mobile.tools.execute') as run:
            with self.assertRaisesRegex(UserError, 'staging cannot be created safely'):
                collect(root, db, self.workspace, 'ios', 'TESTUDID')
            run.assert_not_called()
            self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='collection.started'").fetchone()[0], 0)
        self.assertEqual(list(foreign.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b'UNCHANGED')

    def test_failed_backup_cannot_overwrite_linked_final_receipt(self):
        sentinel = self.base / 'foreign-receipt'
        sentinel.write_bytes(b'UNCHANGED')
        def run(argv, output, *args, **kwargs):
            result = execute(argv, output, *args, **kwargs)
            os.link(sentinel, output.parent / 'collection.json')
            return result
        with connect(self.workspace, 'IOS') as (root, db), patch('lawliet_mobile.tools.execute', side_effect=run):
            with self.assertRaises((UserError, OSError)):
                collect(root, db, self.workspace, 'ios', 'FAILUDID')
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)
        self.assertEqual(sentinel.read_bytes(), b'UNCHANGED')
        with connect(self.workspace, 'IOS') as (root, db):
            terminal = json.loads(db.execute(
                "SELECT detail FROM audit WHERE action='collection.finished'").fetchone()[0])
            self.assertEqual(terminal['status'], 'failed')
            self.assertEqual(terminal['collection_status'], 'failed')
            self.assertEqual(terminal['receipt_status'], 'failed')
            self.assertIsNone(terminal['evidence_id'])
            self.assertIn('receipt publication failed', terminal['errors'][-1]['error'])
            self.assertTrue(verify(root, db)['ok'])

    @unittest.skipUnless(os.name == 'nt', 'Native Windows directory ownership')
    def test_collection_parent_stays_pinned_during_actual_backup(self):
        attempted = []
        def run(argv, output, *args, **kwargs):
            for path in (output.parent, output.parent.parent):
                with self.assertRaises(PermissionError):
                    path.rename(path.with_name(path.name + '-replaced'))
            attempted.append(True)
            return execute(argv, output, *args, **kwargs)
        with connect(self.workspace, 'IOS') as (root, db), patch('lawliet_mobile.tools.execute', side_effect=run):
            result = collect(root, db, self.workspace, 'ios', 'TESTUDID')
            self.assertEqual(result['status'], 'complete')
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(attempted, [True])


if __name__ == '__main__':
    unittest.main()
