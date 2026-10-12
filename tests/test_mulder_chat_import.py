import hashlib
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lawliet_mobile.core import UserError, connect, create_case
try:
    from mulder.server.tools import phone
except ModuleNotFoundError as error:
    if error.name != "mulder":
        raise
    phone = None


@unittest.skipUnless(phone, "Requires the patched Mulder integration runtime")
class MulderChatImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / 'lawliet-review'
        create_case(self.workspace, 'first')
        create_case(self.workspace, 'other')
        self.case = self.workspace / 'first'
        self.source = self.base / 'chat.txt'
        self.source.write_text('10/01/26, 09:00 - Jamie: First line\nSecond 😀\n')
        self.fn = inspect.unwrap(phone.import_ancalor_chat_review)
        context = patch.object(phone, 'get_ctx', return_value=SimpleNamespace(
            db=SimpleNamespace(db_path=self.base / 'active.db')))
        context.start()
        self.addCleanup(context.stop)

    def run_import(self, **options):
        return self.fn(str(self.case), str(self.source), 'mdy', **options)

    def test_same_case_declared_time_source_bytes_and_audit(self):
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        result = self.run_import(timezone_name='America/New_York', year_century=2000)
        self.assertTrue(result['integrity']['ok'])
        self.assertEqual(result['case_path'], str(self.case))
        self.assertFalse(result['existing_exports_refreshed'])
        with connect(self.workspace, 'first') as (_, db):
            row = db.execute('SELECT * FROM artifacts').fetchone()
            self.assertEqual(row['timestamp'], '2026-10-01T13:00:00.000000Z')
            self.assertEqual(row['body'], 'First line\nSecond 😀')
            self.assertEqual(json.loads(row['data'])['source_kind'], 'user_export')
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='mulder.chat_review.imported'").fetchone()[0], 1)
        with connect(self.workspace, 'other') as (_, db):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), before)

    def test_unknown_century_and_dst_overlap_stay_undated(self):
        self.run_import(timezone_name='America/New_York')
        self.source.write_text('11/02/25, 01:30 - Jamie: Ambiguous clock\n')
        self.run_import(timezone_name='America/New_York', year_century=2000)
        with connect(self.workspace, 'first') as (_, db):
            self.assertEqual(db.execute('SELECT timestamp FROM artifacts').fetchall()[0][0], None)
            self.assertTrue(all(r[0] is None for r in db.execute('SELECT timestamp FROM artifacts')))

    def test_repeated_imports_preserve_occurrences_and_prior_export_snapshot(self):
        exports = self.case / 'exports'
        exports.mkdir(exist_ok=True)
        snapshot = exports / 'records.jsonl'
        snapshot.write_bytes(b'prior snapshot\n')
        a = self.run_import()
        b = self.run_import()
        self.assertNotEqual(a['import']['evidence_id'], b['import']['evidence_id'])
        with connect(self.workspace, 'first') as (_, db):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 2)
        self.assertEqual(snapshot.read_bytes(), b'prior snapshot\n')

    def test_external_case_and_symlink_sources_are_refused(self):
        elsewhere = self.base / 'external'
        create_case(elsewhere, 'foreign')
        with self.assertRaises(ValueError):
            self.fn(str(elsewhere / 'foreign'), str(self.source), 'mdy')
        link = self.base / 'linked.txt'
        link.symlink_to(self.source)
        with self.assertRaises(ValueError):
            self.fn(str(self.case), str(link), 'mdy')
        folder = self.base / 'linked-folder'
        folder.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.fn(str(self.case), str(folder / 'chat.txt'), 'mdy')

    def test_input_and_declarations_rejected_before_evidence_import(self):
        for options in ({'year_century': True}, {'year_century': 2026}, {'timezone_name': 'invalid/zone'}):
            with self.assertRaises(UserError):
                self.run_import(**options)
        with self.assertRaises(UserError):
            self.fn(str(self.case), str(self.source), 'invalid')
        with self.source.open('wb') as stream:
            stream.truncate(64 * 1024**2 + 1)
        with self.assertRaises(ValueError):
            self.run_import()
        with connect(self.workspace, 'first') as (_, db):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 0)

    def test_existing_case_tampering_blocks_import(self):
        first = self.run_import()
        with connect(self.workspace, 'first') as (root, db):
            file = db.execute('SELECT * FROM files WHERE evidence_id=?',
                              (first['import']['evidence_id'],)).fetchone()
            (root / 'evidence' / file['evidence_id'] / file['path']).write_text('changed')
        with self.assertRaisesRegex(ValueError, 'integrity failed'):
            self.run_import()
        with connect(self.workspace, 'first') as (_, db):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 1)
