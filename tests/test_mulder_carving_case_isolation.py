"""Actual raw-image carving must preserve originals and isolate retained runs."""
import hashlib
import inspect
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    from mulder.audit import AuditLog
    from mulder.db import CaseDB
    from mulder.server import app
    from mulder.server.tools import phone
except ImportError:
    phone = None


@unittest.skipUnless(phone and hasattr(phone, '_carving_paths'), 'Requires case-isolated Mulder carving candidate')
class MulderCarvingIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.store = self.root / 'cases'
        self.carve = inspect.unwrap(phone.carve_sqlite_from_raw)
        self.a, self.image_a = self.make_case('A', 'CASE_A_ONLY')
        self.b, self.image_b = self.make_case('B', 'CASE_B_ONLY')

    def make_case(self, name, marker):
        evidence = self.root / ('evidence-' + name)
        evidence.mkdir()
        dbfile = self.root / (name + '-seed.sqlite')
        with closing(sqlite3.connect(dbfile)) as db:
            db.execute('CREATE TABLE messages(body TEXT)')
            db.execute('INSERT INTO messages VALUES(?)', (marker,))
            db.commit()
        image = evidence / 'phone.bin'
        image.write_bytes(b'X' * 4096 + dbfile.read_bytes() + b'END')
        db = CaseDB.create(name, str(evidence), self.store)
        self.addCleanup(db.close)
        ctx = SimpleNamespace(case_id=name, db=db, audit=AuditLog(self.store / (name + '-audit.jsonl')))
        return ctx, image

    def run_carve(self, ctx, image, **params):
        with patch.object(app, '_ctx', ctx):
            return self.carve(str(image), **params)

    def outputs(self, name):
        return sorted((self.store / 'carved_sqlite' / name).glob('run-*/carved_*.sqlite'))

    def content(self, path):
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
            return db.execute('SELECT body FROM messages').fetchone()[0]

    def test_equal_offsets_in_two_cases_keep_both_databases_and_originals(self):
        originals = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.image_a, self.image_b)}
        self.assertEqual(self.run_carve(self.a, self.image_a)['status'], 'success')
        output_a = self.outputs('A')[0]
        first_bytes = output_a.read_bytes()
        self.assertEqual(self.run_carve(self.b, self.image_b)['status'], 'success')
        output_b = self.outputs('B')[0]
        self.assertEqual(output_a.name, output_b.name)
        self.assertNotEqual(output_a.parent, output_b.parent)
        self.assertEqual(output_a.read_bytes(), first_bytes)
        self.assertEqual(self.content(output_a), 'CASE_A_ONLY')
        self.assertEqual(self.content(output_b), 'CASE_B_ONLY')
        for path, digest in originals.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        with closing(sqlite3.connect(self.a.db.db_path.as_uri() + '?mode=ro', uri=True)) as db:
            indexed = '\n'.join(row[0] for row in db.execute('SELECT raw_text FROM windows'))
        self.assertIn(str(output_a), indexed)
        self.assertNotIn(str(output_b), indexed)
        audit = [json.loads(line) for line in (self.store / 'A-audit.jsonl').read_text().splitlines()]
        self.assertTrue(any(row.get('tool_name') == 'carve_sqlite_from_raw' for row in audit))

    def test_rerun_uses_a_new_directory_without_overwriting_prior_run(self):
        self.run_carve(self.a, self.image_a)
        first = self.outputs('A')[0]
        digest = hashlib.sha256(first.read_bytes()).hexdigest()
        self.run_carve(self.a, self.image_a)
        self.assertEqual(len(self.outputs('A')), 2)
        self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(), digest)

    def test_foreign_evidence_is_rejected_before_output_creation(self):
        result = self.run_carve(self.a, self.image_b)
        self.assertEqual(result['status'], 'error')
        self.assertIn('outside', result['error_message'])
        self.assertFalse((self.store / 'carved_sqlite').exists())

    def test_linked_input_and_output_roots_are_rejected(self):
        link = self.image_a.parent / 'linked.bin'
        link.symlink_to(self.image_a)
        self.assertEqual(self.run_carve(self.a, link)['status'], 'error')
        outside = self.root / 'outside'
        outside.mkdir()
        (self.store / 'carved_sqlite').symlink_to(outside)
        self.assertEqual(self.run_carve(self.a, self.image_a)['status'], 'error')
        self.assertEqual(list(outside.iterdir()), [])

    def test_linked_case_namespace_is_rejected(self):
        carved = self.store / 'carved_sqlite'
        carved.mkdir()
        outside = self.root / 'foreign-output'
        outside.mkdir()
        (carved / 'A').symlink_to(outside)
        self.assertEqual(self.run_carve(self.a, self.image_a)['status'], 'error')
        self.assertEqual(list(outside.iterdir()), [])

    def test_case_identity_mismatch_is_rejected(self):
        self.a.case_id = 'B'
        result = self.run_carve(self.a, self.image_a)
        self.assertEqual(result['status'], 'error')
        self.assertFalse((self.store / 'carved_sqlite').exists())

    def test_output_inside_evidence_is_rejected(self):
        with patch.object(self.a.db, 'get_case_metadata', return_value=SimpleNamespace(case_id='A', evidence_root=str(self.root))):
            result = self.run_carve(self.a, self.image_a)
        self.assertEqual(result['status'], 'error')
        self.assertIn('outside original evidence', result['error_message'])
        self.assertFalse((self.store / 'carved_sqlite').exists())

    def test_existing_offset_file_and_symlink_are_never_overwritten(self):
        output = self.root / 'helper-output'
        output.mkdir()
        candidate = output / 'carved_0000001000.sqlite'
        candidate.write_bytes(b'PRESERVE')
        with self.assertRaises(FileExistsError):
            phone._carve_sqlite_databases(str(self.image_a), str(output))
        self.assertEqual(candidate.read_bytes(), b'PRESERVE')
        candidate.unlink()
        target = self.root / 'unrelated'
        target.write_bytes(b'KEEP')
        candidate.symlink_to(target)
        with self.assertRaises(FileExistsError):
            phone._carve_sqlite_databases(str(self.image_a), str(output))
        self.assertEqual(target.read_bytes(), b'KEEP')

    def test_invalid_limits_do_not_create_outputs(self):
        for value in (True, False, 0, -1, 51, 1.5, '1'):
            with self.subTest(value=value):
                self.assertEqual(self.run_carve(self.a, self.image_a, max_databases=value)['status'], 'error')
        self.assertFalse((self.store / 'carved_sqlite').exists())

    def test_empty_input_is_a_valid_no_database_observation(self):
        empty = self.image_a.parent / 'empty.bin'
        empty.write_bytes(b'')
        result = self.run_carve(self.a, empty)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(json.loads(result['preview'])['status'], 'no_databases_found')
        self.assertEqual(self.outputs('A'), [])


if __name__ == '__main__':
    unittest.main()
