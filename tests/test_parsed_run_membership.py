import json
import tempfile
import unittest
from pathlib import Path

from lawliet_mobile.core import UserError, connect, create_case, select_artifacts, verify
from lawliet_mobile.parsed_import import import_parsed


class ParsedRunMembershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'reports')

    def test_single_tsv_and_jsonl_link_exact_report_occurrences(self):
        tsv = self.base / 'Unknown.tsv'
        tsv.write_text('Key\tValue\nOne\tUnicode 😀\n')
        jsonl = self.base / 'observations.jsonl'
        jsonl.write_text(json.dumps({'category': 'messages', 'body': 'Original body', 'data': {}}) + '\n')
        with connect(self.workspace, 'reports') as (root, db):
            first = import_parsed(root, db, tsv, 'tsv')
            second = import_parsed(root, db, jsonl, 'jsonl')
            for result in (first, second):
                rows = select_artifacts(db, run=result['run_id'])
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['evidence_id'], result['evidence_id'])
                self.assertEqual(rows[0]['source_ref'], 'report:record=2' if result is first else 'report:record=1')
                self.assertEqual(db.execute('SELECT COUNT(*) FROM artifact_runs WHERE run_id=?',
                                            (result['run_id'],)).fetchone()[0], 1)
            self.assertEqual(select_artifacts(db, run=second['run_id'])[0]['body'], 'Original body')
            repeat = import_parsed(root, db, tsv, 'tsv')
            self.assertEqual(repeat['status'], 'already_imported')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0], 2)
            self.assertTrue(verify(root, db)['ok'])

    def test_repeated_folder_imports_keep_distinct_runs_and_source_instances(self):
        folder = self.base / 'folder'
        folder.mkdir()
        for name in ('One.tsv', 'Two.tsv'):
            (folder / name).write_text('Key\tValue\nOne\tShared text\n')
        with connect(self.workspace, 'reports') as (root, db):
            first = import_parsed(root, db, folder, 'folder')
            second = import_parsed(root, db, folder, 'folder')
            for result in (first, second):
                rows = select_artifacts(db, run=result['run_id'])
                self.assertEqual(len(rows), 2)
                self.assertEqual({r['evidence_id'] for r in rows}, {result['evidence_id']})
                self.assertEqual({r['source_ref'] for r in rows}, {'One.tsv:record=2', 'Two.tsv:record=2'})
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 4)
            self.assertTrue(verify(root, db)['ok'])

    def test_header_only_tsv_has_explicit_empty_run_membership(self):
        source = self.base / 'empty.tsv'
        source.write_text('Key\tValue\n')
        with connect(self.workspace, 'reports') as (root, db):
            result = import_parsed(root, db, source, 'tsv')
            self.assertEqual((result['status'], result['records']), ('complete', 0))
            self.assertEqual(select_artifacts(db, run=result['run_id']), [])
            self.assertEqual(db.execute('SELECT schema_version FROM run_artifact_indexes WHERE run_id=?',
                                        (result['run_id'],)).fetchone()[0], 1)

    def test_partial_parse_failures_roll_back_both_rows_and_membership(self):
        single = self.base / 'bad.tsv'
        single.write_text('Key\tValue\nOne\tGood first\nTwo\tBad\tExtra\n')
        folder = self.base / 'bad-folder'
        folder.mkdir()
        (folder / 'a.tsv').write_text('Key\tValue\nOne\tGood file\n')
        (folder / 'z.tsv').write_text('Key\tValue\nTwo\tBad\tExtra\n')
        with connect(self.workspace, 'reports') as (root, db):
            for source, fmt in ((single, 'tsv'), (folder, 'folder')):
                with self.assertRaises(UserError):
                    import_parsed(root, db, source, fmt)
            runs = db.execute('SELECT id,status FROM runs').fetchall()
            self.assertEqual(len(runs), 2)
            for run in runs:
                self.assertEqual(run['status'], 'failed')
                self.assertEqual(select_artifacts(db, run=run['id']), [])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifact_runs').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM run_artifact_indexes').fetchone()[0], 2)
            self.assertTrue(verify(root, db)['ok'])
