import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lawliet_mobile.cli import main
from lawliet_mobile.core import UserError, add_artifact, connect, create_case, import_evidence, select_artifacts, verify
from lawliet_mobile.messages import leapp_message
from lawliet_mobile.review import review


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name) / 'cases'
        create_case(self.workspace, 'test')
        self.source = Path(self.tmp.name) / 'messages.db'
        with sqlite3.connect(self.source) as db:
            db.execute('CREATE TABLE sms(_id INTEGER, address TEXT, body TEXT, date INTEGER, type INTEGER)')
            db.executemany('INSERT INTO sms VALUES(?,?,?,?,?)', [(1, '+12025550100', 'first\nline', 1700000000000, 1), (2, '+12025550100', '=FORMULA', 1700000001000, 2)])
        with connect(self.workspace, 'test') as (root, db):
            self.eid = import_evidence(root, db, self.source, 'android')[0]

    def test_native_handoff_complete_export_bounded_preview_and_reuse(self):
        with connect(self.workspace, 'test') as (root, db):
            result = review(root, db, self.workspace, self.eid, preview_limit=1)
            folder = Path(result['folder'])
            self.assertEqual(result['status'], 'ready_for_review')
            self.assertEqual(result['message_rows'], 2)
            self.assertEqual(result['preview_rows'], 1)
            exported = [json.loads(line) for line in (folder / 'messages.jsonl').read_text().splitlines()]
            self.assertEqual(exported[0]['body'], 'first\nline')
            self.assertIn("'=FORMULA", (folder / 'messages.csv').read_text())
            summary = json.loads((folder / 'summary.json').read_text())
            self.assertTrue(summary['preview']['truncated'])
            self.assertIn('additional rows exist', (folder / 'preview.html').read_text())
            again = review(root, db, self.workspace, self.eid)
            self.assertEqual(result['analysis_run'], again['analysis_run'])
            self.assertNotEqual(result['folder'], again['folder'])
            self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0], 1)
            self.assertTrue(verify(root, db)['ok'])

    def test_exact_run_selection_excludes_repeated_engine_runs(self):
        with connect(self.workspace, 'test') as (root, db):
            for run in ('one', 'two'):
                db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES(?,?,?,?,?)', (run, self.eid, 'ileapp', '2026-10-10', 'complete'))
                row = {'Message Timestamp': '2026-10-10 10:00:00+00:00', 'Message': run, 'Service': 'iMessage', 'Message Direction': 'Incoming', 'Message Row ID': '42', 'Chat ID': '7', 'Sender': 'Alex'}
                mapped = leapp_message('SMS', row, self.eid)
                add_artifact(db, self.eid, None, *mapped[:5], f'runs/{run}/output/SMS.tsv:line=2', 'ileapp', mapped[5])
            self.assertEqual([r['body'] for r in select_artifacts(db, run='two')], ['two'])
            result = review(root, db, self.workspace, self.eid, run='two')
            self.assertEqual(result['message_rows'], 1)
            self.assertEqual(result['analysis_run'], 'two')
            self.assertEqual(result['rows_by_app'], {'imessage': 1})
            with self.assertRaises(UserError):
                review(root, db, self.workspace, self.eid, run='two', reanalyze=True)
            with self.assertRaises(UserError):
                select_artifacts(db, run='missing')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(['--workspace', str(self.workspace), '--json', 'messages', '--case', 'test', '--run', 'one'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())[0]['body'], 'one')

    def test_failed_acquisition_visible_and_tampering_blocks_review(self):
        with connect(self.workspace, 'test') as (root, db):
            folder = root / 'collections' / 'failed'
            folder.mkdir(parents=True)
            (folder / 'collection.json').write_text(json.dumps({'status': 'failed', 'errors': ['storage guard']}))
            result = review(root, db, self.workspace, self.eid)
            summary = json.loads(Path(result['summary']).read_text())
            self.assertEqual(summary['case_collection_statuses'], ['failed'])
            # Case-wide failures remain in internal review metadata; scoped HTML
            # must not disclose unrelated collection attempts or their counts.
            coverage = json.loads((Path(result['folder']) / 'coverage.json').read_text())
            self.assertEqual([a['status'] for a in coverage['collection_attempts']], ['failed'])
            self.assertEqual(coverage['collection_attempts'][0]['errors'], ['storage guard'])
            preview = Path(result['preview']).read_text()
            self.assertNotIn('incomplete acquisition attempts:', preview)
            self.assertIn('Missing, inaccessible, unsupported, empty and failed inputs never establish no evidence or no activity.', preview)
            file = db.execute('SELECT path FROM files WHERE evidence_id=?', (self.eid,)).fetchone()[0]
            (root / 'evidence' / self.eid / file).write_bytes(b'tampered')
            with self.assertRaisesRegex(UserError, 'integrity'):
                review(root, db, self.workspace, self.eid)

    def test_empty_source_is_not_ready_and_invalid_limit_rejected(self):
        empty = Path(self.tmp.name) / 'empty.txt'
        empty.write_text('no supported messages')
        with connect(self.workspace, 'test') as (root, db):
            eid = import_evidence(root, db, empty, 'android')[0]
            result = review(root, db, self.workspace, eid)
            self.assertEqual(result['status'], 'no_messages')
            self.assertEqual(result['message_rows'], 0)
            with self.assertRaises(UserError):
                review(root, db, self.workspace, self.eid, preview_limit=10001)
