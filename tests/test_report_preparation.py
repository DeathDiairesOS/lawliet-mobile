import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, connect, create_case, select_artifacts
from lawliet_mobile.findings import add_finding
from lawliet_mobile.report_preparation import from_findings


class ReportPreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'one')
        create_case(self.workspace, 'two')
        self.source = self.base / 'rows.jsonl'
        self.source.write_text(''.join(json.dumps({'category': 'messages', 'body': 'fixture '+str(i), 'data': {}})+'\n' for i in range(3)))
        handle(self.workspace, {'action': 'import', 'case': 'one', 'path': str(self.source), 'format': 'jsonl'})
        with connect(self.workspace, 'one') as (_, db):
            self.saved = [add_finding(db, r['id'], 'Operator interpretation '+str(i), 'fixture operator')
                          for i, r in enumerate(select_artifacts(db))]
        self.ids = [r['id'] for r in self.saved]

    def test_explicit_selection_preserves_claims_and_source_scope(self):
        before = self.source.read_bytes()
        result = handle(self.workspace, {'action': 'investigation-from-findings', 'case': 'one',
                       'objective': 'Review two selected fixture records', 'finding_ids': self.ids[:2]})
        self.assertEqual(len(result['selected']), 2)
        self.assertEqual(result['review_status'], 'unreviewed')
        self.assertFalse(result['scope']['report_release'])
        with connect(self.workspace, 'one') as (_, db):
            events = list(db.execute('SELECT kind,request FROM investigation_events'))
            self.assertEqual(len(events), 2)
            self.assertTrue(all(e['kind'] == 'analyst.interpretation' for e in events))
            self.assertTrue(all('Unreviewed operator interpretation' in e['request'] for e in events))
            self.assertEqual(db.execute('SELECT count(*) FROM findings').fetchone()[0], 3)
        self.assertEqual(self.source.read_bytes(), before)

    def test_foreign_duplicate_oversized_and_changed_sources_refused(self):
        for case, ids in [('two', self.ids[:1]), ('one', [self.ids[0], self.ids[0]]), ('one', [])]:
            with self.subTest(case=case, ids=ids), self.assertRaises(UserError):
                handle(self.workspace, {'action': 'investigation-from-findings', 'case': case,
                                       'objective': 'Fixture', 'finding_ids': ids})
        with connect(self.workspace, 'one') as (root, db):
            db.execute('UPDATE artifacts SET body=? WHERE id=?', ('changed interpretation input', self.saved[0]['artifact_id']))
            with self.assertRaisesRegex(UserError, 'snapshot differs'):
                from_findings(root, db, 'Fixture', self.ids[:1])

    def test_failed_binding_rolls_back_every_new_entry(self):
        from lawliet_mobile import investigation
        original = investigation.note
        calls = 0
        def failing(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise UserError('Fixture second-entry failure')
            return original(*args, **kwargs)
        with connect(self.workspace, 'one') as (root, db):
            before = db.execute('SELECT count(*) FROM audit').fetchone()[0]
            with patch('lawliet_mobile.investigation.note', side_effect=failing), self.assertRaises(UserError):
                from_findings(root, db, 'Fixture', self.ids[:2])
            self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0], before)
            self.assertFalse(db.execute("SELECT 1 FROM sqlite_master WHERE name='investigations'").fetchone())

    def test_real_stdio_binding_draft_and_unapproved_release_refusal(self):
        def call(action, **values):
            proc = subprocess.run([sys.executable, '-m', 'lawliet_mobile.app_backend'],
                input=json.dumps({'workspace': str(self.workspace), 'case': 'one', 'action': action, **values}),
                text=True, capture_output=True, check=False)
            data = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0 if data['ok'] else 1)
            return data
        bound = call('investigation-from-findings', objective='Fixture selected finding review', finding_ids=self.ids[:1])
        self.assertTrue(bound['ok'])
        draft = call('customer-report-draft', investigation_id=bound['result']['investigation_id'])
        self.assertTrue(draft['ok'])
        released = call('customer-report-release', draft_id=draft['result']['draft_id'], path=str(self.base/'release'))
        self.assertFalse(released['ok'])
        self.assertFalse((self.base/'release').exists())
