import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.cli import main, parser
from lawliet_mobile.core import connect, digest
from lawliet_mobile.demo import create_demo


class CaseAssessmentEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / 'cases'
        create_demo(self.workspace, 'qa')
        with connect(self.workspace, 'qa') as (root, db):
            self.root = root
            self.evidence = db.execute("SELECT id FROM evidence WHERE platform='android'").fetchone()[0]
            self.foreign_run = db.execute("SELECT r.id FROM runs r JOIN evidence e ON e.id=r.evidence_id WHERE e.platform='ios'").fetchone()[0]

    def cli(self, *args):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(['case-assess', '--case', 'qa', '--workspace', str(self.workspace), '--json', *args])
        return code, json.loads(stream.getvalue())

    def test_cli_backend_parity_and_no_case_writes(self):
        paths = [self.root / 'case.sqlite', *(self.root / 'evidence').rglob('*')]
        before = {str(p): digest(p) for p in paths if p.is_file()}
        with patch('lawliet_mobile.tools.execute', side_effect=AssertionError('No tools during assessment')):
            backend = handle(self.workspace, {'action': 'scenario-assessment', 'case': 'qa',
                                              'evidence': self.evidence, 'scenario': 'messages'})
            code, cli = self.cli('--evidence', self.evidence, '--scenario', 'messages')
        self.assertEqual(code, 0)
        self.assertEqual(backend, cli)
        self.assertEqual(cli['status'], 'records_available_for_review')
        self.assertEqual(next(r['record_count'] for r in cli['requirements'] if r['category'] == 'messages'), 3)
        self.assertNotIn('Package awaiting verification', json.dumps(cli))
        self.assertEqual(before, {str(p): digest(p) for p in paths if p.is_file()})

    def test_absent_app_is_a_successful_assessment_not_a_clean_phone(self):
        code, result = self.cli('--evidence', self.evidence, '--scenario', 'whatsapp')
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'no_relevant_indexed_records')
        self.assertTrue(result['limitations'])
        self.assertTrue(result['next_actions'])
        self.assertNotIn('ready', result)

    def test_foreign_run_refused_through_public_cli(self):
        code, result = self.cli('--evidence', self.evidence, '--run', self.foreign_run)
        self.assertEqual(code, 1)
        self.assertIn('error', result)

    def test_help_and_required_scope(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), self.assertRaises(SystemExit) as stopped:
            main(['case-assess', '--help'])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn('--evidence', stream.getvalue())
        args = parser().parse_args(['case-assess', '--case', 'qa', '--evidence', self.evidence])
        self.assertEqual(args.scenario, 'messages')


if __name__ == '__main__':
    unittest.main()
