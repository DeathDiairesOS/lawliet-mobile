import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.app_backend import handle
from lawliet_mobile.tools import configure, leapp_diagnostics
from tests.test_leapp_review import android_fixture
from tests.test_leapp_integration import RealLeappTests
from lawliet_mobile.core import create_case


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name); self.workspace=self.base/'cases'
        create_case(self.workspace,'pipeline')

    def call(self, action, **kw):
        return handle(self.workspace,dict(action=action,case='pipeline',**kw))

    def test_unknown_and_missing_engine_preserve_selectable_evidence(self):
        source=self.base/'unknown.txt'; source.write_text('Synthetic unrecognized input')
        result=self.call('import-evidence',path=str(source),engine='auto')
        self.assertEqual(result['status'],'needs_platform')
        self.assertIn(result['source_id'],[s['id'] for s in self.call('overview')['sources']])
        with patch('lawliet_mobile.pipeline.command',side_effect=RuntimeError('Missing engine')):
            result=self.call('import-evidence',path=str(source),platform='android',engine='auto')
        self.assertEqual(result['status'],'processing_failed')
        self.assertIn('Missing engine',result['message'])
        self.assertIn(result['source_id'],[s['id'] for s in self.call('overview')['sources']])
        self.assertTrue(self.call('verify')['ok'])

    def test_diagnostics_do_not_equate_missing_input_with_parser_failure(self):
        log=self.base/'stdout.log'
        log.write_text('No file found\nNo files found\n')
        result=leapp_diagnostics(log)
        self.assertEqual(result['missing_input_notices'],2)
        self.assertFalse(result['failed_artifacts']); self.assertFalse(result['error_lines'])
        log.write_text('Example artifact failed after 1s\nException Traceback: example\n')
        result=leapp_diagnostics(log)
        self.assertEqual(len(result['failed_artifacts']),1)
        self.assertEqual(len(result['error_lines']),1)

    @unittest.skipUnless(os.environ.get('LAWLIET_ALEAPP'),'Set LAWLIET_ALEAPP')
    def test_android_import_runs_real_engine_and_indexes_every_report(self):
        source=self.base/'android'; android_fixture(source)
        configure(self.workspace,'aleapp',os.environ['LAWLIET_ALEAPP'])
        result=self.call('import-evidence',path=str(source),engine='auto')
        self.assertEqual(result['engine'],'aleapp',result)
        self.assertIn(result['status'],['complete','needs_review'],result)
        self.check_reports(result,{'contacts':1,'calls':1,'browser':1})

    @unittest.skipUnless(os.environ.get('LAWLIET_ILEAPP'),'Set LAWLIET_ILEAPP')
    def test_ios_import_runs_real_engine_and_indexes_every_report(self):
        source=self.base/'ios'
        RealLeappTests().safari(source/'private/var/mobile/Library/Safari/History.db')
        configure(self.workspace,'ileapp',os.environ['LAWLIET_ILEAPP'])
        result=self.call('import-evidence',path=str(source),engine='auto')
        self.assertEqual(result['engine'],'ileapp',result)
        self.assertIn(result['status'],['complete','needs_review'],result)
        self.check_reports(result,{'browser':1})

    def check_reports(self,result,categories):
        analysis=result['analysis']
        self.assertEqual(sum(r['rows'] for r in analysis['detail']['reports']),analysis['new_records'])
        sources=self.call('overview')['sources']
        source=next(s for s in sources if s['id']==result['source_id'])
        self.assertEqual(source['records'],analysis['new_records'])
        scope=dict(evidence=source['evidence'],parser=source['parser'],run=source['run'])
        self.assertEqual(self.call('source-stats',**scope)['categories'],categories)
        self.assertTrue(self.call('verify')['ok'])
