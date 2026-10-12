"""Use the native source-scope model to query a real two-device synthetic case."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.demo import create_demo
from lawliet_mobile.app_backend import handle

@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc'),'Requires native Swift compiler')
class SourceScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tmp.cleanup)
        cls.workspace=Path(cls.tmp.name)/'cases';create_demo(cls.workspace,'demo')
        root=Path(__file__).resolve().parents[1];cls.binary=Path(cls.tmp.name)/'source-scope'
        built=subprocess.run(['swiftc',str(root/'desktop/SourceScope.swift'),str(root/'tests/SourceScopeCheck.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=60)
        if built.returncode:raise AssertionError(built.stderr)
    def fields(self,mode,evidence='',parser=''):
        result=subprocess.run([str(self.binary),mode,evidence,parser],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr);return json.loads(result.stdout)
    def call(self,action,**kwargs):return handle(self.workspace,{'action':action,'case':'demo',**kwargs})
    def test_case_scope_has_both_phones_and_no_duplicate_source_rows(self):
        fields=self.fields('case');stats=self.call('source-stats',**fields)
        self.assertEqual(stats['total'],15);self.assertEqual(stats['categories']['messages'],7)
        rows=self.call('records',**fields)['records'];self.assertEqual(len({r['id'] for r in rows}),15)
    def test_case_keyword_query_finds_both_device_sources(self):
        rows=self.call('records',query='parcel-review.example',**self.fields('case'))['records']
        self.assertEqual(len(rows),3);self.assertEqual(len({r['evidence_id'] for r in rows}),2)
    def test_individual_scope_stays_with_selected_phone(self):
        source=next(s for s in self.call('overview')['sources'] if 'Android' in s['label'])
        fields=self.fields('individual',source['evidence'],source['parser'])
        rows=self.call('records',**fields)['records'];self.assertEqual(len(rows),5)
        self.assertEqual({r['evidence_id'] for r in rows},{source['evidence']})
    def test_zero_row_run_keeps_its_run_filter(self):
        fields=self.fields('run','evidence-test');self.assertEqual(fields,{'evidence':'evidence-test','parser':'','run':'test-run'})
