import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.adapters import analyze, analyze_file, catalog
from lawliet_mobile.cli import main
from lawliet_mobile.core import UserError, connect, create_case, import_evidence, verify


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.ws=self.base/'cases';create_case(self.ws,'qa')
        self.source=self.base/'contacts.vcf'
        self.source.write_text('BEGIN:VCARD\nVERSION:3.0\nFN:Synthetic Analyst\nTEL:+12025550123\nEND:VCARD\n')

    def test_native_executes_real_parser_and_preserves_evidence(self):
        with connect(self.ws,'qa') as (root,db):
            eid,_,_=import_evidence(root,db,self.source,'android')
            first=analyze(root,db,self.ws,eid,'native')
            second=analyze(root,db,self.ws,eid,'native')
            self.assertEqual(first['status'],'complete')
            self.assertEqual(first['new_records'],1)
            self.assertEqual(second['new_records'],0)
            row=db.execute('SELECT * FROM artifacts').fetchone()
            self.assertEqual(row['category'],'contacts')
            self.assertIsNotNone(row['file_id'])
            self.assertIn('Synthetic Analyst',row['body'])
            self.assertTrue(verify(root,db)['ok'])

    def test_rejected_requests_do_not_start_tools_or_create_runs(self):
        with connect(self.ws,'qa') as (root,db):
            eid,_,_=import_evidence(root,db,self.source,'android')
            other,_,_=import_evidence(root,db,self.source,'ios')
            file_id=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
            with patch('lawliet_mobile.tools.external_analyze',side_effect=AssertionError('Must not run')):
                for name,target in [('mvt',eid),('ileapp',eid),('aleapp','missing')]:
                    with self.assertRaises(UserError):analyze(root,db,self.ws,target,name)
                for timeout in [0,-1,float('inf'),float('nan'),True,'900']:
                    with self.assertRaises(UserError):analyze(root,db,self.ws,eid,'aleapp',timeout)
                with self.assertRaises(UserError):analyze(root,db,self.ws,eid,'aleapp',file_id=file_id)
                with self.assertRaises(UserError):analyze(root,db,self.ws,other,'sqlite-dissect',file_id=file_id)
                with self.assertRaises(UserError):analyze_file(root,db,self.ws,-1,'sqlite-dissect')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],0)

    def test_catalog_is_read_only_and_does_not_claim_external_versions(self):
        with patch('subprocess.Popen',side_effect=AssertionError('Catalog must not execute tools')):
            result=catalog(self.ws)
            output=io.StringIO()
            with redirect_stdout(output):
                code=main(['--workspace',str(self.ws),'tools','adapters'])
        self.assertEqual(code,0)
        self.assertEqual(json.loads(output.getvalue())['contract_version'],1)
        by_name={r['name']:r for r in result['adapters']}
        self.assertEqual(set(by_name),{'native','aleapp','ileapp','exiftool','sqlite-dissect','sqlite4n6'})
        self.assertEqual(by_name['native']['version_status'],'built_in')
        self.assertIsNone(by_name['aleapp']['tool_version'])
        self.assertEqual(by_name['aleapp']['version_status'],'not_probed')
        self.assertFalse((self.ws/'tools.json').exists())

    def test_missing_dependency_is_actionable_and_retains_evidence(self):
        with connect(self.ws,'qa') as (root,db):
            eid,_,_=import_evidence(root,db,self.source,'android')
            with patch('lawliet_mobile.tools.shutil.which',return_value=None):
                with self.assertRaisesRegex(UserError,'not installed/configured'):
                    analyze(root,db,self.ws,eid,'aleapp')
            self.assertTrue(verify(root,db)['ok'])
