"""Existing external parser runner must retain explicit failure under storage pressure."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile import tools
from lawliet_mobile.core import UserError,connect,create_case,import_evidence,verify,digest

class ParserStorageGuardTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.base=Path(self.tmp.name);self.workspace=self.base/'workspace';self.case='GUARD'
  create_case(self.workspace,self.case)
  self.source=self.base/'source';self.source.mkdir();(self.source/'original.txt').write_text('ORIGINAL_GUARD_SENTINEL')
  self.original_hash=digest(self.source/'original.txt')
  with connect(self.workspace,self.case) as (root,db):self.eid,_,_=import_evidence(root,db,self.source,'android')
 def tool(self,engine,body):
  script=self.base/(engine+'.py');script.write_text(body);tools.configure(self.workspace,engine,script)
 def assert_failed(self,engine,exception=UserError,timeout=3):
  with connect(self.workspace,self.case) as (root,db):
   with self.assertRaises(exception):tools.external_analyze(root,db,self.workspace,self.eid,engine,timeout)
   run=dict(db.execute('SELECT * FROM runs ORDER BY rowid DESC LIMIT 1').fetchone())
   self.assertEqual(run['status'],'failed');self.assertEqual(run['records'],0)
   self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
   detail=json.loads(run['detail']);self.assertIn('error',detail);self.assertIn('returncode',detail)
   self.assertEqual(detail['resource_policy']['timeout_seconds'],timeout)
   self.assertEqual(detail['resource_policy']['output_ceiling_bytes'],tools._EXTERNAL_OUTPUT_MAX_BYTES)
   folder=root/'runs'/run['id'];self.assertTrue(folder.exists());self.assertTrue(list(folder.glob('*.stderr')))
   self.assertTrue(verify(root,db)['ok']);self.assertEqual(digest(self.source/'original.txt'),self.original_hash)
   return run,folder
 def test_leapp_output_budget_failure_retains_partial_output(self):
  self.tool('aleapp',"import pathlib,sys\np=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);p.mkdir(exist_ok=True);(p/'partial.tsv').write_text('x'*4096)\nprint('partial parser output',flush=True)\n")
  with patch.object(tools,'_EXTERNAL_OUTPUT_MAX_BYTES',128):
   _,folder=self.assert_failed('aleapp');self.assertTrue((folder/'output/partial.tsv').is_file())
 def test_exiftool_stdout_budget_failure(self):
  self.tool('exiftool',"print('x'*4096,flush=True)\n")
  with patch.object(tools,'_EXTERNAL_OUTPUT_MAX_BYTES',128):self.assert_failed('exiftool')
 def test_low_disk_fails_before_success_and_preserves_logs(self):
  self.tool('aleapp',"print('could otherwise succeed',flush=True)\n")
  with patch.object(tools.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(10,9,1)):self.assert_failed('aleapp')
 def test_timeout_retains_failure_then_safe_retry_has_one_result(self):
  self.tool('aleapp',"import time\nprint('before timeout',flush=True)\ntime.sleep(3)\n")
  self.assert_failed('aleapp',subprocess.TimeoutExpired,timeout=.05)
  self.tool('aleapp',"import pathlib,sys\np=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);p.mkdir(exist_ok=True);(p/'fixture.tsv').write_text('Field\\nRECOVERED_ON_RETRY\\n')\n")
  with connect(self.workspace,self.case) as (root,db):
   result=tools.external_analyze(root,db,self.workspace,self.eid,'aleapp',3)
   self.assertEqual(result['status'],'complete');self.assertEqual(result['new_records'],1)
   self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],1)
   self.assertEqual([r[0] for r in db.execute('SELECT status FROM runs ORDER BY rowid')],['failed','complete'])
   self.assertTrue(verify(root,db)['ok'])
if __name__=='__main__':unittest.main(verbosity=2)
