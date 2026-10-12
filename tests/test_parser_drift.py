import importlib.util,json,os,signal,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,import_evidence,verify,UserError,digest
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from lawliet_mobile import tools
GOOD="import pathlib,sys\np=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);p.mkdir(exist_ok=True);(p/'fixture.tsv').write_text('Field\\nSAME_VALUE\\n')\n"
@unittest.skipUnless(os.name=='posix','Requires POSIX runner leases and signals')
class RunnerTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.base=Path(self.t.name);self.ws=self.base/'cases';create_case(self.ws,'A');self.source=self.base/'input';self.source.mkdir();(self.source/'original').write_text('unchanged')
  with connect(self.ws,'A') as (root,db):self.eid,_,_=import_evidence(root,db,self.source,'android')
  self.script=self.base/'worker.py';self.script.write_text(GOOD);tools.configure(self.ws,'aleapp',self.script)
 def runjob(self):
  with connect(self.ws,'A') as (root,db):return tools.external_analyze(root,db,self.ws,self.eid,'aleapp',3)
 def test_same_component_and_headers_no_drift(self):
  first=self.runjob();second=self.runjob();self.assertEqual(first['detail']['drift']['state'],'no_prior_completed_run');self.assertEqual(second['detail']['drift']['warnings'],[])
  self.assertEqual(second['detail']['drift']['baseline_run_id'],first['run_id']);self.assertEqual(second['detail']['reports'][0]['columns'],['Field'])
 def test_changed_executable_warning_survives_history(self):
  first=self.runjob();self.script.write_text(GOOD+'# deliberate component revision\n');second=self.runjob()
  self.assertEqual(second['detail']['drift']['warnings'],['parser_executable_changed'])
  with connect(self.ws,'A') as (root,db):self.assertEqual(json.loads(db.execute('SELECT detail FROM runs WHERE id=?',(second['run_id'],)).fetchone()[0])['drift'],second['detail']['drift']);self.assertTrue(verify(root,db)['ok'])
 def test_changed_schema_without_executable_change(self):
  selector=self.base/'header';selector.write_text('Field')
  self.script.write_text(GOOD.replace("'Field\\nSAME_VALUE\\n'",f"pathlib.Path({str(selector)!r}).read_text()+'\\nSAME_VALUE\\n'"))
  self.runjob();selector.write_text('OtherField');result=self.runjob();self.assertEqual(result['detail']['drift']['warnings'],['observed_report_schema_changed'])
 def test_legacy_missing_baseline_is_not_no_drift(self):
  result=tools._parser_drift({'id':'old','detail':'{}'},'x',[])
  self.assertEqual(result['state'],'warning');self.assertEqual(set(result['warnings']),{'prior_executable_fingerprint_not_recorded','prior_report_schema_not_recorded'})
 def test_dated_report_container_not_schema_drift(self):
  prior={'id':'old','detail':json.dumps({'executable_sha256':'same','reports':[{'path':'ALEAPP_Output_2026-10-12_Monday_000001/_TSV Exports/A.tsv','columns':['Field']}]})}
  result=tools._parser_drift(prior,'same',[{'path':'ALEAPP_Output_2026-10-12_Monday_000002/_TSV Exports/A.tsv','columns':['Field']}])
  self.assertEqual(result['warnings'],[]);self.assertEqual(result['schema_comparison'],'compared')
 def test_failed_partial_report_inventory_not_schema_drift(self):
  prior={'id':'old','detail':json.dumps({'executable_sha256':'same','reports':[{'path':'A.tsv','columns':['F']},{'path':'B.tsv','columns':['G']}]})}
  result=tools._parser_drift(prior,'same',[{'path':'A.tsv','columns':['F']}],complete=False)
  self.assertEqual(result['warnings'],[]);self.assertEqual(result['schema_comparison'],'not_compared_incomplete_run')
 def test_ambiguous_or_absolute_report_schema_is_unknown(self):
  prior={'id':'old','detail':json.dumps({'executable_sha256':'same','reports':[{'path':'A.tsv','columns':['F']}]})}
  for paths in [['/tmp/A.tsv'],['ALEAPP_Output_2026-10-12_Monday_000001/A.tsv','ALEAPP_Output_2026-10-12_Monday_000002/A.tsv']]:
   result=tools._parser_drift(prior,'same',[{'path':path,'columns':['F']} for path in paths]);self.assertEqual(result['warnings'],['current_report_schema_ambiguous'])
 def test_executable_hash_failure_before_run_record(self):
  with patch.object(tools,'digest',side_effect=OSError('synthetic hashing failure')):
   with self.assertRaises(OSError):self.runjob()
  with connect(self.ws,'A') as (_,db):self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],0)
 def test_real_worker_hard_kill_retains_failure_then_one_retry(self):
  self.script.write_text("import os,signal\nprint('owned parser before hard kill',flush=True)\nos.kill(os.getpid(),signal.SIGKILL)\n")
  with self.assertRaises(UserError):self.runjob()
  self.script.write_text(GOOD);self.runjob()
  with connect(self.ws,'A') as (root,db):
   runs=list(db.execute('SELECT status,detail FROM runs ORDER BY rowid'));self.assertEqual([r[0] for r in runs],['failed','complete']);self.assertEqual(json.loads(runs[0][1])['returncode'],128+signal.SIGKILL);self.assertIn('guardian exit status',json.loads(runs[0][1])['process_status_kind']);self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],1);self.assertTrue(verify(root,db)['ok'])
 def test_real_owned_backend_cancel_retains_interrupted_then_retry(self):
  ready=self.base/'ready';self.script.write_text(f"import pathlib,time\npathlib.Path({str(ready)!r}).write_text('ready')\nprint('partial output',flush=True)\ntime.sleep(30)\n")
  cmd=[sys.executable,str(Path(__file__).resolve()),'--job',str(self.ws),self.eid]
  with (self.base/'backend.log').open('w') as log:
   child=subprocess.Popen(cmd,stdout=log,stderr=log,env={**os.environ,'PYTHONPATH':os.pathsep.join(filter(None,[str(Path(__file__).resolve().parents[1]),os.environ.get('PYTHONPATH','')]))})
   try:
    end=time.monotonic()+10
    while not ready.exists() and child.poll() is None and time.monotonic()<end:time.sleep(.02)
    self.assertTrue(ready.exists());child.send_signal(signal.SIGINT);child.wait(timeout=10)
   finally:
    if child.poll() is None:child.kill();child.wait()
  with connect(self.ws,'A') as (root,db):self.assertEqual(db.execute('SELECT status FROM runs').fetchone()[0],'interrupted');self.assertTrue(verify(root,db)['ok'])
  self.script.write_text(GOOD);self.runjob()
  with connect(self.ws,'A') as (_,db):self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],1)
 def test_malformed_tsv_rolls_back_then_retry(self):
  self.script.write_text(GOOD.replace('Field\\nSAME_VALUE\\n','Field\\nGOOD\\nBAD\\tEXTRA\\n'))
  with self.assertRaises(UserError):self.runjob()
  self.script.write_text(GOOD);self.runjob()
  with connect(self.ws,'A') as (root,db):self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],1);self.assertTrue(verify(root,db)['ok'])
if __name__=='__main__':
 if '--job' in sys.argv:
  with connect(Path(sys.argv[-2]),'A') as (root,db):tools.external_analyze(root,db,Path(sys.argv[-2]),sys.argv[-1],'aleapp',30)
 else:unittest.main(verbosity=2)
