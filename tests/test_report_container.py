"""Bounded report prototype controls; daemon mocked unless separate actual harness."""
import copy,hashlib,io,json,os,sqlite3,tempfile,unittest,shutil,sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from lawliet_mobile import core,parsed_import as parsed,report_container as rc,report_container_worker as worker,report_container_codec as codec

class Reports(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.base=Path(self.t.name).resolve();self.ws=self.base/'cases';core.create_case(self.ws,'A');core.create_case(self.ws,'B')
  self.source=self.base/'report.jsonl';self.source.write_text(json.dumps({'category':'messages','body':'café 🐈','data':{'message':{'app':'sms','conversation':'thread1'}}})+'\n')
  self.cfg={'image':rc.IMAGE,'socket':'/synthetic/socket','docker':'/synthetic/docker','bootstrap_sha256':core.digest(rc.WORKER)}
 def decode(self,root,rid,owner,cfg,manifest,request,raw,profile,folder):
  if sys.platform!='linux':
   # Host publication/recovery semantics stay exercised on Windows. This is
   # deliberately synthetic transport, not a claim of Linux worker execution.
   from tests.container_transport_fixtures import report_transport
   raw_output=report_transport(root/'evidence'/request['source']['evidence_id']/manifest[0]['path'],request,raw,profile)
  else:raw_output=Reports.worker_decode(self,root,rid,owner,cfg,manifest,request,raw,profile,folder)
  (folder/'report.stdout.jsonl').write_bytes(raw_output);(folder/'report.stderr').write_bytes(b'')
  receipt={'protocol':rc.PROTOCOL,'container_id':'d'*64,'cfg':cfg,'labels':rc.labels(root,rid,owner),'state':'removed_after_verified_stop','exit_code':0,'OOMKilled':False,'execution_profile':profile}
  return codec.validate(raw_output,rc.bindings_for(raw,request,profile)),receipt
 def worker_decode(self,root,rid,owner,cfg,manifest,request,raw,profile,folder):
  request_path=folder/'fixture-request.json';request_path.write_bytes(raw);scratch=folder/'fixture-scratch';scratch.mkdir()
  code=folder/'fixture-code';(code/'lawliet_mobile').mkdir(parents=True)
  for path in Path(rc.__file__).parent.glob('*.py'):shutil.copyfile(path,code/'lawliet_mobile'/path.name)
  old_temp=tempfile.tempdir;oldpath=list(__import__('sys').path)
  try:
   with patch.object(worker,'mount_checks'),patch.dict(os.environ,{}):
    out=io.BytesIO();worker.execute(out,request_path=request_path,code_root=code,source_path=root/'evidence'/request['source']['evidence_id']/manifest[0]['path'],scratch=scratch)
  finally:tempfile.tempdir=old_temp;__import__('sys').path[:]=oldpath
  return out.getvalue()
 def contained(self,root,db,source=None,format_name='jsonl',run=None,origin_file_id=None):
  with patch.object(rc,'configured',return_value=self.cfg),patch.object(rc,'run',side_effect=run or self.decode):return parsed.import_parsed(root,db,source or self.source,format_name,contained=True,origin_file_id=origin_file_id)
 def test_same_ids_host_contained_exact_artifact_parity(self):
  fixed=SimpleNamespace(hex='a'*32)
  with patch('uuid.uuid4',return_value=fixed):
   with core.connect(self.ws,'A') as (root,db):parsed.import_parsed(root,db,self.source,'jsonl');host=[tuple(row) for row in db.execute('SELECT * FROM artifacts')]
   with core.connect(self.ws,'B') as (root,db):result=self.contained(root,db);contained=[tuple(row) for row in db.execute('SELECT * FROM artifacts')];self.assertEqual(host,contained);self.assertEqual(result['records'],1)
 def test_tsv_preserves_filename_columns_raw_values_and_header_only_zero(self):
  source=self.base/'Unknown.tsv';source.write_text('B\tA\nhello\t世界\n')
  with core.connect(self.ws,'A') as (root,db):
   result=self.contained(root,db,source,'tsv');artifact=db.execute('SELECT * FROM artifacts').fetchone();data=json.loads(artifact['data']);self.assertEqual(data['_leapp_columns'],['B','A']);self.assertEqual(data['_import_report']['filename'],'Unknown.tsv');self.assertEqual(result['records'],1)
   source.write_text('B\tA\n');empty=self.contained(root,db,source,'tsv');self.assertEqual(empty['records'],0);self.assertEqual(db.execute('SELECT status FROM runs WHERE id=?',(empty['run_id'],)).fetchone()[0],'complete')
 def test_verified_contained_reuse_no_execution_and_host_history_not_rebranded(self):
  with core.connect(self.ws,'A') as (root,db):
   host=parsed.import_parsed(root,db,self.source,'jsonl');selected=db.execute('SELECT id FROM files WHERE evidence_id=?',(host['evidence_id'],)).fetchone()[0];contained=self.contained(root,db,origin_file_id=selected);self.assertNotEqual(host['evidence_id'],contained['evidence_id'])
   with patch.object(rc,'configured',return_value=self.cfg),patch.object(rc,'run',side_effect=AssertionError('reuse must not execute')):
    repeat=parsed.import_parsed(root,db,self.source,'jsonl',contained=True,origin_file_id=selected)
   self.assertTrue(repeat['reused']);self.assertEqual(repeat['run_id'],contained['run_id']);self.assertEqual(repeat['records'],0)
 def test_reuse_mutable_count_corruption_refuses(self):
  with core.connect(self.ws,'A') as (root,db):
   eid,_,_=core.import_evidence(root,db,self.source,expand_archives=False);selected=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
   result=self.contained(root,db,origin_file_id=selected);db.execute('UPDATE runs SET records=99 WHERE id=?',(result['run_id'],));db.commit()
   with self.assertRaisesRegex(core.UserError,'count/source'):self.contained(root,db,origin_file_id=selected)
 def test_reuse_retained_output_tamper_refuses(self):
  with core.connect(self.ws,'A') as (root,db):
   eid,_,_=core.import_evidence(root,db,self.source,expand_archives=False);selected=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
   result=self.contained(root,db,origin_file_id=selected);output=root/'runs'/result['run_id']/'report.stdout.jsonl';output.write_bytes(output.read_bytes().replace(b'caf',b'bad',1))
   with self.assertRaisesRegex(core.UserError,'output integrity'):self.contained(root,db,origin_file_id=selected)
 def test_reuse_artifact_tamper_refuses(self):
  with core.connect(self.ws,'A') as (root,db):
   eid,_,_=core.import_evidence(root,db,self.source,expand_archives=False);selected=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
   self.contained(root,db,origin_file_id=selected);db.execute("UPDATE artifacts SET body='modified'");db.commit()
   with self.assertRaisesRegex(core.UserError,'artifact integrity'):self.contained(root,db,origin_file_id=selected)
 def test_reuse_audit_chain_tamper_refuses(self):
  with core.connect(self.ws,'A') as (root,db):
   eid,_,_=core.import_evidence(root,db,self.source,expand_archives=False);selected=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
   self.contained(root,db,origin_file_id=selected);db.execute("UPDATE audit SET hash=? WHERE id=(SELECT max(id) FROM audit)",('0'*64,));db.commit()
   with self.assertRaisesRegex(core.UserError,'[Ii]ntegrity'):self.contained(root,db,origin_file_id=selected)
 def test_boolean_folder_format_and_missing_configuration_refuse_before_intake(self):
  folder=self.base/'reports';folder.mkdir()
  with core.connect(self.ws,'A') as (root,db):
   for value in ('yes',1,None):
    with self.assertRaises(core.UserError):parsed.import_parsed(root,db,self.source,'jsonl',contained=value)
   with self.assertRaisesRegex(core.UserError,'folders'):parsed.import_parsed(root,db,folder,'folder',contained=True)
   with patch.object(rc,'configured',return_value=None),self.assertRaisesRegex(core.UserError,'configuration'):parsed.import_parsed(root,db,self.source,'jsonl',contained=True)
   self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0],0)
 def test_input_cap_before_hash_and_no_host_fallback(self):
  source=self.base/'huge.tsv'
  with source.open('wb') as stream:stream.truncate(rc.MAX_INPUT+1)
  with core.connect(self.ws,'A') as (root,db),patch.object(parsed,'_import_parsed_owned',side_effect=AssertionError('no fallback')):
   with self.assertRaisesRegex(core.UserError,'32MiB'):parsed.import_parsed(root,db,source,'tsv',contained=True)
   self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0],0)
 def test_expansion_refusal_retains_report_and_no_artifact_prefix(self):
  source=self.base/'Unknown.tsv';source.write_bytes(b'A\tB\tC\n'+b'\t'.join(bytes([65+i])*(2*1024**2) for i in range(3))+b'\n')
  def limited(*args):
   try:return self.decode(*args)
   except Exception as exc:
    root,rid,owner,cfg,manifest,request,raw,profile,folder=args
    exc.tool_result={'container':{'protocol':rc.PROTOCOL,'container_id':'d'*64,'cfg':cfg,'labels':rc.labels(root,rid,owner),'state':'removed_after_verified_stop','exit_code':125,'OOMKilled':False,'execution_profile':profile}};raise
  with core.connect(self.ws,'A') as (root,db):
   with self.assertRaises(core.UserError):self.contained(root,db,source,'tsv',run=limited)
   self.assertEqual(db.execute('SELECT status,records FROM runs').fetchone()[:],('failed',0));self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0);self.assertEqual(db.execute('SELECT count(*) FROM files').fetchone()[0],1)
   source.write_text('A\tB\nx\ty\n');retry=self.contained(root,db,source,'tsv');self.assertEqual(retry['records'],1)
 def test_invalid_late_jsonl_never_promotes_prefix(self):
  self.source.write_text(self.source.read_text()+'{"category":"x","body":"bad","data":{},"data":{}}\n')
  def failed(*args):
   try:return self.decode(*args)
   except Exception as exc:
    root,rid,owner,cfg,manifest,request,raw,profile,folder=args;exc.tool_result={'container':{'protocol':rc.PROTOCOL,'container_id':'d'*64,'cfg':cfg,'labels':rc.labels(root,rid,owner),'state':'removed_after_verified_stop','exit_code':125,'OOMKilled':False,'execution_profile':profile}};raise
  with core.connect(self.ws,'A') as (root,db):
   with self.assertRaises(core.UserError):self.contained(root,db,run=failed)
   self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0);self.assertEqual(db.execute('SELECT count(*) FROM artifact_runs').fetchone()[0],0)
 def test_interruption_is_explicit_and_zero_prefix(self):
  def cancel(*args):
   root,rid,owner,cfg,manifest,request,raw,profile,folder=args
   error=KeyboardInterrupt();error.tool_result={'container':{'protocol':rc.PROTOCOL,'container_id':'d'*64,'cfg':cfg,'labels':rc.labels(root,rid,owner),'state':'removed_after_verified_stop','exit_code':137,'OOMKilled':False,'execution_profile':profile}};raise error
  with core.connect(self.ws,'A') as (root,db):
   with self.assertRaises(KeyboardInterrupt):self.contained(root,db,run=cancel)
   self.assertEqual(db.execute('SELECT status,records FROM runs').fetchone()[:],('interrupted',0));self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0);self.assertEqual(db.execute('SELECT count(*) FROM artifact_runs').fetchone()[0],0)
 def test_terminal_audit_failure_rolls_back_all_publication(self):
  actual=core.audit
  def fail(db,action,detail):
   if action=='parsed_import.complete':raise sqlite3.OperationalError('terminal audit injection')
   return actual(db,action,detail)
  with core.connect(self.ws,'A') as (root,db),patch.object(core,'audit',side_effect=fail):
   with self.assertRaises(core.UserError):self.contained(root,db)
   self.assertEqual(db.execute('SELECT status,records FROM runs').fetchone()[:],('failed',0));self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
 @unittest.skipUnless(sys.platform=='linux','Real container worker syscall qualification executes on Linux.')
 def test_synthetic_host_transport_matches_real_linux_worker(self):
  from tests.container_transport_fixtures import report_transport
  def checked(*args):
   root,rid,owner,cfg,manifest,request,raw,profile,folder=args
   actual=self.worker_decode(*args)
   expected=report_transport(root/'evidence'/request['source']['evidence_id']/manifest[0]['path'],request,raw,profile)
   self.assertEqual(actual,expected)
   (folder/'report.stdout.jsonl').write_bytes(actual);(folder/'report.stderr').write_bytes(b'')
   receipt={'protocol':rc.PROTOCOL,'container_id':'d'*64,'cfg':cfg,'labels':rc.labels(root,rid,owner),'state':'removed_after_verified_stop','exit_code':0,'OOMKilled':False,'execution_profile':profile}
   return codec.validate(actual,rc.bindings_for(raw,request,profile)),receipt
  with core.connect(self.ws,'A') as (root,db):self.contained(root,db,run=checked)

if __name__=='__main__':unittest.main()
