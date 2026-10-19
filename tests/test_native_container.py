"""Controller atomicity with explicitly injected validated worker transports.

These tests do not claim Docker/mount qualification; actual container receipts
are kept separately. They use real CaseDB transactions and SQLite page quotas.
"""
import hashlib,json,pathlib,sqlite3,tempfile,unittest
from unittest.mock import patch
from lawliet_mobile import native_container as nc,core
from lawliet_mobile.native_container_codec import validate
from lawliet_mobile.parsers import native_analyze,VERSION

class Publication(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name).resolve();self.ws=self.base/'cases';core.create_case(self.ws,'A');p=self.base/'packages.txt';p.write_text('package:com.example\n')
  with core.connect(self.ws,'A') as (root,db):self.eid=core.import_evidence(root,db,p,'android')[0]
  self.cfg={'image':nc.IMAGE,'socket':str(self.base/'synthetic.sock'),'docker':'/synthetic/docker','bootstrap_sha256':core.digest(nc.WORKER)}
 def worker(self,*,duplicate=False,large=False,partial=False,quota=None):
  def injected(root,rid,owner,cfg,manifest,request,raw,profile,folder):
   f=manifest[0];bindings={'protocol':'lawliet-native-artifacts/1','request_sha256':hashlib.sha256(raw).hexdigest(),'source_manifest_sha256':hashlib.sha256(nc.canonical(manifest)).hexdigest(),'evidence_id':self.eid,'native_parser_version':VERSION,'package_manifest_sha256':profile['package_manifest_sha256'],'bootstrap_sha256':cfg['bootstrap_sha256']}
   artifact={'kind':'artifact','seq':1,'evidence_id':self.eid,'file_id':f['id'],'category':'apps','timestamp':None,'timestamp_raw':None,'title':'App','body':'X'*200000 if large else 'com.example','source_ref':'packages:line=1','parser':VERSION,'data_json':core.json_text({'package':'com.example'})}
   frames=[artifact]
   if duplicate:frames.append({**artifact,'seq':2})
   line=lambda value:nc.canonical(value)+b'\n'
   data=b''.join(line(v) for v in frames);state='partial' if partial else 'complete';detail={'run_id':'private','engine':VERSION,'status':state,'new_records':len(frames),'sqlite_files_examined':0,'databases_with_records':0,'errors':[{'source':f['logical_path'],'error':'synthetic per-source limitation'}] if partial else [],'unparsed_candidates':[],'sqlite_resource_policy':{'scope':'test'},'coverage':'Synthetic controller seam; no independent absence claim.'}
   output=line({'kind':'header',**bindings})+data+line({'kind':'final','protocol':bindings['protocol'],'request_sha256':bindings['request_sha256'],'source_manifest_sha256':bindings['source_manifest_sha256'],'artifact_count':len(frames),'artifact_bytes':len(data),'artifacts_sha256':hashlib.sha256(data).hexdigest(),'native_status':state,'native_detail_json':core.json_text(detail),'runtime':{'python_version':'test','sqlite_version':'test'}})
   (folder/'native.stdout.jsonl').write_bytes(output);(folder/'native.stderr').write_bytes(b'')
   if quota is not None:quota()
   receipt={'protocol':nc.PROTOCOL,'container_id':'a'*64,'cfg':cfg,'labels':nc.labels(root,rid,owner),'state':'removed_after_verified_stop','exit_code':0,'OOMKilled':False,'execution_profile':profile}
   return validate(output,bindings,manifest),receipt
  return injected
 def use(self,db,root,worker):
  with patch.object(nc,'configured',return_value=self.cfg),patch.object(nc,'run',side_effect=worker):return native_analyze(root,db,self.eid)
 def assert_zero(self,db):
  row=db.execute('SELECT status,records FROM runs ORDER BY rowid DESC LIMIT 1').fetchone();self.assertEqual((row['status'],row['records']),('failed',0));self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0);self.assertEqual(db.execute('SELECT count(*) FROM artifact_runs').fetchone()[0],0)
 def test_removed_configuration_cannot_race_named_endpoint_into_host_native(self):
  import os
  with core.connect(self.ws,'A') as (root,db):
   with patch.dict(os.environ,{'LAWLIET_MCP_PROFILE':'native-container'}),patch.object(nc,'configured',return_value=None),patch('lawliet_mobile.parsers._native_analyze_owned') as host:
    with self.assertRaisesRegex(core.UserError,'no host fallback'):native_analyze(root,db,self.eid)
    host.assert_not_called()
   self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],0)
 def test_duplicate_worker_identity_is_rejected_and_whole_publication_rolled_back(self):
  with core.connect(self.ws,'A') as (root,db):
   with self.assertRaisesRegex(core.UserError,'repeats identities'):self.use(db,root,self.worker(duplicate=True))
   self.assert_zero(db);self.assertTrue(core.verify(root,db)['ok'])
   good=self.use(db,root,self.worker());self.assertEqual(good['new_records'],1);self.assertEqual(good['run_memberships'],1)
 def test_repeat_delta_zero_keeps_membership_and_partial_never_upgraded(self):
  with core.connect(self.ws,'A') as (root,db):
   a=self.use(db,root,self.worker(partial=True));b=self.use(db,root,self.worker(partial=True));self.assertEqual([a['new_records'],b['new_records']],[1,0]);self.assertEqual([a['run_memberships'],b['run_memberships']],[1,1]);self.assertEqual([a['status'],b['status']],['partial','partial']);self.assertTrue(b['errors']);self.assertTrue(core.verify(root,db)['ok'])
 def test_terminal_audit_failure_rolls_back_artifacts_and_memberships(self):
  actual=core.audit
  def fail(db,action,detail):
   if action=='analysis.finished' and detail.get('status')=='complete':raise sqlite3.OperationalError('synthetic terminal audit failure')
   return actual(db,action,detail)
  with core.connect(self.ws,'A') as (root,db):
   with patch.object(core,'audit',side_effect=fail),self.assertRaisesRegex(sqlite3.OperationalError,'terminal audit'):self.use(db,root,self.worker())
   self.assert_zero(db);self.assertTrue(core.verify(root,db)['ok'])
 def test_real_sqlite_full_during_artifact_publication_is_zero_committed_rows(self):
  with core.connect(self.ws,'A') as (root,db):
   def quota():
    pages=db.execute('PRAGMA page_count').fetchone()[0];db.execute('PRAGMA max_page_count='+str(pages+8))
   with self.assertRaises(sqlite3.Error) as caught:self.use(db,root,self.worker(large=True,quota=quota))
   self.assertEqual(caught.exception.sqlite_errorcode&255,sqlite3.SQLITE_FULL);self.assert_zero(db);self.assertTrue(core.verify(root,db)['ok']);db.execute('PRAGMA max_page_count=1073741823');self.assertEqual(self.use(db,root,self.worker())['new_records'],1)
 def test_delivered_interrupt_after_successful_commit_never_overwrites_complete(self):
  with core.connect(self.ws,'A') as (root,db):
   class InterruptAfterCommit:
    def __init__(self,connection):self.connection=connection;self.calls=0
    def __getattr__(self,key):return getattr(self.connection,key)
    def commit(self):
     self.calls+=1;self.connection.commit()
     if self.calls==2:raise KeyboardInterrupt('synthetic delivery after successful commit')
   wrapper=InterruptAfterCommit(db)
   with self.assertRaises(KeyboardInterrupt):self.use(wrapper,root,self.worker())
   row=db.execute('SELECT status,records FROM runs').fetchone();self.assertEqual((row['status'],row['records']),('complete',1));self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],1);self.assertTrue(core.verify(root,db)['ok'])
