"""Audit-first ExifTool recovery controls. Synthetic cases; daemon mocked."""
import copy,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile import core,container_runner as cr,tools
from tests.container_transport_fixtures import move_closed_case

class Registration(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.base=Path(self.t.name).resolve();self.ws=self.base/'cases';self.root=core.create_case(self.ws,'A')
  import sqlite3
  self.db=sqlite3.connect(self.root/'case.sqlite');self.db.row_factory=sqlite3.Row;self.addCleanup(self.db.close)
  self.rid='a'*12;self.eid='b'*12;self.owner={'protocol':'ancalor-runner-lease-v1','nonce':'c'*32,'device':1,'inode':2};self.cfg={'image':cr.IMAGE,'socket':'/synthetic/socket','docker':'/synthetic/docker','tool_root':'/synthetic/exiftool'};self.expected=cr.labels(self.root,self.rid,self.owner)
  self.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)',(self.eid,'Synthetic','android','fixture','now',None,0));self.folder=self.root/'runs'/self.rid;self.folder.mkdir(parents=True)
 def seed(self,legacy=False,status='failed'):
  self.initial={'container_config':self.cfg,'runner_ownership':self.owner}
  if not legacy:self.initial['container_labels']=self.expected
  self.db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)',(self.rid,self.eid,'exiftool','now',status,core.json_text(self.initial)))
  self.claim={'run_id':self.rid,'evidence_id':self.eid,'engine':'exiftool',**self.initial};core.audit(self.db,'analysis.started',self.claim);self.db.commit()
 def settle(self,receipt=None):
  receipt=self.receipt() if receipt is None else receipt
  self.db.execute('UPDATE runs SET detail=?',(core.json_text({**self.initial,'container':receipt}),));core.audit(self.db,'analysis.finished',{'run_id':self.rid,'container':receipt});self.db.commit();return receipt
 def receipt(self):return {'protocol':cr.PROTOCOL,'controller_pid':123,'container_id':'d'*64,'labels':self.expected,'cfg':self.cfg,'state':'removed_after_verified_stop','exit_code':0,'OOMKilled':False,'error':None}
 def recover(self):return cr.recover_before_retry(self.root,self.db)
 def no_daemon(self):return patch.object(cr,'docker',side_effect=AssertionError('Must refuse before daemon'))
 def test_missing_row_and_cleared_detail_cannot_hide_audited_registration(self):
  self.seed()
  with self.no_daemon():
   self.db.execute('UPDATE runs SET detail=?',('{}',))
   with self.assertRaisesRegex(core.UserError,'audited registration'):self.recover()
   self.db.execute('DELETE FROM runs')
   with self.assertRaisesRegex(core.UserError,'missing'):self.recover()
 def test_changed_config_owner_labels_engine_evidence_refused(self):
  self.seed()
  for key in ('container_config','runner_ownership','container_labels'):
   self.db.execute('UPDATE runs SET detail=?',(core.json_text({**self.initial,key:{'changed':True}}),))
   with self.subTest(key=key),self.no_daemon(),self.assertRaises(core.UserError):self.recover()
  self.db.execute('UPDATE runs SET detail=?,engine=?',(core.json_text(self.initial),'foreign'))
  with self.no_daemon(),self.assertRaises(core.UserError):self.recover()
  self.db.execute('UPDATE runs SET engine=?,evidence_id=?',('exiftool','foreign'))
  with self.no_daemon(),self.assertRaises(core.UserError):self.recover()
 def test_duplicate_start_and_unaudited_detail_refuse(self):
  self.seed();core.audit(self.db,'analysis.started',{**self.claim,'runner_ownership':{'nonce':'e'*32}})
  with self.no_daemon(),self.assertRaisesRegex(core.UserError,'unique'):self.recover()
  self.db.execute("DELETE FROM audit WHERE action='analysis.started'")
  with self.no_daemon(),self.assertRaisesRegex(core.UserError,'unique'):self.recover()
 def test_legacy_unresolved_refuses_without_guessing_labels(self):
  self.seed(legacy=True)
  with self.no_daemon(),self.assertRaisesRegex(core.UserError,'Legacy'):self.recover()
 def test_legacy_full_unique_terminal_can_move_and_offline_open(self):
  self.seed(legacy=True);self.settle();move_closed_case(self,self.ws/'MOVED')
  with self.no_daemon(),patch.object(cr,'validate_config',side_effect=AssertionError('Closed legacy needs no runtime')):self.recover()
 def test_legacy_state_only_and_wrong_full_receipt_do_not_settle(self):
  self.seed(legacy=True);self.settle({'state':'removed_after_verified_stop'})
  with self.no_daemon(),self.assertRaisesRegex(core.UserError,'incomplete'):self.recover()
 def test_duplicate_terminal_refuses(self):
  self.seed();r=self.settle();core.audit(self.db,'analysis.finished',{'run_id':self.rid,'container':r})
  with self.no_daemon(),self.assertRaisesRegex(core.UserError,'ambiguous'):self.recover()
 def test_failed_status_live_daemon_refuses_with_audited_old_labels_after_move(self):
  self.seed(status='failed');move_closed_case(self,self.ws/'MOVED')
  self.assertNotEqual(cr.labels(self.root,self.rid,self.owner),self.expected)
  response=subprocess.CompletedProcess([],0,'d'*64+'\n','');state={'State':{'Running':True,'Paused':False,'Restarting':False,'Status':'running'}}
  with patch.object(cr,'validate_config',return_value=self.cfg),patch.object(cr,'docker',return_value=response) as docker,patch.object(cr,'owned_state',return_value=state) as owned:
   with self.assertRaisesRegex(core.UserError,'still runs'):self.recover()
   owned.assert_called_once_with(self.cfg,'d'*64,self.expected)
   self.assertIn('label=lawliet.case='+self.expected['lawliet.case'],docker.call_args.args[1])
 def test_empty_or_malformed_inventory_never_proves_stopped(self):
  self.seed()
  for text in ('','partial-id\n','d'*64+'\n'+'e'*64+'\n'):
   with patch.object(cr,'validate_config',return_value=self.cfg),patch.object(cr,'docker',return_value=subprocess.CompletedProcess([],0,text,'')),self.assertRaises(core.UserError):self.recover()
 def test_daemon_unavailable_refuses(self):
  self.seed()
  with patch.object(cr,'validate_config',return_value=self.cfg),patch.object(cr,'docker',return_value=subprocess.CompletedProcess([],1,'','offline')),self.assertRaisesRegex(core.UserError,'unavailable'):self.recover()
 def test_verified_stopped_future_worker_reconciles_once_and_retains_audit(self):
  self.seed(status='running');state={'State':{'Running':False,'Paused':False,'Restarting':False,'Status':'exited','ExitCode':137,'OOMKilled':True}}
  with patch.object(cr,'validate_config',return_value=self.cfg),patch.object(cr,'docker',return_value=subprocess.CompletedProcess([],0,'d'*64+'\n','')),patch.object(cr,'owned_state',return_value=state),patch.object(cr,'remove_stopped') as removal:self.recover();removal.assert_called_once_with(self.cfg,'d'*64,self.expected)
  d=json.loads(self.db.execute('SELECT detail FROM runs').fetchone()[0]);self.assertTrue(cr.settled_receipt(d['container'],self.cfg,self.expected));self.assertTrue((self.folder/'container-recovered.json').is_file());self.assertTrue(core.verify(self.root,self.db)['ok'])
  with self.no_daemon():self.recover()
  self.assertEqual(self.db.execute("SELECT count(*) FROM audit WHERE action='analysis.container_reconciled'").fetchone()[0],1)
 def test_two_different_full_terminals_refuse_future_and_legacy(self):
  self.seed();first=self.settle();core.audit(self.db,'analysis.finished',{'run_id':self.rid,'container':{**first,'container_id':'e'*64}})
  with self.no_daemon(),self.assertRaisesRegex(core.UserError,'ambiguous'):self.recover()
  self.db.execute('DELETE FROM audit');self.db.execute('DELETE FROM runs');self.seed(legacy=True);first=self.settle();core.audit(self.db,'analysis.finished',{'run_id':self.rid,'container':{**first,'container_id':'e'*64}})
  with self.no_daemon(),self.assertRaisesRegex(core.UserError,'unique'):self.recover()
 def test_surviving_guardian_full_marker_requires_exact_CID_absence_then_audits(self):
  self.seed(status='running');receipt=self.receipt();(self.folder/'container.json').write_text(core.json_text(receipt))
  with patch.object(cr,'validate_config',return_value=self.cfg),patch.object(cr,'confirmed_absent',return_value=True) as absent,self.no_daemon():self.recover();absent.assert_called_once_with(self.cfg,'d'*64)
  detail=json.loads(self.db.execute('SELECT detail FROM runs').fetchone()[0]);self.assertEqual(detail['container'],receipt)
  event=json.loads(self.db.execute("SELECT detail FROM audit WHERE action='analysis.container_reconciled'").fetchone()[0]);self.assertIn('daemon-confirmed exact CID absence',event['authority']);self.assertTrue(core.verify(self.root,self.db)['ok'])
  with self.no_daemon():self.recover()
 def test_guardian_marker_live_or_unknown_CID_does_not_change_history(self):
  self.seed(status='running');(self.folder/'container.json').write_text(core.json_text(self.receipt()));before=self.db.execute('SELECT detail FROM runs').fetchone()[0]
  with patch.object(cr,'validate_config',return_value=self.cfg),patch.object(cr,'confirmed_absent',return_value=False),self.assertRaisesRegex(core.UserError,'still present'):self.recover()
  self.assertEqual(self.db.execute('SELECT detail FROM runs').fetchone()[0],before)
  with patch.object(cr,'validate_config',return_value=self.cfg),patch.object(cr,'confirmed_absent',side_effect=core.UserError('daemon unavailable')),self.assertRaisesRegex(core.UserError,'unavailable'):self.recover()
  self.assertEqual(self.db.execute('SELECT detail FROM runs').fetchone()[0],before)
 def test_guardian_marker_mismatch_and_partial_marker_do_not_settle(self):
  self.seed()
  for receipt in ({**self.receipt(),'labels':{}},{'state':'removed_after_verified_stop'}):
   (self.folder/'container.json').write_text(core.json_text(receipt))
   with patch.object(cr,'validate_config',return_value=self.cfg),patch.object(cr,'confirmed_absent') as absence,self.no_daemon(),self.assertRaisesRegex(core.UserError,'settlement mismatch'):self.recover()
   absence.assert_not_called()
 def test_legacy_unresolved_full_marker_alone_is_not_audited_identity(self):
  self.seed(legacy=True);(self.folder/'container.json').write_text(core.json_text(self.receipt()))
  with self.no_daemon(),patch.object(cr,'confirmed_absent') as absence,self.assertRaisesRegex(core.UserError,'Legacy'):self.recover()
  absence.assert_not_called()
 def test_healthy_legacy_noncontainer_run_unchanged(self):
  self.db.execute('INSERT INTO runs(id,engine,status,detail) VALUES(?,?,?,?)',(self.rid,'native/0.1.12','complete','{}'))
  with self.no_daemon():self.recover()
 def test_full_receipt_types_and_identity_fields_strict(self):
  self.assertTrue(cr.settled_receipt(self.receipt(),self.cfg,self.expected))
  for key,value in [('controller_pid',True),('controller_pid',0),('container_id','bad'),('exit_code',True),('exit_code',256),('OOMKilled',0),('error',[]),('cfg',{}),('labels',{}),('protocol','foreign'),('state','stopped')]:
   with self.subTest(key=key):self.assertFalse(cr.settled_receipt({**self.receipt(),key:value},self.cfg,self.expected))
  self.assertFalse(cr.settled_receipt({**self.receipt(),'labels':{}},self.cfg,{}))
  self.assertFalse(cr.settled_receipt({**self.receipt(),'cfg':{}},{},self.expected))
  for key in self.receipt():
   value=self.receipt();value.pop(key);self.assertFalse(cr.settled_receipt(value,self.cfg,self.expected))
 def test_read_receipt_rejects_parent_and_leaf_links_and_incomplete_receipt(self):
  (self.folder/'container.json').write_text(core.json_text(self.receipt()));self.assertEqual(cr.read_receipt(self.root,self.rid,self.owner,self.cfg),self.receipt())
  (self.folder/'container.json').write_text(core.json_text({'state':'removed_after_verified_stop'}))
  with self.assertRaises(core.UserError):cr.read_receipt(self.root,self.rid,self.owner,self.cfg)
  foreign=self.base/'foreign.json';foreign.write_text(core.json_text(self.receipt()));(self.folder/'container.json').unlink();(self.folder/'container.json').symlink_to(foreign)
  with self.assertRaises((core.UserError,OSError)):cr.read_receipt(self.root,self.rid,self.owner,self.cfg)
  self.folder.rename(self.folder.with_name('HELD'));self.folder.symlink_to(self.folder.with_name('HELD'),target_is_directory=True)
  with self.assertRaises((core.UserError,OSError)):cr.read_receipt(self.root,self.rid,self.owner,self.cfg)

class Producer(unittest.TestCase):
 def test_actual_adapter_records_labels_in_start_and_terminal(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp).resolve();ws=base/'cases';core.create_case(ws,'A');source=base/'source.png';source.write_bytes(b'synthetic');exe=base/'fake-exiftool';exe.write_bytes(b'synthetic executable fingerprint')
   cfg={'image':cr.IMAGE,'socket':'/synthetic/socket','docker':'/synthetic/docker','tool_root':'/synthetic/exiftool'}
   def controlled(root,rid,owner,cfg,input_path,output,timeout,guard):
    output.write_text('[]');return {'returncode':0,'stderr':str(output)+'.stderr','container':{'protocol':cr.PROTOCOL,'controller_pid':123,'container_id':'d'*64,'labels':cr.labels(root,rid,owner),'cfg':cfg,'state':'removed_after_verified_stop','exit_code':0,'OOMKilled':False,'error':None}}
   with core.connect(ws,'A') as (root,db):
    eid=core.import_evidence(root,db,source,'android')[0]
    with patch.object(tools,'command',return_value=[str(exe)]),patch.object(tools,'configuration',return_value={'exiftool':{'container':cfg}}),patch.object(cr,'validate_config',return_value=cfg),patch.object(cr,'run_exiftool',side_effect=controlled):result=tools.external_analyze(root,db,ws,eid,'exiftool')
    detail=json.loads(db.execute('SELECT detail FROM runs').fetchone()[0]);start=json.loads(db.execute("SELECT detail FROM audit WHERE action='analysis.started'").fetchone()[0]);self.assertEqual(detail['container_labels'],start['container_labels']);self.assertEqual(detail['container']['labels'],start['container_labels']);self.assertEqual(result['status'],'complete')
    with patch.object(cr,'docker',side_effect=AssertionError('Already settled')):cr.recover_before_retry(root,db)
    self.assertTrue(core.verify(root,db)['ok'])

if __name__=='__main__':unittest.main()
