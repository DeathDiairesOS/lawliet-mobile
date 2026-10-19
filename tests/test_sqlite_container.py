"""Actual opt-in daemon controls; run only against explicitly supplied local Docker."""
import copy,json,os,pathlib,shutil,sqlite3,subprocess,tempfile,unittest
from unittest.mock import patch,Mock
from types import SimpleNamespace
from lawliet_mobile import sqlite_container as sc
from lawliet_mobile.core import UserError,create_case,connect,import_evidence,verify
from lawliet_mobile.sqlite_workspace import query

@unittest.skipUnless(os.environ.get('LAWLIET_TEST_SQL_CONTAINER')=='1','Explicit existing local Docker qualification required')
class SQLContainerControls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name).resolve();self.ws=self.base/'cases';create_case(self.ws,'A')
  source=self.base/'seed.sqlite';db=sqlite3.connect(source);db.execute('CREATE TABLE seed(x)');db.execute('INSERT INTO seed VALUES(42)');db.commit();db.close()
  with connect(self.ws,'A') as (root,db):import_evidence(root,db,source,'android');self.fid=db.execute('SELECT id FROM files').fetchone()[0]
  self.profile={'image':sc.IMAGE,'socket':os.environ['LAWLIET_TEST_DOCKER_SOCKET'],'docker':shutil.which('docker'),'bootstrap_sha256':sc.digest(sc.WORKER)};self.config(self.profile)
 def config(self,cfg):(self.ws/'tools.json').write_text(json.dumps({'sqlite_workspace_container':cfg}))
 def test_endpoint_socket_pin_mismatch_refused_before_run(self):
  with connect(self.ws,'A') as (root,db):
   with patch.dict(os.environ,{'LAWLIET_CONTAINER_SOCKET':str(self.base/'different.sock')}),self.assertRaisesRegex(UserError,'explicit endpoint'):query(root,db,self.fid,'SELECT x FROM seed')
   self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],0)
 def test_actual_cli_configuration_preserves_existing_settings(self):
  from lawliet_mobile import cli
  from contextlib import redirect_stdout
  import io
  (self.ws/'tools.json').write_text(json.dumps({'existing':'preserve-me'}));output=io.StringIO()
  with redirect_stdout(output):rc=cli.main(['--workspace',str(self.ws),'--json','tools','isolate-sqlite','--image',sc.IMAGE,'--socket',self.profile['socket'],'--docker',self.profile['docker']])
  self.assertEqual(rc,0);self.assertEqual(json.loads(output.getvalue())['container'],sc.validate_config(self.profile));self.assertEqual(json.loads((self.ws/'tools.json').read_text())['existing'],'preserve-me')
 def test_missing_pinned_image_is_setup_refusal_before_audited_run(self):
  actual=sc.docker
  def missing(cfg,args,*a,**kw):
   if args[:2]==['image','inspect']:return subprocess.CompletedProcess([],1,'','synthetic missing pinned image')
   return actual(cfg,args,*a,**kw)
  with connect(self.ws,'A') as (root,db):
   with patch.object(sc,'docker',side_effect=missing),self.assertRaisesRegex(UserError,'image unavailable'):query(root,db,self.fid,'SELECT x FROM seed')
   self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],0)
   self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='sqlite_query.started'").fetchone()[0],0)
   self.assertTrue(verify(root,db)['ok'])
 def test_lost_create_response_with_empty_inventory_cannot_silently_retry(self):
  actual=sc.docker
  def lost(cfg,args,*a,**kw):
   if args[0]=='create':raise subprocess.TimeoutExpired('synthetic lost create transport',10)
   return actual(cfg,args,*a,**kw)
  with connect(self.ws,'A') as (root,db):
   with patch.object(sc,'docker',side_effect=lost):
    result=query(root,db,self.fid,'SELECT x FROM seed');self.assertEqual(result['status'],'failed')
   self.assertEqual(db.execute('SELECT records FROM runs').fetchone()[0],0)
   with self.assertRaisesRegex(UserError,'create outcome uncertain'):query(root,db,self.fid,'SELECT x FROM seed')
   self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],1);self.assertTrue(verify(root,db)['ok'])
 def test_compromised_worker_output_and_oom_retain_diagnostics_and_never_promote(self):
  for mode,program in [('invalid',"import sys;sys.stderr.write('SYNTHETIC-WORKER-DIAGNOSTIC\\n');sys.stdout.write('invalid-envelope\\n')"),('oom','x=bytearray(400*1024**2)')]:
   with self.subTest(mode=mode):
    malicious=self.base/(mode+'.py');malicious.write_text(program)
    self.config({**self.profile,'bootstrap_sha256':sc.digest(malicious)})
    with connect(self.ws,'A') as (root,db):
     with patch.object(sc,'WORKER',malicious),self.assertRaises(UserError):query(root,db,self.fid,'SELECT x FROM seed')
     row=db.execute('SELECT id,status,records,detail FROM runs ORDER BY rowid DESC LIMIT 1').fetchone();detail=json.loads(row['detail']);self.assertEqual((row['status'],row['records']),('failed',0));self.assertEqual(detail['container']['state'],'removed_after_verified_stop');folder=root/'runs'/row['id']
     self.assertFalse((folder/'result.jsonl').exists())
     self.assertTrue((folder/'container.stdout.json').is_file());self.assertTrue((folder/'container.stderr').is_file())
     if mode=='invalid':self.assertEqual((folder/'container.stdout.json').read_bytes(),b'invalid-envelope\n');self.assertEqual((folder/'container.stderr').read_bytes(),b'SYNTHETIC-WORKER-DIAGNOSTIC\n')
     else:self.assertTrue(detail['container']['OOMKilled']);self.assertEqual(detail['container']['exit_code'],137)
     self.assertTrue(verify(root,db)['ok'])
     self.config(self.profile);good=query(root,db,self.fid,'SELECT x FROM seed');self.assertEqual(good['preview']['rows'],[[42]])
 def test_unsafe_profile_inspection_is_refused_before_start(self):
  actual=sc.owned_state;attempted=[];real_docker=sc.docker
  def observe(cfg,args,*a,**kw):
   attempted.append(args[0]);return real_docker(cfg,args,*a,**kw)
  count=0
  def modified(*a,**kw):
   nonlocal count
   value=actual(*a,**kw);count+=1
   if count==1:value=copy.deepcopy(value);value['HostConfig']['Privileged']=True
   return value
  with connect(self.ws,'A') as (root,db):
   proxy=SimpleNamespace(Popen=Mock(side_effect=AssertionError('unsafe container must never start')),TimeoutExpired=subprocess.TimeoutExpired)
   with patch.object(sc,'subprocess',proxy),patch.object(sc,'owned_state',side_effect=modified),patch.object(sc,'docker',side_effect=observe),self.assertRaisesRegex(UserError,'configuration mismatch'):query(root,db,self.fid,'SELECT x FROM seed')
   proxy.Popen.assert_not_called()
   self.assertNotIn('start',attempted);row=db.execute('SELECT records,detail FROM runs').fetchone();self.assertEqual(row['records'],0);self.assertEqual(json.loads(row['detail'])['container']['state'],'removed_after_verified_stop');self.assertTrue(verify(root,db)['ok'])

class SettlementIdentity(unittest.TestCase):
 def test_forged_settlement_fields_cannot_bypass_recovery(self):
  cfg={'image':sc.IMAGE};labels={'owner':'a'};valid={'protocol':sc.PROTOCOL,'container_id':'a'*64,'cfg':cfg,'labels':labels,'state':'removed_after_verified_stop','exit_code':0,'OOMKilled':False,'execution_profile':{'profile':'synthetic'}};profile=valid['execution_profile'];self.assertTrue(sc.settled_receipt(valid,cfg,labels,profile))
  for key,value in [('protocol','foreign'),('container_id','bad'),('cfg',{}),('labels',{}),('state','running'),('exit_code',True),('OOMKilled',0)]:
   with self.subTest(key=key):self.assertFalse(sc.settled_receipt({**valid,key:value},cfg,labels,profile))
