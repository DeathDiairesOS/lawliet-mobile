import importlib.util,json,os,signal,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
from lawliet_mobile import runner_lease as lease, tools
from lawliet_mobile.core import create_case,connect,import_evidence,verify,UserError,digest
GOOD="import pathlib,sys\np=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);p.mkdir(exist_ok=True);(p/'fixture.tsv').write_text('Field\\nRECOVERED\\n')\n"
@unittest.skipUnless(os.name=='posix','Requires POSIX runner leases and signals')
class Ownership(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.b=Path(self.t.name);self.ws=self.b/'cases';create_case(self.ws,'A');self.source=self.b/'source';self.source.mkdir();(self.source/'original').write_text('ORIGINAL');self.before=digest(self.source/'original');self.ready=self.b/'ready';self.script=self.b/'worker.py';self.script.write_text(GOOD);tools.configure(self.ws,'aleapp',self.script)
  with connect(self.ws,'A') as (root,db):self.root=root;self.eid=import_evidence(root,db,self.source,'android')[0]
 def job(self):
  with connect(self.ws,'A') as (root,db):return tools.external_analyze(root,db,self.ws,self.eid,'aleapp',10)
 def launch(self,seconds=2):
  self.script.write_text(f"import pathlib,os,time,sys\np=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);p.mkdir(exist_ok=True);(p/'partial').write_text('retained')\npathlib.Path({str(self.ready)!r}).write_text(str(os.getpid())+','+str(os.getppid()))\ntime.sleep({seconds})\n")
  log=(self.b/'parent.log').open('w');self.addCleanup(log.close)
  parent=subprocess.Popen([sys.executable,str(Path(__file__)),'--job',str(self.ws),self.eid],stdout=log,stderr=log,env={**os.environ,'PYTHONPATH':os.pathsep.join(filter(None,[str(Path(__file__).resolve().parents[1]),os.environ.get('PYTHONPATH','')]))});self.addCleanup(lambda:parent.poll() is None and (parent.kill(),parent.wait()))
  end=time.monotonic()+8
  while not self.ready.exists() and parent.poll() is None and time.monotonic()<end:time.sleep(.02)
  self.assertTrue(self.ready.exists(),(self.b/'parent.log').read_text());return parent,[int(x) for x in self.ready.read_text().split(',')]
 def stable(self,expected):
  with connect(self.ws,'A') as (root,db):
   self.assertEqual([r[0] for r in db.execute('SELECT status FROM runs ORDER BY rowid')],expected);self.assertTrue(verify(root,db)['ok']);self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],1)
  self.assertEqual(digest(self.source/'original'),self.before)
 def test_parent_sigkill_guardian_eof_recovery_retry(self):
  parent,pids=self.launch(20);parent.kill();parent.wait();end=time.monotonic()+8
  while True:
   try:
    with connect(self.ws,'A') as (root,db):
     with lease.lease(root,db):pass
    break
   except UserError:
    if time.monotonic()>end:raise
    time.sleep(.05)
  self.assertTrue(list((self.root/'runs').glob('*/output/partial')));self.script.write_text(GOOD);self.job();self.stable(['interrupted','complete'])
 def test_guardian_sigkill_child_lease_refuses_retry(self):
  parent,(child,guardian)=self.launch(2);os.kill(guardian,signal.SIGKILL);parent.wait(timeout=5)
  with self.assertRaisesRegex(UserError,'still owns'):self.job()
  time.sleep(2.2);self.script.write_text(GOOD);self.job();self.stable(['failed','complete'])
 def test_parent_and_guardian_killed_child_still_blocks_recovery(self):
  parent,(child,guardian)=self.launch(2);parent.send_signal(signal.SIGSTOP);os.kill(guardian,signal.SIGKILL);parent.kill();parent.wait()
  with self.assertRaisesRegex(UserError,'still owns'):self.job()
  time.sleep(2.2);self.script.write_text(GOOD);self.job();self.stable(['interrupted','complete'])
 def test_replaced_lease_cannot_claim_abandoned_owner(self):
  parent,(child,guardian)=self.launch(1);parent.send_signal(signal.SIGSTOP);os.kill(guardian,signal.SIGKILL);parent.kill();parent.wait();time.sleep(1.2)
  lock=self.root/'.external-runner.lease';lock.rename(self.root/'old-lease-retained');lock.write_text(lease.PROTOCOL+'\n')
  with self.assertRaisesRegex(UserError,'uncertain'):self.job()
 def test_short_configuration_writes_launch_real_guardian(self):
  original=os.write;writes=[]
  def short(fd,data):
   count=original(fd,data[:7]);writes.append(count);return count
  with connect(self.ws,'A') as (root,db):
   with lease.lease(root,db),open(os.devnull,'wb') as log:
    with patch.object(lease.os,'write',side_effect=short):
     child,alive=lease.spawn([sys.executable,'-c','print("owned fixture")'],cwd=None,stdout=log,stderr=log)
    try:self.assertEqual(child.wait(timeout=5),0)
    finally:os.close(alive)
  self.assertGreater(len(writes),1)
 def test_configuration_pipe_failure_reaps_real_guardian(self):
  actual=subprocess.Popen;created=[]
  def record(*args,**kw):
   child=actual(*args,**kw);created.append(child);return child
  with connect(self.ws,'A') as (root,db):
   with lease.lease(root,db),open(os.devnull,'wb') as log:
    with patch.object(lease.subprocess,'Popen',side_effect=record),patch.object(lease.os,'write',side_effect=BrokenPipeError('owned configuration failure')):
     with self.assertRaises(BrokenPipeError):lease.spawn([sys.executable,'-c','import time;time.sleep(30)'],cwd=None,stdout=log,stderr=log)
  self.assertEqual(len(created),1);self.assertIsNotNone(created[0].poll())
  with connect(self.ws,'A') as (root,db):
   with lease.lease(root,db):pass
 def test_guardian_select_exception_reaps_only_new_child(self):
  import select
  actual=subprocess.Popen;created=[]
  def record(*args,**kw):
   child=actual(*args,**kw);created.append(child);return child
  read,write=os.pipe();cr,cw=os.pipe();os.write(cw,json.dumps({'argv':[sys.executable,'-c','import time;time.sleep(30)'],'cwd':None}).encode());os.close(cw)
  try:
   with connect(self.ws,'A') as (root,db):
    with lease.lease(root,db):
     with patch.object(lease.subprocess,'Popen',side_effect=record),patch.object(select,'select',side_effect=OSError('owned select failure')):
      with self.assertRaises(OSError):lease.guardian(lease.CURRENT.get()['fd'],read,cr)
   self.assertEqual(len(created),1);self.assertEqual(created[0].poll(),-signal.SIGKILL)
  finally:os.close(write)
 def test_concurrent_start_refused(self):
  parent,_=self.launch(2)
  with self.assertRaisesRegex(UserError,'still owns'):self.job()
  parent.send_signal(signal.SIGINT);parent.wait(timeout=8);self.script.write_text(GOOD);self.job();self.stable(['interrupted','complete'])
 def test_symlink_and_malformed_lease_refused(self):
  lock=self.root/'.external-runner.lease';target=self.b/'target';target.write_text('keep');lock.symlink_to(target)
  with self.assertRaises(UserError):self.job()
  self.assertEqual(target.read_text(),'keep');lock.unlink();lock.write_text('malformed')
  with self.assertRaisesRegex(UserError,'malformed'):self.job()
 def test_legacy_running_refused_without_mutation(self):
  with connect(self.ws,'A') as (_,db):db.execute("INSERT INTO runs(id,evidence_id,engine,status,detail) VALUES('legacy',?,'aleapp','running','{}')",(self.eid,))
  with self.assertRaisesRegex(UserError,'Legacy'):self.job()
  with connect(self.ws,'A') as (_,db):self.assertEqual(db.execute("SELECT status FROM runs WHERE id='legacy'").fetchone()[0],'running')
 def test_forged_owner_without_audited_start_refused(self):
  with connect(self.ws,'A') as (root,db):
   with lease.lease(root,db):owner=lease.ownership()
   db.execute("INSERT INTO runs(id,evidence_id,engine,status,detail) VALUES('forged',?,'aleapp','running',?)",(self.eid,json.dumps({'runner_ownership':owner})))
  with self.assertRaisesRegex(UserError,'audited start'):self.job()
if __name__=='__main__':
 if '--job' in sys.argv:
  with connect(Path(sys.argv[-2]),'A') as (root,db):tools.external_analyze(root,db,Path(sys.argv[-2]),sys.argv[-1],'aleapp',30)
 else:unittest.main(verbosity=2)
