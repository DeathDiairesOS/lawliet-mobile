"""Real SQLite worker death must preserve history and block premature retry."""
import json,os,signal,sqlite3,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from lawliet_mobile.core import UserError,connect,create_case,import_evidence,verify
from lawliet_mobile import sqlite_workspace as sw

@unittest.skipUnless(os.name=='posix','POSIX guarded worker')
class SQLiteOwnership(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name).resolve();self.ws=self.base/'cases';create_case(self.ws,'A');source=self.base/'seed.db';c=sqlite3.connect(source);c.execute('CREATE TABLE seed(x)');c.execute('INSERT INTO seed VALUES(42)');c.commit();c.close();self.ready=self.base/'ready.json'
  with connect(self.ws,'A') as (root,db):self.root=root;import_evidence(root,db,source,'android');self.fid=db.execute('SELECT id FROM files').fetchone()[0]
 def launch(self,seconds):
  script=self.base/'parent.py';script.write_text('from pathlib import Path\nimport subprocess,json\nfrom lawliet_mobile.core import connect\nfrom lawliet_mobile.sqlite_workspace import query\nactual=subprocess.Popen\ndef record(*args,**kwargs):\n p=actual(*args,**kwargs);Path('+repr(str(self.ready))+').write_text(json.dumps({"pid":p.pid,"argv":args[0]}));return p\nsubprocess.Popen=record\nwith connect(Path('+repr(str(self.ws))+'),"A") as (root,db):query(root,db,'+str(self.fid)+',"WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT sum(x) FROM n",timeout_seconds='+str(seconds)+')\n')
  log=(self.base/'parent.log').open('w');self.addCleanup(log.close);p=subprocess.Popen([sys.executable,str(script)],stdout=log,stderr=log,env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1])});self.addCleanup(lambda:p.poll() is None and (p.kill(),p.wait()))
  deadline=time.monotonic()+10
  while time.monotonic()<deadline:
   if self.ready.exists():
    guardian=json.loads(self.ready.read_text());listing=subprocess.check_output(['ps','-axo','pid=,ppid=,command='],text=True)
    for line in listing.splitlines():
     fields=line.strip().split(None,2)
     if len(fields)==3 and fields[1]==str(guardian['pid']) and 'sqlite_workspace.py --worker' in fields[2] and str(self.root) in fields[2]:return p,guardian['pid'],int(fields[0])
   if p.poll() is not None:break
   time.sleep(.02)
  self.fail('Owned worker not observed: '+(self.base/'parent.log').read_text())
 def retry(self):
  deadline=time.monotonic()+8
  while True:
   try:
    with connect(self.ws,'A') as (root,db):return sw.query(root,db,self.fid,'SELECT x FROM seed')
   except UserError as exc:
    if 'still owns' not in str(exc) or time.monotonic()>deadline:raise
    time.sleep(.05)
 def assert_history(self):
  with connect(self.ws,'A') as (root,db):
   self.assertTrue(verify(root,db)['ok']);rows=[dict(x) for x in db.execute('SELECT id,status,records FROM runs ORDER BY rowid')];self.assertEqual([x['status'] for x in rows],['interrupted','complete']);self.assertEqual([x['records'] for x in rows],[0,1]);self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='sqlite_query.abandoned'").fetchone()[0],1)
   with self.assertRaises(UserError):sw.read_result(root,db,rows[0]['id'])
   self.assertTrue((root/'runs'/rows[0]['id']/'query.json').is_file())
 def test_parent_sigkill_stops_worker_before_safe_retry(self):
  parent,guardian,worker=self.launch(30);parent.kill();parent.wait();result=self.retry();self.assertEqual(result['preview']['rows'],[[42]]);self.assert_history()
  deadline=time.monotonic()+2
  while time.monotonic()<deadline:
   p=subprocess.run(['ps','-p',str(worker),'-o','command='],capture_output=True,text=True)
   if not p.stdout.strip() or 'sqlite_workspace.py --worker' not in p.stdout:break
   time.sleep(.02)
  else:self.fail('Worker still alive after parent death')
 def test_parent_and_guardian_death_live_worker_blocks_retry(self):
  parent,guardian,worker=self.launch(2);parent.send_signal(signal.SIGSTOP);os.kill(guardian,signal.SIGKILL);parent.kill();parent.wait()
  with connect(self.ws,'A') as (root,db):
   before=[tuple(x) for x in db.execute('SELECT id,status,records FROM runs')]
   with self.assertRaisesRegex(UserError,'still owns'):sw.query(root,db,self.fid,'SELECT x FROM seed')
   self.assertEqual(before,[tuple(x) for x in db.execute('SELECT id,status,records FROM runs')])
  result=self.retry();self.assertEqual(result['preview']['rows'],[[42]]);self.assert_history()
 def test_legacy_running_job_is_not_fabricated_as_recoverable(self):
  with connect(self.ws,'A') as (root,db):
   eid=db.execute('SELECT id FROM evidence').fetchone()[0];db.execute("INSERT INTO runs(id,evidence_id,engine,status,detail) VALUES('000000000001',?,'sqlite-workspace/1','running','{}')",(eid,));db.commit()
   with self.assertRaisesRegex(UserError,'Legacy or unknown'):sw.query(root,db,self.fid,'SELECT x FROM seed')
   self.assertEqual(db.execute('SELECT status FROM runs').fetchone()[0],'running');self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],1)
