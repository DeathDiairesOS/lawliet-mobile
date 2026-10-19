"""Real SQLite page quotas must not turn rolled-back rows into counts."""
import hashlib,json,sqlite3,tempfile,unittest,zlib
from pathlib import Path
from lawliet_mobile.core import create_case,connect,import_evidence,verify
from lawliet_mobile.parsers import native_analyze

class NativeLowDisk(unittest.TestCase):
 def test_real_case_page_quota_failure_and_coherent_retry(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp).resolve();source=base/'mmssms.db';db=sqlite3.connect(source)
   try:
    db.execute('CREATE TABLE sms(_id INTEGER,address TEXT,date INTEGER,type INTEGER,body TEXT)');db.executemany('INSERT INTO sms VALUES(?,?,?,?,?)',[(i,'+12025550101',1700000000000+i,1,'ROW-'+str(i)+' '+'X'*2000) for i in range(20)]);db.commit()
   finally:db.close()
   expected=hashlib.sha256(source.read_bytes()).hexdigest()
   for extra in (2,8,12):
    with self.subTest(extra_pages=extra):
     case='quota'+str(extra);create_case(base/'cases',case)
     with connect(base/'cases',case) as (root,case_db):
      eid=import_evidence(root,case_db,source,'android')[0];pages=case_db.execute('PRAGMA page_count').fetchone()[0];case_db.execute('PRAGMA max_page_count='+str(pages+extra))
      with self.assertRaises(sqlite3.OperationalError) as caught:native_analyze(root,case_db,eid)
      self.assertEqual(caught.exception.sqlite_errorcode & 255,sqlite3.SQLITE_FULL)
      case_db.execute('PRAGMA max_page_count=1073741823')
      self.assertEqual(case_db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
      if case_db.execute("SELECT 1 FROM sqlite_master WHERE name='artifact_runs'").fetchone():self.assertEqual(case_db.execute('SELECT count(*) FROM artifact_runs').fetchone()[0],0)
      failed=case_db.execute('SELECT id,status,records FROM runs').fetchone()
      if failed:
       self.assertIn(failed['status'],('failed','running'));self.assertEqual(failed['records'],0)
      self.assertTrue(verify(root,case_db)['ok'])
      result=native_analyze(root,case_db,eid);self.assertEqual(result['status'],'complete');self.assertEqual(result['new_records'],20)
      if failed:
       old=case_db.execute('SELECT status,records FROM runs WHERE id=?',(failed['id'],)).fetchone();self.assertIn(old['status'],('failed','interrupted'));self.assertEqual(old['records'],0)
      self.assertEqual(case_db.execute('SELECT count(*) FROM artifacts').fetchone()[0],20)
      self.assertEqual(native_analyze(root,case_db,eid)['new_records'],0);self.assertEqual(case_db.execute('SELECT count(*) FROM artifacts').fetchone()[0],20)
      self.assertTrue(verify(root,case_db)['ok'])
     self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),expected)

 def test_real_telephony_backup_full_is_not_swallowed_as_partial(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp).resolve()
   for family in ('sms','mms'):
    with self.subTest(family=family):
     source=base/('seed_'+family+'_backup');rows=[{'address':'+12025550101','date':1700000000000 if family=='sms' else 1700000000,'type':1,'msg_box':1,'body':'ROW-'+str(i)+' '+'X'*2000,'mms_body':'ROW-'+str(i)+' '+'X'*2000} for i in range(20)];source.write_bytes(zlib.compress(json.dumps(rows).encode()));original=hashlib.sha256(source.read_bytes()).hexdigest();create_case(base/'cases',family)
     with connect(base/'cases',family) as (root,db):
      eid=import_evidence(root,db,source,'android')[0];pages=db.execute('PRAGMA page_count').fetchone()[0];db.execute('PRAGMA max_page_count='+str(pages+12))
      with self.assertRaises(sqlite3.OperationalError) as caught:native_analyze(root,db,eid)
      self.assertEqual(caught.exception.sqlite_errorcode & 255,sqlite3.SQLITE_FULL);self.assertFalse(db.in_transaction)
      db.execute('PRAGMA max_page_count=1073741823');self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
      for run in db.execute('SELECT status,records FROM runs'):self.assertNotEqual(run['status'],'complete');self.assertEqual(run['records'],0)
      result=native_analyze(root,db,eid);self.assertEqual(result['status'],'complete');self.assertEqual(result['new_records'],20);self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],20);self.assertTrue(verify(root,db)['ok'])
     self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),original)
