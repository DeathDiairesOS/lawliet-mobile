"""Bound native source values without silently truncating phone observations."""
import hashlib,json,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,import_evidence,verify
import lawliet_mobile.parsers as native

class NativeSQLiteLimits(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.base=Path(tmp.name).resolve();self.ws=self.base/'cases';create_case(self.ws,'A')
 def source(self,name,body):
  path=self.base/(name+'.db');db=sqlite3.connect(path)
  try:
   db.execute('CREATE TABLE sms(_id INTEGER,address TEXT,date INTEGER,type INTEGER,body TEXT)');db.execute('INSERT INTO sms VALUES(1,?,?,1,?)',('+12025550101',1700000000000,body));db.commit()
  finally:db.close()
  return path
 def test_oversized_utf8_value_is_partial_resource_failure_not_clean_zero(self):
  source=self.source('mmssms','東京'*300);before=hashlib.sha256(source.read_bytes()).hexdigest()
  with connect(self.ws,'A') as (root,db):
   eid=import_evidence(root,db,source,'android')[0]
   with patch.object(native,'MAX_SQLITE_VALUE_BYTES',1024):result=native.native_analyze(root,db,eid)
   self.assertEqual(result['status'],'partial');self.assertEqual(result['new_records'],0)
   error=result['errors'][0];self.assertEqual(error['state'],'resource-limited');self.assertEqual(error['max_value_or_encoded_row_bytes'],1024)
   self.assertIn('1024-byte processing limit',error['error']);self.assertIn('coverage incomplete',error['reason']);self.assertEqual(result['sqlite_resource_policy']['max_value_or_encoded_row_bytes'],1024)
   self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0);self.assertTrue(verify(root,db)['ok'])
  self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),before)
 def test_positive_after_limited_run_is_not_blocked_and_values_unchanged(self):
  source=self.source('mmssms','東京'*300)
  with connect(self.ws,'A') as (root,db):
   eid=import_evidence(root,db,source,'android')[0]
   with patch.object(native,'MAX_SQLITE_VALUE_BYTES',1024):self.assertEqual(native.native_analyze(root,db,eid)['status'],'partial')
   result=native.native_analyze(root,db,eid);self.assertEqual(result['status'],'complete');self.assertEqual(result['new_records'],1)
   self.assertEqual(db.execute('SELECT body FROM artifacts').fetchone()[0],'東京'*300);self.assertTrue(verify(root,db)['ok'])
 def test_limit_is_per_source_and_other_supported_sources_remain_visible(self):
  folder=self.base/'inputs';folder.mkdir();large=self.source('large','X'*2048);small=self.source('small','kept');large.rename(folder/'large.db');small.rename(folder/'small.db')
  with connect(self.ws,'A') as (root,db):
   eid=import_evidence(root,db,folder,'android')[0]
   with patch.object(native,'MAX_SQLITE_VALUE_BYTES',1024):result=native.native_analyze(root,db,eid)
   self.assertEqual(result['status'],'partial');self.assertEqual(result['new_records'],1);self.assertEqual(db.execute('SELECT body FROM artifacts').fetchone()[0],'kept')
   self.assertEqual(len(result['errors']),1);self.assertEqual(result['errors'][0]['source'],'large.db');self.assertTrue(verify(root,db)['ok'])
