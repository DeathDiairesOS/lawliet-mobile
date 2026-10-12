"""Conservative native rich-event flags and source-profile isolation."""
import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from lawliet_mobile.core import connect,create_case,import_evidence,select_artifacts,verify
from lawliet_mobile.parsers import VERSION,native_analyze,parse_database
from lawliet_mobile.media import resolve_attachment

class MessageEventBoundaryTests(unittest.TestCase):
 def rows(self):
  db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row;self.addCleanup(db.close)
  db.executescript('''CREATE TABLE handle(id TEXT);INSERT INTO handle VALUES('+12025550100');
   CREATE TABLE message(date INTEGER,handle_id INTEGER,is_from_me INTEGER,service TEXT,text TEXT,
    associated_message_type INTEGER,associated_message_guid TEXT,date_edited INTEGER,attributedBody BLOB);
  ''')
  inputs=[(1,1,0,'iMessage','Plain 😀\nline',0,None,0,None),
          (2,1,0,'iMessage','Uninterpreted linked event',2001,'p:0/RAW-GUID',0,None),
          (3,1,1,'iMessage','Current text preserved',0,None,456,None),
          (4,1,0,'iMessage',None,0,None,0,b'opaque\x00bytes'),
          (5,1,0,'iMessage','Unknown marker',999999,None,0,None)]
  db.executemany('INSERT INTO message VALUES(?,?,?,?,?,?,?,?,?)',inputs)
  return db,list(parse_database(db,'HomeDomain/Library/SMS/sms.db'))
 def test_plaintext_body_and_zero_markers_not_reclassified(self):
  _,rows=self.rows();row=rows[0]
  self.assertEqual(row[4],'Plain 😀\nline');self.assertNotIn('Undecoded',row[3])
  self.assertEqual(row[-1]['message']['rich_event']['state'],'no_nonzero_marker_observed')
 def test_linked_and_unknown_events_visible_without_semantic_guess(self):
  _,rows=self.rows()
  for index,expected in [(1,2001),(4,999999)]:
   row=rows[index];self.assertTrue(row[3].startswith('Undecoded message event · '))
   rich=row[-1]['message']['rich_event'];self.assertEqual(rich['state'],'not_decoded')
   self.assertEqual(rich['markers']['associated_message_type'],expected)
   self.assertEqual(row[-1]['associated_message_type'],expected)
   self.assertNotIn('reaction_type',rich)
  self.assertEqual(rows[1][-1]['associated_message_guid'],'p:0/RAW-GUID')
 def test_edit_marker_retained_without_inventing_edit_history(self):
  _,rows=self.rows();row=rows[2]
  self.assertEqual(row[4],'Current text preserved');self.assertEqual(row[-1]['date_edited'],456)
  self.assertEqual(row[-1]['message']['rich_event']['markers']['date_edited'],456)
  self.assertEqual(row[1],'2001-01-01T00:00:03.000000Z');self.assertNotIn('edit_history',row[-1]['message'])
 def test_opaque_body_is_explicit_and_original_blob_remains(self):
  db,rows=self.rows();row=rows[3]
  self.assertEqual(row[-1]['message']['body_status'],'opaque_body_not_decoded')
  self.assertEqual(row[-1]['message']['rich_event']['opaque_body_fields']['attributedBody']['blob_bytes'],12)
  self.assertEqual(db.execute('SELECT attributedBody FROM message WHERE rowid=4').fetchone()[0],b'opaque\x00bytes')
  self.assertTrue(row[3].startswith('Undecoded message event · '));self.assertEqual(row[4],'')
 def test_two_android_profiles_keep_equal_thread_ids_separate(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp);source=base/'source';original={}
   for user in ['0','10']:
    p=source/f'data/user/{user}/com.android.providers.telephony/databases/mmssms.db';p.parent.mkdir(parents=True)
    with closing(sqlite3.connect(p)) as db,db:
     db.execute('CREATE TABLE sms(_id INTEGER,thread_id INTEGER,address TEXT,body TEXT,date INTEGER,type INTEGER)')
     db.execute('INSERT INTO sms VALUES(1,7,?,?,1000,1)',('+12025550100','PROFILE_'+user))
    original[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
   workspace=base/'work';create_case(workspace,'PROFILES')
   with connect(workspace,'PROFILES') as (root,db):
    eid,_,_=import_evidence(root,db,source,'android');run=native_analyze(root,db,eid)
    rows=select_artifacts(db,category='messages',run=run['run_id'])
    self.assertEqual(len(rows),2);self.assertEqual({r['body'] for r in rows},{'PROFILE_0','PROFILE_10'})
    self.assertEqual(len({r['data']['message']['conversation_id'] for r in rows}),2)
    self.assertEqual({r['data']['message']['conversation'] for r in rows},{'7'})
    self.assertTrue(all(r['parser']==VERSION for r in rows));self.assertTrue(verify(root,db)['ok'])
   self.assertEqual(original,{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in original})
 def test_attachment_missing_size_mismatch_and_ambiguous_stay_distinct(self):
  record={'filename':'Library/SMS/Attachments/image.jpg','expected_bytes':42}
  acquired={'id':1,'logical_path':record['filename'],'sha256':'fixture-digest','size':42}
  self.assertEqual(resolve_attachment(record,[])['status'],'not_acquired')
  self.assertEqual(resolve_attachment(record,[acquired])['status'],'available')
  self.assertEqual(resolve_attachment(record,[{**acquired,'size':41}])['status'],'size_mismatch')
  self.assertEqual(resolve_attachment(record,[acquired,{**acquired,'id':2}])['status'],'ambiguous_path')
if __name__=='__main__':unittest.main(verbosity=2)
