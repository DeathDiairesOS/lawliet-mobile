import sqlite3,unittest,json
from lawliet_mobile.messages import ios_event_markers
from lawliet_mobile.parsers import parse_database
class Controls(unittest.TestCase):
 def parse(self,field,value):
  db=sqlite3.connect(':memory:');self.addCleanup(db.close);db.row_factory=sqlite3.Row;db.executescript(f'CREATE TABLE handle(id TEXT);INSERT INTO handle VALUES("synthetic");CREATE TABLE message(text TEXT,date INTEGER,is_from_me INTEGER,handle_id INTEGER,"{field}");');db.execute('INSERT INTO message VALUES(?,1,0,1,?)',('Plaintext 😀\nunchanged',value));return list(parse_database(db,'Library/SMS/sms.db'))[0]
 def test_link_fields_retained_warn_without_decoding(self):
  for field in ['reply_to_guid','thread_originator_guid','thread_originator_part','associated_message_emoji']:
   for value in ['supplied','0',2,-1,0.5,b'opaque']:
    row=self.parse(field,value);raw=row[-1];rich=raw['message']['rich_event'];expected={'blob_bytes':6} if isinstance(value,bytes) else value
    self.assertEqual(raw[field],expected);self.assertEqual(rich['markers'][field],expected);self.assertEqual(rich['state'],'not_decoded');self.assertTrue(row[3].startswith('Undecoded message event · '));self.assertEqual(row[4],'Plaintext 😀\nunchanged');self.assertEqual(row[1],'2001-01-01T00:00:01.000000Z');self.assertEqual(raw['message']['direction'],'incoming');self.assertEqual(set(rich),{'schema','state','markers','opaque_body_fields','limitation'});self.assertNotIn('reply_target',raw['message']);self.assertNotIn('actor',raw['message'])
 def test_null_empty_and_zero_part_not_positive(self):
  for field in ['reply_to_guid','thread_originator_guid','thread_originator_part','associated_message_emoji']:
   for value in [None,'']:
    row=self.parse(field,value);self.assertEqual(row[-1]['message']['rich_event']['state'],'no_nonzero_marker_observed');self.assertFalse(row[3].startswith('Undecoded'))
  for value in [0,0.0]:self.assertEqual(self.parse('thread_originator_part',value)[-1]['message']['rich_event']['markers'],{})
 def test_zero_guid_is_uninterpreted_invalid_value_not_absent(self):
  for field in ['reply_to_guid','thread_originator_guid','associated_message_emoji']:
   self.assertEqual(self.parse(field,0)[-1]['message']['rich_event']['markers'][field],0)
 def test_existing_markers_unchanged_and_no_join(self):
  old={'text':'body','associated_message_type':2001,'associated_message_guid':'unknown-source','date_edited':456};result=ios_event_markers(old);self.assertEqual(result['markers'],{k:v for k,v in old.items() if k!='text'});self.assertEqual(result['state'],'not_decoded');self.assertIn('No reaction, reply relationship',result['limitation'])
if __name__=='__main__':unittest.main(verbosity=2)
