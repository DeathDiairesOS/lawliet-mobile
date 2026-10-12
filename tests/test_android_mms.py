import sqlite3
import unittest
from lawliet_mobile.android_mms import decode

class AndroidMMSTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:');self.addCleanup(self.db.close)
        self.db.executescript('CREATE TABLE pdu(_id,thread_id,date,msg_box,m_type,date_sent);CREATE TABLE part(_id,mid,seq,ct,text,_data,chset);CREATE TABLE addr(_id,msg_id,address,type,charset);')
    def pdu(self,pid=1,**values):
        row={'_id':pid,'thread_id':3,'date':1700000000,'msg_box':1,'m_type':132,'date_sent':1700000100};row.update(values)
        self.db.execute('INSERT INTO pdu VALUES(?,?,?,?,?,?)',tuple(row.values()))
    def parse(self,**kw):return decode(self.db,'data/user_de/0/com.android.providers.telephony/databases/mmssms.db',platform='android',**kw)
    def test_multiple_recipients_parts_raw_and_one_parent(self):
        self.pdu();self.db.executemany('INSERT INTO addr VALUES(?,?,?,?,?)',[(1,1,'sender',137,106),(2,1,'one',151,106),(3,1,'two',151,106),(4,1,'cc',130,106)])
        self.db.executemany('INSERT INTO part VALUES(?,?,?,?,?,?,?)',[(1,1,2,'text/plain','world',None,106),(2,1,1,'text/plain','hello😀',None,106),(3,1,0,'application/smil','<smil href="https://example.invalid"/>',None,106)])
        rows,warnings,supported=self.parse();self.assertTrue(supported);self.assertEqual(len(rows),1);row=rows[0];data=row[-1]
        self.assertEqual(row[4],'hello😀\nworld');self.assertEqual(row[1],'2023-11-14T22:13:20.000000Z');self.assertEqual(data['raw_pdu']['date_sent'],1700000100)
        self.assertEqual(data['message']['recipients'],['one','two']);self.assertEqual(data['message']['recipient'],'');self.assertEqual(len(data['addresses']),4);self.assertEqual(len(data['parts']),3);self.assertTrue(warnings)
    def test_orphan_control_duplicate_parent_and_null(self):
        self.pdu(1,m_type=130);self.pdu(2);self.pdu(2)
        self.db.executemany('INSERT INTO part VALUES(?,?,?,?,?,?,?)',[(1,999,0,'text/plain','orphan',None,106),(2,2,0,'text/plain','ambiguous',None,106),(3,None,None,None,None,None,None)])
        self.db.execute('INSERT INTO addr VALUES(1,999,?,137,106)',('unlinked',))
        rows,warnings,_=self.parse();self.assertEqual(len(rows),7);self.assertTrue(all(r[0]=='mms_candidates' for r in rows));self.assertTrue(all(r[1] is None for r in rows[3:]));self.assertEqual(len(warnings),7)
    def test_payload_exact_missing_and_no_basename_or_alias_match(self):
        self.pdu();self.db.executemany('INSERT INTO part VALUES(?,?,?,?,?,?,?)',[(1,1,0,'image/jpeg',None,'/data/user_de/0/pkg/parts/A',None),(2,1,1,'image/jpeg',None,'/data/user_de/10/pkg/parts/A',None),(3,1,2,'image/jpeg',None,'/data/../escape',None)])
        files=[{'id':7,'logical_path':'data/user_de/0/pkg/parts/A','sha256':'testhash','size':4}]
        rows,_,_=self.parse(files=files);parts=rows[0][-1]['parts'];self.assertEqual([p['payload']['status'] for p in parts],['exact-retained-path-reference','not-acquired','unsupported-path']);self.assertFalse(parts[0]['payload']['payload_decoded'])
    def test_unknown_schema_platform_charset_and_raw_blob(self):
        self.pdu();self.db.execute('INSERT INTO part VALUES(1,1,0,?,?,NULL,999)',('text/plain',b'\x00\xff'))
        self.db.execute('INSERT INTO addr VALUES(1,1,?,137,999)',('raw',));rows,warnings,_=self.parse();self.assertEqual(rows[0][4],'');self.assertEqual(rows[0][-1]['parts'][0]['raw']['text'],{'sqlite_blob_hex':'00ff'});self.assertEqual(rows[0][-1]['message']['sender'],'');self.assertTrue(warnings)
        self.assertFalse(decode(self.db,'mmssms.db',platform='unknown')[2]);self.db.execute('DROP TABLE addr');self.assertFalse(self.parse()[2])
    def test_direction_datetime_boundaries_and_ambiguous_sender(self):
        for i,(stamp,box) in enumerate([(1700000000,2),(1700000000000,0),(None,99),('1700000000',3),(0,4),(2**63-1,5)],1):self.pdu(i,date=stamp,msg_box=box)
        self.db.executemany('INSERT INTO addr VALUES(?,?,?,?,?)',[(1,1,'one',137,106),(2,1,'two',137,106),(3,1,'insert-address-token',151,106)])
        rows,_,_=self.parse();self.assertEqual(rows[0][-1]['message']['sender'],'');self.assertEqual([r[-1]['message']['direction'] for r in rows],['outgoing','unknown','unknown','draft','outbox','failed']);self.assertTrue(all(r[1] is None for r in rows[1:]));self.assertEqual(rows[1][2],1700000000000)

    def test_native_integration_source_locators_and_preservation(self):
        import tempfile,json
        from pathlib import Path
        from lawliet_mobile.core import create_case,connect,import_evidence
        from lawliet_mobile.parsers import native_analyze, VERSION
        self.pdu();self.db.execute('INSERT INTO part VALUES(1,1,0,?,?,NULL,106)',('text/plain','content'));self.db.commit()
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'mmssms.db';target=sqlite3.connect(source);self.db.backup(target);target.close();original=source.read_bytes()
            ws=base/'cases';create_case(ws,'A')
            with connect(ws,'A') as (root,db):
                eid=import_evidence(root,db,source,'android')[0];result=native_analyze(root,db,eid)
                row=db.execute("SELECT * FROM artifacts WHERE category='messages'").fetchone();data=json.loads(row['data'])
                self.assertEqual(row['body'],'content');self.assertIn('pdu:rowid=1',row['source_ref']);self.assertEqual(row['parser'],VERSION);self.assertIn('conversation_id',data['message']);self.assertIn('integer Unix seconds',data['timestamp_semantics'])
                self.assertEqual(next((root/'evidence'/eid).rglob('mmssms.db')).read_bytes(),original)
            self.assertEqual(source.read_bytes(),original)

    def test_value_and_aggregate_budgets_refuse_without_partial_rows(self):
        from unittest.mock import patch
        self.pdu();self.db.execute('INSERT INTO part VALUES(1,1,0,?,?,NULL,106)',('text/plain','x'*4096))
        prior=self.db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        with patch('lawliet_mobile.android_mms.MAX_VALUE_BYTES',1024):
            rows,warnings,supported=self.parse()
            self.assertEqual(rows,[]);self.assertFalse(supported);self.assertEqual(warnings[0]['state'],'resource-limited')
        self.assertEqual(self.db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH),prior)
        with patch('lawliet_mobile.android_mms.MAX_RAW_TABLE_BYTES',1024):
            rows,warnings,supported=self.parse()
            self.assertEqual(rows,[]);self.assertFalse(supported);self.assertIn('byte budget',warnings[0]['reason'])
        with patch('lawliet_mobile.android_mms.LIMIT',0):
            self.assertEqual(self.parse()[0],[])
    def test_reserved_citation_column_rejected(self):
        self.db.execute('ALTER TABLE part ADD COLUMN __SOURCE_ROWID__')
        rows,warnings,supported=self.parse();self.assertFalse(supported);self.assertEqual(rows,[]);self.assertIn('alias collision',warnings[0]['reason'])
    def test_infinity_raw_json_tagged_and_ambiguous_sequences_not_combined(self):
        import json
        self.pdu(date=float('inf'),date_sent=float('-inf'))
        self.db.executemany('INSERT INTO part VALUES(?,?,?,?,?,?,?)',[(1,1,0,'text/plain','first',None,106),(2,1,0,'text/plain','second',None,106)])
        rows,warnings,_=self.parse();data=rows[0][-1]
        self.assertEqual(data['raw_pdu']['date'],{'sqlite_nonfinite_float':'inf'});json.dumps(rows,allow_nan=False)
        self.assertEqual(rows[0][4],'');self.assertEqual(data['part_ordering'],'unknown');self.assertTrue(warnings)
        for seq in (None,'1'):
            self.db.execute('UPDATE part SET seq=? WHERE _id=2',(seq,));rows,_,_=self.parse()
            self.assertEqual(rows[0][4],'');self.assertEqual(rows[0][-1]['part_ordering'],'unknown')
