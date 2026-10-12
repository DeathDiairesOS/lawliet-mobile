import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.core import create_case,connect,import_evidence
from lawliet_mobile.parsers import native_analyze,android_residual_coverage,VERSION
from lawliet_mobile.coverage_ledger import ledger_page

class AndroidResidualCoverageTests(unittest.TestCase):
    def test_sms_preserved_and_table_limitations_reach_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'mmssms.db'
            with sqlite3.connect(source) as fixture:
                fixture.executescript('CREATE TABLE sms(_id INTEGER,address TEXT,body TEXT,date INTEGER,type INTEGER);CREATE TABLE part(_id INTEGER,ct TEXT);CREATE TABLE pdu(_id INTEGER);CREATE TABLE addr(_id INTEGER);CREATE TABLE rcs_message(_id INTEGER);')
                fixture.execute('INSERT INTO sms VALUES(1,?,?,1700000000123,1)',('+15550100','raw 😀 body'))
                fixture.executemany('INSERT INTO part VALUES(?,?)',[(i,'image/jpeg') for i in range(47)])
                fixture.execute('INSERT INTO pdu VALUES(1)');fixture.execute('INSERT INTO rcs_message VALUES(2)')
            before=source.read_bytes();ws=base/'cases';create_case(ws,'A')
            with connect(ws,'A') as (root,db):
                eid=import_evidence(root,db,source,'android')[0];result=native_analyze(root,db,eid)
                warnings={x['table']:x for x in result['unparsed_candidates'] if 'table' in x}
                self.assertEqual(warnings['part']['rows_observed'],47);self.assertEqual(warnings['addr']['rows_observed'],0)
                self.assertEqual(set(warnings),{'part','pdu','addr','rcs_message'})
                row=db.execute("SELECT * FROM artifacts WHERE category='messages'").fetchone()
                self.assertEqual(row['body'],'raw 😀 body');self.assertEqual(row['timestamp'],'2023-11-14T22:13:20.123000Z')
                data=json.loads(row['data']);self.assertEqual(data['date'],1700000000123);self.assertEqual(row['parser'],VERSION)
                self.assertEqual(db.execute("SELECT count(*) FROM artifacts WHERE category='attachments'").fetchone()[0],0)
                self.assertIn('Observed table rows: 47',json.dumps(ledger_page(root,db)))
                retained=next((root/'evidence'/eid).rglob('mmssms.db'));self.assertEqual(retained.read_bytes(),before)
            self.assertEqual(source.read_bytes(),before)
    def test_no_sms_does_not_hide_mms_only_tables(self):
        with sqlite3.connect(':memory:') as db:
            db.executescript('CREATE TABLE pdu(_id);CREATE TABLE part(_id);INSERT INTO part VALUES(1);')
            warnings=list(android_residual_coverage(db,'mmssms.db'))
            self.assertEqual(len(warnings),2);self.assertTrue(all(w['state']=='unsupported' for w in warnings))
    def test_unrelated_part_and_ios_attachment_not_mislabeled(self):
        with sqlite3.connect(':memory:') as db:
            db.executescript('CREATE TABLE part(_id);CREATE TABLE attachment(_id);CREATE TABLE message(_id);CREATE TABLE handle(_id);')
            self.assertEqual(list(android_residual_coverage(db,'HomeDomain/Library/SMS/sms.db')),[])

    def test_known_message_bad_header_retains_explicit_unparsed_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'mmssms.db';source.write_bytes(b'broken header but retained source')
            ws=base/'cases';create_case(ws,'A')
            with connect(ws,'A') as (root,db):
                eid=import_evidence(root,db,source,'android')[0];result=native_analyze(root,db,eid)
                self.assertEqual(result['new_records'],0);self.assertEqual(len(result['unparsed_candidates']),1)
                self.assertEqual(result['unparsed_candidates'][0]['state'],'unparsed')
                self.assertIn('unsupported',result['unparsed_candidates'][0]['reason'])
