import json
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.core import create_case,connect,import_evidence,UserError
from lawliet_mobile import sqlite_workspace as sw
from tests.test_recovery_acceptance import sms_database,wal_fixture,tree_hashes

class SQLiteWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'A')
        self.source=self.base/'original.db';sms_database(self.source,5)
    def intake(self,root,db,source=None):
        eid=import_evidence(root,db,source or self.source,'android')[0]
        return db.execute("SELECT id FROM files WHERE evidence_id=? AND path LIKE '%.db'",(eid,)).fetchone()[0]
    def test_schema_typed_values_duplicate_names_and_pagination(self):
        with connect(self.ws,'A') as (root,db):
            fid=self.intake(root,db);before=tree_hashes(root/'evidence')
            result=sw.schema(root,db,fid);self.assertEqual(result['state'],'parsed');self.assertIn('sms',str(result['preview']))
            result=sw.query(root,db,fid,'SELECT _id AS same,body AS same,payload,NULL FROM sms WHERE _id>=? ORDER BY _id',[1])
            self.assertEqual(result['preview']['columns'][:2],['same','same']);row=result['preview']['rows'][0]
            self.assertIn('😀',row[1]);self.assertEqual(row[2],{'sqlite_blob_hex':'00ff'});self.assertIsNone(row[3])
            page=sw.read_result(root,db,result['run_id'],offset=1,limit=2);self.assertEqual(page['rows'][0][0],2);self.assertTrue(page['has_more'])
            self.assertEqual(before,tree_hashes(root/'evidence'))
    def test_write_attach_pragma_extensions_denied(self):
        with connect(self.ws,'A') as (root,db):
            fid=self.intake(root,db);before=tree_hashes(root/'evidence')
            for sql in ['DELETE FROM sms','CREATE TABLE evil(a)',"ATTACH DATABASE '/tmp/lawliet-not-created.db' AS evil",'PRAGMA table_info(sms)',"SELECT load_extension('/tmp/evil')",'SELECT * FROM pragma_table_info(\'sms\')']:
                with self.subTest(sql=sql):
                    result=sw.query(root,db,fid,sql);self.assertEqual(result['status'],'failed');self.assertIsNone(result['preview'])
            self.assertEqual(before,tree_hashes(root/'evidence'))
    def test_row_byte_caps_and_deadline(self):
        with connect(self.ws,'A') as (root,db):
            fid=self.intake(root,db)
            result=sw.query(root,db,fid,'SELECT * FROM sms',row_limit=2);self.assertTrue(result['truncated']);self.assertEqual(result['rows_returned'],2)
            result=sw.query(root,db,fid,'SELECT ? FROM sms',['a'*700],max_output_bytes=1024);self.assertEqual(result['limit_reason'],'output_bytes')
            result=sw.query(root,db,fid,'WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT sum(x) FROM n',timeout_seconds=.05)
            self.assertEqual(result['state'],'timed-out');self.assertEqual(result['status'],'failed')
    def test_wal_sources_preserved_and_pairing_never_asserted(self):
        fixtures=self.base/'wals';fixtures.mkdir();wal_fixture(fixtures)
        with connect(self.ws,'A') as (root,db):
            for name,count in [('paired',22),('missing',20),('foreign',21),('mismatched',20)]:
                fid=self.intake(root,db,fixtures/name);before=tree_hashes(root/'evidence')
                result=sw.query(root,db,fid,'SELECT count(*) FROM sms')
                self.assertEqual(result['state'],'limited');self.assertEqual(result['preview']['rows'],[[count]])
                self.assertTrue(result['warnings']);self.assertEqual(before,tree_hashes(root/'evidence'))
    def test_corrupt_unknown_schema_and_empty_are_distinct(self):
        bad=self.base/'bad.db';bad.write_bytes(b'not sqlite')
        with connect(self.ws,'A') as (root,db):
            fid=self.intake(root,db)
            self.assertEqual(sw.query(root,db,fid,'SELECT * FROM absent')['state'],'unsupported-schema')
            self.assertEqual(sw.query(root,db,fid,'SELECT * FROM sms WHERE 0')['state'],'empty')
            fid=self.intake(root,db,bad);self.assertEqual(sw.query(root,db,fid,'SELECT * FROM sms')['state'],'unsupported-or-corrupt')
    def test_result_receipt_and_mutable_metadata_tampering_refused(self):
        with connect(self.ws,'A') as (root,db):
            fid=self.intake(root,db)
            for target in ['result.jsonl','query.json','receipt.json','run']:
                result=sw.query(root,db,fid,'SELECT * FROM sms');rid=result['run_id']
                if target=='run':db.execute('UPDATE runs SET detail=? WHERE id=?',('{}',rid))
                else:
                    path=root/'runs'/rid/target;path.write_text(path.read_text()+' ')
                with self.assertRaises(UserError):sw.read_result(root,db,rid)
    def test_source_tamper_and_symlink_container_rejected(self):
        with connect(self.ws,'A') as (root,db):
            fid=self.intake(root,db);row=db.execute('SELECT * FROM files WHERE id=?',(fid,)).fetchone();folder=root/'evidence'/row['evidence_id'];moved=self.base/'moved';folder.rename(moved);folder.symlink_to(moved,target_is_directory=True)
            with self.assertRaisesRegex(UserError,'Unsafe'):sw.query(root,db,fid,'SELECT 1')
            folder.unlink();moved.rename(folder);(folder/row['path']).write_text('tamper')
            with self.assertRaisesRegex(UserError,'integrity'):sw.query(root,db,fid,'SELECT 1')
    def test_validation_audit_tamper_and_wrong_case(self):
        create_case(self.ws,'B')
        with connect(self.ws,'A') as (root,db):
            fid=self.intake(root,db)
            with self.assertRaises(UserError):sw.query(root,db,fid,'SELECT ?',[2**80])
            result=sw.query(root,db,fid,'SELECT 1');rid=result['run_id']
            db.execute("UPDATE audit SET detail='{}' WHERE action='sqlite_query.finished'")
            with self.assertRaisesRegex(UserError,'audit'):sw.read_result(root,db,rid)
        with connect(self.ws,'B') as (root,db):
            with self.assertRaises(UserError):sw.read_result(root,db,rid)
