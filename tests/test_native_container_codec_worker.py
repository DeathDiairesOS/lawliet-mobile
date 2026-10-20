"""Actual private worker/native parser -> host codec, without Docker or production writes."""
import unittest
import sqlite3

from lawliet_mobile import native_container_codec as codec
from lawliet_mobile import native_container_worker as worker
from tests import test_native_container_worker as fixtures


class CodecWorkerTests(unittest.TestCase):
    def exercise(self, items):
        fixture = fixtures.WorkerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for index, (path, content) in enumerate(items,1):
            fixture.add(path, content, file_id=index)
        raw = fixture.execute()
        bindings = dict(protocol=codec.PROTOCOL, request_sha256=worker.sha(fixture.request_path.read_bytes()),
                        source_manifest_sha256=worker.sha(worker.canonical(fixture.request['inputs'])),
                        evidence_id=fixture.eid, native_parser_version='native/0.1.12',
                        package_manifest_sha256=worker.sha(worker.canonical(fixture.request['package_sha256'])),
                        bootstrap_sha256=fixture.request['bootstrap_sha256'])
        result = codec.validate(raw, bindings, fixture.request['inputs'])
        return result, list(result.iter_artifacts())

    def test_actual_packages_native_order_and_full_detail(self):
        result, rows = self.exercise([('packages.txt', b'package:z.app\npackage:a.app\n')])
        self.assertEqual([r['title'] for r in rows], ['z.app','a.app'])
        self.assertEqual(result.detail['status'], 'complete')
        self.assertEqual(result.detail['new_records'], 2)

    def test_actual_partial_source_error_not_clean_negative(self):
        result, rows = self.exercise([('broken.xml', b'<broken>'),('packages.txt', b'package:good.app\n')])
        self.assertEqual(result.footer['native_status'], 'partial')
        self.assertEqual(len(rows),1)
        self.assertEqual(result.detail['errors'][0]['source'],'broken.xml')

    def test_actual_empty(self):
        result, rows = self.exercise([])
        self.assertEqual(rows, [])
        self.assertEqual(result.artifact_count,0)
        self.assertEqual(result.footer['native_status'],'complete')

    def test_actual_media_semantic_file_binding(self):
        result, rows = self.exercise([('photo.jpg', b'\xff\xd8\xff\xe0' + b'x'*20)])
        self.assertEqual(result.artifact_count,1)
        self.assertEqual(rows[0]['data']['media']['file_id'],1)
        self.assertEqual(rows[0]['data']['media']['bytes'],24)

    def test_actual_mms_retained_and_missing_payloads(self):
        db=sqlite3.connect(':memory:')
        try:
            db.executescript("""
                CREATE TABLE pdu(_id,thread_id,date,msg_box,m_type);
                CREATE TABLE part(_id,mid,seq,ct,text,_data,chset);
                CREATE TABLE addr(_id,msg_id,address,type,charset);
                INSERT INTO pdu VALUES(1,7,1700000000,1,132);
                INSERT INTO part VALUES(1,1,0,'text/plain','known body',NULL,106);
                INSERT INTO part VALUES(2,1,1,'image/jpeg',NULL,'photo.jpg',NULL);
                INSERT INTO part VALUES(3,1,2,'image/jpeg',NULL,'missing.jpg',NULL);
                INSERT INTO addr VALUES(1,1,'+15550000000',137,106);
            """)
            raw=db.serialize()
        finally: db.close()
        result,rows=self.exercise([('mmssms.db',raw),('photo.jpg',b'\xff\xd8\xff\xe0'+b'x'*20)])
        messages=[r for r in rows if r['category']=='messages']
        self.assertEqual(len(messages),1)
        payloads=[part['payload'] for part in messages[0]['data']['parts']]
        self.assertEqual(payloads[1]['file_id'],2)
        self.assertEqual(payloads[1]['logical_path'],'photo.jpg')
        self.assertEqual(payloads[2]['status'],'not-acquired')
        self.assertIsNone(payloads[2]['file_id'])
        self.assertEqual(result.footer['native_status'],'complete')

    def test_actual_mms_candidates_control_pdu_and_orphans_keep_raw_provenance(self):
        # Independent synthetic schema matching the acquired decoder branch;
        # no acquired person's message content or identifiers are embedded here.
        db=sqlite3.connect(':memory:')
        try:
            db.executescript("""
                CREATE TABLE pdu(_id,thread_id,date,msg_box,m_type);
                CREATE TABLE part(_id,mid,seq,ct,text,_data,chset);
                CREATE TABLE addr(_id,msg_id,address,type,charset);
                INSERT INTO pdu VALUES(1,7,1700000000,1,130);
                INSERT INTO part VALUES(2,99,0,'image/jpeg',NULL,'photo.jpg',NULL);
                INSERT INTO addr VALUES(3,99,'synthetic-address',137,106);
            """)
            raw=db.serialize()
        finally: db.close()
        result,rows=self.exercise([('mmssms.db',raw),('photo.jpg',b'\xff\xd8\xff\xe0'+b'x'*20)])
        candidates=[r for r in rows if r['category']=='mms_candidates']
        self.assertEqual(len(candidates),3)
        self.assertFalse(any(r['category']=='messages' for r in rows))
        control=[r for r in candidates if r['source_ref'].startswith('pdu:')][0]
        self.assertEqual(control['data']['raw_pdu']['m_type'],130)
        self.assertEqual(control['data']['record_state'],'control-or-unsupported-pdu')
        self.assertEqual(control['body'],'')
        self.assertNotIn('message',control['data'])
        orphan=[r for r in candidates if r['source_ref']=='part:rowid=1'][0]
        self.assertIsNone(orphan['timestamp']);self.assertEqual(orphan['data']['record_state'],'missing-parent')
        self.assertEqual(orphan['data']['payload']['file_id'],2)
        self.assertEqual(orphan['data']['payload']['logical_path'],'photo.jpg')
        self.assertNotIn('message',orphan['data'])
        self.assertGreaterEqual(len(result.detail['unparsed_candidates']),3)
        self.assertEqual(result.footer['native_status'],'complete')

if __name__ == '__main__': unittest.main()
