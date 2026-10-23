"""Actual private worker/native parser -> host codec, without Docker or production writes."""
import unittest
import sqlite3
import plistlib
import hashlib
import json
from pathlib import Path

from lawliet_mobile import native_container_codec as codec
from lawliet_mobile import native_container_worker as worker
from tests import test_native_container_worker as fixtures


class CodecWorkerTests(unittest.TestCase):
    def exercise(self, items, platform='android'):
        fixture = fixtures.WorkerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.request['evidence']['platform'] = platform
        for index, (path, content) in enumerate(items,1):
            fixture.add(path, content, file_id=index)
        raw = fixture.execute()
        bindings = dict(protocol=codec.PROTOCOL, request_sha256=worker.sha(fixture.request_path.read_bytes()),
                        source_manifest_sha256=worker.sha(worker.canonical(fixture.request['inputs'])),
                        evidence_id=fixture.eid, native_parser_version='native/0.1.14',
                        package_manifest_sha256=worker.sha(worker.canonical(fixture.request['package_sha256'])),
                        bootstrap_sha256=fixture.request['bootstrap_sha256'])
        result = codec.validate(raw, bindings, fixture.request['inputs'])
        return result, list(result.iter_artifacts())

    def test_actual_packages_native_order_and_full_detail(self):
        result, rows = self.exercise([('packages.txt', b'package:z.app\npackage:a.app\n')])
        self.assertEqual([r['title'] for r in rows], ['z.app','a.app'])
        self.assertEqual(result.detail['status'], 'complete')
        self.assertEqual(result.detail['new_records'], 2)

    def test_actual_ios_inventory_original_fields_and_locations(self):
        app = {'CFBundleIdentifier': 'example.synthetic', 'CFBundleDisplayName': 'Synthetic café',
               'CFBundleShortVersionString': '2.3', 'ApplicationType': 'User'}
        device = {'ProductType': 'iPhone17,2', 'ProductVersion': '26.0'}
        result, rows = self.exercise([('ios-apps.plist', plistlib.dumps([app])),
                                      ('ios-device.plist', plistlib.dumps(device))], platform='ios')
        self.assertEqual(result.footer['native_status'], 'complete')
        self.assertEqual(len(rows), 2)
        indexed = {row['category']: row for row in rows}
        for category, original, fid, ref in [('apps', app, 1, 'plist:array[index=0]'),
                                              ('device', device, 2, 'plist:dict')]:
            row = indexed[category]
            self.assertEqual(row['data']['original'], original)
            self.assertEqual(row['file_id'], fid)
            self.assertEqual(row['source_ref'], ref)
            self.assertEqual(row['parser'], 'native/0.1.14')
            self.assertIsNone(row['timestamp'])

    def test_actual_ios_contact_values_keep_independent_record_references(self):
        db = sqlite3.connect(':memory:')
        try:
            db.executescript("""
                CREATE TABLE ABPerson(First, Last, Organization, ModificationDate);
                CREATE TABLE ABMultiValue(record_id, property, value, label, UID);
                CREATE TABLE ABMultiValueLabel(value);
                INSERT INTO ABPerson(ROWID, First, Last, Organization, ModificationDate)
                    VALUES(11, 'Morgan', 'Synthetic', 'LAWLIET lab', NULL);
                INSERT INTO ABMultiValueLabel(ROWID, value) VALUES(7, '_$!<Mobile>!$_');
                INSERT INTO ABMultiValue(ROWID, record_id, property, value, label, UID)
                    VALUES(21, 11, 3, '+1 (202) 555-0101', 7, 901);
                INSERT INTO ABMultiValue(ROWID, record_id, property, value, label, UID)
                    VALUES(22, 11, 4, 'test@example.test', NULL, 902);
            """)
            raw = db.serialize()
        finally:
            db.close()
        result, rows = self.exercise([('Library/AddressBook/AddressBook.sqlitedb', raw)], platform='ios')
        self.assertEqual(result.footer['native_status'], 'complete')
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row['category'], row['title'], row['source_ref'], row['file_id'], row['parser']),
                         ('contacts', 'Morgan Synthetic', 'ABPerson:ROWID=11', 1, 'native/0.1.14'))
        self.assertIsNone(row['timestamp'])
        self.assertEqual((row['data']['First'], row['data']['Last'], row['data']['Organization']),
                         ('Morgan', 'Synthetic', 'LAWLIET lab'))
        contact = row['data']['ios_contact']
        self.assertEqual((contact['schema'], contact['person_ref'], contact['values_state']),
                         ('ios-addressbook-contact/1', 'ABPerson:ROWID=11', 'examined'))
        values = contact['values']
        self.assertEqual(len(values), 2)
        self.assertEqual([(v['kind'], v['value'], v['source_ref'], v['person_ref'], v['original']['UID'])
                          for v in values],
                         [('phone', '+1 (202) 555-0101', 'ABMultiValue:ROWID=21', 'ABPerson:ROWID=11', 901),
                          ('email', 'test@example.test', 'ABMultiValue:ROWID=22', 'ABPerson:ROWID=11', 902)])
        self.assertEqual(values[0]['label'], {'identifier': 7, 'value': '_$!<Mobile>!$_',
                         'source_ref': 'ABMultiValueLabel:ROWID=7', 'state': 'linked'})
        self.assertEqual(values[1]['label'], {'identifier': None, 'value': None,
                         'source_ref': None, 'state': 'not_supplied'})

    def test_actual_ios_attributed_text_and_unsupported_body_keep_provenance(self):
        manifest = json.loads((Path(__file__).parent / 'fixtures' / 'ios_attributed_body' /
                               'fixtures.json').read_text(encoding='utf-8'))
        fixture = next(item for item in manifest['fixtures']
                       if item['id'] == 'immutable-unicode-typedstream')
        attributed = bytes.fromhex(fixture['hex'])
        unsupported = b'Unsupported archive; this text must not become a decoded message.'
        db = sqlite3.connect(':memory:')
        try:
            db.executescript("""
                CREATE TABLE message(text, attributedBody BLOB, date INTEGER,
                                     handle_id INTEGER, is_from_me INTEGER, service TEXT);
                CREATE TABLE handle(id TEXT);
                INSERT INTO handle(ROWID, id) VALUES(7, 'test@example.test');
            """)
            db.executemany('INSERT INTO message(ROWID, text, attributedBody, date, handle_id, is_from_me, service) '
                           "VALUES(?, NULL, ?, 725760000000000000, 7, 0, 'iMessage')",
                           [(41, attributed), (42, unsupported)])
            raw = db.serialize()
        finally:
            db.close()
        result, rows = self.exercise([('Library/SMS/sms.db', raw)], platform='ios')
        self.assertEqual(result.footer['native_status'], 'complete')
        self.assertEqual(len(rows), 2)
        by_ref = {row['source_ref']: row for row in rows}
        decoded = by_ref['message:rowid=41']
        missing = by_ref['message:rowid=42']
        self.assertEqual(decoded['body'], fixture['expected_text'])
        self.assertEqual(missing['body'], '')
        self.assertEqual(decoded['data']['message']['body_status'], 'attributed_body_text')
        self.assertEqual(missing['data']['message']['body_status'], 'opaque_body_not_decoded')
        for row, blob, state in [(decoded, attributed, 'decoded'), (missing, unsupported, 'unsupported')]:
            self.assertEqual((row['category'], row['file_id'], row['parser']), ('messages', 1, 'native/0.1.14'))
            self.assertEqual((row['timestamp'], row['timestamp_raw']),
                             ('2024-01-01T00:00:00.000000Z', '725760000000000000'))
            self.assertIsNone(row['data']['text'])
            self.assertEqual(row['data']['attributedBody'], {'blob_bytes': len(blob)})
            body = row['data']['ios_message_body']
            self.assertEqual((body['state'], body['source_field'], body['blob_bytes'], body['blob_sha256']),
                             (state, 'attributedBody', len(blob), hashlib.sha256(blob).hexdigest()))
            self.assertTrue(body['limitation'])
        start, end = decoded['data']['ios_message_body']['source_byte_range']
        self.assertEqual(attributed[start:end].decode('utf-8'), fixture['expected_text'])
        self.assertTrue(any(item.get('body_decode_state') == 'unsupported' and item.get('rows_observed') == 1
                            for item in result.detail['unparsed_candidates']))

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
