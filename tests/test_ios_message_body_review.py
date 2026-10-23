"""Retained iPhone text/contacts reach the existing review/export paths."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect, create_case, digest, import_evidence, select_artifacts, verify
from lawliet_mobile.parsers import native_analyze, parse_database
from lawliet_mobile.report import write_jsonl_export


class IOSMessageBodyReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'IOS')
        self.source = self.base / 'phone'
        self.source.mkdir()
        fixtures = json.loads((Path(__file__).parent / 'fixtures/ios_attributed_body/fixtures.json').read_text())
        fixture = next(f for f in fixtures['fixtures'] if f['id'] == 'immutable-unicode-typedstream')
        self.text = 'LAWLIET fixture: café 🦉\nSecond line'
        self.assertEqual(fixture['expected_text'], self.text)
        self.blob = bytes.fromhex(fixture['hex'])
        self.sms = self.source / 'sms.db'
        with closing(sqlite3.connect(self.sms)) as db, db:
            db.executescript('''
                CREATE TABLE handle(id TEXT);
                INSERT INTO handle VALUES ('+12025550101');
                CREATE TABLE message(text TEXT, attributedBody BLOB, date INTEGER,
                    is_from_me INTEGER, handle_id INTEGER, service TEXT, reply_to_guid TEXT);
            ''')
            db.executemany('INSERT INTO message VALUES(?,?,?,?,1,\'iMessage\',?)', [
                (None, self.blob, 725760000000000001, 0, None),
                ('Authoritative plaintext', self.blob, 725760001000000000, 1, None),
                (None, b'unsupported opaque payload', 725760002000000000, 0, None),
                ('', self.blob, 725760003000000000, 1, 'unresolved-reply-target'),
            ])
        self.contacts = self.source / 'AddressBook.sqlitedb'
        with closing(sqlite3.connect(self.contacts)) as db, db:
            db.executescript('''
                CREATE TABLE ABPerson(First TEXT, Last TEXT, ModificationDate INTEGER);
                INSERT INTO ABPerson(ROWID,First,Last,ModificationDate) VALUES(11,'Fixture','Contact',725760000);
                CREATE TABLE ABMultiValue(record_id INTEGER,property INTEGER,value TEXT,label INTEGER);
                INSERT INTO ABMultiValue(ROWID,record_id,property,value,label) VALUES
                    (21,11,3,'+1 (202) 555-0101',7),(22,11,4,'fixture@example.test',NULL);
                CREATE TABLE ABMultiValueLabel(value TEXT);
                INSERT INTO ABMultiValueLabel(ROWID,value) VALUES(7,'_$!<Mobile>!$_');
            ''')
        self.hashes = {p.name: digest(p) for p in self.source.iterdir()}
        with connect(self.workspace, 'IOS') as (root, db):
            self.evidence = import_evidence(root, db, self.source, 'ios')[0]
            self.run = native_analyze(root, db, self.evidence)

    def records(self, **filters):
        return handle(self.workspace, {'action': 'records', 'case': 'IOS',
            'evidence': self.evidence, 'run': self.run['run_id'], **filters})['records']

    def test_decoded_text_search_timeline_and_original_record_fields(self):
        self.assertEqual(self.run['status'], 'complete')
        messages = {r['source_ref']: r for r in self.records(category='messages')}
        self.assertEqual(len(messages), 4)
        first = messages['message:rowid=1']
        self.assertEqual(first['body'], self.text)
        self.assertIsNone(first['data']['text'])
        self.assertEqual(first['data']['attributedBody'], {'blob_bytes': len(self.blob)})
        self.assertEqual(first['data']['ios_message_body']['blob_sha256'], hashlib.sha256(self.blob).hexdigest())
        self.assertEqual(first['data']['ios_message_body']['source_field'], 'attributedBody')
        self.assertEqual(first['source_sha256'], self.hashes['sms.db'])
        self.assertEqual(first['timestamp'], '2024-01-01T00:00:00.000000Z')
        self.assertEqual(first['data']['timestamp_conversion']['source_minus_normalized_nanoseconds'], 1)
        self.assertEqual(first['data']['message']['direction'], 'incoming')
        self.assertEqual(first['data']['message']['body_status'], 'attributed_body_text')
        self.assertEqual(messages['message:rowid=2']['body'], 'Authoritative plaintext')
        missing = messages['message:rowid=3']
        self.assertEqual(missing['body'], '')
        self.assertEqual(missing['data']['ios_message_body']['state'], 'unsupported')
        self.assertTrue(missing['title'].startswith('Undecoded message event'))
        reply = messages['message:rowid=4']
        self.assertEqual(reply['body'], self.text)
        self.assertEqual(reply['data']['message']['rich_event']['state'], 'not_decoded')
        self.assertEqual(reply['data']['message']['rich_event']['markers']['reply_to_guid'], 'unresolved-reply-target')
        self.assertNotIn('reply_target', reply['data']['message'])
        self.assertEqual({r['source_ref'] for r in self.records(category='messages', query='café')},
                         {'message:rowid=1', 'message:rowid=4'})
        self.assertEqual({r['source_ref'] for r in self.records(category='messages',
            since='2024-01-01T00:00:00Z', until='2024-01-01T00:00:01Z')},
            {'message:rowid=1', 'message:rowid=2'})
        limits = [item for item in self.run['unparsed_candidates'] if item.get('body_decode_state') == 'unsupported']
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0]['rows_observed'], 1)
        review = {r['source_ref']: r for r in self.records(category='messages', presentation='investigator')}
        fields = lambda row: {f['name']: f['value'] for f in row['display_fields']}
        self.assertEqual(fields(review['message:rowid=1'])['Text decoding'], 'Decoded text only')
        self.assertEqual(fields(review['message:rowid=1'])['Text source'], 'message.attributedBody')
        self.assertIn('Text field only', review['message:rowid=1']['investigator_view']['note'])
        self.assertEqual(fields(review['message:rowid=3'])['Text decoding'],
                         'Unsupported encoding; text unavailable')
        self.assertEqual(review['message:rowid=3']['display_body'], '[Text unavailable: unsupported encoding]')
        self.assertEqual(review['message:rowid=3']['body'], '')
        self.assertEqual(fields(review['message:rowid=4'])['Event semantics'], 'Not decoded')
        self.assertNotIn('Text decoding', fields(review['message:rowid=2']))

    def test_contact_phone_email_and_message_records_share_case_without_identity_inference(self):
        contacts = self.records(category='contacts', presentation='investigator', phone_query='+12025550101')
        self.assertEqual(len(contacts), 1)
        self.assertIn('fixture@example.test', contacts[0]['display_body'])
        self.assertEqual(contacts[0]['source_sha256'], self.hashes['AddressBook.sqlitedb'])
        self.assertEqual({v['source_ref'] for v in contacts[0]['data']['ios_contact']['values']},
                         {'ABMultiValue:ROWID=21', 'ABMultiValue:ROWID=22'})
        messages = self.records(category='messages', phone_query='+12025550101')
        self.assertEqual(len(messages), 4)
        self.assertTrue(all('person_id' not in r['data']['message'] for r in messages))

    def test_export_reopen_and_rerun_preserve_evidence_and_record_provenance(self):
        with connect(self.workspace, 'IOS') as (root, db):
            before = select_artifacts(db, evidence=self.evidence, limit=None)
            report = write_jsonl_export(root, db, root / 'exports' / 'ios-fields.jsonl',
                                       iter(before), {'evidence': self.evidence})
            exported = [json.loads(line) for line in Path(report['path']).read_text().splitlines()]
            self.assertEqual({r['id'] for r in exported}, {r['id'] for r in before})
            self.assertEqual(next(r for r in exported if r['source_ref'] == 'message:rowid=1')['body'], self.text)
            self.assertTrue(verify(root, db)['ok'])
        with connect(self.workspace, 'IOS') as (root, db):
            repeated = native_analyze(root, db, self.evidence)
            self.assertEqual(repeated['new_records'], 0)
            self.assertEqual(before, select_artifacts(db, evidence=self.evidence, limit=None))
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(self.hashes, {p.name: digest(p) for p in self.source.iterdir()})

    def test_source_column_cannot_impersonate_decoder_provenance(self):
        with closing(sqlite3.connect(':memory:')) as db:
            db.row_factory = sqlite3.Row
            db.executescript('CREATE TABLE handle(id TEXT); '
                             'CREATE TABLE message(text TEXT,ios_message_body TEXT); '
                             'INSERT INTO message VALUES(NULL,\'{"state":"decoded"}\');')
            with self.assertRaisesRegex(ValueError, 'collides with decoded-body provenance'):
                list(parse_database(db, 'sms.db'))

    def test_android_source_column_does_not_trigger_ios_coverage(self):
        source = self.base / 'android-sms.db'
        with closing(sqlite3.connect(source)) as db, db:
            db.executescript('CREATE TABLE sms(_id INTEGER, body TEXT, address TEXT, date INTEGER, '
                             'type INTEGER, ios_message_body TEXT); '
                             "INSERT INTO sms VALUES(1,'Android fixture','+12025550101',1704067200000,1,'literal source field');")
        with connect(self.workspace, 'IOS') as (root, db):
            evidence = import_evidence(root, db, source, 'android')[0]
            run = native_analyze(root, db, evidence)
            self.assertEqual(run['status'], 'complete')
            records = select_artifacts(db, evidence=evidence)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['body'], 'Android fixture')
            self.assertEqual(records[0]['data']['ios_message_body'], 'literal source field')
            self.assertFalse(any('body_decode_state' in item for item in run['unparsed_candidates']))


if __name__ == '__main__':
    unittest.main()
