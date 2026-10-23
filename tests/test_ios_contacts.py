"""Independent known-answer AddressBook fixtures; no phone or external parser."""
from contextlib import closing
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect, create_case, digest, import_evidence, select_artifacts, verify
from lawliet_mobile.ios_contacts import contact_coverage, contact_values, person_records
from lawliet_mobile.parsers import VERSION, native_analyze
from lawliet_mobile.phone_search import has_phone
from lawliet_mobile.validation import validate_case


def fixture(db):
    db.executescript('''
        CREATE TABLE ABPerson(First TEXT,Middle TEXT,Last TEXT,Organization TEXT,ModificationDate REAL,Note TEXT);
        INSERT INTO ABPerson(rowid,First,Middle,Last,Organization,ModificationDate,Note) VALUES
            (11,'Zoë','雪','Tester','Example Lab',700000000.25,'Not a phone: +12025550199'),
            (12,'Other',NULL,'Contact',NULL,NULL,'+12025550101');
        CREATE TABLE ABMultiValue(record_id,property,value,label,UID);
        CREATE TABLE ABMultiValueLabel(value TEXT);
        INSERT INTO ABMultiValueLabel(rowid,value) VALUES (7,'_$!<Mobile>!$_'),(8,'Custom 雪');
        INSERT INTO ABMultiValue(rowid,record_id,property,value,label,UID) VALUES
            (21,11,3,'+1 (202) 555-0101',7,901),
            (22,11,3,'202-555-0102',8,902),
            (23,11,4,'zoe@example.test',NULL,903),
            (24,11,3,'+1 (202) 555-0101',999,904),
            (25,11,22,'https://example.test',NULL,905),
            (26,99,3,'+12025550198',NULL,906),
            (27,11,3,X'010203',NULL,907),
            (28,12,4,'+12025550101',NULL,908),
            (29,'11',3,'+12025550197',NULL,909);
    ''')
    db.commit()


class IOSContactsHelperTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        fixture(self.db)

    def coverage(self):
        return {item['code']: item for item in contact_coverage(self.db, 'HomeDomain/Library/AddressBook/AddressBook.sqlitedb')}

    def test_join_preserves_individual_value_and_label_locations(self):
        rows = list(person_records(self.db))
        self.assertEqual(len(rows), 2)
        zoe, other = rows
        self.assertEqual((zoe['__rowid__'], zoe['First'], zoe['ModificationDate']), (11, 'Zoë', 700000000.25))
        values = zoe['ios_contact']['values']
        self.assertEqual([item['source_ref'] for item in values],
            ['ABMultiValue:ROWID=21', 'ABMultiValue:ROWID=22', 'ABMultiValue:ROWID=23', 'ABMultiValue:ROWID=24', 'ABMultiValue:ROWID=27'])
        self.assertEqual(values[0]['original'], {'__rowid__': 21, 'record_id': 11, 'property': 3,
            'value': '+1 (202) 555-0101', 'label': 7, 'UID': 901})
        self.assertEqual(values[0]['label'], {'identifier': 7, 'value': '_$!<Mobile>!$_',
            'source_ref': 'ABMultiValueLabel:ROWID=7', 'state': 'linked'})
        self.assertEqual(values[3]['label']['state'], 'unresolved')
        self.assertEqual(values[-1]['value'], {'blob_bytes': 3})
        self.assertEqual(values[-1]['value_state'], 'unsupported-or-empty')
        self.assertEqual(contact_values(zoe, 'phone'), ['+1 (202) 555-0101', '202-555-0102', '+1 (202) 555-0101'])
        self.assertEqual(contact_values(zoe, 'email'), ['zoe@example.test'])
        self.assertEqual(contact_values(other, 'phone'), [])
        self.assertIn('contact modification time', zoe['timestamp_semantics'])

    def test_diagnostics_count_orphans_unknown_properties_and_invalid_values(self):
        checks = self.coverage()
        self.assertEqual(checks['ios_contacts_orphan_values']['rows_observed'], 2)
        self.assertEqual(checks['ios_contacts_unsupported_properties']['rows_observed'], 1)
        self.assertEqual(checks['ios_contacts_invalid_values']['rows_observed'], 1)
        self.assertEqual(checks['ios_contacts_unresolved_labels']['rows_observed'], 1)
        serialized = json.dumps(checks)
        for private in ('Zoë', 'zoe@example.test', '+12025550198'):
            self.assertNotIn(private, serialized)

    def test_missing_multivalue_keeps_person_and_explicit_coverage_gap(self):
        self.db.execute('DROP TABLE ABMultiValue')
        rows = list(person_records(self.db))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['ios_contact']['values'], [])
        self.assertEqual(rows[0]['ios_contact']['values_state'], 'unsupported-schema')
        self.assertIn('ios_contacts_values_schema', self.coverage())

    def test_missing_labels_preserves_typed_values_without_inventing_label(self):
        self.db.execute('DROP TABLE ABMultiValueLabel')
        zoe = next(person_records(self.db))
        self.assertEqual(len(contact_values(zoe, 'phone')), 3)
        self.assertEqual(zoe['ios_contact']['values'][0]['label'],
            {'identifier': 7, 'value': None, 'source_ref': None, 'state': 'unresolved'})
        self.assertEqual(self.coverage()['ios_contacts_unresolved_labels']['rows_observed'], 3)

    def test_missing_optional_uid_and_label_column_are_supported_honestly(self):
        self.db.execute('DROP TABLE ABMultiValue')
        self.db.execute('CREATE TABLE ABMultiValue(record_id INTEGER,property INTEGER,value TEXT)')
        self.db.execute("INSERT INTO ABMultiValue VALUES(11,3,'2025550100')")
        zoe = next(person_records(self.db))
        self.assertEqual(contact_values(zoe, 'phone'), ['2025550100'])
        self.assertNotIn('UID', zoe['ios_contact']['values'][0]['original'])
        self.assertIn('ios_contacts_label_schema', self.coverage())

    def test_unsupported_required_columns_and_without_rowid_do_not_invent_links(self):
        for ddl in ('CREATE TABLE ABMultiValue(record_id INTEGER,property INTEGER)',
                    'CREATE TABLE ABMultiValue(UID INTEGER PRIMARY KEY,record_id INTEGER,property INTEGER,value TEXT) WITHOUT ROWID'):
            with self.subTest(ddl=ddl):
                self.db.execute('DROP TABLE ABMultiValue')
                self.db.execute(ddl)
                self.assertEqual(next(person_records(self.db))['ios_contact']['values'], [])
                self.assertIn('ios_contacts_values_schema', self.coverage())
        self.db.execute('DROP TABLE ABPerson')
        self.db.execute('CREATE TABLE ABPerson(id INTEGER PRIMARY KEY,First TEXT) WITHOUT ROWID')
        self.db.execute("INSERT INTO ABPerson VALUES(11,'Fixture')")
        self.assertEqual(list(person_records(self.db)), [])
        self.assertIn('ios_contacts_person_schema', self.coverage())

    def test_property_types_and_notes_do_not_become_phone_numbers(self):
        self.db.execute("INSERT INTO ABMultiValue VALUES(11,'3','+12025550196',NULL,910)")
        zoe, other = list(person_records(self.db))
        self.assertTrue(has_phone(json.dumps(zoe), '12025550101'))
        for number in ('2025550101', '12025550199', '12025550196', '12025550198'):
            self.assertFalse(has_phone(json.dumps(zoe), number))
        self.assertFalse(has_phone(json.dumps(other), '12025550101'))
        malformed = copy.deepcopy(zoe)
        malformed['ios_contact']['values'][0]['property'] = []
        self.assertEqual(len(contact_values(malformed, 'phone')), 2)
        malformed['ios_contact']['values'][1]['person_ref'] = 'ABPerson:ROWID=12'
        self.assertEqual(len(contact_values(malformed, 'phone')), 1)

    def test_bounded_join_reports_failure_without_yielding_truncated_contact(self):
        for name, limit in [('MAX_VALUES_PER_CONTACT', 2), ('MAX_VALUE_BYTES_PER_CONTACT', 32)]:
            with self.subTest(name=name), patch('lawliet_mobile.ios_contacts.' + name, limit):
                with self.assertRaisesRegex(ValueError, 'bounded count/byte limit'):
                    next(person_records(self.db))

    def test_source_columns_cannot_overwrite_provenance_fields(self):
        self.db.execute('ALTER TABLE ABPerson ADD COLUMN ios_contact TEXT')
        with self.assertRaisesRegex(ValueError, 'collide'):
            next(person_records(self.db))

    def test_declared_rowid_alias_does_not_change_value_linkage(self):
        self.db.execute('ALTER TABLE ABMultiValue RENAME TO saved_values')
        self.db.execute('CREATE TABLE ABMultiValue(ROWID INTEGER PRIMARY KEY,record_id INTEGER,property INTEGER,value TEXT,label INTEGER)')
        self.db.execute("INSERT INTO ABMultiValue VALUES(101,11,3,'2025550109',7)")
        zoe = next(person_records(self.db))
        self.assertEqual(zoe['ios_contact']['values'][0]['source_ref'], 'ABMultiValue:ROWID=101')
        self.assertEqual(contact_values(zoe, 'phone'), ['2025550109'])

    def test_unrelated_database_has_no_contacts_diagnostic(self):
        with closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE unrelated(value TEXT)')
            self.assertEqual(contact_coverage(db, 'unrelated.db'), [])
            self.assertEqual(list(person_records(db)), [])


class IOSContactsNativeReviewTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='lawliet-ios-contact-review-')
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'IOS')
        create_case(self.workspace, 'OTHER')
        self.folder = self.base / 'source'
        self.folder.mkdir()
        self.source = self.folder / 'AddressBook.sqlitedb'
        with closing(sqlite3.connect(self.source)) as db:
            fixture(db)

    def ingest(self):
        original = {p.name: digest(p) for p in self.folder.iterdir() if not p.name.endswith('-shm')}
        with connect(self.workspace, 'IOS') as (root, db):
            evidence = import_evidence(root, db, self.folder, 'ios')[0]
            run = native_analyze(root, db, evidence)
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(original, {p.name: digest(p) for p in self.folder.iterdir() if not p.name.endswith('-shm')})
        return evidence, run, original

    def query(self, **values):
        return handle(self.workspace, {'action': 'records', 'case': 'IOS', 'category': 'contacts', **values})

    def test_native_to_gui_search_keeps_source_rows_and_exact_hash(self):
        evidence, run, hashes = self.ingest()
        self.assertEqual(run['status'], 'complete')
        self.assertEqual(run['new_records'], 2)
        rows = self.query(evidence=evidence, run=run['run_id'], presentation='investigator')['records']
        zoe = next(row for row in rows if row['data']['__rowid__'] == 11)
        fields = {item['name']: item['value'] for item in zoe['display_fields']}
        self.assertEqual(fields['Name'], 'Zoë 雪 Tester')
        self.assertEqual(fields['Phone number'], '+1 (202) 555-0101\n202-555-0102')
        self.assertEqual(fields['Email'], 'zoe@example.test')
        self.assertEqual(zoe['source_ref'], 'ABPerson:ROWID=11')
        self.assertEqual(zoe['source_sha256'], hashes['AddressBook.sqlitedb'])
        self.assertEqual(zoe['timestamp_raw'], '700000000.25')
        self.assertEqual(zoe['data']['ModificationDate'], 700000000.25)
        self.assertEqual(zoe['timestamp'], '2023-03-08T20:26:40.250000Z')
        self.assertEqual(len(zoe['data']['ios_contact']['values']), 5)
        self.assertEqual(len(zoe['investigator_view']['observations']), 1)
        for mode in (None, 'investigator'):
            for query in ({'query': 'zoe@example.test'}, {'phone_query': '+12025550101'}, {'phone_query': '2025550102'}):
                with self.subTest(mode=mode, query=query):
                    selection = {'presentation': mode} if mode else {}
                    matching = self.query(**selection, **query)['records']
                    self.assertEqual([row['id'] for row in matching], [zoe['id']])
            selection = {'presentation': mode} if mode else {}
            self.assertEqual(self.query(**selection, phone_query='+12025550199')['records'], [])
            self.assertEqual(self.query(**selection, phone_query='2025550101')['records'], [])
        self.assertEqual(handle(self.workspace, {'action': 'records', 'case': 'OTHER'})['records'], [])
        checks = {item.get('code') for item in run['unparsed_candidates']}
        self.assertIn('ios_contacts_orphan_values', checks)

    def test_duplicate_ids_in_other_evidence_do_not_merge_and_rerun_reuses_rows(self):
        first, first_run, _ = self.ingest()
        second, _, _ = self.ingest()
        self.assertNotEqual(first, second)
        self.assertEqual(len(self.query(presentation='investigator')['records']), 4)
        with connect(self.workspace, 'IOS') as (root, db):
            before = select_artifacts(db, evidence=first, run=first_run['run_id'])
            rerun = native_analyze(root, db, first)
            self.assertEqual(rerun['new_records'], 0)
            self.assertEqual(before, select_artifacts(db, evidence=first, run=rerun['run_id']))

    def test_wal_only_value_reaches_gui_with_sidecar_provenance(self):
        writer = sqlite3.connect(self.source)
        self.addCleanup(writer.close)
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute('PRAGMA wal_autocheckpoint=0')
        writer.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        writer.execute("INSERT INTO ABMultiValue(rowid,record_id,property,value,label,UID) VALUES(50,12,3,'+12025550150',7,950)")
        writer.commit()
        evidence, _, hashes = self.ingest()
        rows = self.query(evidence=evidence, presentation='investigator', phone_query='+12025550150')['records']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['source_ref'], 'ABPerson:ROWID=12')
        self.assertIn({'logical_path': 'AddressBook.sqlitedb-wal',
            'sha256': hashes['AddressBook.sqlitedb-wal']}, rows[0]['data']['source_sidecars'])
        self.assertEqual(rows[0]['data']['sqlite_wal_coverage']['pairing'], 'unverified')

    def test_native_count_validation_remains_one_record_per_person(self):
        evidence, run, _ = self.ingest()
        with connect(self.workspace, 'IOS') as (root, db), patch(
                'lawliet_mobile.validation.doctor', return_value={'tools': []}):
            report = validate_case(root, db, self.workspace, evidence, parser=VERSION, run=run['run_id'])
        checks = next(item for item in report['checks'] if item['check'] == 'native_table_counts')
        table = next(item for item in checks['tables'] if item['table'] == 'ABPerson')
        self.assertEqual((table['source_rows'], table['indexed_rows'], table['status']), (2, 2, 'pass'))

    def test_missing_multivalue_schema_is_visible_in_native_run(self):
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute('DROP TABLE ABMultiValue')
        _, run, _ = self.ingest()
        self.assertEqual(run['new_records'], 2)
        self.assertTrue(any(item.get('code') == 'ios_contacts_values_schema' for item in run['unparsed_candidates']))
        rows = self.query(presentation='investigator')['records']
        self.assertTrue(all(row['data']['ios_contact']['values_state'] == 'unsupported-schema' for row in rows))

    def test_native_value_limit_is_partial_and_does_not_publish_truncated_contact(self):
        with patch('lawliet_mobile.ios_contacts.MAX_VALUES_PER_CONTACT', 2):
            _, run, _ = self.ingest()
        self.assertEqual(run['status'], 'partial')
        self.assertTrue(any('bounded count/byte limit' in item['error'] for item in run['errors']))
        self.assertEqual(self.query()['records'], [])

    def test_pagination_retains_all_distinct_contact_entries(self):
        with closing(sqlite3.connect(self.source)) as db, db:
            db.executemany('INSERT INTO ABPerson(rowid,First) VALUES(?,?)',
                [(1000 + i, f'Fixture {i:03}') for i in range(103)])
            db.executemany('INSERT INTO ABMultiValue(record_id,property,value) VALUES(?,3,?)',
                [(1000 + i, f'202555{i:04}') for i in range(103)])
        evidence, _, _ = self.ingest()
        first = self.query(evidence=evidence, presentation='investigator', offset=0)
        second = self.query(evidence=evidence, presentation='investigator', offset=100)
        self.assertEqual((len(first['records']), len(second['records'])), (100, 5))
        self.assertTrue(first['has_more'])
        self.assertFalse(second['has_more'])
        self.assertFalse({row['id'] for row in first['records']} & {row['id'] for row in second['records']})


if __name__ == '__main__':
    unittest.main()
