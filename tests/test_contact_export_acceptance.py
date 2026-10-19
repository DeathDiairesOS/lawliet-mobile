"""Offline contact-export acceptance; not a qualification of USB collection."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect, create_case, import_evidence, select_artifacts, verify
from lawliet_mobile.parsers import native_analyze


class ContactExportAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'contacts-qa')
        self.source = self.base / 'selected-contacts.vcf'

    def ingest(self, text):
        self.source.write_text(text, encoding='utf-8')
        with connect(self.workspace, 'contacts-qa') as (root, db):
            evidence = import_evidence(root, db, self.source, 'android')[0]
            result = native_analyze(root, db, evidence)
        return evidence, result

    def test_values_source_and_gui_backend_search(self):
        text = ('\ufeffBEGIN:VCARD\nVERSION:3.0\nFN:LM-SEED Zoë\\, 李\n'
                'TEL;TYPE=CELL:+1 (202) 555-0101\nTEL;TYPE=HOME:202-555-0102\n'
                'EMAIL:zoe@example.test\nEMAIL:other@example.test\n'
                'NOTE:First\\nSecond and\n\t folded\nEND:VCARD\n'
                'BEGIN:VCARD\nVERSION:4.0\nFN:LM-SEED Bob\n'
                'TEL:tel:+12025550103\nEND:VCARD\n')
        evidence, result = self.ingest(text)
        self.assertEqual((result['status'], result['new_records']), ('complete', 2))
        with connect(self.workspace, 'contacts-qa') as (root, db):
            rows = select_artifacts(db, evidence=evidence, run=result['run_id'], category='contacts')
            zoe = next(row for row in rows if 'Zoë' in row['title'])
            self.assertEqual(zoe['title'], 'LM-SEED Zoë, 李')
            self.assertEqual(zoe['data']['properties']['TEL'], ['+1 (202) 555-0101', '202-555-0102'])
            self.assertEqual(zoe['data']['properties']['EMAIL'], ['zoe@example.test', 'other@example.test'])
            self.assertEqual(zoe['data']['properties']['NOTE'], ['First\nSecond and folded'])
            self.assertEqual(zoe['source_ref'], 'vcard:record=1')
            self.assertEqual(zoe['logical_path'], self.source.name)
            self.assertEqual(zoe['source_sha256'], hashlib.sha256(self.source.read_bytes()).hexdigest())
            self.assertTrue(verify(root, db)['ok'])
        for query in ('zoë', '202-555-0102', 'other@example.test'):
            result = handle(self.workspace, {'action': 'records', 'case': 'contacts-qa',
                'evidence': evidence, 'category': 'contacts', 'query': query})
            self.assertEqual([r['id'] for r in result['records']], [zoe['id']])

    def test_revision_times_keep_original_and_do_not_invent_timezone(self):
        evidence, result = self.ingest(
            'BEGIN:VCARD\nVERSION:4.0\nFN:With offset\nREV:20261015T100000-0400\nEND:VCARD\n'
            'BEGIN:VCARD\nVERSION:3.0\nFN:Without timezone\nREV:20261015T100000\nEND:VCARD\n')
        with connect(self.workspace, 'contacts-qa') as (_, db):
            rows = {r['title']: r for r in select_artifacts(db, evidence=evidence, run=result['run_id'])}
            self.assertEqual(rows['With offset']['timestamp'], '2026-10-15T14:00:00.000000Z')
            self.assertEqual(rows['With offset']['timestamp_raw'], '20261015T100000-0400')
            self.assertIsNone(rows['Without timezone']['timestamp'])
            self.assertEqual(rows['Without timezone']['timestamp_raw'], '20261015T100000')

    def test_phone_pivot_uses_all_tel_values_without_note_or_identity_inference(self):
        evidence, result = self.ingest(
            'BEGIN:VCARD\nVERSION:3.0\nFN:LM-SEED Alice\n'
            'TEL:+1 (202) 555-0101\nTEL:202-555-0102\nEND:VCARD\n'
            'BEGIN:VCARD\nVERSION:4.0\nFN:LM-SEED Bob\n'
            'TEL:tel:+12025550103\nNOTE:+12025550101\nUID:2025550102\nEND:VCARD\n'
            'BEGIN:VCARD\nVERSION:4.0\nFN:LM-SEED Extension\n'
            'TEL:tel:+12025550101;ext=9\nEND:VCARD\n')
        for number, expected in [('+12025550101', ['LM-SEED Alice']),
                ('(202) 555-0102', ['LM-SEED Alice']),
                ('+1 202 555 0103', ['LM-SEED Bob']),
                ('2025550101', []), ('+442025550101', [])]:
            with self.subTest(number=number):
                page = handle(self.workspace, {'action': 'records', 'case': 'contacts-qa',
                    'evidence': evidence, 'run': result['run_id'], 'category': 'contacts',
                    'phone_query': number})
                self.assertEqual([row['title'] for row in page['records']], expected)

    def test_malformed_later_card_does_not_leave_partial_contact_rows(self):
        evidence, result = self.ingest(
            'BEGIN:VCARD\nVERSION:3.0\nFN:Valid first\nEND:VCARD\n'
            'BEGIN:VCARD\nVERSION:2.1\nFN:Unsupported later\nEND:VCARD\n')
        self.assertNotEqual(result['status'], 'complete')
        with connect(self.workspace, 'contacts-qa') as (root, db):
            self.assertEqual(select_artifacts(db, evidence=evidence, category='contacts'), [])
            self.assertTrue(verify(root, db)['ok'])

    def test_rerun_reuses_rows_and_imported_bytes_survive_source_change(self):
        evidence, first = self.ingest('BEGIN:VCARD\nVERSION:3.0\nFN:LM-SEED Alice\nTEL:202-555-0101\nEND:VCARD\n')
        self.source.write_text('Changed external source', encoding='utf-8')
        with connect(self.workspace, 'contacts-qa') as (root, db):
            first_rows = select_artifacts(db, evidence=evidence, run=first['run_id'])
            second = native_analyze(root, db, evidence)
            self.assertEqual(second['new_records'], 0)
            self.assertEqual(first_rows, select_artifacts(db, evidence=evidence, run=second['run_id']))
            self.assertEqual(first_rows[0]['title'], 'LM-SEED Alice')
            self.assertTrue(verify(root, db)['ok'])
