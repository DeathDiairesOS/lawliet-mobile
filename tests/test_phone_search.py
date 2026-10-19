import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from lawliet_mobile.core import UserError, connect, create_case, import_evidence, select_artifacts
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.phone_search import has_phone


class PhoneSearchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / 'cases'
        create_case(self.workspace, 'phones')
        self.source = self.root / 'mmssms.db'
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute('CREATE TABLE sms(_id INTEGER,date INTEGER,address TEXT,body TEXT,type INTEGER)')
            db.executemany('INSERT INTO sms VALUES(?,?,?,?,?)', [
                (1, 1700000000001, '2025550100', 'national literal', 1),
                (2, 1700000000002, '(202) 555-0100', 'national formatted', 2),
                (3, 1700000000003, '+12025550100', 'country literal', 1),
                (4, 1700000000004, '+1 (202) 555-0100', 'country formatted', 2),
                (5, 1700000000005, '+442025550100', 'different country', 1),
                (6, 1700000000006, '5550100', 'seven digits', 1),
                (7, 1700000000007, '02025550100', 'leading zero', 1),
                (8, 1700000000008, '+12025550100', 'unknown direction', 99),
                (9, 1700000000009, None, 'body mentions +12025550100', 1),
            ])
        self.original = self.source.read_bytes()
        with connect(self.workspace, 'phones') as (root, db):
            eid, _, _ = import_evidence(root, db, self.source, 'android')
            native_analyze(root, db, eid)

    def rows(self, **filters):
        with connect(self.workspace, 'phones') as (_, db):
            rows = select_artifacts(db, limit=None, **filters)
        self.assertEqual(self.source.read_bytes(), self.original)
        return {row['data']['_id'] for row in rows}

    def test_parenthesized_stored_phone_and_query_match_formatting(self):
        self.assertEqual(self.rows(phone_query='2025550100'), {1, 2})
        self.assertEqual(self.rows(phone_query='(202) 555-0100'), {1, 2})

    def test_national_country_suffix_and_leading_zero_stay_distinct(self):
        for phone, expected in [('+12025550100', {3, 4}), ('+442025550100', {5}),
                                ('5550100', {6}), ('02025550100', {7}),
                                ('00442025550100', set())]:
            with self.subTest(phone=phone):
                self.assertEqual(self.rows(phone_query=phone), expected)

    def test_unknown_direction_and_body_only_do_not_assign_phone_roles(self):
        self.assertEqual(self.rows(phone_query='+12025550100'), {3, 4})
        self.assertEqual(self.rows(query='unknown direction'), {8})
        self.assertEqual(self.rows(query='body mentions'), {9})

    def test_phone_and_text_filters_are_combined(self):
        self.assertEqual(self.rows(phone_query='(202) 555-0100', query='formatted'), {2})

    def test_supplied_leapp_phone_field_uses_same_formatting_rule(self):
        data = {'_leapp_report_name': 'Fixture report', '_leapp_fields': {'Phone Number': '(202) 555-0100'}}
        self.assertTrue(has_phone(json.dumps(data), '2025550100'))
        self.assertFalse(has_phone(json.dumps(data), '12025550100'))

    def test_extensions_short_unicode_and_signed_inputs_remain_refused(self):
        for phone in ('2025550100 ext 9', '123', '２０２５５５０１００', '-2025550100', '++12025550100'):
            with self.subTest(phone=phone), self.assertRaises(UserError):
                self.rows(phone_query=phone)


if __name__ == '__main__':
    unittest.main()
