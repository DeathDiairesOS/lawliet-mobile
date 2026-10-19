"""Exact integer timestamp conversion with explicit microsecond reduction."""
import sqlite3
import unittest
from lawliet_mobile.parsers import timestamp,parse_database

class TimestampPrecision(unittest.TestCase):
    def test_apple_nanosecond_rounding_without_float_loss(self):
        base=780000000000000000
        expected={499:'00.000000',500:'00.000000',501:'00.000001',1499:'00.000001',1500:'00.000002',1501:'00.000002',999999499:'00.999999',999999500:'01.000000',999999501:'01.000000',999999999:'01.000000'}
        for tail,clock in expected.items():
            with self.subTest(tail=tail):
                value=base+tail
                want='2025-09-19T18:40:'+clock+'Z'
                self.assertEqual(timestamp(value,'apple','nanoseconds'),want)
                self.assertEqual(timestamp(str(value),'apple','nanoseconds'),want)

    def test_negative_nanoseconds_and_even_ties(self):
        for value,want in [(-499,'2001-01-01T00:00:00.000000Z'),(-500,'2001-01-01T00:00:00.000000Z'),(-501,'2000-12-31T23:59:59.999999Z'),(-1500,'2000-12-31T23:59:59.999998Z')]:
            self.assertEqual(timestamp(value,'apple','nanoseconds'),want)

    def test_integer_seconds_milliseconds_and_date_range(self):
        self.assertEqual(timestamp(1760000000123,unit='milliseconds'),'2025-10-09T08:53:20.123000Z')
        self.assertEqual(timestamp('1760000000'),'2025-10-09T08:53:20.000000Z')
        self.assertIsNone(timestamp(10**100,'apple','nanoseconds'))
        self.assertIsNone(timestamp('9'*5000,'apple','nanoseconds'))

    def test_existing_offset_unknown_timezone_and_float_behavior(self):
        self.assertEqual(timestamp('2026-10-10T10:00:00-04:00'),'2026-10-10T14:00:00.000000Z')
        self.assertIsNone(timestamp('2026-10-10 10:00:00'))
        self.assertEqual(timestamp(1760000000.25),'2025-10-09T08:53:20.250000Z')
        self.assertIsNone(timestamp(float('inf')))

    def rows(self,value,column_type='INTEGER'):
        db=sqlite3.connect(':memory:');self.addCleanup(db.close);db.row_factory=sqlite3.Row
        db.execute('CREATE TABLE handle(id TEXT)')
        db.execute('INSERT INTO handle VALUES(?)',('seed',))
        db.execute(f'CREATE TABLE message(date {column_type},text TEXT,is_from_me INTEGER,service TEXT,handle_id INTEGER)')
        db.execute('INSERT INTO message VALUES(?,?,?,?,?)',(value,'precision seed',1,'iMessage',1))
        return list(parse_database(db,'sms.db'))

    def test_ios_raw_integer_and_reduction_metadata_preserved(self):
        value=780000000000000501
        category,when,raw,title,body,source,data=self.rows(value)[0]
        self.assertEqual((when,raw,data['date']),('2025-09-19T18:40:00.000001Z',value,value))
        conversion=data['timestamp_conversion']
        self.assertEqual(conversion['source_field'],'date')
        self.assertEqual(conversion['normalized_resolution'],'microsecond')
        self.assertEqual(conversion['source_minus_normalized_nanoseconds'],-499)
        self.assertEqual(conversion['method'],'exact_integer_nearest_microsecond_ties_even')
        self.assertIn('not independently verified',conversion['limitation'])
        self.assertIn('heuristic',conversion['unit_selection'])

    def test_stored_real_is_not_claimed_exact(self):
        data=self.rows(float(780000000000000501),'REAL')[0][-1]
        self.assertEqual(data['timestamp_conversion']['method'],'floating_point_approximation')
        self.assertNotIn('source_minus_normalized_nanoseconds',data['timestamp_conversion'])

    def test_dst_offsets_remain_distinct_and_unknown_zone_undated(self):
        self.assertEqual(timestamp('2025-11-02T01:30:00-04:00'),'2025-11-02T05:30:00.000000Z')
        self.assertEqual(timestamp('2025-11-02T01:30:00-05:00'),'2025-11-02T06:30:00.000000Z')
        self.assertIsNone(timestamp('2025-11-02T01:30:00'))
        for value in [None,'','invalid','2025-99-99T00:00:00Z']:
            self.assertIsNone(timestamp(value))

    def test_missing_ios_date_remains_undated_with_unavailable_status(self):
        row=self.rows(None)[0]
        self.assertIsNone(row[1]);self.assertIsNone(row[2])
        self.assertEqual(row[-1]['timestamp_conversion']['method'],'unavailable')
        self.assertEqual(row[-1]['timestamp_conversion']['normalization_status'],'unavailable')
