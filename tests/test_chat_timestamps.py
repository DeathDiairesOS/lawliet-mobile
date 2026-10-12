import unittest
import json
import tempfile
from pathlib import Path
from zoneinfo import ZoneInfo
from lawliet_mobile.messages import local_time
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, connect, create_case
class DeclaredCenturyTests(unittest.TestCase):
 def test_declared_year_exact_utc(self):
  self.assertEqual(local_time('10/01/26, 09:00','mdy',ZoneInfo('America/New_York'),2000)[0],'2026-10-01T13:00:00.000000Z')
 def test_undeclared_century_stays_unknown(self):
  self.assertIsNone(local_time('10/01/26, 09:00','mdy',ZoneInfo('America/New_York'))[0])
 def test_repeated_hour_stays_unknown(self):
  when,reason=local_time('11/02/25, 01:30:00','mdy',ZoneInfo('America/New_York'),2000)
  self.assertIsNone(when);self.assertIn('Ambiguous',reason)
 def test_missing_zone_stays_unknown(self):
  self.assertIsNone(local_time('10/01/26, 09:00','mdy',None,2000)[0])
 def test_gap_stays_unknown(self):
  self.assertIsNone(local_time('03/09/25, 02:30:00','mdy',ZoneInfo('America/New_York'),2000)[0])
 def test_four_digit_year_unaltered(self):
  self.assertEqual(local_time('10/01/2026, 09:00','mdy',ZoneInfo('America/New_York'),1900)[0],'2026-10-01T13:00:00.000000Z')

class ChatBackendTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'chat')
        self.source = self.base / 'chat.txt'
        self.source.write_text('10/01/26, 09:00 - Jamie: First line\nSecond 😀\n')
        self.request = {'action': 'import-chat', 'case': 'chat',
                        'path': str(self.source), 'date_order': 'mdy',
                        'timezone': 'America/New_York'}

    def test_declared_century_reaches_parser_and_preserves_provenance(self):
        result = handle(self.workspace, dict(self.request, year_century=2000))
        self.assertEqual(result['records'], 1)
        with connect(self.workspace, 'chat') as (_, db):
            row = db.execute('SELECT * FROM artifacts').fetchone()
            self.assertEqual(row['timestamp'], '2026-10-01T13:00:00.000000Z')
            self.assertEqual(row['timestamp_raw'], '10/01/26, 09:00')
            self.assertEqual(row['body'], 'First line\nSecond 😀')
            metadata = json.loads(row['data'])
            self.assertEqual(metadata['year_century'], 2000)
            self.assertEqual(metadata['source_time_precision'], 'minute')

    def test_missing_century_remains_undated_through_backend(self):
        handle(self.workspace, self.request)
        with connect(self.workspace, 'chat') as (_, db):
            self.assertIsNone(db.execute('SELECT timestamp FROM artifacts').fetchone()[0])

    def test_invalid_century_rejected_before_import(self):
        for century in [True, '2000', 2026, 0]:
            with self.subTest(century=century), self.assertRaises(UserError):
                handle(self.workspace, dict(self.request, year_century=century))
        with connect(self.workspace, 'chat') as (_, db):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 0)


if __name__=='__main__':unittest.main()
