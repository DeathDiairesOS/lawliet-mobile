import unittest,sqlite3,tempfile
from pathlib import Path
from lawliet_mobile.parsers import parse_database,chromium_timestamp
class ChromiumVisitTests(unittest.TestCase):
 def test_integer_microseconds_exact(self):
  self.assertEqual(chromium_timestamp(13404528000123457),'2025-10-10T00:00:00.123457Z')
 def test_url_summary_distinct_from_visits_and_orphan_retained(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'History'
   with sqlite3.connect(p) as c:
    c.row_factory=sqlite3.Row
    c.executescript('CREATE TABLE urls(id INTEGER,url TEXT,title TEXT,last_visit_time INTEGER);CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER,transition INTEGER);INSERT INTO urls VALUES(1,"https://example.test/cache","cache",13404528000123457);INSERT INTO urls VALUES(2,"https://example.test/visited","visited",13404528000123457);INSERT INTO visits VALUES(10,2,13404528000123457,0);INSERT INTO visits VALUES(11,99,13404528000123458,256);')
    rows=list(parse_database(c,str(p)))
   summaries=[r for r in rows if r[-1].get('browser',{}).get('record_kind')=='url_summary'];visits=[r for r in rows if r[-1].get('browser',{}).get('record_kind')=='visit']
   self.assertEqual(len(summaries),2);self.assertEqual(len(visits),2)
   self.assertFalse(any(r[-1]['url']==1 for r in visits));self.assertEqual(visits[1][-1]['browser']['url_link_state'],'missing');self.assertEqual(visits[1][-1]['transition'],256);self.assertTrue(visits[1][-2].startswith('visits:id=11'))
 def test_unknown_times_not_fabricated(self):
  for value in [None,0,'bad',13404528000123457.0]:self.assertIsNone(chromium_timestamp(value))
if __name__=='__main__':unittest.main()
