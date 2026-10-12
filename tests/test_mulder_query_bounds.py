import hashlib,importlib.util,inspect,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
class BoundsTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  try:
   from mulder.server.tools import phone
  except ModuleNotFoundError as error:
   if error.name != 'mulder': raise
   raise unittest.SkipTest('Requires the patched Mulder integration runtime')
  from lawliet_mobile.core import create_case,connect
  cls.temp=tempfile.TemporaryDirectory();cls.base=Path(cls.temp.name).resolve();ws=cls.base/'lawliet-review';create_case(ws,'BOUNDS')
  with connect(ws,'BOUNDS') as (root,db):
   cls.root=root
   db.execute("INSERT INTO evidence(id,label) VALUES('e','fixture')")
   db.execute("INSERT INTO files(evidence_id,path,logical_path,sha256,size) VALUES('e','sms.db','sms.db',?,0)",('0'*64,))
   stamps=['2025-11-02T00:00:00.000000Z','2025-11-02T05:30:00.000000Z','2025-11-02T05:30:00.000001Z','2025-11-02T06:30:00.000000Z',None]
   for i,stamp in enumerate(stamps):
    data={'message':{'app':'sms','conversation_id':'group','sender':'+12025550100','recipient':''}}
    db.execute('INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?)',(str(i),'e',1,'messages',stamp,str(i),'title','literal 東京 %_',f'sms:{i}','synthetic/1',json.dumps(data)))
   db.commit()
  cls.mod=phone
  cls.fn=staticmethod(inspect.unwrap(cls.mod.query_ancalor_review));cls.ctx=patch.object(cls.mod,'get_ctx',return_value=SimpleNamespace(db=SimpleNamespace(db_path=cls.base/'case.db')));cls.ctx.start();cls.before=hashlib.sha256((cls.root/'case.sqlite').read_bytes()).hexdigest()
 @classmethod
 def tearDownClass(cls):
  assert hashlib.sha256((cls.root/'case.sqlite').read_bytes()).hexdigest()==cls.before
  cls.ctx.stop();cls.temp.cleanup()
 def query(self,**kw):return self.fn(str(self.root),**kw)
 def ids(self,r):return [x['id'] for x in r['records']]
 def test_seconds_and_six_fraction_inclusive(self):
  for lo,hi in [('2025-11-02T05:30:00Z','2025-11-02T06:30:00Z'),('2025-11-02T05:30:00.000000Z','2025-11-02T06:30:00.000000Z')]:
   r=self.query(since=lo,until=hi);self.assertEqual(self.ids(r),['1','2','3']);self.assertEqual(r['requested_bounds'],{'since':lo,'until':hi});self.assertEqual(r['since'],'2025-11-02T05:30:00.000000Z')
 def test_dst_distinct_offsets(self):
  self.assertEqual(self.ids(self.query(since='2025-11-02T01:30:00-04:00',until='2025-11-02T01:30:00-05:00')),['1','2','3'])
 def test_microsecond_not_rounded(self):
  self.assertEqual(self.ids(self.query(since='2025-11-02T05:30:00.000001Z',until='2025-11-02T05:30:00.000001Z')),['2'])
 def test_date_only_midnight(self):
  r=self.query(since='2025-11-02',until='2025-11-02');self.assertEqual(self.ids(r),['0']);self.assertEqual(r['since'],'2025-11-02T00:00:00.000000Z')
 def test_none_default_and_undated(self):
  self.assertEqual(self.ids(self.query()),['0','1','2','3','4']);self.assertEqual(self.ids(self.query(since='2025-11-02')),['0','1','2','3']);self.assertEqual(self.query()['requested_bounds'],{'since':None,'until':None})
 def test_invalid_refused_before_case_probe(self):
  for bound in ('since','until'):
   for value in ('',' ','garbage','1762061400','2025-11-02T01:30:00','2025-11-02T05:30:00.0000001Z','2025-13-02','2025-11-02Tbad',True,42):
    with self.subTest(bound=bound,value=value),patch.object(self.mod,'_ancalor_review_case',side_effect=AssertionError('case probed')):
     with self.assertRaises(ValueError):self.query(**{bound:value})
 def test_selectors_pagination_unchanged(self):
  r=self.query(since='2025-11-02',query='東京 %_',category='messages',app='sms',conversation='group',phone_query='+1 (202) 555-0100',limit=2,offset=1)
  self.assertEqual(self.ids(r),['1','2']);self.assertTrue(r['truncated']);self.assertEqual(r['next_offset'],3);self.assertEqual(self.query(query='absent')['returned_records'],0)
if __name__=='__main__':unittest.main()
