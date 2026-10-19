import json
from pathlib import Path
import tempfile
import unittest

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import add_artifact, connect, create_case, import_evidence, UserError


class RecordPaginationTests(unittest.TestCase):
    """Seeded-index navigation tests; not independent parser/device accuracy."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.ws=self.base/'cases';create_case(self.ws,'A')
        self.key=[]
        for i in range(237):
            self.key.append({'source_ref':f'seed:id={i:03d}','category':'messages' if i<127 else 'browser',
                'timestamp':f'2025-11-{1+i//24:02d}T{i%24:02d}:00:00.000000Z' if i<230 else None,
                'body':f'Row {i} '+('café 東京' if i%17==0 else 'ordinary'),
                'data':{'message':{'app':'sms','sender':'+12025550100' if i%3==0 else '+442025550100'}}})
        source=self.base/'frozen-seed.jsonl';source.write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in self.key))
        with connect(self.ws,'A') as (root,db):
            eid=import_evidence(root,db,source,'android')[0];fid=db.execute('SELECT id FROM files').fetchone()[0]
            for x in self.key:add_artifact(db,eid,fid,x['category'],x['timestamp'],x['timestamp'],'Synthetic',x['body'],x['source_ref'],'seeded-index/1',x['data'])
            ids=dict(db.execute('SELECT source_ref,id FROM artifacts'))
        for x in self.key:x['id']=ids[x['source_ref']]
        self.key.sort(key=lambda x:(x['timestamp'] is None,x['timestamp'] or '',x['id']))

    def call(self, **kwargs):return handle(self.ws,{'case':'A','action':'records',**kwargs})

    def test_invalid_cursor_refused_without_coercion(self):
        for value in [True,False,-1,1.5,'1',None,2**63]:
            with self.subTest(offset=value),self.assertRaises(UserError):self.call(offset=value)

    def test_exact_page_sets_in_both_presentations(self):
        for presentation in ['source','investigator']:
            seen=[]
            for offset,size,more in [(0,100,True),(100,100,True),(200,37,False),(237,0,False),(2**63-1,0,False)]:
                with self.subTest(presentation=presentation,offset=offset):
                    result=self.call(presentation=presentation,offset=offset)
                    self.assertEqual(len(result['records']),size);self.assertEqual(result['has_more'],more)
                    self.assertEqual([x['id'] for x in result['records']],[x['id'] for x in self.key[offset:offset+100]])
                    if offset<237:seen.extend(x['id'] for x in result['records'])
            self.assertEqual(len(seen),237);self.assertEqual(len(set(seen)),237)

    def test_scoped_messages_remain_exact_across_pages(self):
        expected=[x for x in self.key if x['category']=='messages']
        for presentation in ['source','investigator']:
            first=self.call(category='messages',presentation=presentation,offset=0)
            second=self.call(category='messages',presentation=presentation,offset=100)
            self.assertTrue(first['has_more']);self.assertFalse(second['has_more'])
            self.assertEqual([x['id'] for x in first['records']+second['records']],[x['id'] for x in expected])

    def test_combined_unicode_category_dates_and_phone_match_frozen_key(self):
        filters={'category':'messages','query':'CAFÉ 東京','since':'2025-11-02','until':'2025-11-05','phone_query':'+1 (202) 555-0100'}
        expected=[x for x in self.key if x['category']=='messages' and 'café 東京' in x['body'].casefold()
                  and x['timestamp'] and '2025-11-02T00:00:00.000000Z'<=x['timestamp']<='2025-11-05T00:00:00.000000Z'
                  and x['data']['message']['sender']=='+12025550100']
        self.assertTrue(expected)
        for presentation in ['source','investigator']:
            result=self.call(presentation=presentation,**filters)
            self.assertEqual([x['id'] for x in result['records']],[x['id'] for x in expected])
            out=self.base/(presentation+'.jsonl');handle(self.ws,{'case':'A','action':'export','path':str(out),**filters})
            exported=[json.loads(line) for line in out.read_text().splitlines()]
            self.assertEqual([x['id'] for x in exported],[x['id'] for x in expected])
            for row,key in zip(exported,expected):
                for field in ['body','source_ref','timestamp','category']:self.assertEqual(row[field],key[field])

    def test_zero_match_and_undated_are_distinct(self):
        result=self.call(query='NO_SUCH_LITERAL');self.assertEqual(result['records'],[]);self.assertFalse(result['has_more'])
        last=self.call(offset=200)['records'];self.assertEqual(sum(x['timestamp'] is None for x in last),7)
        dated=[]
        for offset in [0,100,200]:dated+=self.call(since='2025-11-01',offset=offset)['records']
        self.assertEqual(len(dated),230);self.assertTrue(all(x['timestamp'] for x in dated))
