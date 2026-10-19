import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile import investigator_view as view
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, add_artifact, connect, create_case, import_evidence


class ReviewBudgetTests(unittest.TestCase):
    def row(self, **values):
        return {'id':'row','evidence_id':'e','file_id':1,'category':'messages',
                'timestamp':None,'timestamp_raw':None,'title':'title','body':'body',
                'source_ref':'row=1','logical_path':'source.db','source_sha256':'a'*64,
                'parser':'native/0.1.11','data':{},**values}

    def test_body_title_and_locator_are_counted_not_only_metadata(self):
        for field in ['body','title','logical_path','source_ref','parser']:
            with self.subTest(field=field):
                row=self.row(**{field:'X'*2048})
                with patch.object(view,'iter_artifacts',return_value=iter([row])),patch.object(view,'MAX_BYTES',1024):
                    with self.assertRaisesRegex(UserError,'byte budget'):
                        view.investigator_records(None,{'category':'messages'})

    def test_utf8_bytes_not_character_count(self):
        row=self.row(body='東京'*300)
        chars=len(json.dumps(row,ensure_ascii=False));size=len(json.dumps(row,ensure_ascii=False).encode())
        self.assertGreater(size,chars)
        with patch.object(view,'iter_artifacts',return_value=iter([row])),patch.object(view,'MAX_BYTES',chars):
            with self.assertRaisesRegex(UserError,'byte budget'):view.investigator_records(None,{'category':'messages'})

    def test_exact_budget_accepts_and_one_byte_less_refuses(self):
        row=self.row();size=len(json.dumps(row,ensure_ascii=False).encode())
        for limit,accepted in [(size,True),(size-1,False)]:
            with self.subTest(limit=limit),patch.object(view,'iter_artifacts',return_value=iter([row])),patch.object(view,'MAX_BYTES',limit):
                if accepted:self.assertEqual(len(view.investigator_records(None,{'category':'messages'})['records']),1)
                else:
                    with self.assertRaises(UserError):view.investigator_records(None,{'category':'messages'})

    def test_stops_iterator_at_first_oversized_row(self):
        visits=[]
        def source():
            visits.append('oversized');yield self.row(body='X'*4096)
            visits.append('unexpected');raise AssertionError('Should stop at budget refusal')
        with patch.object(view,'iter_artifacts',side_effect=lambda *a,**k:source()),patch.object(view,'MAX_BYTES',1024):
            with self.assertRaises(UserError):view.investigator_records(None,{'category':'messages'})
        self.assertEqual(visits,['oversized'])

    def test_combined_records_share_the_budget_and_no_partial_result(self):
        rows=[self.row(id='1'),self.row(id='2')];size=sum(len(json.dumps(row,ensure_ascii=False).encode()) for row in rows)
        with patch.object(view,'iter_artifacts',return_value=iter(rows)),patch.object(view,'MAX_BYTES',size-1):
            with self.assertRaises(UserError):view.investigator_records(None,{'category':'messages'})

    def test_record_ceiling_stops_on_sentinel(self):
        visits=[]
        def source():
            for i in range(4):visits.append(i);yield self.row(id=str(i))
        with patch.object(view,'iter_artifacts',side_effect=lambda *a,**k:source()),patch.object(view,'MAX_RECORDS',1):
            with self.assertRaisesRegex(UserError,'record budget'):view.investigator_records(None,{'category':'messages'})
        self.assertEqual(visits,[0,1])

    def test_contact_uses_same_full_record_budget(self):
        with patch.object(view,'iter_artifacts',return_value=iter([self.row(category='contacts',body='X'*4096)])),patch.object(view,'MAX_BYTES',1024):
            with self.assertRaisesRegex(UserError,'Contact.*byte budget'):view.investigator_records(None,{'category':'contacts'})

    def test_real_backend_refuses_review_but_preserves_source_records_and_export(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp).resolve();ws=base/'cases';create_case(ws,'A');source=base/'source.txt';source.write_text('synthetic')
            with connect(ws,'A') as (root,db):
                eid=import_evidence(root,db,source,'android')[0];fid=db.execute('SELECT id FROM files').fetchone()[0]
                add_artifact(db,eid,fid,'messages',None,None,'Synthetic','東京'*800,'row=1','native/0.1.11',{})
            request={'case':'A','action':'records','category':'messages'}
            with patch.object(view,'MAX_BYTES',1024):
                with self.assertRaisesRegex(UserError,'byte budget'):handle(ws,{**request,'presentation':'investigator'})
                rows=handle(ws,request)['records'];self.assertEqual(len(rows),1)
                out=base/'export.jsonl';result=handle(ws,{'case':'A','action':'export','category':'messages','path':str(out)})
                self.assertEqual(result['records'],1);self.assertEqual(json.loads(out.read_text())['body'],'東京'*800)
            self.assertTrue(handle(ws,{'case':'A','action':'verify'})['ok'])
