import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.core import create_case,connect,UserError,import_evidence
from lawliet_mobile import competency as c

class CompetencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.ws=Path(self.tmp.name)/'cases'
        create_case(self.ws,'A');create_case(self.ws,'B')
        self.value={'examiner':'Synthetic examiner','method':'SQLite WAL review','method_version':'fixture-v1','kind':'training','recorded_by':'Synthetic recorder','description':'Operator says training occurred','references':['Synthetic course receipt; unverified']}
    def review(self,event,**updates):
        return {**self.value,'kind':'review','reviewer':'Synthetic reviewer','review_outcome':'sign-off-recorded','declaration':'Test-only documentary sign-off claim','independence':'claimed','reviewed_event_ids':[event['event_id']],**updates}
    def test_training_practice_signoff_never_promote_competence(self):
        with connect(self.ws,'A') as (_,db):
            first=c.record(db,self.value);practice=c.record(db,{**self.value,'kind':'practice','description':'Claimed all fixture checks passed'})
            signoff=c.record(db,self.review(practice));self.assertEqual(signoff['review_outcome'],'sign-off-recorded')
            for event in c.history(db)['events']:
                self.assertEqual(event['competency_status'],'not-assessed-by-software');self.assertFalse(event['authenticated'])
            self.assertEqual(first['review_outcome'],None)
    def test_scope_wrong_case_and_method_version_rejected(self):
        with connect(self.ws,'A') as (_,db):first=c.record(db,self.value)
        with connect(self.ws,'B') as (_,db):
            with self.assertRaises(UserError):c.record(db,self.review(first))
        with connect(self.ws,'A') as (_,db):
            for change in [{'method':'Different'},{'method_version':'v2'},{'examiner':'Other'}]:
                with self.assertRaises(UserError):c.record(db,self.review(first,**change))
    def test_signoff_declaration_and_self_review_not_inferred(self):
        with connect(self.ws,'A') as (_,db):
            first=c.record(db,self.value)
            for change in [{'declaration':''},{'reviewed_event_ids':[]},{'reviewer':self.value['examiner']},{'review_outcome':'competent'},{'independence':True}]:
                with self.assertRaises(UserError):c.record(db,self.review(first,**change))
            result=c.record(db,self.review(first,reviewer=self.value['examiner'],independence='not-claimed'));self.assertFalse(result['authenticated'])
            with self.assertRaises(UserError):c.record(db,{**self.value,'review_outcome':'sign-off-recorded'})
    def test_correction_preserves_history_and_tamper_refused(self):
        with connect(self.ws,'A') as (_,db):
            first=c.record(db,self.value);review=c.record(db,self.review(first))
            corrected=c.record(db,self.review(first,review_outcome='withdrawn',supersedes_event_id=review['event_id'],change_reason='Operator withdraws claim'))
            self.assertEqual(corrected['supersedes_event_id'],review['event_id']);self.assertEqual(len(c.history(db)['events']),3)
            db.execute("UPDATE audit SET detail='{}' WHERE action=?",(c.ACTION,))
            with self.assertRaises(UserError):c.history(db)
            with self.assertRaises(UserError):c.record(db,self.value)
    def test_pagination_source_snapshot_filters_and_input_bounds(self):
        source=Path(self.tmp.name)/'test.log';source.write_text('synthetic test output')
        with connect(self.ws,'A') as (root,db):
            eid=import_evidence(root,db,source,'unknown')[0];fid=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
            event=c.record(db,{**self.value,'file_ids':[fid]});self.assertEqual(event['sources'][0]['logical_path'],'test.log')
            for i in range(2):c.record(db,{**self.value,'kind':'practice'})
            first=c.history(db,limit=2,method=self.value['method']);self.assertTrue(first['has_more']);self.assertEqual(len(c.history(db,after=first['next_cursor'])['events']),1)
            self.assertEqual(c.history(db,examiner='other')['events'],[])
            for patch in [{'references':[]},{'file_ids':[99999]},{'kind':[]},{'competency_status':'complete'}]:
                with self.assertRaises(UserError):c.record(db,{**self.value,**patch})
            self.assertEqual(source.read_text(),'synthetic test output')

    def test_stdio_bridge_scope_filters_and_tamper_rejection(self):
        import json,subprocess,sys
        def call(action,case='A',**values):
            proc=subprocess.run([sys.executable,'-m','lawliet_mobile.app_backend'],input=json.dumps({'workspace':str(self.ws),'case':case,'action':action,**values}),text=True,capture_output=True)
            result=json.loads(proc.stdout);self.assertEqual(proc.returncode,0 if result['ok'] else 1);return result
        saved=call('competency-record',event=self.value);self.assertTrue(saved['ok'],saved)
        review=call('competency-record',event=self.review(saved['result']));self.assertTrue(review['ok'],review)
        self.assertEqual(review['result']['competency_status'],'not-assessed-by-software');self.assertFalse(review['result']['authenticated'])
        page=call('competency-history',method=self.value['method'],limit=1)['result'];self.assertTrue(page['has_more'])
        self.assertEqual(len(call('competency-history',after=page['next_cursor'])['result']['events']),1)
        self.assertEqual(call('competency-history',case='B')['result']['events'],[])
        self.assertEqual(call('competency-history',examiner='Other')['result']['events'],[])
        self.assertFalse(call('competency-record',event=None)['ok'])
        with connect(self.ws,'A') as (_,db):db.execute("UPDATE audit SET detail='{}' WHERE action=?",(c.ACTION,))
        self.assertFalse(call('competency-history')['ok']);self.assertFalse(call('competency-record',event=self.value)['ok'])

    def test_documentary_correction_branches_do_not_establish_current_qualification(self):
        with connect(self.ws,'A') as (_,db):
            original=c.record(db,self.value)
            for description in ['Operator correction one','Operator correction two']:
                c.record(db,{**self.value,'description':description,'supersedes_event_id':original['event_id'],'change_reason':'Documentary correction claim'})
            history=c.history(db)
            self.assertEqual(len(history['events']),3)
            self.assertEqual([e['supersedes_event_id'] for e in history['events'][1:]],[original['event_id']]*2)
            self.assertEqual(history['competency_status'],'not-assessed-by-software');self.assertFalse(history['authenticated'])
