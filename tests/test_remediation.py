import json
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.core import create_case,connect,import_evidence,UserError
from lawliet_mobile import remediation as r, investigation as inv

class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.ws=self.base/'cases'
        create_case(self.ws,'A');create_case(self.ws,'B');source=self.base/'source.txt';source.write_text('synthetic source')
        with connect(self.ws,'A') as (root,db):
            self.eid=import_evidence(root,db,source,'unknown')[0];self.fid=db.execute('SELECT id FROM files').fetchone()[0]
        self.value={'actor':'Synthetic operator','description':'Operator-chosen step, not product advice','category':'remediation','status':'recommended','file_ids':[self.fid]}
    def test_recommendation_completion_and_correction_keep_history(self):
        with connect(self.ws,'A') as (root,db):
            first=r.record(db,self.value);self.assertEqual(first['status'],'recommended');self.assertEqual(first['execution'],'not-executed-by-tool')
            update={**self.value,'action_id':first['action_id'],'latest_event_id':first['event_id'],'status':'completed','supporting_reference':'Operator receipt TEST-ONLY','preservation_agreement_reference':'Synthetic agreed preservation reference','change_reason':'Operator reports completion'}
            completed=r.record(db,update)
            unknown=r.record(db,{**update,'latest_event_id':completed['event_id'],'status':'unknown','change_reason':'Completion receipt disputed'})
            events=r.history(db)['events'];self.assertEqual([e['status'] for e in events],['recommended','completed','unknown']);self.assertEqual(unknown['previous_event_id'],completed['event_id'])
            self.assertEqual(events[0]['sources'][0]['logical_path'],'source.txt');self.assertEqual(len(events[0]['sources'][0]['sha256']),64)
    def test_completion_and_preservation_require_distinct_support(self):
        with connect(self.ws,'A') as (root,db):
            for updates in [{'status':'completed'},{'status':'completed','supporting_reference':'receipt'},{'category':'preservation','status':'preserved'},{'category':'preservation','status':'completed'},{'status':'preserved'}]:
                with self.subTest(updates=updates),self.assertRaises(UserError):r.record(db,{**self.value,**updates})
            preserved=r.record(db,{**self.value,'category':'preservation','status':'preserved','supporting_reference':'Preservation receipt'})
            self.assertEqual(preserved['verification'],'operator-recorded; independently unverified');self.assertEqual(r.history(db)['events'][0]['status'],'preserved')
    def test_wrong_case_unknown_source_and_scope_refused(self):
        with connect(self.ws,'B') as (root,db):
            with self.assertRaises(UserError):r.record(db,self.value)
        with connect(self.ws,'A') as (root,db):
            other=self.base/'other.txt';other.write_text('other');eid=import_evidence(root,db,other,'unknown')[0];iid=inv.create(db,'Other scope',[eid])['id']
            with self.assertRaisesRegex(UserError,'scope'):r.record(db,{**self.value,'investigation_id':iid})
            with self.assertRaises(UserError):r.record(db,{**self.value,'file_ids':[]})
            result=r.record(db,{**self.value,'file_ids':[],'investigation_id':iid,'status':'unknown'});self.assertEqual(result['sources'],[])
    def test_stale_update_scope_change_and_mutation_refused(self):
        with connect(self.ws,'A') as (root,db):
            first=r.record(db,self.value)
            for updates in [{'latest_event_id':'wrong'},{'latest_event_id':first['event_id'],'category':'preservation','status':'unknown'},{'latest_event_id':first['event_id'],'change_reason':''}]:
                with self.assertRaises(UserError):r.record(db,{**self.value,'action_id':first['action_id'],'change_reason':'reason',**updates})
            db.execute("UPDATE audit SET detail='{}' WHERE action=?",(r.ACTION,))
            with self.assertRaisesRegex(UserError,'audit chain'):r.history(db)
            with self.assertRaises(UserError):r.record(db,self.value)
    def test_pagination_and_no_source_changes(self):
        with connect(self.ws,'A') as (root,db):
            before={str(p):p.read_bytes() for p in (root/'evidence').rglob('*') if p.is_file()}
            for i in range(3):r.record(db,{**self.value,'description':str(i)})
            page=r.history(db,limit=2);self.assertTrue(page['has_more']);last=r.history(db,after=page['next_cursor'],limit=2);self.assertEqual(len(last['events']),1)
            self.assertEqual(before,{str(p):p.read_bytes() for p in (root/'evidence').rglob('*') if p.is_file()})
            self.assertEqual(r.history(db,action_id='unknown')['events'],[])

    def test_stdio_bridge_scopes_records_and_rejects_tampering(self):
        import subprocess,sys
        def call(action,case='A',**values):
            proc=subprocess.run([sys.executable,'-m','lawliet_mobile.app_backend'],input=json.dumps({'workspace':str(self.ws),'case':case,'action':action,**values}),text=True,capture_output=True)
            result=json.loads(proc.stdout);self.assertEqual(proc.returncode,0 if result['ok'] else 1);return result
        saved=call('remediation-record',event=self.value);self.assertTrue(saved['ok'],saved)
        page=call('remediation-history',limit=1)['result'];self.assertEqual(page['events'][0]['event_id'],saved['result']['event_id'])
        self.assertEqual(call('remediation-history',case='B')['result']['events'],[])
        self.assertFalse(call('remediation-record',event=None)['ok'])
        with connect(self.ws,'A') as (_,db):db.execute("UPDATE audit SET detail='{}' WHERE action=?",(r.ACTION,))
        self.assertFalse(call('remediation-history')['ok']);self.assertFalse(call('remediation-record',event=self.value)['ok'])

    def test_two_connection_stale_revision_serialized(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        with connect(self.ws,'A') as (_,db):first=r.record(db,self.value)
        barrier=threading.Barrier(2)
        update={**self.value,'action_id':first['action_id'],'latest_event_id':first['event_id'],'change_reason':'Concurrent operator correction','status':'unknown'}
        def write():
            with connect(self.ws,'A') as (_,db):
                barrier.wait(timeout=5)
                try:return r.record(db,update)['event_id']
                except UserError as exc:return str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:write(),range(2)))
        self.assertEqual(sum('Stale remediation action' in item for item in results),1,results)
        with connect(self.ws,'A') as (_,db):self.assertEqual(len(r.history(db)['events']),2)
