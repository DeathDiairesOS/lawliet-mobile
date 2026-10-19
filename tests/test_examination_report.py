import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile import investigation as inv
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, create_case, connect, import_evidence, add_artifact, now
from lawliet_mobile.examination_report import prepare, checked
from lawliet_mobile.investigation_report import (build_customer_draft, approve_customer_draft,
    release_customer_draft, create_redacted_customer_draft)


class ExaminationReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name); self.ws=self.base/'cases'; create_case(self.ws,'A'); create_case(self.ws,'B')
        self.eids=[]
        with connect(self.ws,'A') as (root,db):
            for name in ('selected','EXCLUDED_CANARY'):
                source=self.base/(name+'.txt');source.write_text(name+' known activity')
                eid=import_evidence(root,db,source,'android')[0];self.eids.append(eid)
                fid=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
                add_artifact(db,eid,fid,'messages',None,None,name,'known activity','line=1','synthetic/1',{})
            db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',('failed-run',self.eids[0],'synthetic/1',now(),now(),'failed',0,json.dumps({'error':'fixture failed module'})))

    def request(self, **changes):
        return {'action':'investigation-from-examination','case':'A','objective':'Examine selected indexed records',
                'evidence_ids':[self.eids[0]],'outcome':'no_matches','examiner':'Synthetic Examiner',
                'examination_scope':'Selected indexed title/body only','limitations':'No complete device acquisition',
                'queries':['missing phrase'],**changes}

    def bind(self, root, db, **changes):
        q=self.request(**changes)
        return prepare(root,db,*[q[k] for k in ('objective','evidence_ids','outcome','examiner','examination_scope','limitations','queries')])

    def test_real_query_receipt_dedicated_summary_draft_approval_and_release(self):
        result=handle(self.ws,self.request())
        with connect(self.ws,'A') as (root,db):
            iid=result['investigation_id'];summary=result['examination'];q=summary['queries'][0]
            self.assertEqual(summary['label'],'No indexed matches');self.assertEqual(q['returned_records'],0)
            self.assertFalse(q['has_more']);self.assertEqual(q['event_sha256'],inv.event_receipt(db,iid,q['action_key']))
            self.assertEqual([r[0] for r in db.execute('SELECT kind FROM investigation_events ORDER BY sequence')],['tool.completed','examination.summary'])
            self.assertEqual(inv.verify_ledger(db)['events_checked'],2)
            draft=build_customer_draft(root,db,iid);folder=Path(draft['path'])
            annex=json.loads((folder/'technical-annex.json').read_text());machine=json.loads((folder/'investigation.json').read_text())
            self.assertEqual(annex['examination'],summary);self.assertEqual(machine['examination'],summary)
            self.assertEqual(annex['entries'],[]);self.assertEqual(annex['citations'],[])
            self.assertEqual(draft['counts'],{'unique_cited_artifacts':0,'entries':0})
            for f in folder.iterdir():self.assertNotIn('EXCLUDED_CANARY',f.read_text())
            self.assertIn('No indexed matches',(folder/'report.txt').read_text());self.assertIn(q['action_key'],(folder/'report.txt').read_text())
            with self.assertRaisesRegex(UserError,'approval'):release_customer_draft(root,db,draft['draft_id'],self.base/'unapproved')
            approve_customer_draft(root,db,draft['draft_id'],'Fixture reviewer','Fixture exact-byte approval')
            release_customer_draft(root,db,draft['draft_id'],self.base/'released')

    def test_inconclusive_empty_index_captures_failed_and_missing_processing(self):
        with connect(self.ws,'A') as (root,db):
            db.execute('DELETE FROM artifacts WHERE evidence_id=?',(self.eids[0],))
            result=self.bind(root,db,outcome='inconclusive',queries=[])
            summary=result['examination'];self.assertEqual(summary['queries'],[])
            self.assertEqual(summary['snapshot']['counts']['artifacts'],0)
            self.assertEqual(summary['snapshot']['processing_status_counts'],{'failed':1})
            self.assertEqual(build_customer_draft(root,db,result['investigation_id'])['counts']['entries'],0)
            other=self.bind(root,db,outcome='inconclusive',queries=[],evidence_ids=[self.eids[1]])
            self.assertEqual(other['examination']['snapshot']['evidence_inventory'][0]['runs'],0)

    def test_no_matches_requires_real_queries_and_index_and_all_zero(self):
        for changes in ({'queries':[]},{'queries':['known activity']},{'queries':['missing','activity']},
                        {'evidence_ids':[]},{'evidence_ids':[self.eids[0]]*2},{'evidence_ids':['foreign']},
                        {'examiner':''},{'limitations':''},{'examination_scope':''},{'queries':['x']*21},
                        {'queries':['x'*1001]},{'outcome':{}},{'queries':[1]},{'queries':['x','x']}):
            with self.subTest(changes=changes), self.assertRaises(UserError):handle(self.ws,self.request(**changes))
        with connect(self.ws,'A') as (root,db):
            db.execute('DELETE FROM artifacts WHERE evidence_id=?',(self.eids[0],))
            with self.assertRaisesRegex(UserError,'nonempty indexed'):self.bind(root,db)
            self.assertFalse(db.execute("SELECT 1 FROM sqlite_master WHERE name='investigations'").fetchone())

    def test_literal_queries_and_paginated_positive_inconclusive_results(self):
        with connect(self.ws,'A') as (root,db):
            for i in range(105):add_artifact(db,self.eids[0],None,'messages',None,None,str(i),'repeated marker',str(i),'synthetic/1',{})
            result=self.bind(root,db,outcome='inconclusive',queries=['repeated marker','%'])
            self.assertEqual(result['examination']['queries'][0]['returned_records'],100)
            self.assertTrue(result['examination']['queries'][0]['has_more'])
            self.assertEqual(result['examination']['queries'][1]['returned_records'],0)

    def test_failed_query_rolls_back_entire_investigation_and_audit(self):
        with connect(self.ws,'A') as (root,db):
            before=db.execute('SELECT count(*) FROM audit').fetchone()[0];original=inv.query
            calls=[]
            def fail(*args,**kwargs):
                calls.append(1)
                if len(calls)==2:raise UserError('Synthetic interrupted second query')
                return original(*args,**kwargs)
            with patch.object(inv,'query',side_effect=fail),self.assertRaises(UserError):self.bind(root,db,queries=['missing','absent'])
            self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0],before)
            self.assertFalse(db.execute("SELECT 1 FROM sqlite_master WHERE name='investigations'").fetchone())

    def test_selected_index_changes_block_draft_and_approval(self):
        for change in ('artifact','run','file'):
            with self.subTest(change=change),connect(self.ws,'A') as (root,db):
                result=self.bind(root,db);draft=build_customer_draft(root,db,result['investigation_id'])
                db.execute('SAVEPOINT mutation')
                if change=='artifact':db.execute("UPDATE artifacts SET body='changed' WHERE evidence_id=?",(self.eids[0],))
                elif change=='run':db.execute("UPDATE runs SET status='complete' WHERE evidence_id=?",(self.eids[0],))
                else:db.execute("UPDATE files SET logical_path='new mapping' WHERE evidence_id=?",(self.eids[0],))
                with self.assertRaisesRegex(UserError,'input index'):build_customer_draft(root,db,result['investigation_id'])
                with self.assertRaisesRegex(UserError,'input index'):approve_customer_draft(root,db,draft['draft_id'],'Fixture','Fixture approval')
                db.execute('ROLLBACK TO mutation');db.execute('RELEASE mutation')

    def test_source_tamper_or_symlink_blocks_preparation_approval_and_release(self):
        with connect(self.ws,'A') as (root,db):
            result=self.bind(root,db);draft=build_customer_draft(root,db,result['investigation_id'])
            approve_customer_draft(root,db,draft['draft_id'],'Fixture','Fixture approval')
            row=db.execute('SELECT * FROM files WHERE evidence_id=?',(self.eids[0],)).fetchone();source=root/'evidence'/self.eids[0]/row['path'];original=source.read_bytes()
            source.write_bytes(b'changed')
            for callback in (lambda:self.bind(root,db),lambda:approve_customer_draft(root,db,draft['draft_id'],'Fixture','Fixture approval'),lambda:release_customer_draft(root,db,draft['draft_id'],self.base/'blocked')):
                with self.assertRaisesRegex(UserError,'source integrity'):callback()
            self.assertFalse((self.base/'blocked').exists())
            outside=self.base/'same';outside.write_bytes(original);source.unlink();source.symlink_to(outside)
            with self.assertRaisesRegex(UserError,'unsafe'):self.bind(root,db)

    def test_unselected_changes_do_not_invalidate_scope_or_leak_content(self):
        with connect(self.ws,'A') as (root,db):
            result=self.bind(root,db)
            db.execute("UPDATE artifacts SET body='FOREIGN_NEW_CANARY' WHERE evidence_id=?",(self.eids[1],))
            db.execute('CREATE TABLE artifact_runs(run_id TEXT,artifact_id TEXT)')
            self.assertEqual(checked(root,db,result['investigation_id']),result['examination'])
            draft=build_customer_draft(root,db,result['investigation_id'])
            for f in Path(draft['path']).iterdir():self.assertNotIn('FOREIGN_NEW_CANARY',f.read_text())

    def test_directory_replacement_during_hashing_is_refused(self):
        from contextlib import contextmanager
        from lawliet_mobile import examination_report as module
        with connect(self.ws,'A') as (root,db):
            row=db.execute('SELECT * FROM files WHERE evidence_id=?',(self.eids[0],)).fetchone()
            parent=root/'evidence'/self.eids[0]; original=module.os.fdopen; swapped=[]
            @contextmanager
            def replacing(*args,**kwargs):
                with original(*args,**kwargs) as stream:
                    if not swapped:
                        moved=parent.with_name(parent.name+'-old');parent.rename(moved);parent.mkdir()
                        (parent/row['path']).write_bytes((moved/row['path']).read_bytes());swapped.append(True)
                    yield stream
            with patch.object(module.os,'fdopen',side_effect=replacing),self.assertRaisesRegex(UserError,'directory changed'):
                self.bind(root,db)

    def test_tampered_summary_and_wrong_case_refused(self):
        result=handle(self.ws,self.request())
        with connect(self.ws,'B') as (root,db):
            with self.assertRaises(UserError):build_customer_draft(root,db,result['investigation_id'])
        with connect(self.ws,'A') as (root,db):
            db.execute("UPDATE investigation_events SET result='{}' WHERE kind='examination.summary'")
            with self.assertRaisesRegex(UserError,'integrity'):build_customer_draft(root,db,result['investigation_id'])

    def test_redaction_cannot_rewrite_outcome_but_can_mask_examiner(self):
        with connect(self.ws,'A') as (root,db):
            result=self.bind(root,db);draft=build_customer_draft(root,db,result['investigation_id'])
            with self.assertRaisesRegex(UserError,'examination outcome'):create_redacted_customer_draft(root,db,draft['draft_id'],['no_matches'])
            derivative=create_redacted_customer_draft(root,db,draft['draft_id'],['Synthetic Examiner'])
            value=json.loads((Path(derivative['path'])/'technical-annex.json').read_text())['examination']
            self.assertEqual(value['outcome'],'no_matches');self.assertEqual(value['examiner'],'[REDACTED]')


if __name__=='__main__':unittest.main()
