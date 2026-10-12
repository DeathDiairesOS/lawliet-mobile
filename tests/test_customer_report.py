import json
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.core import create_case,connect,import_evidence,add_artifact,UserError,digest
from lawliet_mobile import investigation as inv
from lawliet_mobile.investigation_report import build_customer_draft,approve_customer_draft,release_customer_draft

class CustomerReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'A');create_case(self.ws,'B')
        with connect(self.ws,'A') as (root,db):
            eids=[];aids=[]
            for name in ('selected','EXCLUDED_CANARY'):
                source=self.base/(name+'.txt');source.write_text(name);eid=import_evidence(root,db,source,'unknown')[0];eids.append(eid)
                fid=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
                add_artifact(db,eid,fid,'messages',None,'ambiguous',name,name+' body','line=1','whatsapp-export/2',{'message':{'attachment_status':'not_acquired'}})
                aids.append(db.execute('SELECT id FROM artifacts WHERE evidence_id=?',(eid,)).fetchone()[0])
            self.iid=inv.create(db,'Did the meeting occur?',[eids[0]])['id'];self.aid=aids[0]
            inv.note(db,self.iid,'observation','Message proposes meeting.',[self.aid]);inv.note(db,self.iid,'interpretation','A proposal is not proof of attendance.',[self.aid]);inv.note(db,self.iid,'question','Attendance remains unknown.');self.source=self.base/'selected.txt';self.hash=digest(self.source)
    def test_draft_source_links_counts_scope_and_missing_attachment(self):
        with connect(self.ws,'A') as (root,db):
            result=build_customer_draft(root,db,self.iid);folder=Path(result['path']);annex=json.loads((folder/'technical-annex.json').read_text())
            self.assertEqual(result['review_status'],'draft_unreviewed');self.assertEqual(result['counts'],{'unique_cited_artifacts':1,'entries':3})
            citation=annex['citations'][0];self.assertEqual(citation['source_tier'],'supplied-text-export');self.assertEqual(citation['source_locator']['recorded_source_sha256'],self.hash);self.assertEqual(citation['source_locator']['record_table_key_or_offset'],'line=1');self.assertEqual(citation['attachment_state'],'not_acquired');self.assertEqual(citation['parser_run_link_state'],'unavailable')
            for path in folder.iterdir():self.assertNotIn('EXCLUDED_CANARY',path.read_text())
            self.assertIn('UTC unknown',(folder/'report.txt').read_text());self.assertIn('INFERENCES / INTERPRETATIONS',(folder/'report.txt').read_text())
            self.assertEqual(digest(self.source),self.hash)
    def test_release_requires_explicit_content_bound_approval(self):
        with connect(self.ws,'A') as (root,db):
            draft=build_customer_draft(root,db,self.iid);dest=self.base/'released'
            with self.assertRaisesRegex(UserError,'approval'):release_customer_draft(root,db,draft['draft_id'],dest)
            self.assertFalse(dest.exists())
            for reviewer,statement in [('', 'approved'),('Synthetic test examiner','')]:
                with self.assertRaises(UserError):approve_customer_draft(root,db,draft['draft_id'],reviewer,statement)
            approve_customer_draft(root,db,draft['draft_id'],'Synthetic test examiner','Test-only approval of exact unredacted draft; not actual customer approval.')
            result=release_customer_draft(root,db,draft['draft_id'],dest);self.assertEqual(result['review_status'],'recorded_examiner_approval')
            manifest=json.loads((dest/'manifest.json').read_text())
            for f in manifest['files']:self.assertEqual(digest(dest/f['path']),f['sha256'])
    def test_changed_content_or_investigation_invalidates_approval(self):
        with connect(self.ws,'A') as (root,db):
            draft=build_customer_draft(root,db,self.iid);approve_customer_draft(root,db,draft['draft_id'],'Synthetic reviewer','Fixture approval only')
            path=Path(draft['path'])/'report.txt';path.write_text(path.read_text()+'tamper')
            with self.assertRaisesRegex(UserError,'integrity'):release_customer_draft(root,db,draft['draft_id'],self.base/'blocked')
            fresh=build_customer_draft(root,db,self.iid);approve_customer_draft(root,db,fresh['draft_id'],'Synthetic reviewer','Fixture approval only')
            inv.note(db,self.iid,'question','New unresolved question')
            with self.assertRaisesRegex(UserError,'changed'):release_customer_draft(root,db,fresh['draft_id'],self.base/'blocked2')
    def test_unsafe_draft_parent_and_incomplete_release_cleanup(self):
        from unittest.mock import patch
        import shutil
        with connect(self.ws,'A') as (root,db):
            outside=self.base/'outside';outside.mkdir();(root/'customer-drafts').symlink_to(outside,target_is_directory=True)
            with self.assertRaisesRegex(UserError,'Unsafe'):build_customer_draft(root,db,self.iid)
            self.assertEqual(list(outside.iterdir()),[]);(root/'customer-drafts').unlink()
            draft=build_customer_draft(root,db,self.iid);approve_customer_draft(root,db,draft['draft_id'],'Synthetic reviewer','Fixture declaration')
            dest=self.base/'failed-copy';original=shutil.copyfile
            def copy_extra(source,target):
                result=original(source,target);(Path(target).parent/'unexpected').write_text('CANARY');return result
            with patch('shutil.copyfile',side_effect=copy_extra),self.assertRaisesRegex(UserError,'Unexpected'):
                release_customer_draft(root,db,draft['draft_id'],dest)
            self.assertFalse(dest.exists())
            with patch('shutil.copyfile',side_effect=OSError('simulated copy failure')),self.assertRaises(OSError):
                release_customer_draft(root,db,draft['draft_id'],dest)
            self.assertFalse(dest.exists())

    def test_retained_source_changes_block_approval_and_release(self):
        with connect(self.ws,'A') as (root,db):
            draft=build_customer_draft(root,db,self.iid)
            row=db.execute('SELECT f.* FROM files f JOIN artifacts a ON a.file_id=f.id WHERE a.id=?',(self.aid,)).fetchone()
            (root/'evidence'/row['evidence_id']/row['path']).write_text('changed source')
            with self.assertRaisesRegex(UserError,'source integrity'):approve_customer_draft(root,db,draft['draft_id'],'Synthetic reviewer','Fixture declaration')

    def test_redactions_wrong_case_and_unmanifested_assets_are_refused(self):
        with connect(self.ws,'A') as (root,db):
            with self.assertRaisesRegex(UserError,'Redacted'):build_customer_draft(root,db,self.iid,redactions=['secret'])
            draft=build_customer_draft(root,db,self.iid)
            with self.assertRaisesRegex(UserError,'Redacted'):release_customer_draft(root,db,draft['draft_id'],self.base/'redacted',redactions=[])
            (Path(draft['path'])/'thumbnail.jpg').write_bytes(b'UNMANIFESTED')
            with self.assertRaisesRegex(UserError,'unmanifested'):approve_customer_draft(root,db,draft['draft_id'],'Synthetic reviewer','Fixture approval only')
        with connect(self.ws,'B') as (root,db):
            with self.assertRaises(UserError):approve_customer_draft(root,db,draft['draft_id'],'Synthetic reviewer','Fixture approval only')
