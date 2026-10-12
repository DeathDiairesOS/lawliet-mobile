import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,import_evidence,add_artifact,UserError,digest,audit
from lawliet_mobile import investigation as inv
from lawliet_mobile.investigation_report import build_customer_draft,approve_customer_draft,release_customer_draft
from lawliet_mobile.masking_preview import create,_render,TOKEN


class MaskingPreviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'A');create_case(self.ws,'B')
        self.source=self.base/'input.txt';self.source.write_text('PERSON_CANARY text\n秘密 😀')
        with connect(self.ws,'A') as (root,db):
            eid=import_evidence(root,db,self.source,'unknown')[0];fid=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
            add_artifact(db,eid,fid,'messages',None,None,'Fixture','PERSON_CANARY text\n秘密 😀','line=1','native/0.1.5',{'body':'PERSON_CANARY','json_only':'JSON_ONLY_CANARY','attachment':{'status':'not-acquired'}})
            aid=db.execute('SELECT id FROM artifacts').fetchone()[0]
            self.iid=inv.create(db,'Question about PERSON_CANARY',[eid])['id'];inv.note(db,self.iid,'observation','PERSON_CANARY is stored text; no identity conclusion.',[aid])
            self.draft=build_customer_draft(root,db,self.iid);self.root=root
        self.original={str(p):digest(p) for p in Path(self.draft['path']).iterdir()}
        self.original[str(self.source)]=digest(self.source)

    def unchanged(self):
        self.assertEqual({p:digest(Path(p)) for p in self.original},self.original)

    def test_actual_stdio_preview_contains_only_allowlisted_masked_outputs(self):
        request={'workspace':str(self.ws),'case':'A','action':'customer-report-masking-preview','draft_id':self.draft['draft_id'],'literals':['PERSON_CANARY','秘密 😀','ABSENT_SELECTION_CANARY']}
        proc=subprocess.run([sys.executable,'-m','lawliet_mobile.app_backend'],input=json.dumps(request),text=True,capture_output=True)
        self.assertEqual(proc.returncode,0,proc.stdout);result=json.loads(proc.stdout)['result'];folder=Path(result['path'])
        self.assertEqual({p.name for p in folder.iterdir()},{'preview.txt','selection-spans.json','manifest.json'})
        self.assertFalse(result['release_allowed']);self.assertEqual(result['source_manifest_sha256'],self.draft['manifest_sha256'])
        manifest=json.loads((folder/'manifest.json').read_text());self.assertFalse(manifest['release_allowed'])
        for item in manifest['files']:self.assertEqual(digest(folder/item['path']),item['sha256'])
        for p in folder.iterdir():
            for value in request['literals']:self.assertNotIn(value,p.read_text())
        self.assertTrue((folder/'preview.txt').read_text().startswith('INTERNAL MASKED TEXT PREVIEW'))
        self.assertEqual(result['selections'][2],{'index':2,'consumed_matches':0,'present_in_source':False})
        with connect(self.ws,'A') as (_,db):
            receipt=db.execute("SELECT detail FROM audit WHERE action='customer_report.masking_preview_created'").fetchone()[0]
            self.assertNotIn('CANARY',receipt);self.assertNotIn('literals',receipt)
        self.unchanged()

    def test_leftmost_longest_overlaps_unicode_and_nonrecursive_replacement(self):
        result=_render('Alice Alicia Al\n姓名😀!', ['Al','Alice','Alicia','姓名😀'])
        self.assertEqual([r['consumed_matches'] for r in result['selections']],[1,1,1,1])
        self.assertEqual(result['spans'][0],{'selection_index':1,'start_character':0,'end_character':5})
        self.assertEqual(result['text'].count(TOKEN),4)
        overlap=_render('abcdef',['abc','cdef'])
        self.assertEqual(overlap['selections'][1],{'index':1,'consumed_matches':0,'present_in_source':True})
        self.assertNotIn('cdef',overlap['text'])
        with self.assertRaises(UserError):_render('secret '+TOKEN,['secret',TOKEN])

    def test_invalid_absent_or_metadata_colliding_selections_never_produce_output(self):
        for values in [None,[],[''],['same','same'],[1],['x'*513],['x']*129,['\ud800'],['NEVER_PRESENT_CANARY'],['INTERNAL'],['source_draft_id','PERSON_CANARY']]:
            with connect(self.ws,'A') as (root,db):
                before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
                with self.assertRaises(UserError):create(root,db,self.draft['draft_id'],values)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before)
                self.assertFalse((root/'report-previews').exists() and list((root/'report-previews').iterdir()))
        self.unchanged()

    def test_preview_cannot_reuse_original_draft_approval(self):
        with connect(self.ws,'A') as (root,db):
            approve_customer_draft(root,db,self.draft['draft_id'],'Synthetic fixture examiner','Test-only declaration of original unredacted fixture.')
            before=[r[0] for r in db.execute("SELECT detail FROM audit WHERE action='customer_report.approved'")]
            result=create(root,db,self.draft['draft_id'],['PERSON_CANARY']);target=self.base/'released-preview'
            with self.assertRaises(UserError):release_customer_draft(root,db,result['preview_id'],target)
            self.assertFalse(target.exists())
            self.assertEqual([r[0] for r in db.execute("SELECT detail FROM audit WHERE action='customer_report.approved'")],before)
            with self.assertRaisesRegex(UserError,'Redacted'):release_customer_draft(root,db,self.draft['draft_id'],target,redactions=['PERSON_CANARY'])
        self.unchanged()

    def test_stale_tampered_wrong_case_and_unmanifested_drafts_refused(self):
        with connect(self.ws,'B') as (root,db):
            with self.assertRaises(UserError):create(root,db,self.draft['draft_id'],['PERSON_CANARY'])
        with connect(self.ws,'A') as (root,db):
            (Path(self.draft['path'])/'thumbnail.jpg').write_bytes(b'PRIVATE_THUMBNAIL')
            with self.assertRaises(UserError):create(root,db,self.draft['draft_id'],['PERSON_CANARY'])
            (Path(self.draft['path'])/'thumbnail.jpg').unlink()
            inv.note(db,self.iid,'question','New unresolved question')
            with self.assertRaisesRegex(UserError,'changed'):create(root,db,self.draft['draft_id'],['PERSON_CANARY'])
            fresh=build_customer_draft(root,db,self.iid);path=Path(fresh['path'])/'report.txt';path.write_text(path.read_text()+' tampered')
            with self.assertRaisesRegex(UserError,'integrity'):create(root,db,fresh['draft_id'],['PERSON_CANARY'])

    def test_symlink_parent_and_existing_directory_preserved(self):
        with connect(self.ws,'A') as (root,db):
            parent=root/'report-previews';outside=self.base/'outside';outside.mkdir();parent.symlink_to(outside,target_is_directory=True)
            with self.assertRaisesRegex(UserError,'Unsafe'):create(root,db,self.draft['draft_id'],['PERSON_CANARY'])
            self.assertEqual(list(outside.iterdir()),[]);parent.unlink();parent.mkdir()
            existing=parent/('a'*32);existing.mkdir();(existing/'KEEP').write_text('PRESERVE')
            with patch('lawliet_mobile.masking_preview.uuid.uuid4') as uuid_mock:
                uuid_mock.return_value.hex='a'*32
                with self.assertRaises(FileExistsError):create(root,db,self.draft['draft_id'],['PERSON_CANARY'])
            self.assertEqual((existing/'KEEP').read_text(),'PRESERVE')

    def test_worker_timeout_and_match_output_caps(self):
        with connect(self.ws,'A') as (root,db):
            with patch('lawliet_mobile.masking_preview.subprocess.run',side_effect=subprocess.TimeoutExpired('fixture',5)),self.assertRaisesRegex(UserError,'time limit'):
                create(root,db,self.draft['draft_id'],['PERSON_CANARY'])
        with patch('lawliet_mobile.masking_preview.MAX_MATCHES',1),self.assertRaises(UserError):_render('xx xx',['xx'])
        with patch('lawliet_mobile.masking_preview.MAX_TEXT',90),self.assertRaises(UserError):_render('xx'*20,['xx'])
        self.unchanged()

    def test_source_change_during_render_and_audit_failure_cleanup(self):
        from lawliet_mobile import masking_preview
        original=masking_preview._run_worker
        def change(text,literals):
            result=original(text,literals);path=Path(self.draft['path'])/'report.txt';path.write_text(path.read_text()+' changed');return result
        with connect(self.ws,'A') as (root,db):
            with patch('lawliet_mobile.masking_preview._run_worker',side_effect=change),self.assertRaises(UserError):create(root,db,self.draft['draft_id'],['PERSON_CANARY'])
            self.assertFalse((root/'report-previews').exists())
        # Restore fixture draft separately; mutation-control result is preserved in this test.
        with connect(self.ws,'A') as (root,db):
            fresh=build_customer_draft(root,db,self.iid);before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            def fail(db,action,detail):audit(db,action,detail);raise OSError('fixture audit failure')
            with patch('lawliet_mobile.masking_preview.audit',side_effect=fail),self.assertRaises(OSError):create(root,db,fresh['draft_id'],['PERSON_CANARY'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before)
            self.assertEqual(list((root/'report-previews').iterdir()),[])

    def test_source_container_symlink_blocks_preview_approval_and_release(self):
        with connect(self.ws,'A') as (root,db):
            approve_customer_draft(root,db,self.draft['draft_id'],'Synthetic fixture examiner','Test-only original draft approval.')
            eid=db.execute('SELECT evidence_id FROM files LIMIT 1').fetchone()[0]
            container=root/'evidence'/eid;outside=self.base/'moved-evidence';container.rename(outside)
            container.symlink_to(outside,target_is_directory=True)
            before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            for action in [lambda:create(root,db,self.draft['draft_id'],['PERSON_CANARY']),
                           lambda:approve_customer_draft(root,db,self.draft['draft_id'],'Synthetic fixture examiner','Fixture declaration'),
                           lambda:release_customer_draft(root,db,self.draft['draft_id'],self.base/'blocked-release')]:
                with self.assertRaisesRegex(UserError,'Unsafe'):action()
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before)
            self.assertFalse((root/'report-previews').exists());self.assertFalse((self.base/'blocked-release').exists())
