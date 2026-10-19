import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,import_evidence,add_artifact,digest,UserError
from lawliet_mobile import investigation as inv
HERE=Path(__file__).resolve().parent
from lawliet_mobile import investigation_report as m
CANARIES=['PERSON_CANARY','NOTE_CANARY','FIELD_CANARY','秘密😀','PATH_CANARY']
class RedactionTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name).resolve();self.ws=self.base/'cases'
  create_case(self.ws,'A');create_case(self.ws,'B');source=self.base/'PATH_CANARY.txt';source.write_text('PERSON_CANARY 秘密😀')
  with connect(self.ws,'A') as (root,db):
   eid=import_evidence(root,db,source,'unknown')[0];fid=db.execute('SELECT id FROM files').fetchone()[0]
   data={'FIELD_CANARY':'PERSON_CANARY','nested_json':json.dumps({'FIELD_CANARY':'秘密😀'}),'attachment':{'status':'not-acquired','path':'PATH_CANARY.jpg'}}
   add_artifact(db,eid,fid,'messages','2025-01-01T00:00:00.000000Z','1','PERSON_CANARY','PERSON_CANARY 秘密😀','row=1','native/0.1.6',data)
   aid=db.execute('SELECT id FROM artifacts').fetchone()[0];self.iid=inv.create(db,'Question PERSON_CANARY',[eid])['id'];inv.note(db,self.iid,'observation','NOTE_CANARY observation PERSON_CANARY',[aid])
   self.draft=m.build_customer_draft(root,db,self.iid);self.root=root
  other=self.base/'wrongcase.txt';other.write_text('WRONG_CASE_CANARY')
  with connect(self.ws,'B') as (root,db):
   eid=import_evidence(root,db,other,'unknown')[0];inv.create(db,'WRONG_CASE_CANARY objective',[eid])
  self.original={str(p):digest(p) for p in Path(self.draft['path']).iterdir()};self.original[str(source)]=digest(source)
 def create(self,root,db):return m.create_redacted_customer_draft(root,db,self.draft['draft_id'],CANARIES)
 def test_derivative_heading_distinguishes_current_status_from_source_labels(self):
  with connect(self.ws,'A') as (root,db):
   result=self.create(root,db);text=(Path(result['path'])/'report.txt').read_text()
   self.assertTrue(text.startswith('LAWLIET — SELECTED-LITERAL REDACTED REPORT DRAFT\n\nUNREVIEWED /'))
   self.assertIn('REFERENCES ONLY',text)
   self.assertIn('Only operator-selected case-sensitive literals were removed.',text)
   context=text.index('SOURCE DRAFT TEXT — inherited labels below')
   self.assertGreater(text.index('DRAFT / UNREVIEWED / UNREDACTED'),context)
   self.assertIn('DRAFT / UNREVIEWED / UNREDACTED',(Path(self.draft['path'])/'report.txt').read_text())
  self.unchanged()
 def test_selected_literal_in_new_heading_is_removed_too(self):
  with connect(self.ws,'A') as (root,db):
   result=m.create_redacted_customer_draft(root,db,self.draft['draft_id'],['LAWLIET'])
   folder=Path(result['path']);self.assertNotIn('LAWLIET',(folder/'report.txt').read_text())
   m._redaction_scan({p.name:p.read_text() for p in folder.iterdir()},['LAWLIET'])
  self.unchanged()
 def test_heading_only_match_cannot_create_a_false_redaction_success(self):
  with connect(self.ws,'A') as (root,db):
   with self.assertRaises(UserError):m.create_redacted_customer_draft(root,db,self.draft['draft_id'],['SOURCE DRAFT TEXT'])
   self.assertFalse((root/'customer-redacted-drafts').exists())
  self.unchanged()
 def unchanged(self):self.assertEqual({p:digest(Path(p)) for p in self.original},self.original)
 def test_full_surface_scan_counts_and_links_originals_unchanged(self):
  with connect(self.ws,'A') as (root,db):
   result=self.create(root,db);folder=Path(result['path']);self.assertFalse(result['release_allowed'])
   self.assertEqual({p.name for p in folder.iterdir()},m._REDACT_FILES|{'manifest.json'})
   for p in folder.iterdir():
    raw=p.read_text()
    for canary in CANARIES+['WRONG_CASE_CANARY']:self.assertNotIn(canary,raw)
   payloads={p.name:p.read_text() for p in folder.iterdir()};m._redaction_scan(payloads,CANARIES+['WRONG_CASE_CANARY'])
   annex=json.loads((folder/'technical-annex.json').read_text());exhibits=[json.loads(x) for x in (folder/'exhibits.jsonl').read_text().splitlines()]
   self.assertEqual(annex['citations'],exhibits);self.assertEqual(result['counts'],{'entries':1,'unique_cited_artifacts':1});self.assertEqual(annex['entries'][0]['artifact_ids'],[exhibits[0]['artifact_id']])
   raw=db.execute("SELECT detail FROM audit WHERE action='customer_report.redacted_created'").fetchone()[0]
   for canary in CANARIES:self.assertNotIn(canary,raw)
  self.unchanged()
 def test_fresh_approval_required_and_exact_local_release(self):
  with connect(self.ws,'A') as (root,db):
   m.approve_customer_draft(root,db,self.draft['draft_id'],'Synthetic','Original only')
   result=self.create(root,db);target=self.base/'release'
   with self.assertRaisesRegex(UserError,'Fresh'):m.release_redacted_customer_draft(root,db,result['derivative_id'],target)
   self.assertFalse(target.exists())
   for reviewer,declaration in [('', 'test'),('test','')]:
    with self.assertRaises(UserError):m.approve_redacted_customer_draft(root,db,result['derivative_id'],reviewer,declaration)
   m.approve_redacted_customer_draft(root,db,result['derivative_id'],'PERSON_CANARY reviewer','NOTE_CANARY approval is internal only')
   m.release_redacted_customer_draft(root,db,result['derivative_id'],target)
   self.assertEqual({p.name:digest(p) for p in target.iterdir()},{p.name:digest(p) for p in Path(result['path']).iterdir()});m._redaction_scan({p.name:p.read_text() for p in target.iterdir()},CANARIES)
  self.unchanged()
 def test_wrong_case_tamper_and_unmanifested_binary_refused(self):
  with connect(self.ws,'B') as (root,db):
   with self.assertRaises(UserError):self.create(root,db)
  with connect(self.ws,'A') as (root,db):
   result=self.create(root,db);folder=Path(result['path']);m.approve_redacted_customer_draft(root,db,result['derivative_id'],'Synthetic','Test declaration')
   (folder/'report.txt').write_text('tampered')
   with self.assertRaises(UserError):m.release_redacted_customer_draft(root,db,result['derivative_id'],self.base/'bad-release')
   binary=Path(self.draft['path'])/'thumbnail.jpg';binary.write_bytes(b'PERSON_CANARY')
   with self.assertRaises(UserError):self.create(root,db)
 def test_protected_source_hash_and_key_collision_fail_closed(self):
  with connect(self.ws,'A') as (root,db):
   value=json.loads((Path(self.draft['path'])/'technical-annex.json').read_text())['citations'][0]['artifact_id']
   with self.assertRaisesRegex(UserError,'identity'):m.create_redacted_customer_draft(root,db,self.draft['draft_id'],[value])
  payload={'report.txt':'A B','technical-annex.json':'{"A":1,"B":2}','investigation.json':'{}','exhibits.jsonl':''}
  with self.assertRaisesRegex(UserError,'collide'):m._redaction_transform(payload,['A','B'])
 def test_duplicate_json_nonfinite_and_decoded_escaped_unicode(self):
  with self.assertRaises(UserError):m._redaction_json('{"x":1,"x":2}')
  with self.assertRaises(UserError):m._redaction_json('{"x":NaN}')
  p={'report.txt':'秘密😀','technical-annex.json':json.dumps({'秘密😀':'secret'}),'investigation.json':json.dumps({'embedded':json.dumps({'秘密😀':'secret'})}),'exhibits.jsonl':json.dumps({'key':'秘密😀'})+'\n'}
  result=m._redaction_transform(p,['秘密😀']);m._redaction_scan(result['payloads'],['秘密😀']);self.assertEqual(result['consumed_matches'],4)
 def test_quoted_json_scalar_and_double_encoded_object(self):
  scalar=json.dumps('秘密😀',ensure_ascii=True)
  nested=json.dumps(json.dumps({'secret':'秘密😀'},ensure_ascii=True),ensure_ascii=True)
  payload={'report.txt':'plain secret','technical-annex.json':json.dumps({'scalar':scalar,'double':nested}), 'investigation.json':'{}','exhibits.jsonl':''}
  with self.assertRaises(UserError):m._redaction_scan(payload,['秘密😀'])
  result=m._redaction_transform(payload,['秘密😀']);decoded=json.loads(result['payloads']['technical-annex.json'])
  self.assertEqual(json.loads(decoded['scalar']),'[REDACTED]')
  self.assertEqual(json.loads(json.loads(decoded['double'])),{'secret':'[REDACTED]'})
  self.assertEqual(result['consumed_matches'],2);m._redaction_scan(result['payloads'],['秘密😀'])
 def test_encoded_json_key_transform_and_collision(self):
  key=json.dumps('秘密😀',ensure_ascii=True)
  payload={'report.txt':'plain','technical-annex.json':json.dumps({key:'value'}),'investigation.json':'{}','exhibits.jsonl':''}
  transformed=m._redaction_transform(payload,['秘密😀'])
  decoded=json.loads(transformed['payloads']['technical-annex.json'])
  self.assertEqual(json.loads(next(iter(decoded))),'[REDACTED]');m._redaction_scan(transformed['payloads'],['秘密😀'])
  payload['technical-annex.json']=json.dumps({json.dumps('one'):1,json.dumps('two'):2})
  with self.assertRaisesRegex(UserError,'collide'):m._redaction_transform(payload,['one','two'])
 def test_fixed_manifest_collision_refused(self):
  with connect(self.ws,'A') as (root,db):
   with self.assertRaises(UserError):m.create_redacted_customer_draft(root,db,self.draft['draft_id'],CANARIES+['literal'])
   self.assertFalse((root/'customer-redacted-drafts').exists() and list((root/'customer-redacted-drafts').iterdir()))
 def test_recursive_json_depth_budget(self):
  # Encoding layers grow exponentially; use nested objects for bounded-size depth refusal.
  value='秘密😀'
  for i in range(34):value={'nested':value}
  payload={'report.txt':'plain','technical-annex.json':json.dumps(value,ensure_ascii=False),'investigation.json':'{}','exhibits.jsonl':''}
  with self.assertRaises(UserError):m._redaction_transform(payload,['秘密😀'])
 def test_overlap_nonrecursive_and_caps(self):
  p={'report.txt':'ABC AB','technical-annex.json':'{}','investigation.json':'{}','exhibits.jsonl':''}
  result=m._redaction_transform(p,['AB','ABC']);self.assertEqual(result['payloads']['report.txt'],'[REDACTED] [REDACTED]');self.assertEqual(result['selection_counts'],[1,1])
  with patch.object(m,'_REDACT_MATCHES',1),self.assertRaises(UserError):m._redaction_transform(p,['AB'])
  with patch.object(m,'_REDACT_BYTES',1),self.assertRaises(UserError):m._redaction_transform(p,['AB'])
  with self.assertRaises(UserError):m._redaction_transform(p,['REDACTED','AB'])
 def test_symlinks_and_existing_outputs_refused(self):
  with connect(self.ws,'A') as (root,db):
   outside=self.base/'outside';outside.mkdir();(root/'customer-redacted-drafts').symlink_to(outside,target_is_directory=True)
   with self.assertRaises(UserError):self.create(root,db)
   self.assertEqual(list(outside.iterdir()),[]);(root/'customer-redacted-drafts').unlink()
   result=self.create(root,db);m.approve_redacted_customer_draft(root,db,result['derivative_id'],'Synthetic','Test approval')
   target=self.base/'alias';target.symlink_to(self.base/'missing')
   with self.assertRaises(UserError):m.release_redacted_customer_draft(root,db,result['derivative_id'],target)
   (outside/'keep').write_text('KEEP')
   with self.assertRaises(UserError):m.release_redacted_customer_draft(root,db,result['derivative_id'],outside)
   self.assertEqual((outside/'keep').read_text(),'KEEP')
 def test_worker_and_source_drift_refused(self):
  import subprocess
  with connect(self.ws,'A') as (root,db):
   with patch('subprocess.run',side_effect=subprocess.TimeoutExpired('test',6)),self.assertRaises(UserError):self.create(root,db)
   original=m._redaction_worker
   def changed(*args,**kwargs):
    result=original(*args,**kwargs);p=Path(self.draft['path'])/'report.txt';p.write_text(p.read_text()+' drift');return result
   with patch.object(m,'_redaction_worker',side_effect=changed),self.assertRaises(UserError):self.create(root,db)
   self.assertFalse((root/'customer-redacted-drafts').exists())
 def test_release_audit_failure_cleans_new_copy_and_preserves_draft(self):
  with connect(self.ws,'A') as (root,db):
   result=self.create(root,db);m.approve_redacted_customer_draft(root,db,result['derivative_id'],'Synthetic','Test declaration')
   before={p.name:digest(p) for p in Path(result['path']).iterdir()};target=self.base/'failedrelease'
   with patch.object(m,'audit',side_effect=RuntimeError('synthetic')),self.assertRaises(RuntimeError):m.release_redacted_customer_draft(root,db,result['derivative_id'],target)
   self.assertFalse(target.exists());self.assertEqual({p.name:digest(p) for p in Path(result['path']).iterdir()},before)
 def test_audit_failure_cleans_only_created_derivative(self):
  with connect(self.ws,'A') as (root,db):
   before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
   with patch.object(m,'audit',side_effect=RuntimeError('synthetic failure')),self.assertRaises(RuntimeError):self.create(root,db)
   self.assertFalse(list((root/'customer-redacted-drafts').iterdir()));self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before)
  self.unchanged()
if __name__=='__main__':unittest.main()
