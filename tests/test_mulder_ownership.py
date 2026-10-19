"""Shared case store is not proof that a review belongs to the active case."""
import hashlib,json,sqlite3,tempfile,unittest
from pathlib import Path
from lawliet_mobile.core import UserError,create_case,connect
from lawliet_mobile.mulder_ownership import bind_review_case,require_review_case,KEY

class MulderOwnership(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.base=Path(tmp.name).resolve();self.store=self.base/'db';self.store.mkdir();self.parent={}
  for name in ('A','B'):
   p=self.store/(name+'.db');c=sqlite3.connect(p);c.executescript('CREATE TABLE case_metadata(case_id TEXT,ingested_at TEXT);CREATE TABLE sources(source_id INTEGER,case_id TEXT,source_name TEXT);CREATE TABLE windows(source_id INTEGER,line_start INTEGER,raw_text TEXT);');c.execute('INSERT INTO case_metadata VALUES(?,?)',(name,'2026-01-01-'+name));c.commit();c.close();self.parent[name]=p
  self.workspace=self.store/'lawliet-review';self.root=create_case(self.workspace,'REVIEW-A')
 def test_same_case_binding_and_cross_case_refusal(self):
  bind_review_case(self.root,self.parent['A'],'tc_created');self.assertEqual(require_review_case(self.root,self.parent['A']),self.root)
  with self.assertRaisesRegex(UserError,'another'):require_review_case(self.root,self.parent['B'])
 def test_unbound_operator_case_cannot_borrow_sibling_scope(self):
  with self.assertRaisesRegex(UserError,'not bound'):require_review_case(self.root,self.parent['A'])
 def test_binding_is_idempotent_and_cannot_retarget(self):
  first=bind_review_case(self.root,self.parent['A']);self.assertEqual(first,bind_review_case(self.root,self.parent['A']))
  with self.assertRaises(UserError):bind_review_case(self.root,self.parent['B'])
  with connect(self.workspace,self.root.name) as (_,db):self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='mulder.review_case_bound'").fetchone()[0],1)
 def test_recreated_same_named_parent_is_a_different_instance(self):
  bind_review_case(self.root,self.parent['A']);p=self.parent['A'];p.rename(self.store/'preserved-A.db');c=sqlite3.connect(p);c.execute('CREATE TABLE case_metadata(case_id,ingested_at)');c.execute("INSERT INTO case_metadata VALUES('A','2026-01-01-A')");c.commit();c.close()
  with self.assertRaises(UserError):require_review_case(self.root,p)
 def test_changed_binding_metadata_without_audit_refused(self):
  bind_review_case(self.root,self.parent['A'])
  with connect(self.workspace,self.root.name) as (_,db):db.execute('UPDATE meta SET value=? WHERE key=?',('{}',KEY))
  with self.assertRaises(UserError):require_review_case(self.root,self.parent['A'])
 def test_missing_binding_metadata_keeps_existing_audit_refusal(self):
  bind_review_case(self.root,self.parent['A'])
  with connect(self.workspace,self.root.name) as (_,db):db.execute('DELETE FROM meta WHERE key=?',(KEY,))
  with self.assertRaises(UserError):require_review_case(self.root,self.parent['A'])
 def test_audit_mutation_cannot_certify_binding(self):
  bind_review_case(self.root,self.parent['A'])
  with connect(self.workspace,self.root.name) as (_,db):db.execute("UPDATE audit SET detail='{}' WHERE action='mulder.review_case_bound'")
  with self.assertRaises(UserError):require_review_case(self.root,self.parent['A'])
 def test_legacy_owned_index_readonly_compatibility(self):
  c=sqlite3.connect(self.parent['A']);c.execute("INSERT INTO sources VALUES(1,'A','phone.ancalor_native')");c.execute('INSERT INTO windows VALUES(1,1,?)',(json.dumps({'retained':{'case_path':str(self.root)}})+'\n'+json.dumps({'body':'SYNTHETIC'}),));c.commit();c.close();before=(self.root/'case.sqlite').read_bytes()
  self.assertEqual(require_review_case(self.root,self.parent['A']),self.root);self.assertEqual((self.root/'case.sqlite').read_bytes(),before)
  with self.assertRaises(UserError):require_review_case(self.root,self.parent['B'])
 def test_ordinary_evidence_text_cannot_forge_legacy_header(self):
  c=sqlite3.connect(self.parent['B']);c.execute("INSERT INTO sources VALUES(1,'B','supplied.user_text')");c.execute('INSERT INTO windows VALUES(1,1,?)',(json.dumps({'retained':{'case_path':str(self.root)}}),));c.commit();c.close()
  with self.assertRaises(UserError):require_review_case(self.root,self.parent['B'])
 def test_parent_symlink_and_review_symlink_refused(self):
  alias=self.store/'ALIAS.db';alias.symlink_to(self.parent['A']);link=self.workspace/'LINK';link.symlink_to(self.root)
  with self.assertRaises(UserError):bind_review_case(self.root,alias)
  with self.assertRaises(UserError):bind_review_case(link,self.parent['A'])
