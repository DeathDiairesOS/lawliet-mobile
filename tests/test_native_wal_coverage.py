import importlib.util,json,shutil,sqlite3,tempfile,unittest
from pathlib import Path
from lawliet_mobile.core import create_case,connect,import_evidence,select_artifacts
from lawliet_mobile.acquisition import case_coverage
from lawliet_mobile.report import write_jsonl_export
from tests.test_recovery_acceptance import wal_fixture,sms_database,tree_hashes
from lawliet_mobile import parsers as stage
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name).resolve();self.inputs=self.base/'inputs';self.inputs.mkdir();wal_fixture(self.inputs)
 def analyze(self,label):
  path=self.inputs/label;before=tree_hashes(path);ws=self.base/'cases';create_case(ws,label)
  with connect(ws,label) as (root,db):
   eid=import_evidence(root,db,path,'android')[0];retained=tree_hashes(root/'evidence');result=stage.native_analyze(root,db,eid);rows=select_artifacts(db,limit=None)
   coverage=case_coverage(root,db);out=write_jsonl_export(root,db,root/'exports/control.jsonl',iter(rows),{'evidence':eid});companion=json.loads(Path(out['coverage_path']).read_text())
   self.assertEqual(tree_hashes(root/'evidence'),retained)
  self.assertEqual(tree_hashes(path),before);return result,rows,coverage,companion
 def test_complete_pair22_limited_and_hashes_preserved(self):
  result,rows,coverage,out=self.analyze('paired');self.assertEqual(len(rows),22);self.assertTrue(all(r['data']['sqlite_wal_coverage']['pairing']=='unverified' for r in rows));self.assertEqual(rows[0]['data']['sqlite_wal_coverage']['format_version_bytes'],[2,2]);self.assertTrue(result['unparsed_candidates'])
 def test_missing20_explicit_and_no_source_shm_created(self):
  result,rows,_,_=self.analyze('missing');self.assertEqual(len(rows),20);c=rows[0]['data']['sqlite_wal_coverage'];self.assertFalse(c['wal_present']);self.assertEqual(c['pairing'],'not_available');self.assertIn('no WAL companion',c['reason']);self.assertFalse((self.inputs/'missing/mmssms.db-shm').exists())
 def test_malformed_wal_not_silent_clean_success(self):
  result,rows,_,_=self.analyze('mismatched');self.assertEqual(len(rows),20);self.assertIn('malformed',result['unparsed_candidates'][0]['reason']);self.assertEqual(rows[0]['data']['sqlite_wal_coverage']['pairing'],'unverified')
 def test_readable_foreign_rows_carry_unverified_limitation(self):
  _,rows,_,_=self.analyze('foreign');self.assertEqual(len(rows),21);foreign=next(r for r in rows if 'FOREIGN_WAL' in r['body']);self.assertEqual(foreign['data']['sqlite_wal_coverage']['pairing'],'unverified')
 def test_clean_rollback_main_does_not_claim_missing_wal(self):
  sms_database(self.inputs/'clean/mmssms.db',20);r,rows,_,_=self.analyze('clean');self.assertEqual(len(rows),20);self.assertFalse(r['unparsed_candidates']);self.assertTrue(all('sqlite_wal_coverage' not in row['data'] for row in rows))
 def test_mixed_header_does_not_claim_exact_wal_mode(self):
  sms_database(self.inputs/'mixed/mmssms.db',2);p=self.inputs/'mixed/mmssms.db';raw=bytearray(p.read_bytes());raw[18]=2;raw[19]=1;p.write_bytes(raw)
  result,rows,_,_=self.analyze('mixed');limit=result['unparsed_candidates'][0]['sqlite_wal_coverage'];self.assertFalse(limit['wal_mode_header']);self.assertEqual(limit['format_version_bytes'],[2,1]);self.assertIn('mode is not established',limit['reason'])
 def test_same_basename_no_cross_directory_pairing(self):
  folder=self.inputs/'nested';folder.mkdir();shutil.copytree(self.inputs/'paired',folder/'a');shutil.copytree(self.inputs/'missing',folder/'b');_,rows,_,_=self.analyze('nested');self.assertEqual(len(rows),42)
  for row in rows:self.assertEqual(row['data']['sqlite_wal_coverage']['wal_present'],row['logical_path'].startswith('a/'))
 def test_internal_and_portable_source_module_category_limitation(self):
  _,_,coverage,out=self.analyze('missing');entries=coverage['ledger']['entries'];self.assertTrue(any(r['state']=='unresolved' and r['category']=='messages' and r['source']=='mmssms.db' for r in entries))
  context=out['coverage_context'];rendered=json.dumps(context);self.assertIn('unresolved',rendered);self.assertIn('native',rendered);self.assertIn('messages',rendered)
 def test_ios_wal_only_attachment_inherits_source_limits_and_category(self):
  live=self.base/'ios-live.db';folder=self.inputs/'ios';folder.mkdir()
  db=sqlite3.connect(live);db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
  db.executescript("CREATE TABLE message(text TEXT,date INTEGER,handle_id INTEGER,is_from_me INTEGER);CREATE TABLE handle(id TEXT);CREATE TABLE attachment(filename TEXT,total_bytes INTEGER);CREATE TABLE message_attachment_join(message_id INTEGER,attachment_id INTEGER);INSERT INTO message VALUES('fixture',1,1,0);INSERT INTO handle VALUES('fixture');")
  db.commit();db.execute('PRAGMA wal_checkpoint(TRUNCATE)');db.execute("INSERT INTO attachment VALUES('Library/SMS/Attachments/missing.png',10)");db.execute('INSERT INTO message_attachment_join VALUES(1,1)');db.commit()
  for suffix in ('','-wal'):shutil.copyfile(Path(str(live)+suffix),folder/('sms.db'+suffix))
  db.close();before=tree_hashes(folder);ws=self.base/'ioscases';create_case(ws,'IOS')
  with connect(ws,'IOS') as (root,db):
   eid=import_evidence(root,db,folder,'ios')[0];retained=tree_hashes(root/'evidence');result=stage.native_analyze(root,db,eid);rows=select_artifacts(db,limit=None);attachments=[r for r in rows if r['category']=='attachments'];self.assertEqual(len(attachments),1)
   item=attachments[0];self.assertEqual(item['source_ref'],'attachment:rowid=1');self.assertEqual(item['data']['attachment']['filename'],'Library/SMS/Attachments/missing.png');self.assertEqual(item['logical_path'],'sms.db')
   message=next(r for r in rows if r['category']=='messages');self.assertEqual(item['data']['sqlite_wal_coverage'],message['data']['sqlite_wal_coverage']);self.assertEqual(item['data']['source_sidecars'],message['data']['source_sidecars']);self.assertEqual(item['source_sha256'],item['data']['sqlite_wal_coverage']['source_sha256']);self.assertEqual(item['data']['sqlite_wal_coverage']['pairing'],'unverified')
   cov=case_coverage(root,db)['ledger']['entries'];self.assertEqual({r['category'] for r in cov if r['state']=='unresolved'},{'messages','attachments'})
   exported=write_jsonl_export(root,db,root/'exports/attachments.jsonl',iter(attachments),{'category':'attachments','evidence':eid});portable=json.loads(Path(exported['coverage_path']).read_text());self.assertTrue(any(r['category']=='attachments' and r['state']=='unresolved' and r['module']=='native' for r in portable['coverage_context']['observations']))
   self.assertEqual(tree_hashes(root/'evidence'),retained)
  self.assertEqual(tree_hashes(folder),before);self.assertFalse((folder/'sms.db-shm').exists())
if __name__=='__main__':unittest.main()
