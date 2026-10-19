"""Qualify empty supplied SMS views without hiding unknown schemas or WAL limits."""
import sqlite3,tempfile,unittest,json,hashlib
from contextlib import closing
from pathlib import Path
from lawliet_mobile.empty_schema import no_record_diagnostic
from lawliet_mobile.core import create_case,connect,import_evidence
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.coverage_ledger import ledger_page
from lawliet_mobile.app_backend import handle
SQL='CREATE TABLE sms(_id INTEGER,thread_id INTEGER,address TEXT,date INTEGER,type INTEGER,body TEXT);'
class EmptySchemaTests(unittest.TestCase):
 def direct(self,sql,platform='android'):
  with closing(sqlite3.connect(':memory:')) as db:
   db.executescript(sql);return no_record_diagnostic(db,'mmssms.db',platform)
 def test_exact_empty(self):
  r=self.direct(SQL);self.assertEqual(r['state'],'parsed-empty');self.assertEqual(r['rows_observed'],0);self.assertEqual(r['table'],'sms');self.assertIn('missing/unverified WAL',r['reason'])
 def test_unknown_schema(self):
  self.assertEqual(self.direct('CREATE TABLE unsupported_control(id);')['state'],'unsupported')
 def test_partial_sms_not_empty(self):
  self.assertEqual(self.direct('CREATE TABLE sms(body);')['state'],'unresolved')
 def test_other_platform_not_claimed(self):
  self.assertEqual(self.direct(SQL,'ios')['state'],'unresolved')
 def test_nonempty_without_decoded_records_not_empty(self):
  self.assertEqual(self.direct(SQL+'INSERT INTO sms VALUES(1,1,"a",0,1,"b");')['state'],'unresolved')
 def test_empty_ios_family_unqualified(self):
  self.assertEqual(self.direct('CREATE TABLE message(id);CREATE TABLE handle(id);','ios')['state'],'unresolved')
 def test_empty_call_families_unqualified(self):
  for platform,sql in [('android','CREATE TABLE calls(number TEXT);'),('ios','CREATE TABLE ZCALLRECORD(ZDATE REAL);')]:
   with self.subTest(platform=platform):
    self.assertEqual(self.direct(sql,platform)['state'],'unresolved')
 def test_empty_call_sources_survive_pipeline_without_unsupported_claim(self):
  with tempfile.TemporaryDirectory() as tmp:
   b=Path(tmp);ws=b/'cases'
   for platform,sql in [('android','CREATE TABLE calls(number TEXT);'),('ios','CREATE TABLE ZCALLRECORD(ZDATE REAL);')]:
    source=b/(platform+'.db');create_case(ws,platform)
    with closing(sqlite3.connect(source)) as db:db.executescript(sql);db.commit()
    original=source.read_bytes()
    with connect(ws,platform) as (root,db):
     eid=import_evidence(root,db,source,platform)[0];result=native_analyze(root,db,eid)
     self.assertEqual(result['new_records'],0)
     self.assertEqual([x['state'] for x in result['unparsed_candidates']],['unresolved'])
     rows=ledger_page(root,db)['entries'];self.assertTrue(any(x['state']=='unresolved' for x in rows))
     self.assertFalse(any(x['state'] in {'unsupported','parsed-empty','verified','reviewed'} for x in rows))
    self.assertEqual(source.read_bytes(),original)
 def test_portable_empty_reason(self):
  from lawliet_mobile.portable_coverage import Context
  c=Context(set(),{'E'});c.add({'evidence_id':'E','source':'private.db','state':'parsed-empty','axis':'parsing','tool_version':'native/0.1.10','category':'messages','origin':'derived'})
  r=c.result();self.assertEqual(r['observations'][0]['reason_code'],'recognized_empty_supplied_view');self.assertNotIn('private.db',json.dumps(r))
 def test_missing_wal_limit_remains(self):
  with tempfile.TemporaryDirectory() as tmp:
   b=Path(tmp);source=b/'mmssms.db'
   with closing(sqlite3.connect(source)) as db:
    db.execute('PRAGMA journal_mode=WAL');db.executescript(SQL);db.commit();db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
   ws=b/'cases';create_case(ws,'A')
   with connect(ws,'A') as (root,db):
    eid=import_evidence(root,db,source,'android')[0];r=native_analyze(root,db,eid)
    self.assertTrue(any(x['state']=='parsed-empty' for x in r['unparsed_candidates']))
    self.assertTrue(any(x.get('sqlite_wal_coverage',{}).get('wal_mode_header') for x in r['unparsed_candidates']))
    entries=ledger_page(root,db)['entries'];self.assertTrue(any(x['state']=='unresolved' and 'no WAL companion' in x['reason'] for x in entries))
 def test_pipeline_and_rerun_and_source_integrity(self):
  with tempfile.TemporaryDirectory() as tmp:
   b=Path(tmp);src=b/'input';src.mkdir()
   for name,sql in [('empty-mmssms.db',SQL),('unknown.db','CREATE TABLE unsupported_control(id);'),('healthy-mmssms.db',SQL+'INSERT INTO sms VALUES(1,1,"+15550100",1700000000000,1,"retained");')]:
    with closing(sqlite3.connect(src/name)) as db:db.executescript(sql);db.commit()
   (src/'broken.db').write_bytes(b'SQLite format 3\0broken')
   before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in src.iterdir()}
   ws=b/'cases';create_case(ws,'A')
   with connect(ws,'A') as (root,db):
    eid=import_evidence(root,db,src,'android')[0]
    r=native_analyze(root,db,eid);self.assertEqual(r['new_records'],1);self.assertEqual(r['status'],'partial')
    page=ledger_page(root,db);rows=page['entries']
    empty=[x for x in rows if x['state']=='parsed-empty'];self.assertEqual(len(empty),1);self.assertEqual(empty[0]['rows_observed'],0)
    self.assertTrue(any(x['state']=='unsupported' and x['source']=='unknown.db' for x in rows))
    self.assertTrue(any(x['state']=='parser-failed' for x in rows));self.assertEqual(db.execute('SELECT body FROM artifacts').fetchone()[0],'retained')
    r2=native_analyze(root,db,eid);self.assertEqual(r2['new_records'],0)
    self.assertEqual(len([x for x in ledger_page(root,db)['entries'] if x['state']=='parsed-empty']),2)
    db.execute("UPDATE runs SET detail=? WHERE id=?",(json.dumps({'unparsed_candidates':[{'source':'legacy.db','state':'no_native_records','reason':'historical uncertain'}]}),r['run_id']));db.commit()
    self.assertTrue(any(x['state']=='unresolved' and x['source']=='legacy.db' for x in ledger_page(root,db)['entries']))
   result=handle(ws,{'case':'A','action':'coverage-ledger','filters':{'state':'parsed-empty'}})
   self.assertEqual(result['filtered_total'],1)
   self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in src.iterdir()})
if __name__=='__main__':unittest.main(verbosity=2)
