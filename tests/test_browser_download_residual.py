"""Bounded browser omissions; no download decoding, daemon or acquired-input claim."""
import hashlib,json,sqlite3,tempfile,unittest
from contextlib import closing
from pathlib import Path
from lawliet_mobile import core,parsers
from lawliet_mobile.coverage_ledger import build_ledger
from lawliet_mobile.report import write_jsonl_export
from lawliet_mobile import native_container_worker as worker,native_container_codec as codec
from tests import test_native_container_worker as fixtures
SCHEMA='CREATE TABLE urls(id INTEGER,url TEXT,title TEXT,last_visit_time INTEGER);CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER);'
ROWS='INSERT INTO urls VALUES(1,"https://browser.invalid/known","Known",13404528000123457);INSERT INTO visits VALUES(10,1,13404528000123458);'
DOWNLOADS='CREATE TABLE downloads(id INTEGER,target_path TEXT,url TEXT);CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT);'
POPULATED='INSERT INTO downloads VALUES(20,"DOWNLOAD_PATH_CANARY","https://DOWNLOAD_URL_CANARY.invalid");INSERT INTO downloads_url_chains VALUES(20,0,"https://CHAIN_URL_CANARY.invalid");'
LOGICAL='data/data/com.android.chrome/app_chrome/Default/History'
class BrowserResidual(unittest.TestCase):
 def database(self,sql):
  db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row;db.executescript(sql);self.addCleanup(db.close);return db
 def observe(self,db):return list(parsers.browser_download_residual_coverage(db,LOGICAL))
 def test_populated_and_empty_are_unsupported_without_exact_nonempty_count(self):
  for populated in (False,True):
   with self.subTest(populated=populated):
    rows=self.observe(self.database(SCHEMA+DOWNLOADS+(POPULATED if populated else '')));self.assertEqual([r['table'] for r in rows],['downloads','downloads_url_chains'])
    for row in rows:self.assertEqual(row['state'],'unsupported');self.assertEqual(row['category'],'browser');self.assertEqual(row['rows_observed'],None if populated else 0);self.assertEqual(row['count_state'],'nonempty_in_supplied_sqlite_view' if populated else 'empty_in_supplied_sqlite_view')
    self.assertNotIn('CANARY',json.dumps(rows));self.assertTrue(all('not decoded' in r['reason'] for r in rows))
 def test_url_only_history_warns_and_missing_or_drifted_urls_schema_does_not(self):
  db=self.database('CREATE TABLE urls(id INTEGER,url TEXT,last_visit_time INTEGER);'+DOWNLOADS);self.assertEqual(len(self.observe(db)),2)
  for prefix in ('','CREATE TABLE urls(id INTEGER,url TEXT);','CREATE TABLE urls(last_visit_time INTEGER);'):
   with self.subTest(prefix=prefix):self.assertEqual(self.observe(self.database(prefix+DOWNLOADS)),[])
 def test_absent_or_similarly_named_tables_and_views_do_not_trigger(self):
  for suffix in ('','CREATE TABLE downloads_other(id);','CREATE VIEW downloads AS SELECT 1 AS id;'):
   with self.subTest(suffix=suffix):self.assertEqual(self.observe(self.database(SCHEMA+suffix)),[])
 def test_unknown_download_columns_are_not_interpreted(self):
  db=self.database(SCHEMA+'CREATE TABLE downloads(unknown BLOB);INSERT INTO downloads VALUES(zeroblob(1048576));');row=self.observe(db)[0];self.assertEqual(row['count_state'],'nonempty_in_supplied_sqlite_view');self.assertNotIn('unknown',json.dumps(row));self.assertIsNone(row['rows_observed'])
 def test_presence_probe_is_fixed_bounded_and_never_reads_cells_or_counts(self):
  db=self.database(SCHEMA+DOWNLOADS+POPULATED);queries=[];db.set_trace_callback(queries.append)
  def authorize(action,a,b,*unused):
   if action==sqlite3.SQLITE_FUNCTION and str(b).lower()=='count':return sqlite3.SQLITE_DENY
   if action==sqlite3.SQLITE_READ and a in ('downloads','downloads_url_chains') and b:return sqlite3.SQLITE_DENY
   return sqlite3.SQLITE_OK
  db.set_authorizer(authorize);rows=self.observe(db);self.assertEqual(len(rows),2);self.assertTrue(all(r['count_state']=='nonempty_in_supplied_sqlite_view' for r in rows));probes=[q for q in queries if q.startswith('SELECT 1 FROM')];self.assertEqual(probes,['SELECT 1 FROM "downloads" LIMIT 1','SELECT 1 FROM "downloads_url_chains" LIMIT 1'])
 def test_failed_presence_probe_does_not_claim_empty_or_leak_error_prose(self):
  db=self.database(SCHEMA+DOWNLOADS)
  def authorize(action,a,b,*unused):return sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_READ and a=='downloads' else sqlite3.SQLITE_OK
  db.set_authorizer(authorize);rows=self.observe(db);self.assertEqual(rows[0]['count_state'],'presence_probe_unavailable');self.assertIsNone(rows[0]['rows_observed']);self.assertNotIn('not authorized',rows[0]['reason']);self.assertEqual(rows[1]['rows_observed'],0)
 def test_diagnostics_leave_existing_browser_rows_and_repeated_observations_unchanged(self):
  db=self.database(SCHEMA+ROWS+DOWNLOADS+POPULATED);before=list(parsers.parse_database(db,LOGICAL));one=self.observe(db);two=self.observe(db);after=list(parsers.parse_database(db,LOGICAL));self.assertEqual(before,after);self.assertEqual(one,two);self.assertEqual([r[-1]['browser']['record_kind'] for r in after],['url_summary','visit']);self.assertEqual([r[-2] for r in after],['urls:id=1 (last recorded visit, not full visit history)','visits:id=10 -> urls:id=1']);self.assertEqual(after[1][1],'2025-10-10T00:00:00.123458Z')
 def test_native_pipeline_ledger_scoped_export_and_rerun_preserve_omissions(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp).resolve();source=base/'History';source.write_bytes(self.database(SCHEMA+ROWS+DOWNLOADS+POPULATED).serialize());before=core.digest(source);ws=base/'cases';core.create_case(ws,'A')
   with core.connect(ws,'A') as (root,db):
    eid=core.import_evidence(root,db,source,'android')[0];result=parsers.native_analyze(root,db,eid);self.assertEqual(result['new_records'],2);self.assertEqual(result['status'],'complete');self.assertEqual(len(result['unparsed_candidates']),2);artifacts=[tuple(r) for r in db.execute('SELECT * FROM artifacts ORDER BY rowid')]
    ledger=build_ledger(root,db);unsupported=[r for r in ledger['entries'] if r['state']=='unsupported'];self.assertEqual({r['table'] for r in unsupported},{'downloads','downloads_url_chains'});self.assertTrue(all(r['category']=='browser' and r['count_state']=='nonempty_in_supplied_sqlite_view' for r in unsupported));self.assertTrue(any(r['state']=='parsed' and r['category']=='browser' for r in ledger['entries']))
    export=write_jsonl_export(root,db,base/'selected.jsonl',core.iter_artifacts(db,evidence=eid,category='browser',limit=None,run=result['run_id']),scope_filters={'evidence':eid,'run':result['run_id'],'category':'browser'});db.commit();portable=json.loads(Path(export['coverage_path']).read_text());observations=portable['coverage_context']['observations'];self.assertTrue(any(r['state']=='unsupported' and r['category']=='browser' for r in observations));self.assertNotIn('DOWNLOAD_PATH_CANARY',Path(export['coverage_path']).read_text());self.assertNotIn('DOWNLOAD_URL_CANARY',Path(export['path']).read_text());self.assertTrue(portable['detail_withheld'])
    repeat=parsers.native_analyze(root,db,eid);self.assertEqual(repeat['new_records'],0);self.assertEqual(repeat['unparsed_candidates'],result['unparsed_candidates']);self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM artifacts ORDER BY rowid')],artifacts)
   self.assertEqual(core.digest(source),before)
 def test_actual_private_worker_footer_passes_existing_host_codec_with_omissions(self):
  fixture=fixtures.WorkerTests();fixture.setUp();self.addCleanup(fixture.doCleanups);db=self.database(SCHEMA+ROWS+DOWNLOADS+POPULATED);fixture.add('History',db.serialize(),logical=LOGICAL);raw=fixture.execute();bindings={'protocol':codec.PROTOCOL,'request_sha256':worker.sha(fixture.request_path.read_bytes()),'source_manifest_sha256':worker.sha(worker.canonical(fixture.request['inputs'])),'evidence_id':fixture.eid,'native_parser_version':parsers.VERSION,'package_manifest_sha256':worker.sha(worker.canonical(fixture.request['package_sha256'])),'bootstrap_sha256':fixture.request['bootstrap_sha256']};decoded=codec.validate(raw,bindings,fixture.request['inputs']);self.assertEqual(decoded.artifact_count,2);self.assertEqual({r['table'] for r in decoded.detail['unparsed_candidates']},{'downloads','downloads_url_chains'});self.assertTrue(all(r['state']=='unsupported' for r in decoded.detail['unparsed_candidates']));self.assertNotIn(b'CANARY',raw)
if __name__=='__main__':unittest.main()
