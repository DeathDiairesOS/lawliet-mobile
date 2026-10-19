"""Synthetic retained MVT review; no MVT, model or phone is needed."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from lawliet_mobile.core import UserError, connect, create_case, json_text, verify
from lawliet_mobile.findings import add_finding
from lawliet_mobile import mvt_review as m


def bundle(folder, rows=None, errors=None, state='limited'):
    folder.mkdir()
    receipt = {'case_id':'UPSTREAM-A', 'mvt_version':'2026.10.5', 'execution_state':state,
               'receipt_scope':'MVT execution and output parsing before indexing', 'input_type':'androidqf',
               'source_unchanged':True, 'ioc_matching_requested':False, 'errors':errors or [],
               'module_execution_coverage':'not independently verified'}
    (folder/m.RECEIPT).write_text(json.dumps(receipt))
    (folder/'observations.json').write_text(json.dumps(rows if rows is not None else [{'name':'synthetic','value':'Observation 😀','timestamp':'2021-02-03 04:05:06'}]))
    (folder/'info.json').write_text('{"version":"2026.10.5"}')
    (folder/'command.log').write_text('Synthetic log only')
    manifest(folder)


def manifest(folder):
    entries=[{'path':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(folder.iterdir()) if p.is_file() and p.name!=m.MANIFEST]
    (folder/m.MANIFEST).write_text(json.dumps({'tool':'run_mvt_android','tool_call_id':'tc_12345678','files':entries}))


class MVTReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.ws=self.base/'cases';create_case(self.ws,'LOCAL')
        self.source=self.base/'bundle';bundle(self.source)

    def ingest(self, root, db):
        preview=m.inspect_bundle(self.source)
        return m.import_bundle(root,db,self.source,preview['manifest_sha256'],preview['upstream_case_id'])

    def test_preserve_import_review_cite_and_save_finding(self):
        before={p.name:p.read_bytes() for p in self.source.iterdir()}
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);eid=result['evidence_id']
            page=m.review(root,db,eid)
            self.assertEqual(page['total'],1);self.assertEqual(page['summary']['upstream_case_id'],'UPSTREAM-A')
            row=page['records'][0];detail=m.record(root,db,eid,row['id'])
            self.assertTrue(detail['source_verified']);self.assertEqual(detail['source_record_index'],0)
            self.assertEqual(detail['original']['value'],'Observation 😀')
            self.assertEqual(detail['source_sha256'],hashlib.sha256(before['observations.json']).hexdigest())
            self.assertIn('#json-record=0',detail['source_ref'])
            finding=add_finding(db,row['id'],'Review observation; no compromise conclusion','Synthetic examiner')
            self.assertEqual(finding['snapshot']['source_sha256'],detail['source_sha256'])
            self.assertIsNone(finding['snapshot']['timestamp'])
            self.assertTrue(verify(root,db)['ok'])
            self.assertEqual(m.list_bundles(root,db)['bundles'][0]['evidence_id'],eid)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.source.iterdir()})

    def test_reimport_same_manifest_reuses_run(self):
        with connect(self.ws,'LOCAL') as (root,db):
            first=self.ingest(root,db);second=self.ingest(root,db)
            self.assertTrue(second['reused']);self.assertEqual(first['evidence_id'],second['evidence_id'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],1)

    def test_preview_binding_refuses_changes_and_wrong_case(self):
        preview=m.inspect_bundle(self.source)
        with connect(self.ws,'LOCAL') as (root,db):
            for sha,case in [('0'*64,preview['upstream_case_id']),(preview['manifest_sha256'],'OTHER')]:
                with self.assertRaises(UserError):m.import_bundle(root,db,self.source,sha,case)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],0)

    def test_hash_tamper_refused_before_case_writes(self):
        (self.source/'observations.json').write_text('[]')
        with self.assertRaisesRegex(UserError,'integrity'):m.inspect_bundle(self.source)

    def test_unknown_version_refused(self):
        p=self.source/m.RECEIPT;value=json.loads(p.read_text());value['mvt_version']='2099';p.write_text(json.dumps(value));manifest(self.source)
        with self.assertRaisesRegex(UserError,'Unsupported'):m.inspect_bundle(self.source)

    def test_traversal_and_duplicate_manifest_paths_refused(self):
        p=self.source/m.MANIFEST;original=p.read_text()
        for path in ('../outside','/outside','a/../b','a\\b','a//b'):
            value=json.loads(original);value['files'][0]['path']=path;p.write_text(json.dumps(value))
            with self.subTest(path=path),self.assertRaises(UserError):m.inspect_bundle(self.source)
        value=json.loads(original);value['files'].append(value['files'][0]);p.write_text(json.dumps(value))
        with self.assertRaises(UserError):m.inspect_bundle(self.source)

    def test_symlink_and_unlisted_file_refused(self):
        (self.source/'extra').write_text('unlisted')
        with self.assertRaisesRegex(UserError,'unlisted'):m.inspect_bundle(self.source)
        (self.source/'extra').unlink();(self.source/'link').symlink_to(self.base)
        with self.assertRaises(UserError):m.inspect_bundle(self.source)

    def test_duplicate_json_keys_refused(self):
        p=self.source/m.MANIFEST;p.write_text(p.read_text().replace('"tool":','"tool":"run_mvt_android","tool":',1))
        with self.assertRaisesRegex(UserError,'JSON'):m.inspect_bundle(self.source)

    def test_partial_module_and_execution_errors_are_visible(self):
        (self.source/'broken.json').write_text('{')
        receipt=json.loads((self.source/m.RECEIPT).read_text());receipt['errors']=[{'error':'upstream module failed'}]
        (self.source/m.RECEIPT).write_text(json.dumps(receipt));manifest(self.source)
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);page=m.review(root,db,result['evidence_id'])
            self.assertEqual(page['import_status'],'partial');self.assertEqual(page['total'],1)
            self.assertEqual(page['summary']['import_issues'][0]['file'],'broken.json')
            self.assertEqual(page['summary']['receipt']['errors'][0]['error'],'upstream module failed')
            self.assertTrue((root/'evidence'/result['evidence_id']/'broken.json').exists())

    def test_zero_records_retains_empty_not_clean_disclosure(self):
        (self.source/'observations.json').write_text('[]');manifest(self.source)
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);page=m.review(root,db,result['evidence_id'])
            self.assertEqual(page['total'],0)
            self.assertTrue(any('cannot exclude compromise' in line for line in page['summary']['limitations']))

    def test_pagination_search_and_exact_escaped_text(self):
        (self.source/'observations.json').write_text(json.dumps([{'value':f'row {i} 100%_literal'} for i in range(65)]));manifest(self.source)
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);eid=result['evidence_id']
            page=m.review(root,db,eid,query='100%_literal',limit=10)
            self.assertEqual(len(page['records']),10);self.assertEqual(page['total'],65);self.assertTrue(page['has_more'])
            second=m.review(root,db,eid,query='100%_literal',limit=10,offset=10)
            self.assertFalse(set(r['id'] for r in page['records']) & set(r['id'] for r in second['records']))
            for offset,limit in [(True,10),(0,False),(-1,10),(0,101)]:
                with self.assertRaises(UserError):m.review(root,db,eid,offset=offset,limit=limit)

    def test_case_evidence_and_artifact_mismatch_refused(self):
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);aid=m.review(root,db,result['evidence_id'])['records'][0]['id']
            with self.assertRaises(UserError):m.record(root,db,'unknown',aid)
            with self.assertRaises(UserError):m.record(root,db,result['evidence_id'],'unknown')

    def test_copied_source_and_receipt_tamper_refused(self):
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);eid=result['evidence_id'];aid=m.review(root,db,eid)['records'][0]['id']
            source=root/'evidence'/eid/'observations.json';original=source.read_bytes();source.write_text('[]')
            with self.assertRaisesRegex(UserError,'integrity'):m.record(root,db,eid,aid)
            source.write_bytes(original);(root/'evidence'/eid/m.RECEIPT).write_text('{}')
            with self.assertRaisesRegex(UserError,'integrity'):m.review(root,db,eid)

    def test_oversized_record_is_retained_without_partial_value(self):
        (self.source/'observations.json').write_text(json.dumps([{'small':1},{'value':'x'*65536}]));manifest(self.source)
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);page=m.review(root,db,result['evidence_id'])
            self.assertEqual(page['total'],1);self.assertEqual(page['import_status'],'partial')
            self.assertTrue(page['summary']['import_issues'])

    def test_row_object_is_retained_as_one_record(self):
        (self.source/'observations.json').write_text('{"value":"object"}');manifest(self.source)
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);eid=result['evidence_id'];row=m.review(root,db,eid)['records'][0]
            self.assertEqual(m.record(root,db,eid,row['id'])['original'],{'value':'object'})

    def test_alert_display_reaches_fields_after_long_event_without_merging_sources(self):
        alert = {'event':{'large_context':'x'*1000}, 'event_time':'', 'level':'CRITICAL',
                 'module':'aqf_packages', 'message':'Synthetic package indicator matched 😀',
                 'matched_indicator':{'type':'app_ids','value':'com.example.synthetic'}}
        (self.source/'observations.json').write_text(json.dumps([alert]))
        (self.source/'alerts.json').write_text(json.dumps([alert]));manifest(self.source)
        before = {p.name:p.read_bytes() for p in self.source.iterdir()}
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);eid=result['evidence_id']
            page=m.review(root,db,eid,query='matched_indicator')
            self.assertEqual(page['total'],2)
            for row in page['records']:
                self.assertNotIn(alert['message'],row['preview'])
                self.assertEqual(row['display'],{'message':alert['message'],'upstream_level':'CRITICAL',
                     'module':'aqf_packages','indicator_type':'app_ids','indicator_value':'com.example.synthetic'})
                self.assertNotIn('display_json',row)
                detail=m.record(root,db,eid,row['id'])
                self.assertEqual(detail['original'],alert);self.assertTrue(detail['source_verified'])
            self.assertEqual(len({r['source_ref'] for r in page['records']}),2)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.source.iterdir()})

    def test_display_clamps_are_explicit_and_original_values_remain_complete(self):
        alert={'message':'😀'*650,'level':'X'*40,'module':'M'*120,
               'matched_indicator':{'type':'T'*80,'value':'V'*300}}
        (self.source/'observations.json').write_text(json.dumps([alert]));manifest(self.source)
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);eid=result['evidence_id'];row=m.review(root,db,eid)['records'][0]
            expected={'message':600,'upstream_level':32,'module':100,'indicator_type':64,'indicator_value':256}
            self.assertEqual(set(row['display']['truncated_fields']),set(expected))
            self.assertEqual({k:len(row['display'][k]) for k in expected},expected)
            self.assertEqual(m.record(root,db,eid,row['id'])['original'],alert)

    def test_nonalert_and_mistyped_display_fields_fall_back_without_inference(self):
        original={'message':{'text':'not a string'},'level':40,'module':False,
                  'matched_indicator':['not','an','object']}
        (self.source/'observations.json').write_text(json.dumps([original]));manifest(self.source)
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);eid=result['evidence_id'];row=m.review(root,db,eid)['records'][0]
            self.assertEqual(row['display'],{})
            self.assertEqual(m.record(root,db,eid,row['id'])['original'],original)

    def test_indexed_provenance_tamper_refused(self):
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);eid=result['evidence_id'];aid=m.review(root,db,eid)['records'][0]['id']
            data=json.loads(db.execute('SELECT data FROM artifacts WHERE id=?',(aid,)).fetchone()[0])
            data['mvt']['source_file']='invented.json'
            db.execute('UPDATE artifacts SET data=? WHERE id=?',(json_text(data),aid))
            with self.assertRaisesRegex(UserError,'integrity'):m.record(root,db,eid,aid)

    def test_cached_execution_receipt_tamper_refused(self):
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db);eid=result['evidence_id']
            detail=json.loads(db.execute('SELECT detail FROM runs WHERE id=?',(result['run_id'],)).fetchone()[0])
            detail['receipt']['ioc_matching_requested']=True
            db.execute('UPDATE runs SET detail=? WHERE id=?',(json_text(detail),result['run_id']))
            with self.assertRaisesRegex(UserError,'cached execution receipt'):m.review(root,db,eid)

    def test_import_audit_binding_required(self):
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db)
            db.execute("DELETE FROM audit WHERE action='mvt.review_imported'")
            with self.assertRaisesRegex(UserError,'audit receipt'):m.review(root,db,result['evidence_id'])

    def test_reimport_does_not_reuse_tampered_retained_bytes(self):
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db)
            (root/'evidence'/result['evidence_id']/'observations.json').write_text('[]')
            with self.assertRaisesRegex(UserError,'integrity'):self.ingest(root,db)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],1)

    def test_reimport_refuses_failed_and_incomplete_prior_run(self):
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db)
            for state in ('failed','importing'):
                db.execute('UPDATE runs SET status=? WHERE id=?',(state,result['run_id']))
                with self.subTest(state=state),self.assertRaisesRegex(UserError,'failed or incomplete'):self.ingest(root,db)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],1)

    def test_reimport_requires_existing_import_audit(self):
        with connect(self.ws,'LOCAL') as (root,db):
            self.ingest(root,db)
            db.execute("DELETE FROM audit WHERE action='mvt.review_imported'")
            with self.assertRaisesRegex(UserError,'audit receipt'):self.ingest(root,db)

    def test_reimport_refuses_changed_case_inventory(self):
        with connect(self.ws,'LOCAL') as (root,db):
            result=self.ingest(root,db)
            db.execute("UPDATE files SET sha256=? WHERE evidence_id=? AND path='observations.json'",('0'*64,result['evidence_id']))
            with self.assertRaisesRegex(UserError,'file inventory'):self.ingest(root,db)


if __name__=='__main__':unittest.main()
