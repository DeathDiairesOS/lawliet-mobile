import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,import_evidence,UserError,select_artifacts,audit,add_artifact
from lawliet_mobile.app_backend import handle
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.acquisition import case_coverage
from lawliet_mobile.report import write_export,write_report
from lawliet_mobile.findings import add_finding,export_findings
from lawliet_mobile.coverage_ledger import record_observation,portable_summary

class CoverageLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'A');create_case(self.ws,'B')
    def observation(self,state,**changes):
        return {**dict(state=state,source='expected/sms.db',category='messages',reason='Declared bounded scope',actor='Reviewer',profile='work',schema='unknown',input_tier='logical'),**changes}
    def test_supported_sms_does_not_hide_unsupported_mms_table_counts(self):
        source=self.base/'mmssms.db'
        with sqlite3.connect(source) as fixture:
            fixture.executescript("CREATE TABLE sms(_id,address,body,date,type); INSERT INTO sms VALUES(1,'+15550123456','visible SMS',1700000000000,1); CREATE TABLE part(_id,ct); INSERT INTO part VALUES(1,'image/jpeg'); CREATE TABLE pdu(_id); INSERT INTO pdu VALUES(1);")
        with connect(self.ws,'A') as (root,db):
            eid=import_evidence(root,db,source,'android')[0];native_analyze(root,db,eid)
        ledger=handle(self.ws,{'action':'coverage-ledger','case':'A','filters':{'state':'unsupported'}})
        self.assertEqual(ledger['filtered_total'],2)
        self.assertEqual({e['table'] for e in ledger['entries']},{'part','pdu'})
        self.assertTrue(all(e['rows_observed']==1 for e in ledger['entries']))
        self.assertTrue(all(e['category']!='unknown' for e in ledger['entries']))
        self.assertGreater(ledger['summary']['state_counts']['parsed'],0)
        self.assertEqual(ledger['summary']['state_counts']['verified'],0)
    def test_paged_bridge_full_axis_summary_and_exact_filters(self):
        with connect(self.ws,'A') as (_,db):
            for i in range(105):
                values=self.observation('requested' if i%2 else 'inaccessible')
                values['source']='literal_%' if i%2 else 'other'
                record_observation(db,values)
        with patch('lawliet_mobile.coverage_ledger.build_ledger',side_effect=AssertionError('Full ledger materialized')):
            first=handle(self.ws,{'action':'coverage-ledger','case':'A','limit':10})
            self.assertEqual(len(first['entries']),10)
            self.assertEqual(first['total'],105)
            self.assertEqual(first['summary']['axis_counts']['acquisition'],105)
            self.assertEqual(first['summary']['axis_counts']['review'],0)
            second=handle(self.ws,{'action':'coverage-ledger','case':'A','offset':first['next_offset'],'limit':100})
            self.assertEqual(len(second['entries']),95)
            self.assertFalse(second['has_more'])
            ids=[r['id'] for r in first['entries']+second['entries']]
            self.assertEqual(len(set(ids)),105)
            filtered=handle(self.ws,{'action':'coverage-ledger','case':'A','filters':{'source':'literal_%'}})
            self.assertEqual(filtered['filtered_total'],52)
            self.assertEqual(filtered['total'],105)
            self.assertEqual(filtered['filtered_summary']['state_counts']['requested'],52)
            summary=handle(self.ws,{'action':'coverage-ledger','case':'A','limit':0})
            self.assertEqual(summary['entries'],[])
            self.assertEqual(summary['summary'],first['summary'])
            overview=handle(self.ws,{'action':'overview','case':'A'})
            self.assertEqual(overview['coverage']['ledger']['entries'],[])
            self.assertEqual(overview['coverage']['ledger']['total'],105)
        for params in [{'limit':101},{'offset':True},{'filters':{'query':'x'}},{'filters':[]}]:
            with self.subTest(params=params),self.assertRaises(UserError):
                handle(self.ws,{'action':'coverage-ledger','case':'A',**params})
    def test_distinct_axes_never_promote_review_or_verification(self):
        source=self.base/'fixture.jsonl';source.write_text(json.dumps({'category':'messages','body':'marker','data':{}})+'\n')
        eid=handle(self.ws,{'action':'import','case':'A','path':str(source),'format':'jsonl'})['evidence_id']
        with connect(self.ws,'A') as (root,db):
            for state in ('requested','excluded','inaccessible','unsupported','decryption-succeeded'):
                record_observation(db,self.observation(state,evidence_id=eid))
            ledger=case_coverage(root,db)['ledger'];states={x['state'] for x in ledger['entries']}
            self.assertTrue({'collected','parsed','requested','excluded','inaccessible','unsupported','decryption-succeeded'}<=states)
            self.assertNotIn('reviewed',states);self.assertNotIn('verified',states)
            with self.assertRaises(UserError):record_observation(db,self.observation('verified'))
            record_observation(db,self.observation('reviewed',reference='review-note:1'))
            record_observation(db,self.observation('verified',reference='examiner-check:1'))
            self.assertFalse(case_coverage(root,db)['ledger']['independent_examiner_signoff'])
        self.assertEqual(handle(self.ws,{'action':'coverage-ledger','case':'B'})['entries'],[])
    def test_corrupt_unknown_schema_and_failed_parser_remain_distinct(self):
        source=self.base/'input';source.mkdir()
        (source/'broken.db').write_bytes(b'SQLite format 3\x00'+b'broken'*40)
        db=sqlite3.connect(source/'unknown.db');db.execute('CREATE TABLE obscure(id INTEGER)');db.commit();db.close()
        with connect(self.ws,'A') as (root,db):
            eid=import_evidence(root,db,source,'android')[0];native_analyze(root,db,eid)
            entries=case_coverage(root,db)['ledger']['entries']
            self.assertTrue(any(x['state']=='parser-failed' and x['source']=='broken.db' for x in entries))
            self.assertTrue(any(x['state']=='unresolved' and x['source']=='unknown.db' for x in entries))
            self.assertFalse(any(x['state']=='searched-with-no-finding' for x in entries))
    def test_missing_expected_and_denied_collection_survive_export(self):
        with connect(self.ws,'A') as (root,db):
            folder=root/'collections'/'attempt';folder.mkdir(parents=True)
            (folder/'collection.json').write_text(json.dumps({'profile':'work','status':'partial','coverage':[{'source':'contacts','state':'access_denied','detail':'OS denied access'}]}))
            record_observation(db,self.observation('requested'))
            record_observation(db,self.observation('inaccessible',reference='missing expected payload'))
            out=self.base/'empty.jsonl';write_export(root,db,out,'jsonl',[])
            ledger=json.loads(Path(str(out)+'.coverage.json').read_text())
            self.assertTrue(ledger['detail_withheld']);self.assertFalse(ledger['scope_sufficient_for_state_counts'])
            self.assertIn('Missing, inaccessible',ledger['limitations'][1])
    def test_preview_and_findings_preserve_escaped_ledger_limitations(self):
        source=self.base/'fixture.jsonl';source.write_text(''.join(json.dumps({'category':'messages','body':str(i),'data':{}})+'\n' for i in range(2)))
        handle(self.ws,{'action':'import','case':'A','path':str(source),'format':'jsonl'})
        with connect(self.ws,'A') as (root,db):
            values=self.observation('inaccessible');values['reason']='<script>unsafe()</script>'
            record_observation(db,values)
            out=self.base/'preview.html';write_report(root,db,out,preview_limit=1)
            self.assertNotIn('unsafe()',out.read_text())
            full=self.base/'full.html';write_report(root,db,full)
            self.assertIn('&lt;script&gt;unsafe()&lt;/script&gt;',full.read_text())
            ledger=json.loads(Path(str(out)+'.coverage.json').read_text());self.assertTrue(ledger['export_scope']['truncated'])
            add_finding(db,select_artifacts(db)[0]['id'],'Examiner note')
            result=export_findings(root,db,self.base/'findings.txt','text')
            self.assertTrue(json.loads(Path(result['coverage_path']).read_text())['detail_withheld'])
            receipt=json.loads(Path(result['receipt_path']).read_text());self.assertTrue(receipt['coverage_sha256'])
    def test_negative_search_requires_actual_bounded_zero_and_review_is_explicit(self):
        source=self.base/'fixture.jsonl';source.write_text(json.dumps({'category':'messages','body':'present','data':{}})+'\n')
        eid=handle(self.ws,{'action':'import','case':'A','path':str(source),'format':'jsonl'})['evidence_id']
        with connect(self.ws,'A') as (_,db):
            with self.assertRaises(UserError):record_observation(db,self.observation('searched-with-no-finding',evidence_id=eid,query='present'))
            row=record_observation(db,self.observation('searched-with-no-finding',evidence_id=eid,query='absent'))
            self.assertIn('Indexed records only',row['search_scope'])
    def test_scoped_exports_do_not_leak_excluded_or_other_case_canaries(self):
        for case,body in [('A','SELECTED'),('B','OTHER_CASE_CANARY')]:
            source=self.base/(case+'.jsonl');source.write_text(json.dumps({'category':'messages','body':body,'data':{}})+'\n')
            handle(self.ws,{'action':'import','case':case,'path':str(source),'format':'jsonl'})
        with connect(self.ws,'A') as (root,db):
            values=self.observation('inaccessible');values['reason']='EXCLUDED_REASON_CANARY';values['source']='EXCLUDED_SOURCE_CANARY'
            record_observation(db,values)
            rows=select_artifacts(db,query='SELECTED');out=self.base/'scoped.jsonl';write_export(root,db,out,'jsonl',rows)
            html=self.base/'scoped.html';write_report(root,db,html,filters={'query':'SELECTED'})
            for path in [out,Path(str(out)+'.coverage.json'),html,Path(str(html)+'.coverage.json')]:
                for marker in ('EXCLUDED_REASON_CANARY','EXCLUDED_SOURCE_CANARY','OTHER_CASE_CANARY'):self.assertNotIn(marker,path.read_text())
            original=out.read_bytes()
            with self.assertRaises(FileExistsError):write_export(root,db,out,'jsonl',[])
            self.assertEqual(out.read_bytes(),original)

    def test_tampered_observation_is_not_exported_as_verified(self):
        with connect(self.ws,'A') as (root,db):
            record_observation(db,self.observation('inaccessible'))
            db.execute("UPDATE audit SET detail='{}' WHERE action='coverage.recorded'")
            with self.assertRaisesRegex(UserError,'integrity'):case_coverage(root,db)

    def test_exact_source_pairs_prevent_cross_evidence_scope_and_forged_run_prefix(self):
        with connect(self.ws,'A') as (root,db):
            selected=[]
            for label,path_name in [('phone-a','x.jsonl'),('phone-b','y.jsonl')]:
                folder=self.base/label;folder.mkdir()
                for name in ('x.jsonl','y.jsonl'):(folder/name).write_text('{"synthetic":true}\n')
                eid=import_evidence(root,db,folder,'android')[0]
                file=db.execute('SELECT id FROM files WHERE evidence_id=? AND logical_path=?',(eid,path_name)).fetchone()
                add_artifact(db,eid,file['id'],'messages',None,None,'selected','PAIR_SELECTION','row:1','fixture',{})
                selected.append((eid,path_name))
            record_observation(db,self.observation('unsupported',evidence_id=selected[0][0],source='y.jsonl'))
            record_observation(db,self.observation('inaccessible',evidence_id=selected[0][0],source='run:FAKE'))
            rows=select_artifacts(db,query='PAIR_SELECTION')
            for format_name in ('jsonl','json','csv'):
                path=self.base/('pair.'+format_name);write_export(root,db,path,format_name,rows)
                data=json.loads(Path(str(path)+'.coverage.json').read_text())
                self.assertEqual(data['state_counts'],{'collected':2,'parsed':2})
                self.assertTrue(data['source_scope_known'])
            path=self.base/'pair.html';write_report(root,db,path,filters={'query':'PAIR_SELECTION'})
            self.assertEqual(json.loads(Path(str(path)+'.coverage.json').read_text())['state_counts'],{'collected':2,'parsed':2})

    def test_legacy_scope_without_pairs_withholds_source_counts(self):
        entry={'state':'unsupported','evidence_id':'A','source':'x','origin':'explicit'}
        result=portable_summary({'entries':[entry]},{'evidence_ids':['A'],'source_paths':['x']})
        self.assertEqual(result['state_counts'],{});self.assertFalse(result['source_scope_known'])
        for pairs in [[['A']], [['A',None]], [['A','x','extra']]]:
            with self.assertRaises(UserError):portable_summary({'entries':[entry]},{'evidence_ids':['A'],'source_pairs':pairs})

    def test_only_actual_run_projection_receives_run_wide_scope(self):
        source=self.base/'run-input.jsonl';source.write_text('{"category":"messages","body":"visible","data":{}}\n')
        eid=handle(self.ws,{'action':'import','case':'A','path':str(source),'format':'jsonl'})['evidence_id']
        with connect(self.ws,'A') as (root,db):
            db.execute("INSERT INTO runs(id,evidence_id,engine,started_at,status,records,detail) VALUES(?,?,?,'2026-01-01','failed',0,?)",('real-run',eid,'native',json.dumps({'error':'RUN_ERROR_CANARY','errors':[{'source':'run:HIDDEN_SOURCE','error':'SOURCE_ERROR_CANARY'}]})))
            record_observation(db,self.observation('unsupported',evidence_id=eid,run_id='real-run',source='run:EXPLICIT_CANARY'))
            out=self.base/'run.jsonl';write_export(root,db,out,'jsonl',select_artifacts(db,evidence=eid))
            data=json.loads(Path(str(out)+'.coverage.json').read_text())
            self.assertEqual(data['state_counts'].get('parser-failed'),1)
            self.assertNotIn('unsupported',data['state_counts'])
            self.assertNotIn('CANARY',Path(str(out)+'.coverage.json').read_text())
