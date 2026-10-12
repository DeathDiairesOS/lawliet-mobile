import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect,create_case,UserError,begin_run_index
from lawliet_mobile.coverage_ledger import record_observation,portable_summary


class PortableCoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'A')
        self.eids=[]
        for name in ('selected','OTHER_SOURCE_CANARY'):
            source=self.base/(name+'.jsonl');source.write_text(json.dumps({'category':'messages','body':'match '+name,'data':{}})+'\n')
            self.eids.append(handle(self.ws,{'case':'A','action':'import','path':str(source),'format':'jsonl'})['evidence_id'])
        with connect(self.ws,'A') as (_,db):
            for eid in (self.eids[0],self.eids[1],None):
                for state in ('requested','inaccessible','unsupported','reviewed','verified'):
                    record_observation(db,{'state':state,'source':'PRIVATE_SOURCE_CANARY','category':'messages','tool_version':'PRIVATE_MODULE_CANARY',
                        'reason':'PRIVATE_REASON_CANARY','profile':'PRIVATE_PROFILE_CANARY','actor':'PRIVATE_ACTOR_CANARY','schema':'PRIVATE_SCHEMA_CANARY',
                        'evidence_id':eid,'reference':'PRIVATE_REFERENCE_CANARY'})

    def test_actual_stdio_zero_match_retains_only_explicit_evidence_context(self):
        path=self.base/'empty.jsonl'
        request={'workspace':str(self.ws),'case':'A','action':'export','evidence':self.eids[0],'query':'absent','path':str(path)}
        proc=subprocess.run([sys.executable,'-m','lawliet_mobile.app_backend'],input=json.dumps(request),text=True,capture_output=True)
        self.assertEqual(proc.returncode,0,proc.stdout)
        result=json.loads(proc.stdout)['result'];self.assertEqual(result['records'],0)
        text=Path(result['coverage_path']).read_text();data=json.loads(text);rows=data['coverage_context']['observations']
        self.assertEqual(data['state_counts'],{})
        self.assertTrue({'requested','inaccessible','unsupported','reviewed','verified'}<={r['state'] for r in rows})
        self.assertEqual({r['evidence_id'] for r in rows},{self.eids[0]})
        self.assertTrue(all('source_path' not in r for r in rows))
        self.assertTrue(all(r['module']=='unknown' for r in rows if r['origin']=='operator-recorded'))
        self.assertFalse(data['independent_examiner_signoff']);self.assertNotIn('CANARY',text)
        self.assertFalse(any(r['state']=='searched-with-no-finding' for r in rows))

    def test_implicit_empty_query_does_not_expand_to_case_wide_context(self):
        out=self.base/'implicit.jsonl';result=handle(self.ws,{'case':'A','action':'export','query':'absent','path':str(out)})
        context=json.loads(Path(result['coverage_path']).read_text())['coverage_context']
        self.assertEqual(context['observations'],[]);self.assertEqual(context['scope'],'represented-sources-only')

    def test_represented_path_disclosed_but_unrepresented_labels_are_opaque(self):
        out=self.base/'selected-export.jsonl';result=handle(self.ws,{'case':'A','action':'export','evidence':self.eids[0],'path':str(out)})
        data=json.loads(Path(result['coverage_path']).read_text());rows=data['coverage_context']['observations']
        paths={json.loads(line)['logical_path'] for line in out.read_text().splitlines()}
        self.assertTrue(any(r.get('source_path') in paths for r in rows))
        self.assertTrue(all(r.get('source_path') in paths for r in rows if 'source_path' in r))
        self.assertNotIn('CANARY',Path(result['coverage_path']).read_text())

    def test_selected_run_excludes_other_run_and_conflicting_evidence_refuses(self):
        with connect(self.ws,'A') as (_,db):
            aid=db.execute('SELECT id FROM artifacts WHERE evidence_id=?',(self.eids[0],)).fetchone()[0]
            for rid in ('selected-run','other-run'):
                db.execute("INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,'2026-01-01','failed',?)",(rid,self.eids[0],'native',json.dumps({'error':'SECRET_'+rid})))
                begin_run_index(db,rid);db.execute('INSERT INTO artifact_runs VALUES(?,?)',(rid,aid))
        out=self.base/'run.jsonl';result=handle(self.ws,{'case':'A','action':'export','run':'selected-run','path':str(out)})
        data=json.loads(Path(result['coverage_path']).read_text());rows=data['coverage_context']['observations']
        self.assertEqual(data['state_counts'].get('parser-failed'),1)
        self.assertEqual(sum(r['observation_count'] for r in rows if r['applies_to']=='run'),1)
        self.assertFalse(any(r['origin']=='operator-recorded' for r in rows))
        self.assertNotIn('SECRET',Path(result['coverage_path']).read_text())
        bad=self.base/'mismatch.jsonl'
        with self.assertRaises(UserError):handle(self.ws,{'case':'A','action':'export','run':'selected-run','evidence':self.eids[1],'path':str(bad)})
        self.assertFalse(bad.exists())
        html=self.base/'run.html'
        from lawliet_mobile.report import write_report
        with connect(self.ws,'A') as (root,db):write_report(root,db,html,filters={'run':'selected-run'})
        self.assertEqual(json.loads(Path(str(html)+'.coverage.json').read_text())['state_counts'].get('parser-failed'),1)

    def test_metadata_caps_refuse_pair_and_roll_back_audit(self):
        with connect(self.ws,'A') as (_,db):before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        for cap,value in [('MAX_ROWS',1),('MAX_BYTES',1)]:
            out=self.base/(cap+'.jsonl')
            with patch('lawliet_mobile.portable_coverage.'+cap,value),self.assertRaises(UserError):
                handle(self.ws,{'case':'A','action':'export','evidence':self.eids[0],'path':str(out)})
            self.assertFalse(out.exists());self.assertFalse(Path(str(out)+'.coverage.json').exists())
        with connect(self.ws,'A') as (_,db):self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before)

    def test_malformed_scope_never_claims_known_scope_or_run_counts(self):
        entry={'state':'parser-failed','axis':'parsing','evidence_id':'A','source':'run:real','run_id':'real','origin':'derived','scope_level':'run'}
        for value in (None,False,'x',1):
            for key in ('source_pairs','evidence_ids','run_ids','coverage_evidence_ids'):
                scope={'evidence_ids':['A'],'source_pairs':[],key:value}
                with self.subTest(key=key,value=value),self.assertRaises(UserError):portable_summary({'entries':[entry]},scope)
        legacy=portable_summary({'entries':[entry]},{'evidence_ids':['A'],'source_paths':['run:real']})
        self.assertEqual(legacy['state_counts'],{});self.assertFalse(legacy['scope_sufficient_for_state_counts'])

    def test_hostile_category_and_module_never_enter_portable_vocabulary(self):
        entry={'state':'unsupported','axis':'parsing','source':'private','evidence_id':'A','origin':'explicit',
               'category':'CATEGORY_CANARY','tool_version':'MODULE_CANARY','reason':'REASON_CANARY'}
        result=portable_summary({'entries':[entry]},{'source_pairs':[],'coverage_evidence_ids':['A']})
        row=result['coverage_context']['observations'][0]
        self.assertEqual(row['category'],'unknown');self.assertEqual(row['module'],'unknown');self.assertNotIn('CANARY',json.dumps(result))

    def test_selected_run_never_attributes_unbound_parser_observations(self):
        rows=[{'state':'parsed','axis':'parsing','source':'other','evidence_id':'A','origin':'derived','tool_version':'ileapp'},
              {'state':'parser-failed','axis':'parsing','source':'other','evidence_id':'A','origin':'derived','run_id':'different'},
              {'state':'parser-failed','axis':'parsing','source':'run:selected','evidence_id':'A','origin':'derived','run_id':'selected','scope_level':'run'},
              {'state':'verified','axis':'examiner-verification','source':'other','evidence_id':'A','origin':'explicit'}]
        result=portable_summary({'entries':rows},{'evidence_ids':['A'],'source_pairs':[['A','other']],'coverage_evidence_ids':['A'],'run_ids':['selected']})
        observations=result['coverage_context']['observations']
        self.assertEqual(len(observations),1);self.assertEqual(observations[0]['state'],'parser-failed')
        self.assertEqual(result['coverage_context']['scope'],'selected-run-with-acquisition-context')
        self.assertEqual(result['state_counts'],{'parser-failed':1})

    def test_serialized_budget_includes_wrapper_whitespace_and_aggregation(self):
        entry={'state':'unsupported','axis':'parsing','source':'private','evidence_id':'A','origin':'explicit'}
        scope={'source_pairs':[],'coverage_evidence_ids':['A']}
        value=portable_summary({'entries':[entry]*12},scope)
        actual=len((json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode())
        with patch('lawliet_mobile.portable_coverage.MAX_BYTES',actual-1),self.assertRaises(UserError):portable_summary({'entries':[entry]*12},scope)
        with patch('lawliet_mobile.portable_coverage.MAX_BYTES',actual):self.assertEqual(portable_summary({'entries':[entry]*12},scope),value)
