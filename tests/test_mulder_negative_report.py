"""A scoped negative examination must retain real search provenance, not invent findings."""
import asyncio
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    from mulder.audit import AuditLog
    from mulder.db import CaseDB
    from mulder.index.correlator import Correlator
    from mulder.models import Finding, WindowRow
    from mulder.server import app
    from mulder.server.extract_helpers import extract_and_index
    from mulder.server.examination_outcome import ScopedExamination
    from mulder.server.tools import core, findings, review
except ModuleNotFoundError as exc:
    if exc.name not in ('mulder', 'mulder.server.examination_outcome'):
        raise
    CaseDB = None


@unittest.skipUnless(CaseDB, 'Requires staged scoped-examination Mulder integration')
class ScopedExaminationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.evidence=self.root/'evidence';self.evidence.mkdir()
        self.source_file=self.evidence/'packages.txt';self.source_file.write_text('com.example.calendar\n')
        self.original_hash=hashlib.sha256(self.source_file.read_bytes()).hexdigest()
        self.db=CaseDB.create('scoped',str(self.evidence),self.root/'cases');self.addCleanup(self.db.close)
        self.ctx=app.ServerContext('scoped',self.db,Correlator(self.db),AuditLog(self.root/'audit.jsonl'))
        p=patch.object(app,'_ctx',self.ctx);p.start();self.addCleanup(p.stop)
        self.indexed=extract_and_index(self.source_file.read_text(),'android.packages',str(self.source_file),'synthetic/1')
        self.db.set_narrative('Synthetic package-name search only. App content and device state were not examined. <script>alert(1)</script>')
        self.search=inspect.unwrap(core.search)
        self.result=self.search('spyware',source='android.packages',evidence_path=str(self.source_file))
        self.assertEqual(self.result['total_matches'],0)
        inspect.unwrap(review.audit_evidence_coverage)()
        inspect.unwrap(review.audit_tool_coverage)()

    def payload(self,outcome='no_matches'):
        return dict(outcome=outcome,objective='Search the acquired package list for the specified term.',
                    scope='Only synthetic indexed package names; query spyware with no time filter.',
                    limitations=['Private application data and full filesystem were not acquired.'],
                    unanswered_questions=['Whether uncollected applications contain monitoring code.'],
                    analysis=[{'source_id':self.indexed['source_id'],'tool_call_id':self.result['tool_call_id']}])

    def finalize(self,payload=None):
        return inspect.unwrap(findings.finalize_report)(ScopedExamination.model_validate(payload or self.payload()))

    def test_real_empty_search_generates_scoped_report_with_trace_and_escaped_html(self):
        ready=inspect.unwrap(review.check_finalize_readiness)(ScopedExamination.model_validate(self.payload()))
        self.assertTrue(ready['ready_to_finalize'])
        result=self.finalize();self.assertEqual(result['status'],'success');self.assertEqual(result['finding_count'],0)
        snapshot=json.loads(Path(result['examination_path']).read_text())
        self.assertEqual(snapshot['review_status'],'unreviewed')
        ref=snapshot['analysis_provenance'][0]
        self.assertEqual(ref['tool_call']['tool_call_id'],self.result['tool_call_id'])
        self.assertEqual(ref['source']['source_path'],str(self.source_file))
        self.assertEqual(ref['current_index_recheck']['total_matches'],0)
        self.assertTrue(self.ctx.audit.has_tool_call(ref['current_index_recheck']['tool_call_id']))
        text=Path(result['report_path']).read_text();self.assertIn('No matches in the recorded searches',text)
        self.assertNotIn('mounted as read-only',text)
        self.assertNotIn('<script>',Path(result['html_report_path']).read_text())
        self.assertEqual(hashlib.sha256(self.source_file.read_bytes()).hexdigest(),self.original_hash)

    def test_reports_are_retained_as_distinct_runs(self):
        one=self.finalize();before=Path(one['report_path']).read_bytes();two=self.finalize()
        self.assertNotEqual(one['report_path'],two['report_path']);self.assertEqual(Path(one['report_path']).read_bytes(),before)

    def test_default_report_still_requires_positive_findings(self):
        result=inspect.unwrap(findings.finalize_report)()
        self.assertEqual(result['status'],'blocked');self.assertIn('minimum_findings',result['error_message'])
        self.assertFalse(inspect.unwrap(review.check_finalize_readiness)()['ready_to_finalize'])

    def test_foreign_unknown_failed_or_unscoped_query_cannot_support_report(self):
        invalid=['foreign-case-call',self.search('',source='android.packages',evidence_path=str(self.source_file))['tool_call_id'],
                 self.search('spyware')['tool_call_id']]
        for ref in invalid:
            with self.subTest(ref=ref):
                payload=self.payload();payload['analysis'][0]['tool_call_id']=ref
                self.assertEqual(self.finalize(payload)['status'],'blocked')
        payload=self.payload();payload['analysis'][0]['source_id']=9999
        self.assertEqual(self.finalize(payload)['status'],'blocked')

    def test_new_indexed_match_blocks_historical_empty_search(self):
        self.db.insert_windows(self.indexed['source_id'],[WindowRow(source_id=self.indexed['source_id'],line_start=2,line_end=2,event_time=None,raw_text='spyware')])
        self.assertEqual(self.finalize()['status'],'blocked')
        self.assertEqual(self.finalize(self.payload('inconclusive'))['status'],'success')

    def test_positive_and_truncated_searches_do_not_become_no_match_claims(self):
        hit=self.search('calendar',source='android.packages',evidence_path=str(self.source_file),max_results=1)
        payload=self.payload();payload['analysis'][0]['tool_call_id']=hit['tool_call_id']
        self.assertEqual(self.finalize(payload)['status'],'blocked')
        payload['outcome']='inconclusive';self.assertEqual(self.finalize(payload)['status'],'success')
        zero=self.search('calendar',source='android.packages',evidence_path=str(self.source_file),max_results=0)
        payload=self.payload();payload['analysis'][0]['tool_call_id']=zero['tool_call_id']
        self.assertEqual(self.finalize(payload)['status'],'blocked')

    def test_existing_findings_cannot_be_hidden_in_scoped_path(self):
        self.db.insert_finding(Finding(finding_id='f1',case_id='scoped',title='Observed application',description='Synthetic',
            severity='info',confidence='inference',evidence_refs=[self.result['tool_call_id']],sources=['android.packages'],
            submitted_at='2026-10-15T12:00:00Z'))
        result=self.finalize();self.assertEqual(result['status'],'blocked')
        self.assertFalse(next(g for g in result['gates'] if g['name']=='zero_finding_path')['passed'])

    def test_required_limitations_questions_and_bounds(self):
        for changed in ({'limitations':[]},{'scope':' ' * 20},{'outcome':'clean_device'},
                        {'outcome':'inconclusive','unanswered_questions':[]},{'analysis':self.payload()['analysis']*21}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                ScopedExamination.model_validate({**self.payload(),**changed})

    def test_missing_narrative_or_coverage_audits_still_block(self):
        self.db.set_narrative('');self.assertEqual(self.finalize()['status'],'blocked')
        self.db.set_narrative('Limited synthetic narrative')
        self.ctx.audit=AuditLog(self.root/'empty-audit.jsonl')
        self.assertEqual(self.finalize()['status'],'blocked')

    def test_case_reopen_preserves_audit_provenance(self):
        self.ctx.audit=AuditLog(self.root/'audit.jsonl')
        result=self.finalize();self.assertEqual(result['status'],'success')

    def test_oversized_report_is_refused_without_output_files(self):
        self.db.set_narrative('Synthetic text ' * 100000)
        self.assertEqual(self.finalize()['status'],'blocked')
        self.assertFalse(list(Path(self.db.db_path).parent.glob('examination-*')))

    def test_autonomous_positive_phase_gate_is_unchanged(self):
        from mulder.orchestrator.gates import validate_cross_system
        self.assertFalse(validate_cross_system({'findings_submitted':0,'findings_with_mitre_ids':0}).passed)
        self.assertTrue(validate_cross_system({'findings_submitted':3,'findings_with_mitre_ids':1}).passed)

    def test_actual_mcp_schema_and_dispatch_support_explicit_outcome(self):
        with patch.multiple(app,_cfg=None,_job_store=None,_tool_limiter=None):
            app.init_server(self.root,max_workers=1,mem_percent_limit=100,cpu_percent_limit=100)
            try:
                tools={t.name:t for t in asyncio.run(app.mcp.list_tools())}
                self.assertIn('examination',tools['finalize_report'].input_schema['properties'])
                result=asyncio.run(app.mcp.call_tool('check_finalize_readiness',{'examination':self.payload()}))
                self.assertFalse(result.is_error);self.assertTrue(result.structured_content['ready_to_finalize'])
                result=asyncio.run(app.mcp.call_tool('finalize_report',{'examination':self.payload()}))
                self.assertFalse(result.is_error);self.assertEqual(result.structured_content['status'],'success')
                self.assertEqual(result.structured_content['outcome'],'no_matches')
            finally:
                app.get_job_store().shutdown(wait=True)


if __name__=='__main__':unittest.main()
