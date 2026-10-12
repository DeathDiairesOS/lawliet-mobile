import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import connect,create_case,UserError,select_artifacts
from lawliet_mobile.app_backend import handle
from lawliet_mobile.coverage_ledger import record_observation
from lawliet_mobile.report import write_jsonl_export

class AppExportCoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'A')
        for label in ('SELECTED','EXCLUDED_CANARY'):
            source=self.base/(label+'.jsonl');source.write_text(json.dumps({'category':'messages','body':label,'data':{}})+'\n')
            result=handle(self.ws,{'case':'A','action':'import','path':str(source),'format':'jsonl'})
            if label=='SELECTED':self.eid=result['evidence_id']
        with connect(self.ws,'A') as (_,db):
            record_observation(db,{'state':'inaccessible','source':'EXCLUDED_SOURCE_CANARY','category':'contacts','reason':'EXCLUDED_REASON_CANARY','actor':'synthetic','profile':'unknown','schema':'unknown','input_tier':'supplied'})
    def test_actual_stdio_scoped_export_binds_companion_and_preserves_privacy(self):
        out=self.base/'export.jsonl';request={'case':'A','workspace':str(self.ws),'action':'export','path':str(out),'query':'SELECTED','evidence':self.eid}
        proc=subprocess.run([sys.executable,'-m','lawliet_mobile.app_backend'],input=json.dumps(request),text=True,capture_output=True);self.assertEqual(proc.returncode,0,proc.stdout)
        result=json.loads(proc.stdout)['result'];self.assertEqual(result['records'],1)
        companion=Path(result['coverage_path']);data=json.loads(companion.read_text())
        self.assertEqual(data['export_scope']['selection'],'filtered');self.assertFalse(data['independent_examiner_signoff'])
        self.assertEqual(result['sha256'],hashlib.sha256(out.read_bytes()).hexdigest());self.assertEqual(result['coverage_sha256'],hashlib.sha256(companion.read_bytes()).hexdigest())
        self.assertEqual(data['export_sha256'],result['sha256'])
        for p in (out,companion):self.assertNotIn('EXCLUDED',p.read_text())
        with connect(self.ws,'A') as (_,db):
            receipt=json.loads(db.execute("SELECT detail FROM audit WHERE action='export.created' ORDER BY id DESC").fetchone()[0]);self.assertEqual(receipt['coverage_sha256'],result['coverage_sha256'])
    def test_empty_filter_scope_and_invalid_explicit_scope(self):
        out=self.base/'empty.jsonl';result=handle(self.ws,{'case':'A','action':'export','path':str(out),'evidence':self.eid,'query':'no match'})
        data=json.loads(Path(result['coverage_path']).read_text());self.assertEqual(result['records'],0);self.assertEqual(data['state_counts'],{});self.assertEqual(data['export_scope']['selection'],'filtered');self.assertTrue(data['export_scope']['empty_result']);self.assertFalse(data['scope_sufficient_for_state_counts'])
        for value in ('',None,[]):
            with self.assertRaises(UserError):handle(self.ws,{'case':'A','action':'export','path':str(self.base/'bad'),'evidence':value})
    def test_failure_cleanup_and_no_overwrite(self):
        with connect(self.ws,'A') as (root,db):
            out=self.base/'failed.jsonl';before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            with patch('lawliet_mobile.coverage_ledger.portable_summary',side_effect=RuntimeError('injected companion failure')),self.assertRaises(RuntimeError):write_jsonl_export(root,db,out,iter(select_artifacts(db)))
            self.assertFalse(out.exists());self.assertFalse(Path(str(out)+'.coverage.json').exists());self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before)
            out.write_text('existing')
            with self.assertRaises(FileExistsError):write_jsonl_export(root,db,out,iter(()))
            self.assertEqual(out.read_text(),'existing')
            other=self.base/'companion-exists.jsonl';Path(str(other)+'.coverage.json').write_text('existing receipt')
            with self.assertRaises(FileExistsError):write_jsonl_export(root,db,other,iter(()))
            self.assertFalse(other.exists())
    def test_iterator_used_once_without_row_materialization_and_atomic_audit_failure(self):
        with connect(self.ws,'A') as (root,db):
            sample=select_artifacts(db,evidence=self.eid)[0]
            class Stream:
                def __len__(self):raise AssertionError('No list materialization')
                def __iter__(self):
                    for i in range(10001):yield {**sample,'id':str(i)}
            result=write_jsonl_export(root,db,self.base/'large.jsonl',Stream());self.assertEqual(result['records'],10001)
            out=self.base/'audit-failed.jsonl'
            with patch('lawliet_mobile.report.audit',side_effect=RuntimeError('injected audit failure')),self.assertRaises(RuntimeError):write_jsonl_export(root,db,out,iter([sample]))
            self.assertFalse(out.exists());self.assertFalse(Path(str(out)+'.coverage.json').exists())
    def test_source_and_symlink_outputs_refused(self):
        with connect(self.ws,'A') as (root,db):
            source=self.base/'SELECTED.jsonl';before=source.read_bytes();alias=self.base/'alias';alias.symlink_to(source)
            for p in (source,alias,root/'case.sqlite'):
                with self.assertRaises(UserError):write_jsonl_export(root,db,p,iter(()))
            self.assertEqual(source.read_bytes(),before)

    def test_arbitrary_record_window_never_claims_whole_case_or_no_truncation(self):
        from lawliet_mobile.report import write_export
        with connect(self.ws,'A') as (root,db):
            rows=select_artifacts(db,limit=1)
            out=Path(write_export(root,db,self.base/'window.jsonl','jsonl',rows))
            scope=json.loads(Path(str(out)+'.coverage.json').read_text())['export_scope']
            self.assertEqual(scope['selection'],'provided-record-window');self.assertEqual(scope['extent'],'unknown');self.assertIsNone(scope['truncated'])
    def test_companion_symlinks_rejected_before_resolution(self):
        with connect(self.ws,'A') as (root,db):
            for name,existing in [('dangling',False),('present',True)]:
                out=self.base/(name+'.jsonl');target=self.base/(name+'-target')
                if existing:target.write_text('PRESERVE TARGET')
                companion=Path(str(out)+'.coverage.json');companion.symlink_to(target)
                with self.assertRaisesRegex(UserError,'symlink'):write_jsonl_export(root,db,out,iter(()))
                self.assertTrue(companion.is_symlink());self.assertFalse(out.exists())
                if existing:self.assertEqual(target.read_text(),'PRESERVE TARGET')
                else:self.assertFalse(target.exists())
