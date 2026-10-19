"""Review calls must leave engine commitments without copying message content."""
import inspect
import sqlite3
from contextlib import closing
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from lawliet_mobile.core import create_case, UserError
from lawliet_mobile.mulder_ownership import bind_review_case
try:
    from mulder.audit import AuditLog
    from mulder.server.helpers import hash_output, current_batch_id
    from mulder.server.tools import phone
except ImportError:
    phone = None

@unittest.skipUnless(phone, 'Requires patched Mulder runtime')
class ReviewAuditTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        base=Path(t.name).resolve();self.workspace=base/'lawliet-review';create_case(self.workspace,'A');self.case=self.workspace/'A'
        parent=base/'active.db'
        with closing(sqlite3.connect(parent)) as db:
            db.execute('CREATE TABLE case_metadata(case_id TEXT,ingested_at TEXT)')
            db.execute("INSERT INTO case_metadata VALUES('active','2026-10-14-test')")
            db.commit()
        bind_review_case(self.case,parent)
        self.log=base/'active.audit.jsonl';self.audit=AuditLog(self.log)
        ctx=SimpleNamespace(db=SimpleNamespace(db_path=base/'active.db'),audit=self.audit)
        for name,val in [('mulder.server.tools.phone.get_ctx',ctx),('mulder.server.helpers.get_ctx',ctx),('mulder.server.helpers.has_ctx',True)]:
            p=patch(name,return_value=val);p.start();self.addCleanup(p.stop)
    def entries(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []
    def test_collection_success_empty_partial_failed_are_committed_without_relabeling(self):
        fn=inspect.unwrap(phone.collect_lawliet_android_sms)
        for status in ['complete','empty','partial','failed']:
            receipt={'status':status,'records':2 if status=='complete' else 0}
            with patch('lawliet_mobile.provider_sms.collect_sms',return_value=receipt):
                result=fn(str(self.case),'CONTROL',prefix='SECRET_BODY_SELECTOR')
            e=self.entries()[-1]
            self.assertEqual(result['collection'],receipt)
            self.assertEqual(set(result),{'case_path','profile','collection','scope'})
            self.assertEqual(e['output_hash'],hash_output(result));self.assertEqual(e['tool_name'],'collect_lawliet_android_sms')
            self.assertEqual(e['params']['prefix_commitment'],hash_output('SECRET_BODY_SELECTOR'))
            self.assertTrue(self.audit.has_tool_call(e['tool_call_id']));self.assertGreaterEqual(e['duration_ms'],0)
        self.assertNotIn('SECRET_BODY_SELECTOR',self.log.read_text())
        self.assertEqual(len({e['tool_call_id'] for e in self.entries()}),4)
    def test_query_commits_full_response_and_batch_link_without_body_copy(self):
        fn=inspect.unwrap(phone.query_ancalor_review)
        rows=[{'body':'SECRET_MESSAGE_BODY','id':'X'}]
        token=current_batch_id.set('BATCH-CONTROL')
        try:
            with patch('lawliet_mobile.core.select_artifacts',return_value=rows):
                result=fn(str(self.case),query='SECRET_QUERY')
        finally:current_batch_id.reset(token)
        e=self.entries()[0];self.assertEqual(e['output_hash'],hash_output(result));self.assertEqual(e['batch_id'],'BATCH-CONTROL')
        self.assertEqual(result['records'],rows);self.assertEqual(e['tool_name'],'query_ancalor_review')
        self.assertNotIn('SECRET_QUERY',self.log.read_text());self.assertNotIn('SECRET_MESSAGE_BODY',self.log.read_text())
    def test_execution_exception_audited_and_original_error_preserved(self):
        for fn,where,args in [(phone.collect_lawliet_android_sms,'lawliet_mobile.provider_sms.collect_sms',(str(self.case),'CONTROL')),(phone.query_ancalor_review,'lawliet_mobile.core.select_artifacts',(str(self.case),))]:
            with patch(where,side_effect=RuntimeError('SECRET_EXCEPTION_DETAIL')),self.assertRaisesRegex(RuntimeError,'SECRET_EXCEPTION_DETAIL'):
                inspect.unwrap(fn)(*args)
            self.assertEqual(self.entries()[-1]['output_hash'],hash_output({'error':'RuntimeError'}))
        self.assertEqual(len(self.entries()),2);self.assertNotIn('SECRET_EXCEPTION_DETAIL',self.log.read_text())
    def test_preflight_refusals_are_not_executed_call_events(self):
        for fn,args,kw in [(phone.collect_lawliet_android_sms,(str(self.case),'CONTROL'),{'max_messages':True}),(phone.query_ancalor_review,(str(self.case),),{'limit':True}),(phone.collect_lawliet_android_sms,(str(self.case.parent.parent/'foreign'),'CONTROL'),{})]:
            with self.assertRaises((ValueError,UserError)):inspect.unwrap(fn)(*args,**kw)
        self.assertEqual(self.entries(),[])
    def test_audit_write_failure_is_not_silently_successful(self):
        with patch('lawliet_mobile.core.select_artifacts',return_value=[]),patch.object(self.audit,'log_tool_call',side_effect=OSError('audit unavailable')),self.assertRaisesRegex(OSError,'audit unavailable'):
            inspect.unwrap(phone.query_ancalor_review)(str(self.case))
