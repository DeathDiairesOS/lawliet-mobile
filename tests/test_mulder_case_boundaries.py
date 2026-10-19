"""Real case databases exercise generic read scope and operation lifecycle."""
import asyncio
import inspect
import json
import sqlite3
import tempfile
import threading
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

try:
    import anyio
    from mulder.db import CaseDB
    from mulder.path_policy import PathPolicyError
    from mulder.server import app
    from mulder.server import case_scope
    from mulder.server.jobs import JobStore
    from mulder.server.tools import artifacts, case, phone
except ImportError:
    case_scope = None


@unittest.skipUnless(case_scope and hasattr(app, '_case_operation'), 'Requires case-boundary Mulder patch')
class MulderCaseBoundariesTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.base=Path(temp.name).resolve();self.store=self.base/'cases'
        self.evidence={}
        for name in ('A','B'):
            root=self.base/('evidence-'+name);root.mkdir()
            (root/'record.txt').write_text(name+'_PRIVATE_CONTENT')
            self.evidence[name]=root
            database=CaseDB.create(name,str(root),self.store);database.close()
        for name,value in [('_cfg',app.ServerConfig(self.store,max_workers=2)),('_ctx',None),('_job_store',None),('_active_case_operations',0),('_transition_owner',None),('_transition_depth',0)]:
            patcher=patch.object(app,name,value);patcher.start();self.addCleanup(patcher.stop)
        self.token=app._bound_case.set(app._UNBOUND_CASE)
        self.addCleanup(app._bound_case.reset,self.token)
        app.load_case('A')
        self.addCleanup(self.close_case)

    def close_case(self):
        if app._ctx:
            app._ctx.db.close()
            app._ctx=None

    def read(self,path):
        return app._tool_dispatch_sync['read_evidence_file'](file_path=str(path))

    def test_shared_store_and_sibling_evidence_are_denied(self):
        for path in (self.store,self.store/'B.db',self.evidence['B']/'record.txt'):
            with self.subTest(path=path),self.assertRaises(PathPolicyError):
                case_scope.resolve_case_read_path(path)
        self.assertEqual(self.read(self.evidence['B']/'record.txt')['status'],'error')
        own=self.read(self.evidence['A']/'record.txt')
        self.assertIn('A_PRIVATE_CONTENT',json.dumps(own))

    def test_symlink_and_dotdot_cannot_reach_sibling(self):
        link=self.evidence['A']/'linked';link.symlink_to(self.evidence['B'])
        for path in (link/'record.txt',self.evidence['A']/'..'/'evidence-B'/'record.txt'):
            self.assertEqual(self.read(path)['status'],'error')

    def test_listing_never_follows_linked_child(self):
        (self.evidence['A']/'foreign').symlink_to(self.evidence['B'])
        result=app._tool_dispatch_sync['list_directory'](path=str(self.evidence['A']),recursive=True)
        self.assertEqual(result['result_count'],1)
        self.assertEqual(result['results'][0]['name'],'record.txt')

    def test_retained_output_claim_survives_restart_and_excludes_other_case(self):
        output=self.base/'parser-output';output.mkdir();(output/'records.json').write_text('[{"body":"A_DERIVED"}]')
        retained=phone._retain_leapp_output(output,'tc_a_claim','synthetic')
        self.assertEqual(case_scope.resolve_case_read_path(retained/'records.json'),retained/'records.json')
        app.load_case('B')
        with self.assertRaises(PathPolicyError):case_scope.resolve_case_read_path(retained/'records.json')
        app.load_case('A')
        self.assertIn('A_DERIVED',json.dumps(self.read(retained/'records.json')))

    def test_unclaimed_legacy_retained_directory_is_denied(self):
        path=self.store/'retained-tools'/'looks-like-A';path.mkdir(parents=True)
        (path/'secret.txt').write_text('UNCLAIMED')
        with self.assertRaises(PathPolicyError):case_scope.resolve_case_read_path(path/'secret.txt')

    def test_concurrent_retention_claims_are_not_lost(self):
        paths=[]
        for i in range(8):
            path=self.store/'retained-tools'/str(i);path.mkdir(parents=True)
            paths.append(path)
        ctx=app.get_ctx()
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda p:case_scope.register_retained_root(p,ctx),paths))
        for path in paths:self.assertIn(path,case_scope.case_read_roots())

    def test_extraction_is_case_namespaced_and_foreign_archive_refused(self):
        archive=self.evidence['A']/'sample.zip'
        with zipfile.ZipFile(archive,'w') as z:z.writestr('item.txt','A_DERIVED')
        result=app._tool_dispatch_sync['extract_archive'](archive_path=str(archive),max_output_bytes=4096,max_files=10)
        self.assertEqual(result['status'],'success',result)
        output=Path(result['extracted_to'])
        self.assertTrue(output.is_relative_to(self.store/'extracted'/'A'))
        self.assertIn('A_DERIVED',json.dumps(self.read(output/'item.txt')))
        app.load_case('B')
        self.assertEqual(self.read(output/'item.txt')['status'],'error')
        rejected=app._tool_dispatch_sync['extract_archive'](archive_path=str(archive),max_output_bytes=4096,max_files=10)
        self.assertEqual(rejected['error_type'],'case_scope_invalid')

    def test_autoruns_discovery_does_not_scan_shared_store(self):
        (self.evidence['A']/'autoruns.csv').write_text('Entry,Image Path\nA,test')
        (self.evidence['B']/'autoruns.csv').write_text('Entry,Image Path\nB,test')
        (self.store/'secret-autoruns.csv').write_text('Entry,Image Path\nSECRET,test')
        self.assertEqual(artifacts._discover_autoruns_csvs(''),[self.evidence['A']/'autoruns.csv'])
        result=app._tool_dispatch_sync['parse_autoruns'](csv_path=str(self.evidence['B']/'autoruns.csv'))
        self.assertEqual(result['status'],'error')

    def test_other_generic_artifact_readers_reject_foreign_inputs(self):
        path=self.evidence['B']/'photo.jpg';path.write_bytes(b'foreign image')
        with patch.object(artifacts.subprocess,'run',side_effect=AssertionError('Must not run parser')):
            for name,arg in [('detect_steganography','target_path'),('extract_steganography','image_path')]:
                result=app._tool_dispatch_sync[name](**{arg:str(path)})
                self.assertEqual(result['status'],'error')
            self.assertFalse(artifacts._icat_extract(str(path),0,'1',self.base/'out'))

    def test_bad_metadata_root_refused(self):
        ctx=app.get_ctx();meta=ctx.db.get_case_metadata()
        from types import SimpleNamespace
        for root in ('','relative'):
            invalid=SimpleNamespace(case_id=meta.case_id,ingested_at=meta.ingested_at,evidence_root=root)
            with patch.object(ctx.db,'get_case_metadata',return_value=invalid),self.assertRaises(PathPolicyError):
                case_scope.case_read_roots()

    def blocking_tool(self,started,release):
        def examine():
            context=app.get_ctx();started.set()
            if not release.wait(3):raise RuntimeError('Test release deadline')
            if app.get_ctx() is not context:raise AssertionError('Case context changed')
            context.db.register_source('synthetic.guard',str(self.evidence['A']/'record.txt'),'test','test',1)
            return {'status':'success','case_id':context.case_id}
        return app._secure_sync_tool(examine)

    def test_direct_tool_blocks_switch_and_create_until_write_finishes(self):
        started=threading.Event();release=threading.Event()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(self.blocking_tool(started,release))
            self.assertTrue(started.wait(2))
            try:
                with self.assertRaisesRegex(RuntimeError,'active'):app.load_case('B')
                with self.assertRaisesRegex(RuntimeError,'active'):app.create_case('C',str(self.evidence['B']))
            finally:release.set()
            self.assertEqual(future.result(2)['case_id'],'A')
        self.assertEqual(app.get_ctx().db.get_source_count(),1)
        app.load_case('B');self.assertEqual(app.get_ctx().db.get_source_count(),0)

    def test_operation_failure_releases_lease(self):
        def fail():raise ValueError('synthetic')
        with self.assertRaises(ValueError):app._secure_sync_tool(fail)()
        self.assertEqual(app._active_case_operations,0)
        app.load_case('B');self.assertEqual(app.get_ctx().case_id,'B')

    def test_transition_reservation_rejects_new_operation_without_deadlock(self):
        started=threading.Event();release=threading.Event();original=CaseDB.open
        def slow_open(*args):
            started.set();release.wait(3);return original(*args)
        with patch.object(CaseDB,'open',side_effect=slow_open),ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(app.load_case,'B');self.assertTrue(started.wait(2))
            try:
                with self.assertRaisesRegex(RuntimeError,'transition'):
                    app._secure_sync_tool(lambda: app.get_ctx())()
            finally:release.set()
            self.assertEqual(future.result(2).case_id,'B')

    def test_background_pending_and_running_jobs_block_switch(self):
        started=threading.Event();release=threading.Event()
        store=JobStore(1,{'examine':self.blocking_tool(started,release)})
        with patch.object(app,'_job_store',store),patch.object(app,'wait_for_resources',return_value=None):
            batch=store.submit_batch([{'tool':'examine'},{'tool':'examine'}])
            try:
                self.assertTrue(started.wait(2))
                with self.assertRaises(RuntimeError):app.load_case('B')
            finally:release.set()
            self.assertTrue(batch.done_event.wait(3))
            self.assertEqual(store.get_batch_status(batch.batch_id)['completed'],2)
            app.load_case('B')
        store.shutdown(wait=True)

    def test_parallel_nested_case_switch_fails_without_deadlock(self):
        async def scenario():
            with patch.object(app,'_tool_limiter',anyio.CapacityLimiter(2)),patch.object(app,'async_wait_for_resources',return_value=None):
                result=await app._tool_dispatch['run_parallel']([{'tool':'open_case','args':{'case_id':'B'}},{'tool':'get_source_stats','args':{}}])
                self.assertIn('error',result['parallel_results'][0]['result'])
                self.assertEqual(app.get_ctx().case_id,'A')
        anyio.run(scenario)
        self.assertEqual(app._active_case_operations,0)
        app.load_case('B')

    def test_completed_batches_are_case_owned_and_foreign_reads_do_not_consume(self):
        from mulder.server.tools import jobs
        secret='A_PRIVATE_RESULT'
        def examine():
            return {'status':'success','source_name':secret,'tool_call_id':'tc_A_PRIVATE'}
        store=JobStore(1,{'examine':app._secure_sync_tool(examine)})
        try:
            with patch.object(app,'_job_store',store),patch.object(app,'wait_for_resources',return_value=None):
                batch=store.submit_batch([{'tool':'examine'}])
                self.assertTrue(batch.done_event.wait(3))
                proof=app.get_ctx().db.get_kv('lawliet.batch_owner.'+batch.batch_id)
                self.assertEqual(json.loads(proof)['database'],str(self.store/'A.db'))
                self.assertEqual(store.batch_ids(),[batch.batch_id])
                app.load_case('B')
                self.assertEqual(store.batch_ids(),[])
                self.assertIsNone(store.get_batch_status(batch.batch_id))
                self.assertIsNone(store.get_completed_results(batch.batch_id))
                self.assertIsNone(store.get_job_result(batch.job_ids[0]))
                self.assertFalse(store.wait_for_batch(batch.batch_id,timeout=0))
                for name,args in [
                    ('check_extraction_status',{'batch_id':batch.batch_id}),
                    ('get_completed_results',{'batch_id':batch.batch_id}),
                    ('wait_all',{'batch_ids':[batch.batch_id]}),
                    ('wait',{'batch_id':batch.batch_id,'seconds':10}),
                    ('wait',{'job_id':batch.job_ids[0],'seconds':10}),
                ]:
                    with self.subTest(tool=name,args=args):
                        result=app._tool_dispatch_sync[name](**args)
                        self.assertEqual(result['status'],'error')
                        self.assertNotIn(secret,json.dumps(result))
                        self.assertNotIn('tc_A_PRIVATE',json.dumps(result))
                audit=(self.store/'B.audit.jsonl').read_text()
                self.assertNotIn(secret,audit);self.assertNotIn('tc_A_PRIVATE',audit)
                self.assertFalse(store._delivered[batch.batch_id])
                app.load_case('A')
                self.assertEqual(app.get_ctx().db.get_kv('lawliet.batch_owner.'+batch.batch_id),proof)
                result=app._tool_dispatch_sync['get_completed_results'](batch_id=batch.batch_id)
                self.assertEqual(result['results_returned'],1)
                self.assertEqual(result['results'][0]['source_name'],secret)
                self.assertIn('tc_A_PRIVATE',(self.store/'A.audit.jsonl').read_text())
                self.assertEqual(app._tool_dispatch_sync['wait'](job_id=batch.job_ids[0],seconds=10)['status'],'done')
        finally:store.shutdown(wait=True)

    def test_legacy_unowned_batch_refused_but_unfinished_global_guard_remains(self):
        started=threading.Event();release=threading.Event()
        store=JobStore(1,{'examine':self.blocking_tool(started,release)})
        try:
            with patch.object(app,'_job_store',store),patch.object(app,'wait_for_resources',return_value=None):
                batch=store.submit_batch([{'tool':'examine'}]);self.assertTrue(started.wait(2))
                batch.owner=None
                try:
                    self.assertEqual(store.batch_ids(),[])
                    self.assertIsNone(store.get_batch_status(batch.batch_id))
                    self.assertIn(batch.batch_id,store._all_batch_ids())
                    self.assertFalse(store._get_batch_status_unscoped(batch.batch_id)['all_done'])
                    with self.assertRaises(RuntimeError):app.load_case('B')
                finally:release.set()
                self.assertTrue(batch.done_event.wait(3))
                self.assertIsNone(store.get_completed_results(batch.batch_id))
                app.load_case('B')
        finally:store.shutdown(wait=True)

    def test_missing_persistent_batch_binding_refuses_without_consuming(self):
        store=JobStore(1,{'examine':app._secure_sync_tool(lambda:'A_PRIVATE_PREVIEW'*30)})
        try:
            with patch.object(app,'_job_store',store),patch.object(app,'wait_for_resources',return_value=None):
                batch=store.submit_batch([{'tool':'examine'}]);self.assertTrue(batch.done_event.wait(3))
                owner=batch.owner
                app.get_ctx().db.set_kv('lawliet.batch_owner.'+batch.batch_id,'unproven')
                self.assertIsNone(store.get_completed_results(batch.batch_id))
                self.assertIsNone(store.get_job_result(batch.job_ids[0]))
                self.assertFalse(store._delivered[batch.batch_id])
                app.get_ctx().db.set_kv('lawliet.batch_owner.'+batch.batch_id,owner)
                self.assertEqual(len(store.get_completed_results(batch.batch_id)),1)
        finally:store.shutdown(wait=True)

    def test_async_aggregator_cannot_be_reported_completed_by_sync_batch(self):
        from mulder.server.tools import jobs
        store=JobStore(1,app._tool_dispatch_sync)
        try:
            with patch.object(app,'_job_store',store):
                result=app._tool_dispatch_sync['start_extraction_batch']([{'tool':'run_parallel','args':{'tasks':[]}}])
                self.assertEqual(result['status'],'error')
                self.assertIn('run_parallel',result['error_message'])
                self.assertFalse(store._batches)
                self.assertIn('run_parallel',app._tool_dispatch)
                self.assertNotIn('run_parallel',app._tool_dispatch_sync)
        finally:store.shutdown(wait=True)

    def test_queued_request_pins_case_before_resource_wait(self):
        async def scenario():
            waiting=anyio.Event();release=anyio.Event();results=[]
            async def throttle(name):
                waiting.set();await release.wait()
            async def request():
                wrapped=app._wrap_sync_tool(app._secure_sync_tool(lambda:app.get_ctx().case_id))
                results.append(await wrapped())
            with patch.object(app,'_tool_limiter',anyio.CapacityLimiter(1)),patch.object(app,'async_wait_for_resources',side_effect=throttle):
                async with anyio.create_task_group() as group:
                    group.start_soon(request);await waiting.wait()
                    try:
                        with self.assertRaises(RuntimeError):app.load_case('B')
                    finally:release.set()
            self.assertEqual(results,['A'])
        anyio.run(scenario)
        self.assertEqual(app._active_case_operations,0)
        app.load_case('B')

    def test_deferred_retry_keeps_case_pinned_until_final_completion(self):
        retry_started=threading.Event();release=threading.Event();calls=[]
        def retryable():
            calls.append(app.get_ctx().case_id)
            if len(calls)==1:return {'status':'error','error_type':'timeout'}
            retry_started.set()
            if not release.wait(3):raise RuntimeError('Test release deadline')
            return {'status':'success'}
        store=JobStore(1,{'retryable':app._secure_sync_tool(retryable)})
        try:
            with patch.object(app,'_job_store',store),patch.object(app,'wait_for_resources',return_value=None),patch('mulder.server.jobs.should_defer',return_value=True):
                batch=store.submit_batch([{'tool':'retryable'}])
                try:
                    self.assertTrue(retry_started.wait(2))
                    self.assertTrue(batch.retry_started)
                    with self.assertRaises(RuntimeError):app.load_case('B')
                finally:release.set()
                self.assertTrue(batch.done_event.wait(3))
                self.assertEqual(calls,['A','A'])
                self.assertEqual(store.get_batch_status(batch.batch_id)['completed'],1)
                app.load_case('B')
        finally:store.shutdown(wait=True)

    def test_cancelled_direct_request_retains_lease_until_worker_finishes(self):
        started=threading.Event();release=threading.Event();scopes=[]
        async def scenario():
            wrapped=app._wrap_sync_tool(self.blocking_tool(started,release))
            async def request():
                with anyio.CancelScope() as scope:
                    scopes.append(scope);await wrapped()
            with patch.object(app,'_tool_limiter',anyio.CapacityLimiter(1)),patch.object(app,'async_wait_for_resources',return_value=None):
                async with anyio.create_task_group() as group:
                    group.start_soon(request)
                    self.assertTrue(await anyio.to_thread.run_sync(started.wait,2))
                    scopes[0].cancel();await anyio.sleep(0)
                    try:
                        with self.assertRaises(RuntimeError):app.load_case('B')
                    finally:release.set()
        anyio.run(scenario)
        self.assertEqual(app._active_case_operations,0)
        app.load_case('B')


if __name__=='__main__':unittest.main()
