"""Acquired MVT inputs: conservative routing, preserved originals and honest output.

Run with the patched optional Mulder runtime. LAWLIET_MVT_CANDIDATE may name a
staged mvt.py during downstream patch review; that path is never downloaded.
"""
import ast
import hashlib
import inspect
import io
import json
import os
import shutil
import stat
import tarfile
import tempfile
import types
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import PropertyMock, patch

try:
    from mulder.audit import AuditLog
    from mulder.db import CaseDB
    from mulder.server import app
    if os.environ.get('LAWLIET_MVT_CANDIDATE'):
        tree = ast.parse(Path(os.environ['LAWLIET_MVT_CANDIDATE']).read_text())
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node.decorator_list = []
        mvt = types.ModuleType('mvt_candidate')
        exec(compile(tree, os.environ['LAWLIET_MVT_CANDIDATE'], 'exec'), mvt.__dict__)
    else:
        from mulder.server.tools import mvt
except ImportError:
    mvt = None


@unittest.skipUnless(mvt and hasattr(mvt, '_android_input_type'), 'Requires patched MVT adapter')
class MulderMVTDispatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.source = self.base / 'qf'; self.source.mkdir()
        (self.source / 'acquisition.json').write_text('{"started":"2026-10-15T10:00:00Z"}')
        (self.source / 'getprop.txt').write_text('[ro.product.model]: [SYNTHETIC]\n[persist.sys.timezone]: [UTC]\n')
        (self.source / 'packages.json').write_text('[]')
        self.run = inspect.unwrap(mvt.run_mvt_android)
        self.calls = []
        self.indexed = []
        self.retained = self.base / 'retained'
        self.limit = 1024**2
        store = tempfile.TemporaryDirectory(); self.addCleanup(store.cleanup)
        self.store = Path(store.name).resolve()
        self.db = CaseDB.create('A', str(self.base), self.store)
        self.addCleanup(self.db.close)
        self.ctx = types.SimpleNamespace(case_id='A', db=self.db, audit=AuditLog(self.store/'A.audit.jsonl'))

    def make_zip(self, name, members):
        path = self.base / name
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for key, value in members.items():
                archive.writestr(key, value)
        return path

    def make_ab(self):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w') as archive:
            data = zlib.compress(json.dumps([{'body':'Synthetic message','date':'1728957600000','date_sent':'0','address':'+15550000000','type':1}]).encode())
            info = tarfile.TarInfo('apps/com.android.providers.telephony/d_f/000_sms_backup')
            info.size = len(data); archive.addfile(info, io.BytesIO(data))
        path = self.base / 'backup.ab'
        path.write_bytes(b'ANDROID BACKUP\n5\n1\nnone\n' + zlib.compress(payload.getvalue()))
        return path

    def execute(self, source=None, behavior=None, help_version='2026.10.5', index_failure=False, **kwargs):
        def process(argv, folder, label, environment, timeout):
            self.calls.append((argv, environment))
            self.assertEqual(environment['MVT_NETWORK_ACCESS_ALLOWED'], 'False')
            self.assertIn('--disable-update-check', argv)
            self.assertIn('--disable-indicator-update-check', argv)
            (folder / (label + '-stderr.txt')).write_text('')
            if '--help' in argv:
                (folder / (label + '-stdout.txt')).write_text('Version: '+help_version+'\n--output --iocs --non-interactive')
                return 0
            self.assertNotEqual(Path(argv[-1]), source or self.source)
            self.assertTrue(Path(argv[-1]).exists())
            (folder / 'info.json').write_text('{"mvt_version":"2026.10.5"}')
            if behavior:
                return behavior(argv, folder)
            (folder / 'aqf_getprop.json').write_text('[{"name":"ro.product.model","value":"SYNTHETIC"}]')
            return 0
        def retain(folder, *args):
            destination=self.base/'index-retained' if args[-1].endswith('-index') else self.retained
            shutil.copytree(folder, destination)
            return destination
        def index(*args):
            if index_failure:
                raise RuntimeError('Synthetic indexing failure')
            self.indexed.append(args)
            return {'windows_indexed': 1, 'status': 'success'}
        with patch.object(app, '_ctx', self.ctx), \
                patch.object(mvt.shutil, 'which', return_value='/synthetic/mvt-android'), \
                patch.object(mvt, '_android_process', side_effect=process), \
                patch('mulder.server.tools.phone._retain_leapp_output', side_effect=retain), \
                patch.object(mvt, 'extract_and_index', side_effect=index):
            return self.run(str(source or self.source), max_input_bytes=self.limit, **kwargs)

    def test_known_layouts_select_exact_commands(self):
        backup = self.base / 'backup'; (backup / 'apps/com.test').mkdir(parents=True)
        (backup / 'apps/com.test/_manifest').write_text('synthetic')
        bug = self.make_zip('bug.zip', {'main_entry.txt':'report.txt','report.txt':'synthetic'})
        qfzip = self.make_zip('qf.zip', {'getprop.txt':'model','packages.json':'[]'})
        for path, expected in [(self.source,'androidqf'),(backup,'backup'),(bug,'bugreport'),(qfzip,'androidqf'),(self.make_ab(),'backup')]:
            with self.subTest(expected=expected, path=path):
                self.assertEqual(mvt._android_input_type(path,'auto',self.limit),expected)

    def test_arbitrary_file_and_misdeclared_layout_are_rejected(self):
        text = self.base / 'random.txt'; text.write_text('dumpstate')
        for path, kind in [(text,'auto'),(self.source,'backup')]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                mvt._android_input_type(path,kind,self.limit)

    def test_unsafe_zip_duplicate_links_and_expansion_budget(self):
        for key in ('../outside','/absolute','./a','a/../b'):
            path = self.make_zip('unsafe.zip', {key:'x'})
            with self.subTest(key=key), self.assertRaises(ValueError):
                mvt._android_archive_names(path,self.limit)
        path = self.make_zip('too-large.zip', {'x':'x'*2000})
        with self.assertRaises(ValueError):
            mvt._android_archive_names(path,1000)
        path = self.base/'linked.zip'
        with zipfile.ZipFile(path,'w') as archive:
            info=zipfile.ZipInfo('link'); info.create_system=3
            info.external_attr=(stat.S_IFLNK|0o777)<<16; archive.writestr(info,'outside')
        with self.assertRaises(ValueError):
            mvt._android_archive_names(path,self.limit)

    def test_symlink_and_input_byte_budget_reject_before_execution(self):
        (self.source/'link').symlink_to(self.source/'getprop.txt')
        result = self.execute()
        self.assertEqual(result['status'],'error'); self.assertFalse(self.calls)
        self.assertFalse(self.indexed)

    def test_directory_command_offline_copy_and_record_references(self):
        before=mvt._android_inventory(self.source,self.limit)
        with patch.dict(os.environ, {'MVT_VIRUSTOTAL_API_KEY':'SECRET','MVT_DATA_FOLDER':'foreign','PYTHONPATH':'untrusted'}):
            result=self.execute()
        self.assertEqual(self.calls[-1][0][3],'check-androidqf')
        self.assertIn('--non-interactive',self.calls[-1][0])
        self.assertNotIn('MVT_VIRUSTOTAL_API_KEY',self.calls[-1][1])
        self.assertNotIn('PYTHONPATH',self.calls[-1][1])
        self.assertEqual(result['state'],'limited')
        self.assertTrue(result['source_unchanged'])
        self.assertEqual(before,mvt._android_inventory(self.source,self.limit))
        record=json.loads(self.indexed[0][0]); self.assertEqual(record['result_file'],'aqf_getprop.json')
        self.assertEqual(record['source_record'],0)
        self.assertEqual(self.indexed[0][2],str(self.retained))
        self.assertEqual(result['results']['output_records'],1)
        self.assertTrue((self.retained/'mulder-input-manifest.txt').is_file())
        self.assertNotIn('SECRET',(self.retained/'mulder-execution-receipt.txt').read_text())

    def test_backup_file_is_validated_expanded_and_routed(self):
        path=self.make_ab(); before=path.read_bytes()
        result=self.execute(path)
        self.assertEqual(self.calls[-1][0][3],'check-backup')
        self.assertEqual(result['input_type'],'backup'); self.assertEqual(path.read_bytes(),before)

    def test_bugreport_zip_retains_original_member_timestamps(self):
        path=self.make_zip('bugreport.zip',{'main_entry.txt':'report.txt','report.txt':'synthetic'})
        def check(argv, folder):
            self.assertTrue(Path(argv[-1]).is_file())
            self.assertEqual(Path(argv[-1]).read_bytes(),path.read_bytes())
            return 0
        result=self.execute(path, behavior=check)
        self.assertEqual(self.calls[-1][0][3],'check-bugreport')
        self.assertNotIn('--non-interactive',self.calls[-1][0])
        self.assertEqual(result['input_type'],'bugreport')

    def test_encrypted_backup_is_refused_without_prompt(self):
        path=self.base/'encrypted.ab';path.write_bytes(b'ANDROID BACKUP\n5\n1\nAES-256\n')
        result=self.execute(path)
        self.assertEqual(result['status'],'error'); self.assertFalse(self.calls)
        self.assertIn('Encrypted',result['errors'][0]['error'])

    def test_metadata_only_is_not_a_success_or_a_clean_verdict(self):
        result=self.execute(behavior=lambda argv,folder:0)
        self.assertEqual(result['state'],'empty');self.assertEqual(result['status'],'limited')
        self.assertFalse(self.indexed);self.assertEqual(result['results']['output_records'],0)
        self.assertNotIn('hint',result)

    def test_timeout_keeps_partial_records_and_marks_error(self):
        def timeout(argv,folder):
            (folder/'sms.json').write_text('[{"body":"SYNTHETIC"}]')
            raise TimeoutError('deadline exceeded')
        result=self.execute(behavior=timeout)
        self.assertEqual(result['state'],'limited');self.assertEqual(len(self.indexed),1)
        self.assertIsNone(result['subprocess_returncode'])
        self.assertIn('deadline',result['errors'][0]['error'])

    def test_nonzero_exit_without_records_is_failed(self):
        result=self.execute(behavior=lambda argv,folder:2)
        self.assertEqual(result['state'],'failed');self.assertEqual(result['status'],'error')
        self.assertFalse(self.indexed)

    def test_source_change_refuses_indexing(self):
        def change(argv,folder):
            (self.source/'packages.json').write_text('[{}]')
            (folder/'packages.json').write_text('[{}]')
            return 0
        result=self.execute(behavior=change)
        self.assertFalse(result['source_unchanged']);self.assertFalse(self.indexed)
        self.assertEqual(result['state'],'failed')

    def test_invalid_result_retained_and_excluded(self):
        def invalid(argv,folder):
            (folder/'broken.json').write_text('{')
            (folder/'good.json').write_text('[{"value":1}]')
            return 0
        result=self.execute(behavior=invalid)
        self.assertEqual(result['state'],'limited')
        self.assertEqual(result['results']['output_records'],1)
        self.assertEqual(result['errors'][0]['file'],'broken.json')

    def test_invalid_boolean_budget_rejected_without_process(self):
        with patch.object(mvt, '_android_process',side_effect=AssertionError('Must not execute')):
            result=self.run(str(self.source),max_input_bytes=True)
        self.assertEqual(result['status'],'error')

    def test_ioc_bundle_copied_and_explicit_only(self):
        ioc=self.base/'iocs.stix2';ioc.write_text('{"type":"bundle","objects":[]}')
        result=self.execute(iocs=str(ioc))
        argv=self.calls[-1][0];self.assertIn('--iocs',argv)
        self.assertNotEqual(argv[argv.index('--iocs')+1],str(ioc))
        self.assertTrue(result['ioc_matching_requested'])

    def test_nested_encrypted_backup_refused(self):
        (self.source/'backup.ab').write_bytes(b'ANDROID BACKUP\n5\n1\nAES-256\n')
        result=self.execute();self.assertEqual(result['status'],'error');self.assertFalse(self.calls)

    def test_nested_oem_archive_explicitly_unsupported(self):
        nested=self.make_zip('nested.zip',{'inside.zip':'fake'})
        shutil.copyfile(nested,self.source/'bugreport.zip')
        result=self.execute();self.assertEqual(result['status'],'error');self.assertFalse(self.calls)

    def test_malformed_compressed_backup_returns_retained_failure(self):
        path=self.base/'invalid.ab';path.write_bytes(b'ANDROID BACKUP\n5\n1\nnone\ninvalid')
        result=self.execute(path)
        self.assertEqual(result['status'],'error');self.assertFalse(self.calls)
        self.assertTrue((self.retained/'mulder-execution-receipt.txt').is_file())

    def test_corrupt_nested_archive_returns_retained_failure(self):
        (self.source/'bugreport.zip').write_bytes(b'invalid zip')
        result=self.execute();self.assertEqual(result['status'],'error');self.assertFalse(self.calls)

    def test_no_follow_copy_refuses_replacement_symlink(self):
        real_open=os.open
        victim=self.source/'packages.json'
        outside=self.base/'outside';outside.write_text('SECRET OUTSIDE SCOPE')
        changed=False
        def swap(path, flags, *args, **kwargs):
            nonlocal changed
            if path == 'packages.json' and not changed:
                changed=True;victim.unlink();victim.symlink_to(outside)
            return real_open(path,flags,*args,**kwargs)
        with patch.object(os,'open',side_effect=swap), self.assertRaises(OSError):
            mvt._android_inventory(self.source,self.limit,self.base/'copy')
        self.assertFalse((self.base/'copy/packages.json').exists())

    def test_result_decoding_budget_keeps_oversized_original(self):
        def huge(argv, folder):
            with (folder/'large.json').open('wb') as stream:
                stream.truncate(8*1024**2+1)
            return 0
        result=self.execute(behavior=huge)
        self.assertEqual(result['state'],'failed');self.assertFalse(self.indexed)
        self.assertTrue((self.retained/'large.json').is_file())

    def test_unknown_version_refused_before_analysis(self):
        result=self.execute(help_version='2099.1')
        self.assertEqual(result['state'],'failed');self.assertEqual(len(self.calls),1)
        self.assertFalse(self.indexed)

    def test_indexing_failure_has_durable_distinct_receipt(self):
        result=self.execute(index_failure=True)
        self.assertEqual(result['state'],'failed');self.assertEqual(result['index_status']['status'],'failed')
        execution=json.loads((self.retained/'mulder-execution-receipt.txt').read_text())
        self.assertEqual(execution['execution_state'],'limited')
        outcome=json.loads((Path(result['index_receipt'])/'index-outcome.json').read_text())
        self.assertEqual(outcome['overall_state'],'failed');self.assertEqual(outcome['index']['status'],'failed')

    def test_upstream_error_with_zero_exit_is_not_empty_success(self):
        def fail(argv,folder):
            (folder/'mulder-process-stdout.txt').write_text('ERROR          [mvt.android.modules.backup.sms] Error in extraction\n')
            return 0
        result=self.execute(behavior=fail)
        self.assertEqual(result['state'],'failed');self.assertEqual(result['subprocess_returncode'],0)
        self.assertEqual(result['errors'][0]['file'],'mulder-process-stdout.txt')
        self.assertEqual(result['errors'][0]['line'],1)

    def reject_without_reading(self, source, context=None):
        with patch.object(app, '_ctx', context or self.ctx), \
                patch.object(mvt, '_android_inventory', side_effect=AssertionError('Must not read evidence')), \
                patch.object(mvt, '_android_process', side_effect=AssertionError('Must not run MVT')):
            result=self.run(str(source))
        self.assertEqual(result['status'],'error')
        self.assertEqual(result['error_type'],'case_scope_invalid')
        self.assertFalse((self.store/'retained-tools').exists())
        return result

    def test_foreign_case_input_rejected_before_copy_or_tool(self):
        foreign=self.store/'foreign-evidence';foreign.mkdir()
        (foreign/'getprop.txt').write_text('OUTSIDE CASE')
        other=CaseDB.create('B',str(foreign),self.store);self.addCleanup(other.close)
        result=self.reject_without_reading(foreign)
        self.assertIn('outside',result['error_message'])

    def test_linked_foreign_input_rejected_before_copy_or_tool(self):
        foreign=self.store/'foreign-evidence';foreign.mkdir()
        link=self.base/'linked';link.symlink_to(foreign)
        result=self.reject_without_reading(link)
        self.assertIn('Linked',result['error_message'])

    def test_case_identity_mismatch_rejected_before_copy_or_tool(self):
        wrong=types.SimpleNamespace(case_id='B',db=self.db,audit=self.ctx.audit)
        result=self.reject_without_reading(self.source,wrong)
        self.assertIn('identity',result['error_message'])

    def test_missing_active_case_rejected_before_copy_or_tool(self):
        with patch.object(app,'_ctx',None),patch.object(mvt,'_android_inventory',side_effect=AssertionError('Must not read')):
            result=self.run(str(self.source))
        self.assertEqual(result['error_type'],'case_scope_invalid')

    def test_file_case_root_does_not_authorize_sibling_input(self):
        backup=self.make_ab()
        file_db=CaseDB.create('FILE',str(backup),self.store);self.addCleanup(file_db.close)
        context=types.SimpleNamespace(case_id='FILE',db=file_db,audit=self.ctx.audit)
        self.reject_without_reading(self.source,context)
        with patch.object(app,'_ctx',context):
            source,scope=mvt._android_case_scope(backup)
        self.assertEqual(source,backup)
        self.assertEqual(scope['case_id'],'FILE')

    def test_ioc_outside_evidence_is_explicit_separate_input(self):
        ioc=self.store/'threat-intelligence.stix2';ioc.write_text('{"type":"bundle","objects":[]}')
        result=self.execute(iocs=str(ioc))
        self.assertEqual(result['case_id'],'A')
        self.assertTrue(result['ioc_matching_requested'])

    def test_empty_or_relative_recorded_evidence_root_is_not_cwd(self):
        for name,root in [('EMPTY',''),('SPACE','   '),('RELATIVE','relative-evidence')]:
            with self.subTest(root=root):
                database=CaseDB.create(name,root,self.store)
                self.addCleanup(database.close)
                context=types.SimpleNamespace(case_id=name,db=database,audit=self.ctx.audit)
                result=self.reject_without_reading(self.source,context)
                self.assertIn('nonempty absolute',result['error_message'])

    def test_relative_recorded_database_path_is_refused(self):
        with patch.object(CaseDB,'db_path',new_callable=PropertyMock,return_value=Path('A.db')):
            result=self.reject_without_reading(self.source)
        self.assertIn('database path must be absolute',result['error_message'])


if __name__ == '__main__':
    unittest.main()
