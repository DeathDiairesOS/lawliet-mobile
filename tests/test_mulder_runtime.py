"""Runtime identity and schema checks need neither a phone nor provider credentials."""
import json
import os
import py_compile
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile import mulder_runtime as runtime
from tools.bootstrap import wrapper


class RuntimeIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='runtime qualification ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root/'upstream'/'mulder'; self.source.mkdir(parents=True)
        self.package = self.source/'src/mulder'
        for name in runtime._REQUIRED_MODULES:
            parts = name.split('.')[1:]
            path = self.package.joinpath(*parts).with_suffix('.py') if parts else self.package/'__init__.py'
            path.parent.mkdir(parents=True, exist_ok=True)
            parent = path.parent
            while parent != self.source/'src':
                (parent/'__init__.py').touch(exist_ok=True)
                parent = parent.parent
            path.write_text("__version__='1.5.2+lawliet.1'\n" if not parts else "VALUE='baseline'\n")
        self.git('init'); self.git('config','user.email','fixture@example.invalid');self.git('config','user.name','Synthetic fixture')
        self.git('add','.');self.git('commit','-m','synthetic baseline')
        self.commit = self.git('rev-parse','HEAD').decode().strip()
        (self.package/'temporal.py').write_text("VALUE='qualified'\n")
        self.repository = self.root/'app'; self.repository.mkdir()
        self.refresh_manifest()
        self.launcher = self.root/'mulder'
        wrapper(self.launcher, [sys.executable,'-c',runtime._CLI_CODE], {'PYTHONPATH':str(self.source/'src')})

    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.source),*args],stderr=subprocess.DEVNULL)

    def refresh_manifest(self):
        self.git('add','-A')
        patch = self.git('diff','HEAD','--binary')
        (self.repository/'patch').write_bytes(patch)
        self.manifest={'sources':{'mulder':{'patch':'patch','patch_sha256':runtime._sha(patch),
            'patched_diff_sha256':runtime._sha(patch),'commit':self.commit}},'expected_mulder_version':'1.5.2+lawliet.1'}

    def identity(self):
        return runtime.inspect_runtime(runtime.resolve_launcher(self.launcher))

    def test_real_imports_and_exact_source_diff_qualify_without_install_layout_assumptions(self):
        identity=self.identity()
        result=runtime.verify_source_identity(identity,self.repository,self.manifest)
        self.assertEqual(result['source_root'],str(self.source))
        self.assertEqual(result['imported_modules']['mulder.temporal']['path'],str(self.package/'temporal.py'))
        self.assertEqual(result['source_files']['src/mulder/temporal.py'],runtime._sha((self.package/'temporal.py').read_bytes()))
        self.assertEqual(len(result['source_fingerprint']),64)

    def test_same_version_with_old_code_is_rejected(self):
        before=self.identity()
        (self.package/'temporal.py').write_text("VALUE='baseline'\n")
        old=self.identity()
        self.assertEqual(before['version'],old['version'])
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'patch differs'):
            runtime.verify_source_identity(old,self.repository,self.manifest)

    def test_unstaged_manual_patch_is_not_a_managed_runtime(self):
        self.git('reset','HEAD','--','src/mulder/temporal.py')
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'exact patch staged'):
            runtime.verify_source_identity(self.identity(),self.repository,self.manifest)

    def test_git_hidden_working_source_flags_are_rejected(self):
        path=self.package/'db.py'
        for flag in ('assume-unchanged','skip-worktree'):
            with self.subTest(flag=flag):
                self.git('update-index','--'+flag,'src/mulder/db.py')
                path.write_text("VALUE='foreign_code'\n")
                self.assertEqual(runtime._sha(self.git('diff','HEAD','--binary')),self.manifest['sources']['mulder']['patched_diff_sha256'])
                with self.assertRaisesRegex(runtime.RuntimeQualificationError,'index has'):
                    runtime.verify_source_identity(self.identity(),self.repository,self.manifest)
                path.write_text("VALUE='baseline'\n")
                self.git('update-index','--no-'+flag,'src/mulder/db.py')

    def test_working_source_blob_check_does_not_trust_cached_git_diff(self):
        original=runtime._run
        expected=self.git('diff','HEAD','--binary')
        (self.package/'db.py').write_text("VALUE='foreign_code'\n")
        identity=self.identity()
        def stale_diff(argv,**kwargs):
            if list(argv)[3:] == ['diff','HEAD','--binary']:return expected
            return original(argv,**kwargs)
        with patch.object(runtime,'_run',side_effect=stale_diff):
            with self.assertRaisesRegex(runtime.RuntimeQualificationError,'pinned index blob'):
                runtime.verify_source_identity(identity,self.repository,self.manifest)

    def test_ignored_injected_python_is_rejected(self):
        (self.source/'.git/info/exclude').write_text('injected.py\n')
        (self.package/'injected.py').write_text('INJECTED=True\n')
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'Unexpected Python'):
            runtime.verify_source_identity(self.identity(),self.repository,self.manifest)

    def test_changed_repository_patch_is_rejected(self):
        (self.repository/'patch').write_text('altered')
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'Repository Mulder patch'):
            runtime.verify_source_identity(self.identity(),self.repository,self.manifest)

    def test_import_hash_disagrees_with_source_is_rejected(self):
        identity=self.identity();identity['modules']['mulder.db']['sha256']='0'*64
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'differs from its qualified source'):
            runtime.verify_source_identity(identity,self.repository,self.manifest)

    def test_missing_runtime_dependency_is_clear_and_not_silently_skipped(self):
        (self.package/'db.py').write_text('import missing_forensic_fixture_dependency\n')
        self.refresh_manifest()
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'missing dependency missing_forensic_fixture_dependency'):
            runtime.verify_source_identity(self.identity(),self.repository,self.manifest)

    def test_foreign_imported_module_is_rejected(self):
        identity=self.identity()
        identity['modules']['mulder.db']['path']=str(self.root/'foreign.py')
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'escaped'):
            runtime.verify_source_identity(identity,self.repository,self.manifest)

    def test_console_entrypoint_and_venv_interpreter_path_are_preserved(self):
        console=self.root/'console';console.write_text('#!'+sys.executable+'\n'+runtime._CONSOLE_SCRIPT);console.chmod(0o755)
        wrapper(self.launcher,[console],{'PYTHONPATH':str(self.source/'src')})
        spec=runtime.resolve_launcher(self.launcher)
        self.assertEqual(spec['python'],sys.executable)
        self.assertEqual(set(spec['launcher_files']),{str(self.launcher),str(console)})
        self.assertEqual(runtime.inspect_runtime(spec)['version'],'1.5.2+lawliet.1')

    def test_stable_symlink_launcher_and_entrypoint_are_supported_but_retargeting_fails(self):
        console=self.root/'console';console.write_text('#!'+sys.executable+'\n'+runtime._CONSOLE_SCRIPT);console.chmod(0o755)
        entry=self.root/'entry';entry.symlink_to(console)
        wrapper(self.launcher,[entry],{'PYTHONPATH':str(self.source/'src')})
        alias=self.root/'alias';alias.symlink_to(self.launcher)
        spec=runtime.resolve_launcher(alias)
        self.assertEqual(runtime.inspect_runtime(spec)['version'],'1.5.2+lawliet.1')
        other=self.root/'other';other.write_text(console.read_text());other.chmod(0o755)
        entry.unlink();entry.symlink_to(other)
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'target changed'):
            runtime.inspect_runtime(spec)
        entry.unlink();entry.symlink_to(console)
        other.write_text(self.launcher.read_text())
        alias.unlink();alias.symlink_to(other)
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'target changed'):
            runtime.inspect_runtime(spec)

    def test_launcher_retarget_during_import_is_detected_after_probe(self):
        alias=self.root/'alias';alias.symlink_to(self.launcher)
        spec=runtime.resolve_launcher(alias)
        other=self.root/'other';other.write_text(self.launcher.read_text());other.chmod(0o755)
        original=runtime._run
        def retarget(argv,**kwargs):
            result=original(argv,**kwargs)
            alias.unlink();alias.symlink_to(other)
            return result
        with patch.object(runtime,'_run',side_effect=retarget):
            with self.assertRaisesRegex(runtime.RuntimeQualificationError,'target changed'):
                runtime.inspect_runtime(spec)

    def test_launcher_retarget_during_mcp_is_detected_after_schema_probe(self):
        alias=self.root/'alias';alias.symlink_to(self.launcher)
        other=self.root/'other';other.write_text(self.launcher.read_text());other.chmod(0o755)
        original=runtime._run
        def retarget(argv,**kwargs):
            if '--schema-probe' in argv:
                alias.unlink();alias.symlink_to(other)
                return json.dumps({'profiles':[{'profile':p} for p in runtime.PROFILES]}).encode()
            return original(argv,**kwargs)
        with patch.object(runtime,'_run',side_effect=retarget):
            with self.assertRaisesRegex(runtime.RuntimeQualificationError,'target changed'):
                runtime.qualify_runtime(alias,self.repository,self.manifest)

    def test_source_only_safe_path_cli_form_and_cache_prefix(self):
        wrapper(self.launcher,[sys.executable,'-B','-P','-c',runtime._CLI_CODE],
                {'PYTHONPATH':str(self.source/'src'),'PYTHONPYCACHEPREFIX':'/dev/null/lawliet-source-only'})
        self.assertEqual(self.identity()['version'],'1.5.2+lawliet.1')
        wrapper(self.launcher,[sys.executable,'-B','-P','-c',runtime._CLI_CODE],
                {'PYTHONPYCACHEPREFIX':str(self.root/'cache')})
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'bytecode-cache location'):
            runtime.resolve_launcher(self.launcher)

    def test_timestamp_valid_stale_bytecode_does_not_replace_probed_source(self):
        path=self.package/'__init__.py'
        py_compile.compile(str(path),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        stamp=path.stat()
        path.write_text("__version__='1.5.2+lawliet.2'\n")
        os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
        env=dict(os.environ,PYTHONPATH=str(self.source/'src'))
        env.pop('PYTHONPYCACHEPREFIX',None)
        cached=subprocess.check_output([sys.executable,'-B','-P','-c','import mulder;print(mulder.__version__)'],env=env,text=True)
        self.assertEqual(cached.strip(),'1.5.2+lawliet.1')
        self.assertEqual(self.identity()['version'],'1.5.2+lawliet.2')

    def test_malformed_cli_code_is_a_qualification_error(self):
        wrapper(self.launcher,[sys.executable,'-c','from mulder.cli import ('])
        with self.assertRaises(runtime.RuntimeQualificationError):runtime.resolve_launcher(self.launcher)

    def test_relative_interpreter_is_not_resolved_against_a_different_cwd(self):
        wrapper(self.launcher, ['python3','-c',runtime._CLI_CODE])
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'interpreter'):
            runtime.resolve_launcher(self.launcher)

    def test_exact_set_eu_existing_launcher_is_supported(self):
        self.launcher.write_text(self.launcher.read_text().replace('#!/bin/sh\n', '#!/bin/sh\nset -eu\n'))
        self.assertEqual(self.identity()['version'], '1.5.2+lawliet.1')

    def test_opaque_or_expanding_launcher_is_refused_without_execution(self):
        marker=self.root/'should-not-exist'
        for contents in ('#!/bin/sh\ntouch '+str(marker)+'\nexec /bin/false "$@"\n',
                         '#!/bin/sh\nexport PYTHONPATH="$(touch '+str(marker)+')"\nexec /bin/false "$@"\n',
                         '#!/bin/sh\nexport PATH=/bin;touch '+str(marker)+'\nexec /bin/false "$@"\n',
                         '#!/bin/sh\nexport TOKEN=secret\nexec /bin/false "$@"\n'):
            self.launcher.write_text(contents)
            with self.assertRaises(runtime.RuntimeQualificationError):runtime.resolve_launcher(self.launcher)
        self.assertFalse(marker.exists())

    def test_run_timeout_output_bound_and_stderr_redaction(self):
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'timed out'):
            runtime._run([sys.executable,'-c','import time;time.sleep(10)'],timeout=.05)
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'output bound'):
            runtime._run([sys.executable,'-c','print("x"*10000)'],maximum=100)
        with self.assertRaises(runtime.RuntimeQualificationError) as error:
            runtime._run([sys.executable,'-c','import sys;print("SECRET_CREDENTIAL",file=sys.stderr);sys.exit(2)'])
        self.assertNotIn('SECRET_CREDENTIAL',str(error.exception))


class RuntimeSchemaTests(unittest.TestCase):
    def standard(self):
        return {**{name:{} for name in ('run_aleapp','run_ileapp','run_mvt_android')},
            'get_timeline':{'properties':{'offset':{'type':'integer'},'limit':{'type':'integer'}}},
            'reindex_timestamps':{'properties':{'after_id':{'type':'integer'},'limit':{'type':'integer'}}}}

    def test_required_new_schemas_and_safe_standard_surface(self):
        tools=self.standard();self.assertEqual(runtime.validate_tool_schemas('standard',tools)['tools_advertised'],5)
        tools['get_timeline']['properties'].pop('offset')
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'input schema'):runtime.validate_tool_schemas('standard',tools)
        tools=self.standard();tools.pop('reindex_timestamps')
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'missing'):runtime.validate_tool_schemas('standard',tools)
        tools=self.standard();tools['collect_lawliet_android_sms']={}
        with self.assertRaisesRegex(runtime.RuntimeQualificationError,'Device collection'):runtime.validate_tool_schemas('standard',tools)

    def test_every_restricted_profile_requires_exact_surface(self):
        for profile,names in runtime.PROFILE_TOOLS.items():
            tools={name:{} for name in names}
            self.assertEqual(runtime.validate_tool_schemas(profile,tools)['profile'],profile)
            tools['get_timeline']={}
            with self.subTest(profile=profile),self.assertRaisesRegex(runtime.RuntimeQualificationError,'surface mismatch'):
                runtime.validate_tool_schemas(profile,tools)


@unittest.skipUnless(os.environ.get('LAWLIET_TEST_MULDER_LAUNCHER'),'Explicit existing Mulder runtime qualification launcher required')
class ExistingRuntimeTests(unittest.TestCase):
    def test_real_candidate_source_and_all_mcp_profiles(self):
        repository=Path(__file__).resolve().parents[1]
        result=runtime.qualify_runtime(os.environ['LAWLIET_TEST_MULDER_LAUNCHER'],repository)
        self.assertEqual(result['status'],'qualified')
        self.assertEqual({p['profile'] for p in result['profiles']},set(runtime.PROFILES))
        self.assertTrue(result['imported_modules']['mulder.temporal']['sha256'])


if __name__=='__main__':unittest.main()
