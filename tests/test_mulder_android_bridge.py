"""Optional local bridge must keep explicit case/tool/transport boundaries."""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tools.mulder_android_sms import launch


class AndroidBridgeLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.runtime=self.base/'runtime';self.store=self.base/'cases';self.store.mkdir()
        (self.store/'A.db').write_bytes(b'controlled preflight file')
        candidate=self.runtime/'bin/mulder-lawliet-candidate';candidate.parent.mkdir(parents=True);candidate.write_text('#!/bin/sh\nexit 0\n');candidate.chmod(0o755)
        self.app=self.runtime/'upstream/mulder-1.5.2-ancalor.1/src/mulder/server/app.py';self.app.parent.mkdir(parents=True);self.app.write_text('_LAWLIET_TOOL_PROFILE = "fixture"\n')
        candidate.write_text('#!/bin/sh\nexport PYTHONPATH='+shlex.quote(str(self.app.parents[2]))+'\nexec '+shlex.quote(sys.executable)+" -c 'from mulder.cli import cli; cli()' \"$@\"\n")
        probe=patch('tools.mulder_endpoint_runtime.inspect_runtime',return_value={'errors':[], 'modules':{
            'mulder':{'path':str(self.app.parents[1]/'__init__.py')},
            'mulder.server.app':{'path':str(self.app)}}})
        probe.start();self.addCleanup(probe.stop)

    @unittest.skipUnless(Path('/usr/bin/sandbox-exec').exists(),'macOS launcher')
    def test_explicit_case_and_filtered_environment(self):
        with patch.dict(os.environ,{'ADB_SERVER_SOCKET':'tcp:remote:1','ANDROID_ADB_SERVER_PORT':'1','ANDROID_ADB_SERVER_ADDRESS':'remote','ANDROID_SERIAL':'hidden-device'}):
            argv,env=launch(self.runtime,self.store,'A')
        self.assertEqual(env['LAWLIET_MCP_PROFILE'],'android-sms')
        self.assertEqual(env['ADB_SERVER_SOCKET'],'tcp:127.0.0.1:5037')
        self.assertTrue(all(k not in env for k in ('ANDROID_ADB_SERVER_PORT','ANDROID_ADB_SERVER_ADDRESS','ANDROID_SERIAL')))
        self.assertEqual(argv[argv.index('serve')+1:],
                         ['--case-id','A','--db-dir',str(self.store.resolve()),
                          '--transport','stdio','--workers','1'])

    def test_missing_unsafe_case_and_symlink_refused(self):
        link=self.store/'LINK.db';link.symlink_to(self.store/'A.db')
        for name in ('','../A','-A','a b','MISSING','LINK'):
            with self.subTest(name=name),self.assertRaises(ValueError):launch(self.runtime,self.store,name)

    @unittest.skipUnless(Path('/usr/bin/sandbox-exec').is_file(),'macOS launcher')
    def test_old_runtime_profile_refused(self):
        self.app.write_text('# old runtime with broad tool surface\n')
        with self.assertRaisesRegex(ValueError,'restricted SMS tool profile'):launch(self.runtime,self.store,'A')


class AndroidBridgeRegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:import mulder.server.app
        except ModuleNotFoundError:raise unittest.SkipTest('Patched Mulder interpreter required')
        cls.script='import asyncio,json;from mulder.server.app import mcp;import mulder.server.tools;print(json.dumps([t.name for t in asyncio.run(mcp.list_tools())]))'

    def probe(self,profile):
        return subprocess.run([sys.executable,'-c',self.script],env={**os.environ,'LAWLIET_MCP_PROFILE':profile},capture_output=True,text=True,timeout=30)

    def test_restricted_surface_has_no_shell_job_or_case_switch_tools(self):
        result=self.probe('android-sms');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(set(json.loads(result.stdout)),{'collect_lawliet_android_sms','query_ancalor_review','list_ancalor_files'})

    def test_standard_surface_keeps_existing_forensic_tools(self):
        result=self.probe('standard');self.assertEqual(result.returncode,0,result.stderr)
        tools=set(json.loads(result.stdout));self.assertIn('scan_evidence',tools);self.assertIn('run_aleapp',tools);self.assertNotIn('collect_lawliet_android_sms',tools);self.assertNotIn('collect_lawliet_android_contacts',tools);self.assertGreater(len(tools),100)

    def test_unknown_profile_fails_closed(self):
        result=self.probe('any-tools');self.assertNotEqual(result.returncode,0);self.assertIn('Unknown LAWLIET MCP profile',result.stderr)
