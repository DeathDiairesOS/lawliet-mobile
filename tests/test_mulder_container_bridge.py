"""Restricted container endpoint must not expose general execution tools."""
import json,os,shlex,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from tools.mulder_parser_container import launch

class ContainerBridgeLaunch(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name).resolve();self.runtime=self.base/'runtime';self.db=self.base/'db';self.db.mkdir();(self.db/'A.db').write_text('preflight fixture')
  candidate=self.runtime/'bin/mulder-lawliet-candidate';candidate.parent.mkdir(parents=True);candidate.write_text('#!/bin/sh\n');candidate.chmod(0o755)
  self.app=self.runtime/'upstream/mulder-1.5.2-ancalor.1/src/mulder/server/app.py';self.app.parent.mkdir(parents=True);self.app.write_text('_LAWLIET_CONTAINER_TOOLS = fixture')
  candidate.write_text('#!/bin/sh\nexport PYTHONPATH='+shlex.quote(str(self.app.parents[2]))+'\nexec '+shlex.quote(sys.executable)+" -c 'from mulder.cli import cli; cli()' \"$@\"\n")
  probe=patch('tools.mulder_endpoint_runtime.inspect_runtime',return_value={'errors':[], 'modules':{'mulder':{'path':str(self.app.parents[1]/'__init__.py')},'mulder.server.app':{'path':str(self.app)}}});probe.start();self.addCleanup(probe.stop)
  self.socket=self.base/'daemon.sock';s=socket.socket(socket.AF_UNIX);self.addCleanup(s.close);s.bind(str(self.socket))
 @unittest.skipUnless(Path('/usr/bin/sandbox-exec').exists(),'macOS only')
 def test_explicit_socket_profile_and_environment(self):
  with patch.dict(os.environ,{'DOCKER_HOST':'tcp://remote:2375','DOCKER_CONTEXT':'remote','DOCKER_TLS_VERIFY':'1','DOCKER_CERT_PATH':'remote'}):args,env=launch(self.runtime,self.db,'A',self.socket)
  self.assertEqual(env['LAWLIET_MCP_PROFILE'],'parser-container');self.assertEqual(env['LAWLIET_CONTAINER_SOCKET'],str(self.socket));self.assertIn('DOCKER_SOCKET='+str(self.socket),args)
  self.assertFalse(any(k in env for k in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH')))
 def test_missing_or_linked_case_refused(self):
  (self.db/'LINK.db').symlink_to(self.db/'A.db')
  for name in ('../A','MISSING','LINK'):
   with self.subTest(name=name),self.assertRaises(ValueError):launch(self.runtime,self.db,name,self.socket)
 def test_regular_file_not_daemon_socket(self):
  with self.assertRaises(ValueError):launch(self.runtime,self.db,'A',self.db/'A.db')
 def test_broad_runtime_refused(self):
  self.app.write_text('# unqualified old profile')
  with self.assertRaises(ValueError):launch(self.runtime,self.db,'A',self.socket)

class ContainerRegistration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  try:import mulder.server.app
  except ModuleNotFoundError:raise unittest.SkipTest('Requires patched Mulder interpreter')
 def test_exact_profile_registration(self):
  code='import asyncio,json;from mulder.server.app import mcp;import mulder.server.tools;print(json.dumps([t.name for t in asyncio.run(mcp.list_tools())]))'
  p=subprocess.run([sys.executable,'-c',code],env={**os.environ,'LAWLIET_MCP_PROFILE':'parser-container'},capture_output=True,text=True,timeout=30)
  self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(set(json.loads(p.stdout)),{'run_lawliet_exiftool_review','query_ancalor_review','list_ancalor_files'})
