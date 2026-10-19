"""Real isolated MCP collection against a synthetic ADB executable, never a phone."""
import asyncio
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile.agent_collection_endpoint import launch, parent_location, case_binding
from lawliet_mobile.mulder_runtime import RuntimeQualificationError
from lawliet_mobile.core import connect, create_case, import_evidence, add_artifact, verify
from lawliet_mobile.agent_collection import create_plan
from lawliet_mobile.tools import configure

try:
    import mulder
    from mulder.server import app
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    AVAILABLE = hasattr(app, '_LAWLIET_WORKFLOW_TOOLS')
except ModuleNotFoundError:
    AVAILABLE = False

TOOLS = {'get_lawliet_collection','run_lawliet_collection','query_lawliet_collection'}


@unittest.skipUnless(AVAILABLE and Path('/usr/bin/sandbox-exec').is_file(), 'Requires staged Mulder workflow and macOS sandbox')
class CollectionMCPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lawliet-collection-mcp-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.workspace = self.root/'cases'
        self.case = create_case(self.workspace, 'A')
        self.foreign = create_case(self.workspace, 'B')
        self.calls = self.root/'synthetic-adb-calls.jsonl'
        self.adb = self.root/'synthetic_adb.py'
        self.adb.write_text('''import json,shlex,sys
from pathlib import Path
from lawliet_mobile.provider_sms import FIELDS
args=sys.argv[1:]
if args[:2]!=['-s','SYNTHETIC-1']: raise SystemExit('Synthetic serial required')
with Path('''+repr(str(self.calls))+''').open('a') as f:f.write(json.dumps(args)+'\\n')
if args[-1]=='get-state':print('device')
elif args[-1]=='version':print('Android Debug Bridge synthetic fixture')
elif args[-2:]==['am','get-current-user']:print('0')
elif 'getprop' in args:print('fixture-build')
elif 'date' in args:print('2026-10-17T12:00:00-0400')
else:
    q=shlex.split(args[-1]);projection=q[q.index('--projection')+1]
    if projection=='_id':print('Row: 0 _id=1\\nRow: 1 _id=2')
    elif q[q.index('--where')+1]=='0=1':print('No result found.')
    else:
        identifier=int(q[q.index('--where')+1].split('=')[1])
        fields={'thread_id':3,'address':'+12025550100','date':1760000000123+identifier,'date_sent':0,'type':1,'body':'fixture message '+str(identifier),'read':1,'status':-1}
        cells=['Row: 0 _id='+str(identifier)]
        for name in FIELDS:
            value=fields[name];kind='integer' if type(value) is int else 'text'
            cells.extend(['typeof('+name+')='+kind,'hex('+name+')='+str(value).encode().hex().upper()])
        print(', '.join(cells))
''')
        configure(self.workspace, 'adb', self.adb, python=sys.executable)
        self.launcher = self.root/'mulder-fixture'
        source = Path(mulder.__file__).resolve().parents[1]
        backend = Path(__file__).resolve().parents[1]
        self.launcher.write_text('#!/bin/sh\nset -eu\nexport PYTHONPATH='+shlex.quote(str(source)+os.pathsep+str(backend))+
            '\nexec '+shlex.quote(sys.executable)+" -B -P -c 'from mulder.cli import cli; cli()' \"$@\"\n")
        self.launcher.chmod(0o755)
        self.plan = self.make_plan('A')
        self.foreign_plan = self.make_plan('B')

    def make_plan(self, case):
        with connect(self.workspace, case) as (root, db):
            return create_plan(root, db, {'objective':'Read synthetic fixture SMS', 'serial':'SYNTHETIC-1',
                'profiles':['sms-provider'], 'examiner':'Synthetic test', 'authorized':True,
                'android_user':0, 'max_records':10, 'max_bytes':1048576, 'timeout':30})

    def session(self, work, changes=None):
        argv, env = launch(self.case, self.launcher)
        env.update(changes or {})
        async def run():
            params = StdioServerParameters(command=argv[0], args=argv[1:], env=env, cwd=str(self.root))
            with tempfile.TemporaryFile(mode='w+') as log:
                async with stdio_client(params, errlog=log) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        return await work(session)
        return asyncio.run(asyncio.wait_for(run(), timeout=90))

    async def call(self, session, name, **kwargs):
        response = await session.call_tool(name, kwargs)
        self.assertFalse(response.is_error, response)
        return response.structured_content

    def test_actual_mcp_collection_parse_query_provenance_and_no_reacquisition(self):
        with connect(self.workspace, 'A') as (root, db):
            unrelated = self.root/'unrelated.txt'; unrelated.write_text('foreign evidence')
            eid, _, _ = import_evidence(root, db, unrelated)
            add_artifact(db,eid,None,'messages',None,None,'Other source','fixture secret elsewhere','row:1','synthetic',{})
        async def workflow(session):
            listed = await session.list_tools()
            self.assertEqual({t.name for t in listed.tools}, TOOLS)
            for tool in listed.tools:
                props = tool.input_schema['properties']
                self.assertNotIn('case_path',props);self.assertNotIn('serial',props);self.assertNotIn('authorized',props)
            before = await self.call(session,'query_lawliet_collection',plan_id=self.plan['id'])
            self.assertEqual(before['results']['records'],[])
            state = await self.call(session,'get_lawliet_collection',plan_id=self.plan['id'])
            self.assertEqual(state['results']['status'],'authorized')
            self.assertEqual(state['results']['serial'],'SYNTHETIC-1')
            self.assertEqual(state['results']['case_path'],str(self.case))
            for field in ('authorized','authorized_at','pulls','max_bytes','examiner'):
                self.assertNotIn(field,state['results'])
            run = await self.call(session,'run_lawliet_collection',plan_id=self.plan['id'])
            self.assertEqual(run['results']['status'],'complete',run)
            self.assertEqual(run['results']['steps'][0]['records'],2)
            self.assertTrue(run['results']['integrity']['ok'])
            count = len(self.calls.read_text().splitlines())
            replay = await self.call(session,'run_lawliet_collection',plan_id=self.plan['id'])
            self.assertEqual(replay['results']['status'],'complete')
            self.assertEqual(len(self.calls.read_text().splitlines()),count)
            page = await self.call(session,'query_lawliet_collection',plan_id=self.plan['id'],query='fixture',limit=1)
            rows = page['results']['records'];self.assertEqual(len(rows),1)
            self.assertTrue(page['results']['has_more'])
            row = rows[0];self.assertEqual(row['body'],'fixture message 1')
            self.assertTrue(row['source_sha256']);self.assertTrue(row['source_ref'])
            self.assertEqual(row['evidence_id'],run['results']['steps'][0]['evidence_id'])
            page2 = await self.call(session,'query_lawliet_collection',plan_id=self.plan['id'],query='fixture',limit=1,offset=1)
            self.assertEqual(page2['results']['records'][0]['body'],'fixture message 2')
            self.assertFalse(page2['results']['has_more'])
            literal = await self.call(session,'query_lawliet_collection',plan_id=self.plan['id'],query='%')
            self.assertEqual(literal['results']['records'],[])
        self.session(workflow)
        with connect(self.workspace,'A') as (root,db):self.assertTrue(verify(root,db)['ok'])
        folder, parent_id = parent_location(case_binding(self.case))
        audit = [json.loads(line) for line in (folder/(parent_id+'.audit.jsonl')).read_text().splitlines()]
        self.assertTrue(any(row.get('tool_name')=='run_lawliet_collection' for row in audit))

    def test_foreign_unknown_plan_and_query_bounds_fail_without_adb(self):
        async def workflow(session):
            for identifier in (self.foreign_plan['id'],'f'*32):
                for name in TOOLS:
                    response=await self.call(session,name,plan_id=identifier)
                    self.assertEqual(response['status'],'error')
            for kwargs in ({'limit':0},{'limit':101},{'offset':-1},{'offset':2147483648},{'query':'x'*1001}):
                response=await self.call(session,'query_lawliet_collection',plan_id=self.plan['id'],**kwargs)
                self.assertEqual(response['status'],'error')
        self.session(workflow)
        self.assertFalse(self.calls.exists())

    def test_deep_offsets_remain_available_and_do_not_collect(self):
        async def workflow(session):
            for offset in (100001, 150000, 2147483647):
                response = await self.call(session, 'query_lawliet_collection', plan_id=self.plan['id'], offset=offset)
                self.assertEqual(response['status'], 'success')
                result = response['results']
                self.assertEqual(result['offset'], offset)
                self.assertEqual(result['records'], [])
                self.assertIsNone(result['next_offset'])
                self.assertFalse(result['pagination_limit_reached'])
        self.session(workflow)
        self.assertFalse(self.calls.exists())

    def test_next_page_never_exceeds_the_declared_offset_limit(self):
        # The boundary is arithmetic, not a reason to create billions of rows.
        # Keep the actual query adapter and return one extra controlled row.
        from mulder.server.tools import lawliet_collection as bridge
        def invoke(name, params, work):
            return work()
        with patch.object(bridge, '_call', side_effect=invoke), \
             patch.object(bridge, '_case', return_value=self.case), \
             patch('lawliet_mobile.core.select_artifacts', return_value=[{}, {}]) as query:
            deep = bridge.query_lawliet_collection(self.plan['id'], limit=1, offset=100000)
            self.assertTrue(deep['has_more'])
            self.assertEqual(deep['next_offset'], 100001)
            self.assertFalse(deep['pagination_limit_reached'])
            result = bridge.query_lawliet_collection(self.plan['id'], limit=1, offset=2147483647)
            self.assertEqual(query.call_args.kwargs['offset'], 2147483647)
            self.assertTrue(result['has_more'])
            self.assertTrue(result['pagination_limit_reached'])
            self.assertIsNone(result['next_offset'])
        self.assertFalse(self.calls.exists())

    def test_host_case_or_transport_mismatch_refused(self):
        async def workflow(session):
            response=await self.call(session,'run_lawliet_collection',plan_id=self.plan['id'])
            self.assertEqual(response['status'],'error')
        for change in ({'LAWLIET_COLLECTION_CASE':str(self.foreign)}, {'ADB_SERVER_SOCKET':'tcp:example.invalid:5037'}):
            self.session(workflow,change)
        self.assertFalse(self.calls.exists())

    def test_real_provider_denial_reports_failure_and_retains_processing_history(self):
        # Change only the controlled responder before execution; no actual ADB
        # process or device is accessible through this configured command.
        text=self.adb.read_text().replace("q=shlex.split(args[-1]);projection=q[q.index('--projection')+1]",
            "print('Error while accessing provider: SecurityException: Permission Denial'); raise SystemExit(0)\n    q=shlex.split(args[-1]);projection=q[q.index('--projection')+1]")
        self.adb.write_text(text)
        async def workflow(session):
            result=await self.call(session,'run_lawliet_collection',plan_id=self.plan['id'])
            self.assertEqual(result['results']['status'],'failed',result)
            self.assertEqual(result['results']['steps'][0]['records'],0)
            self.assertEqual(result['results']['steps'][0]['status'],'failed')
            query=await self.call(session,'query_lawliet_collection',plan_id=self.plan['id'])
            self.assertEqual(query['results']['records'],[])
        self.session(workflow)
        self.assertTrue(self.calls.exists())

    def test_launcher_pins_packaged_backend_ignores_inherited_remote_adb_and_reuses_parent(self):
        stale=self.root/'old-backend';stale.mkdir();(stale/'lawliet_mobile').mkdir()
        (stale/'lawliet_mobile/__init__.py').write_text('raise AssertionError("wrong backend")\n')
        text=self.launcher.read_text().replace(str(Path(__file__).resolve().parents[1]),str(stale))
        self.launcher.write_text(text)
        argv,env=launch(self.case,self.launcher)
        self.assertEqual(env['PYTHONPATH'].split(os.pathsep)[1],str(Path(__file__).resolve().parents[1]))
        self.assertEqual(env['ADB_SERVER_SOCKET'],'tcp:127.0.0.1:5037')
        self.assertEqual(argv[-2:],['--workers','1'])
        again,_=launch(self.case,self.launcher);self.assertEqual(argv,again)
        self.assertFalse(self.calls.exists())

    def test_case_database_replacement_rejected_before_tool_use(self):
        binding=case_binding(self.case)
        initialize=launch(self.case,self.launcher)
        old=self.case/'case.sqlite'; replaced=self.case/'replacement.sqlite'
        replaced.write_bytes(old.read_bytes());replaced.replace(old)
        async def workflow(session):
            result=await self.call(session,'get_lawliet_collection',plan_id=self.plan['id'])
            self.assertEqual(result['status'],'error')
        # Launch a fresh fixed parent, then give it the previous process binding.
        self.session(workflow,{'LAWLIET_COLLECTION_BINDING':json.dumps(binding,sort_keys=True)})
        self.assertFalse(self.calls.exists())

    def test_standard_and_other_profiles_do_not_advertise_workflow(self):
        code="import asyncio,json; from mulder.server.app import mcp; import mulder.server.tools; print(json.dumps([t.name for t in asyncio.run(mcp.list_tools())]))"
        for profile in ('standard','android-contacts','android-sms','parser-container','sqlite-container','native-container','report-container'):
            env=dict(os.environ,LAWLIET_MCP_PROFILE=profile,PYTHONDONTWRITEBYTECODE='1',PYTHONPYCACHEPREFIX='/dev/null/lawliet-source-only')
            run=subprocess.run([sys.executable,'-B','-P','-c',code],env=env,capture_output=True,text=True,timeout=30,check=True)
            names=set(json.loads(run.stdout));self.assertFalse(names & TOOLS)
            if profile!='standard':self.assertEqual(len(names),3)

    def test_same_version_source_tampering_refused_before_parent_initialization(self):
        source=Path(mulder.__file__).resolve().parents[2]
        candidate=self.root/'modified-runtime'
        subprocess.run(['git','clone','--local','--no-hardlinks','--quiet',str(source),str(candidate)],
                       check=True,capture_output=True,timeout=30)
        patch=Path(__file__).resolve().parents[1]/'integrations/mulder/lawliet.patch'
        subprocess.run(['git','apply','--index',str(patch)],cwd=candidate,check=True,capture_output=True,timeout=30)
        db=candidate/'src/mulder/db.py';db.write_text(db.read_text()+'\n# Unqualified same-version source change\n')
        self.launcher.write_text(self.launcher.read_text().replace(str(source/'src'),str(candidate/'src')))
        with self.assertRaisesRegex(RuntimeQualificationError,'source patch differs'):
            launch(self.case,self.launcher)
        parent,_=parent_location(case_binding(self.case))
        self.assertFalse(parent.exists());self.assertFalse(self.calls.exists())


if __name__=='__main__':unittest.main()
