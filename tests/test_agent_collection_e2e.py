"""Actual Mulder MCP -> subprocess collector -> parsers -> native app API.

Set LAWLIET_WORKFLOW_LAUNCHER to the staged/pinned Mulder launcher. The only
transport is a local synthetic executable; no physical phone or model is used.
Run this file with --output to retain the synthetic case for native GUI review.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect, create_case, verify
from lawliet_mobile.tools import configure


async def exercise(base, launcher):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    base = Path(base).resolve(); base.mkdir(parents=True, exist_ok=True)
    workspace = base/'cases'
    create_case(workspace, 'COLLECTION-E2E', 'Synthetic agent collection', 'Validation fixture')
    create_case(workspace, 'FOREIGN', 'Unrelated synthetic case')
    adb = base/'collection_adb.py'
    shutil.copy2(ROOT/'tests/fixtures/collection_adb.py', adb)
    configure(workspace, 'adb', str(adb), sys.executable)
    configure(workspace, 'mulder', launcher)
    def request(action, **values):
        return handle(workspace, dict(action=action,case='COLLECTION-E2E',**values))
    settings = dict(objective='Identify the meeting location and corroborating contact in synthetic evidence.',
                    serial='LAWLIET-SYNTHETIC',profiles=['sms-provider','contacts-provider','files','triage','trash-photos'],
                    pulls=['/sdcard/Download/lawliet-seed'],examiner='Synthetic examiner',authorized=True,
                    max_records=10,max_bytes=128*1024**2,timeout=30)
    plan = request('agent-collection-create',config=settings)
    assert plan['max_bytes']==128*1024**2, plan
    foreign = handle(workspace, dict(action='agent-collection-create',case='FOREIGN',
                                    config={**settings,'profiles':['sms-provider'],'pulls':[]}))
    params = StdioServerParameters(command=sys.executable,
        args=[str(ROOT/'lawliet_mobile/agent_collection_endpoint.py'), '--case-path',str(workspace/'COLLECTION-E2E'),
              '--mulder-launcher',str(launcher)], cwd=str(base))
    trace = []
    async def call(session, name, arguments, expected='success'):
        response = await session.call_tool(name, arguments, read_timeout_seconds=180)
        value = (getattr(response,'structured_content',None) or getattr(response,'structuredContent',None)
                 or json.loads(next(c.text for c in response.content if c.type=='text')))
        trace.append({'tool':name,'arguments':arguments,'response':value})
        (base/'mcp-trace.json').write_text(json.dumps(trace,indent=2))
        assert not getattr(response,'is_error',getattr(response,'isError',False)), value
        assert value['status']==expected, value
        return value.get('results', value)
    with (base/'mcp-stderr.log').open('w') as logs:
        async with stdio_client(params, errlog=logs) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize()
                surface = {tool.name for tool in (await session.list_tools()).tools}
                assert surface=={'get_lawliet_collection','run_lawliet_collection','query_lawliet_collection'}, surface
                before = await call(session,'get_lawliet_collection',{'plan_id':plan['id']})
                assert before['status']=='authorized', before
                assert before['case_path']==str(workspace/'COLLECTION-E2E'), before
                empty = await call(session,'query_lawliet_collection',{'plan_id':plan['id']})
                assert empty['records']==[], empty
                result = await call(session,'run_lawliet_collection',{'plan_id':plan['id']})
                assert result['status']=='complete', result
                steps = {s['profile']:s for s in result['steps']}
                assert set(steps)==set(settings['profiles']), result
                assert all(s['status']=='complete' and s['evidence_id'] and s['run_id'] and s['source_id'] for s in steps.values()), result
                messages = await call(session,'query_lawliet_collection',{'plan_id':plan['id'],'category':'messages','limit':1})
                assert len(messages['records'])==1 and messages['has_more'], messages
                remaining = await call(session,'query_lawliet_collection',{'plan_id':plan['id'],'category':'messages','limit':1,'offset':1})
                assert len(remaining['records'])==1 and not remaining['has_more'], remaining
                first = messages['records'][0]
                assert first['body']=='Meet at the blue station at noon — café.', first
                assert first['timestamp']=='2026-10-17T12:00:00.123000Z', first
                contacts = await call(session,'query_lawliet_collection',{'plan_id':plan['id'],'category':'contacts','query':'+12025550123'})
                assert len(contacts['records'])==1 and contacts['records'][0]['title']=='Alex Fixture', contacts
                followup = await call(session,'query_lawliet_collection',{'plan_id':plan['id'],'query':'blue station'})
                assert len(followup['records'])==1, followup
                media = await call(session,'query_lawliet_collection',{'plan_id':plan['id'],'category':'media'})
                assert len(media['records'])==2, media
                logs = await call(session,'query_lawliet_collection',{'plan_id':plan['id'],'category':'logs'})
                assert len(logs['records'])==1, logs
                log = logs['records'][0]
                assert log['timestamp']=='2026-10-17T12:00:01.250000Z', log
                assert log['timestamp_raw']=='1792238401.250', log
                assert log['source_ref'].endswith('line=2'), log
                assert log['evidence_id']==steps['triage']['evidence_id'], log
                await call(session,'run_lawliet_collection',{'plan_id':foreign['id']},expected='error')
                # The existing app APIs read the same records without an import step.
                gui = request('records',category='messages')
                assert [r['id'] for r in gui['records']]==[first['id'],remaining['records'][0]['id']], gui
                overview = request('overview')
                sources = {s['id'] for s in overview['sources']}
                assert all(s['source_id'] in sources for s in result['steps']), result
                for step in steps.values():
                    source = next(s for s in overview['sources'] if s['id']==step['source_id'])
                    gui_source = request('records',evidence=source['evidence'],parser=source['parser'],run=source.get('run'))
                    assert gui_source['records'] and {r['evidence_id'] for r in gui_source['records']}=={step['evidence_id']}, gui_source
                for row in [first,contacts['records'][0],log,*media['records']]:
                    with connect(workspace,'COLLECTION-E2E') as (case,db):
                        path = db.execute('SELECT path FROM files WHERE id=?',(row['file_id'],)).fetchone()[0]
                    actual = hashlib.sha256((case/'evidence'/row['evidence_id']/path).read_bytes()).hexdigest()
                    assert actual==row['source_sha256'], row
                with connect(workspace,'COLLECTION-E2E') as (case,db):
                    bug = db.execute('SELECT path,sha256 FROM files WHERE evidence_id=? AND path=?',
                                     (steps['triage']['evidence_id'],'bugreport.zip')).fetchone()
                    assert bug, 'Successful diagnostics must preserve the original bugreport ZIP.'
                    bug_path = case/'evidence'/steps['triage']['evidence_id']/bug['path']
                    assert zipfile.is_zipfile(bug_path)
                    assert hashlib.sha256(bug_path.read_bytes()).hexdigest()==bug['sha256']
                    trash = db.execute('SELECT file_id FROM media_acquisition_sources WHERE source_kind=?',('trash',)).fetchall()
                    assert len(trash)==1 and trash[0][0] in {r['file_id'] for r in media['records']}
                calls = [json.loads(line) for line in adb.with_suffix('.calls.jsonl').read_text().splitlines()]
                assert not any(args[2]=='backup' for args in calls), 'Triage must never request legacy backup.'
    calls_before = adb.with_suffix('.calls.jsonl').read_text()
    # A fresh MCP process recovers durable state and reuses completed results.
    with (base/'mcp-restart-stderr.log').open('w') as logs:
        async with stdio_client(params, errlog=logs) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize()
                replay = await call(session,'run_lawliet_collection',{'plan_id':plan['id']})
                assert replay['status']=='complete' and replay['steps']==result['steps'], replay
                assert adb.with_suffix('.calls.jsonl').read_text()==calls_before
                denied = request('agent-collection-create', config={**settings,'serial':'LAWLIET-DENIED',
                                                                  'profiles':['sms-provider'],'pulls':[]})
                failed = await call(session,'run_lawliet_collection',{'plan_id':denied['id']})
                assert failed['status']=='failed', failed
                rows = await call(session,'query_lawliet_collection',{'plan_id':denied['id'],'category':'messages'})
                assert not rows['records'], rows
                partial = request('agent-collection-create', config={**settings,'serial':'LAWLIET-PARTIAL',
                    'profiles':['triage','contacts-provider','files']})
                partial_result = await call(session,'run_lawliet_collection',{'plan_id':partial['id']})
                assert partial_result['status']=='partial', partial_result
                partial_steps = {s['profile']:s for s in partial_result['steps']}
                assert partial_steps['triage']['status']=='partial' and partial_steps['triage']['error'], partial_result
                assert all(partial_steps[p]['status']=='complete' for p in ('contacts-provider','files')), partial_result
                partial_rows = await call(session,'query_lawliet_collection',{'plan_id':partial['id']})
                assert {r['category'] for r in partial_rows['records']} >= {'contacts','logs','media'}, partial_rows
                assert {r['evidence_id'] for r in partial_rows['records']}=={s['evidence_id'] for s in partial_steps.values()}, partial_rows
                assert not {r['evidence_id'] for r in partial_rows['records']} & {s['evidence_id'] for s in result['steps']}
                for step in partial_steps.values():
                    assert step['source_id'] in {s['id'] for s in request('overview')['sources']}
                with connect(workspace,'COLLECTION-E2E') as (case,db):
                    diagnostics = case/'collections'/partial_steps['triage']['collection_id']
                    manifest = json.loads((diagnostics/'collection.json').read_text())
                    assert manifest['errors'], manifest
                    assert not (diagnostics/'bugreport.zip').exists()
                    assert (diagnostics/'bugreport.log.stderr').is_file()
                legacy = request('agent-collection-create', config={**settings,'profiles':['messages'],'pulls':[]})
                legacy_result = await call(session,'run_lawliet_collection',{'plan_id':legacy['id']})
                assert legacy_result['status'] in {'partial','failed'}, legacy_result
                legacy_step = legacy_result['steps'][0]
                assert legacy_step['status'] in {'partial','failed'} and legacy_step['error'] and legacy_step['evidence_id'], legacy_result
                legacy_rows = await call(session,'query_lawliet_collection',{'plan_id':legacy['id'],'category':'messages'})
                assert not legacy_rows['records'], legacy_rows
                with connect(workspace,'COLLECTION-E2E') as (case,db):
                    manifest = json.loads((case/'collections'/legacy_step['collection_id']/'collection.json').read_text())
                    assert any(e.get('source')=='telephony_backup' for e in manifest['errors']), manifest
    calls_after_failures = adb.with_suffix('.calls.jsonl').read_text()
    # Partial and unavailable results also replay without silently reacquiring.
    with (base/'mcp-partial-restart-stderr.log').open('w') as logs:
        async with stdio_client(params, errlog=logs) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize()
                for original in (partial_result,legacy_result):
                    retained = await call(session,'run_lawliet_collection',{'plan_id':original['id']})
                    assert retained['status']==original['status'] and retained['steps']==original['steps'], retained
                assert adb.with_suffix('.calls.jsonl').read_text()==calls_after_failures
    integrity = request('verify'); assert integrity['ok'], integrity
    audit_paths = list((workspace/'COLLECTION-E2E/analyses/agent-collection/mulder').glob('*.jsonl'))
    receipt = {'status':'passed','case_path':str(workspace/'COLLECTION-E2E'),'plan_id':plan['id'],
               'failed_plan_id':denied['id'],'partial_plan_id':partial['id'],'legacy_unavailable_plan_id':legacy['id'],
               'complete_plan_counts':{'messages':2,'contacts':1,'media':2,'logs':1,'verified_trash_photos':1},
               'messages':2,'contacts':1,'media':2,'profiles':settings['profiles'],
               'mcp_calls':len(trace),'transport':'synthetic subprocess; no physical phone',
               'model_calls':0,'actual_mulder_mcp':True,'automatic_parse_and_gui_api':True,
               'restart_without_recollection':True,'source_hashes_verified':True,'integrity':integrity,
               'partial_failure_isolated':True,'legacy_backup_failure_retained':True,
               'triage_without_backup':True,'diagnostic_zip_preserved':True,'large_saved_budget_bytes':settings['max_bytes'],
               'audit_paths':[str(p) for p in audit_paths],
               'limitations':['Native window interaction requires separate GUI walkthrough.',
                              'Synthetic transport does not qualify a physical device or provider permissions.']}
    (base/'receipt.json').write_text(json.dumps(receipt,indent=2))
    return receipt


@unittest.skipUnless(os.environ.get('LAWLIET_WORKFLOW_LAUNCHER'), 'Set LAWLIET_WORKFLOW_LAUNCHER for actual staged MCP integration')
class AgentCollectionEndToEnd(unittest.TestCase):
    def test_actual_mcp_collection_and_followup(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = asyncio.run(exercise(tmp,os.environ['LAWLIET_WORKFLOW_LAUNCHER']))
            self.assertEqual(result['status'],'passed')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--launcher',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(asyncio.run(exercise(args.output,args.launcher)),indent=2))
