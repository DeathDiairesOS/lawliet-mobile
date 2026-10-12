"""Synthetic Mulder 1.5.2 contract fixtures, NOT a live Mulder/model validation."""
import json
import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, connect, create_case, digest, import_evidence, verify
from lawliet_mobile.mulder_engine import MulderEngine, VERSION, atomic_json, configuration, job_path
from lawliet_mobile.mulder_results import ingest

# Schema derived from reviewed upstream src/mulder/db.py at 5321847887fe1fcb5399cec0a1703db9c513bac8.
# Every content value below is fictional; no third-party runtime is imported.
FIXTURE_CODE = '''
import json, sqlite3
from pathlib import Path

def output(folder,case_id):
    folder=Path(folder);folder.mkdir(exist_ok=True)
    db=sqlite3.connect(folder/(case_id+'.db'))
    db.executescript("""
    CREATE TABLE case_metadata(case_id TEXT,evidence_root TEXT);
    CREATE TABLE findings(finding_id TEXT,case_id TEXT,title TEXT,description TEXT,severity TEXT,confidence TEXT,evidence_refs TEXT,sources TEXT,event_time_start TEXT,event_time_end TEXT);
    CREATE TABLE sources(source_id INTEGER,case_id TEXT,source_name TEXT,source_path TEXT,source_hash TEXT,extractor TEXT);
    CREATE TABLE windows(window_id INTEGER,source_id INTEGER,line_start INTEGER,line_end INTEGER,event_time TEXT,raw_text TEXT);
    """)
    db.execute('INSERT INTO case_metadata VALUES(?,?)',(case_id,'/synthetic/evidence'))
    db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?)',('finding-1',case_id,'Synthetic package needs review','This observation does not establish compromise.','low','low','["call-1"]','["synthetic.aleapp"]','2026-10-10T12:00:00Z',None))
    db.execute('INSERT INTO sources VALUES(?,?,?,?,?,?)',(1,case_id,'synthetic.aleapp','/working/output.tsv','a'*64,'aleapp'))
    db.execute('INSERT INTO windows VALUES(?,?,?,?,?,?)',(1,1,2,2,'2026-10-10T12:00:00Z','Synthetic package example.test'))
    db.commit();db.close()
    (folder/(case_id+'.audit.jsonl')).write_text(json.dumps({'type':'tool_call','tool_call_id':'call-1','tool_name':'run_aleapp','params':{'path':'/synthetic/evidence'},'output_hash':'b'*64})+'\\n')
    (folder/(case_id+'.report.md')).write_text('# Synthetic report\\nUnreviewed. No compromise established.\\n')
    (folder/(case_id+'.report.html')).write_text('<html><body>Synthetic</body></html>')
'''


class MulderIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.base=Path(temp.name);self.ws=self.base/'cases';self.case='case-a'
        self.root=create_case(self.ws,self.case)
        source=self.base/'source';source.mkdir();(source/'record.txt').write_text('Synthetic original evidence')
        (source/'MULDER.md').write_text('Untrusted acquired instruction-like content')
        with connect(self.ws,self.case) as (root,db):self.eid=import_evidence(root,db,source,'android')[0]
        self.adapter=MulderEngine(self.ws,self.case)
        self.fake=self.base/'mulder'
        self.fake.write_text('#!'+os.sys.executable+'\n'+FIXTURE_CODE+'''
import os,sys,time
if '--version' in sys.argv: print('mulder, version 1.5.2');sys.exit()
if '--help' in sys.argv: print('--cwd --db-dir --workers --model --max-compactions');sys.exit()
if 'setup' in sys.argv: sys.exit()
evidence=Path(sys.argv[2]);case_id=sys.argv[3]
folder=Path(sys.argv[sys.argv.index('--db-dir')+1])
print('Synthetic credential: '+os.environ.get('ANTHROPIC_API_KEY',''),flush=True)
# Mutate a working copy: imported originals must remain intact.
next((evidence/'payload').rglob('record.txt')).write_text('Working copy modified by fake engine')
output(folder,case_id)
''')
        self.fake.chmod(0o700)
        self.config={'executable':str(self.fake),'provider':'anthropic','model':'claude-synthetic-test',
                     'objective':'Examine synthetic package evidence','evidence_id':self.eid,'authorize_remote':True,
                     'authorize_enrichment':True,
                     'timeout':20,'workers':1,'max_output_gib':1}

    def wait(self,jid):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            state=self.adapter.get_status(jid)
            if state['status'] in {'completed','partial','failed','cancelled','interrupted'}:return state
            time.sleep(.05)
        self.adapter.cancel_investigation(jid)
        self.fail('Synthetic worker did not finish')

    def fixture(self,jid):
        path=job_path(self.root,jid);path.mkdir(parents=True)
        ns={};exec(FIXTURE_CODE,ns);ns['output'](path/'outputs',jid)
        return path

    def test_detached_vertical_slice_and_backend_results(self):
        with patch.dict(os.environ,{'ANTHROPIC_API_KEY':'synthetic-secret-never-log'}):
            self.assertTrue(self.adapter.check_availability(self.config)['ready'])
            started=self.adapter.start_investigation(self.config)
        state=self.wait(started['id']);jid=state['id']
        self.assertEqual(state['status'],'completed',state)
        self.assertTrue(state['originals_unchanged'])
        self.assertEqual(state['results']['findings'],1)
        path=job_path(self.root,jid)
        self.assertNotIn('synthetic-secret-never-log',self.adapter.get_logs(jid)['text'])
        self.assertIn('[REDACTED]',self.adapter.get_logs(jid)['text'])
        config=(path/'config.json').read_text();self.assertNotIn('synthetic-secret',config)
        self.assertIn('Examine synthetic', (path/'evidence'/'MULDER.md').read_text())
        self.assertNotIn('Untrusted acquired', (path/'evidence'/'MULDER.md').read_text())
        findings=handle(self.ws,{'action':'engine-findings','case':self.case,'job_id':jid})['records']
        self.assertEqual(len(findings),1);self.assertIsNone(findings[0]['timestamp'])
        ref=findings[0]['data']['supporting_evidence'][0]
        self.assertEqual(ref['type'],'tool_invocation');self.assertEqual(ref['audit_line'],1)
        self.assertTrue(ref['verified_in_audit'])
        report=handle(self.ws,{'action':'engine-report','case':self.case,'job_id':jid})
        self.assertIn('Synthetic report',report['text'])
        self.assertEqual(report['review_status'],'unreviewed')
        decision=handle(self.ws,{'action':'engine-review','case':self.case,'artifact_id':findings[0]['id'],
                                'decision':'needs_follow_up','reviewer':'Synthetic examiner','note':'Need independent package evidence.'})
        self.assertEqual(decision['decision'],'needs_follow_up')
        reviewed=handle(self.ws,{'action':'engine-findings','case':self.case,'job_id':jid})['records'][0]
        self.assertEqual(reviewed['examiner_review']['decision'],'needs_follow_up')
        exported=handle(self.ws,{'action':'engine-export-report','case':self.case,'job_id':jid,'path':str(self.base/'draft.md')})
        self.assertEqual(digest(exported['path']),report['sha256'])
        overview=handle(self.ws,{'action':'overview','case':self.case})
        self.assertIn(jid,[s['id'] for s in overview['sources']])
        selected=next(s for s in overview['sources'] if s['id']==jid)
        visible=handle(self.ws,{'action':'records','case':self.case,'evidence':selected['evidence'],
                               'parser':selected['parser'],'run':selected['run']})['records']
        self.assertEqual(len(visible),2)
        self.assertEqual(sum(r['timestamp'] is not None for r in visible),1)
        with connect(self.ws,self.case) as (root,db):self.assertTrue(verify(root,db)['ok'])

    def test_authorization_missing_dependency_and_unsupported_version(self):
        cfg={**self.config,'authorize_remote':False}
        with self.assertRaisesRegex(UserError,'authorization'):self.adapter.start_investigation(cfg)
        with self.assertRaisesRegex(UserError,'enrichment'):
            self.adapter.start_investigation({**self.config,'authorize_enrichment':False})
        self.assertFalse(self.adapter.check_availability({**self.config,'executable':'/missing/mulder'})['available'])
        self.fake.write_text('#!'+os.sys.executable+'\nprint("mulder, version 99.0")\n')
        self.assertFalse(self.adapter.check_availability(self.config)['ready'])
        with self.assertRaises(UserError):configuration({**self.config,'api_key':'forbidden'})
        local={**self.config,'provider':'ollama','model':'ollama/test','authorize_remote':False}
        self.assertFalse(self.adapter.check_availability(local)['ready'])

    def test_wrong_case_schema_and_symlink_outputs_rejected(self):
        for kind in ('case','schema','symlink'):
            jid={'case':'a','schema':'b','symlink':'c'}[kind]*32;path=self.fixture(jid)
            if kind=='symlink':(path/'outputs'/'bad').symlink_to(self.base/'source'/'record.txt')
            else:
                db=sqlite3.connect(path/'outputs'/(jid+'.db'))
                db.execute("UPDATE case_metadata SET case_id='wrong'" if kind=='case' else 'DROP TABLE findings')
                db.commit();db.close()
            with connect(self.ws,self.case) as (root,db):
                with self.assertRaises(UserError):ingest(root,db,jid,self.eid,VERSION)
                self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
                self.assertTrue((path/'outputs'/(jid+'.db')).is_file())

    def test_missing_citations_partial_status_and_report_tampering(self):
        jid='d'*32;path=self.fixture(jid)
        (path/'outputs'/(jid+'.audit.jsonl')).unlink()
        with connect(self.ws,self.case) as (root,db):
            r=ingest(root,db,jid,self.eid,VERSION)
            self.assertTrue(r['warnings'])
            self.assertEqual(db.execute('SELECT status FROM runs WHERE id=?',(jid,)).fetchone()[0],'partial')
        atomic_json(path/'status.json',{'id':jid,'engine':'mulder','status':'partial'})
        (path/'outputs'/(jid+'.report.md')).write_text('changed')
        with self.assertRaisesRegex(UserError,'integrity'):
            handle(self.ws,{'action':'engine-report','case':self.case,'job_id':jid})

    def test_nonzero_exit_preserves_partial_results(self):
        with self.fake.open('a') as out:out.write('\nsys.exit(7)\n')
        with patch.dict(os.environ,{'ANTHROPIC_API_KEY':'synthetic-test'}):started=self.adapter.start_investigation(self.config)
        state=self.wait(started['id'])
        self.assertEqual(state['status'],'partial',state)
        self.assertEqual(state['returncode'],7)
        self.assertEqual(state['results']['findings'],1)

    def test_cancel_running_process(self):
        with self.fake.open('a') as out:out.write('\ntime.sleep(30)\n')
        with patch.dict(os.environ,{'ANTHROPIC_API_KEY':'synthetic-test'}):started=self.adapter.start_investigation(self.config)
        jid=started['id'];deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if self.adapter.get_status(jid)['status']=='running':break
            time.sleep(.05)
        self.adapter.cancel_investigation(jid)
        state=self.wait(jid)
        self.assertEqual(state['status'],'cancelled',state)

    def test_cancel_retains_incomplete_output_and_import_error(self):
        code=self.fake.read_text().replace('output(folder,case_id)\n',
            "db=sqlite3.connect(folder/(case_id+'.db'));db.execute('CREATE TABLE incomplete(x)');db.commit();db.close()\n(folder/'partial-ready').write_text('ready')\ntime.sleep(30)\n")
        self.fake.write_text(code)
        with patch.dict(os.environ,{'ANTHROPIC_API_KEY':'synthetic-test'}):
            started=self.adapter.start_investigation(self.config)
        jid=started['id'];path=job_path(self.root,jid);deadline=time.monotonic()+10
        while not (path/'outputs/partial-ready').exists() and time.monotonic()<deadline:
            time.sleep(.02)
        self.assertTrue((path/'outputs/partial-ready').exists())
        self.adapter.cancel_investigation(jid);state=self.wait(jid)
        self.assertEqual(state['status'],'cancelled',state)
        self.assertTrue(state['originals_unchanged'])
        self.assertTrue(state['output_import_error'])
        self.assertTrue(state['results']['import_failed'])
        self.assertTrue((path/'outputs'/(jid+'.db')).exists())

    def external_output(self, name='CUSTOMER-42'):
        folder=self.base/('external-'+name);ns={};exec(FIXTURE_CODE,ns);ns['output'](folder,name)
        return folder

    def import_output(self, folder, name='CUSTOMER-42', version=VERSION):
        return handle(self.ws, {'action':'engine-import-output','case':self.case,'path':str(folder),
                                'upstream_case_id':name,'version':version})

    def test_import_existing_outputs_without_engine_and_reopen(self):
        folder=self.external_output()
        before={p.name:digest(p) for p in folder.iterdir()}
        with patch('subprocess.Popen', side_effect=AssertionError('Import must not launch tools')):
            result=self.import_output(folder)
        self.assertEqual(result['status'],'completed',result)
        self.assertEqual(result['execution_mode'],'output_import')
        self.assertEqual(result['upstream_execution_status'],'unknown')
        self.assertEqual(result['version_source'],'examiner_declared')
        jid=result['id'];self.assertNotEqual(jid,'CUSTOMER-42')
        reopened=MulderEngine(self.ws,self.case).get_status(jid)
        self.assertEqual(reopened['results']['records'],2)
        rows=handle(self.ws,{'action':'engine-findings','case':self.case,'job_id':jid,'query':'package'})['records']
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['data']['upstream_case_id'],'CUSTOMER-42')
        self.assertIn('CUSTOMER-42.db#findings:',rows[0]['source_ref'])
        self.assertIn('Synthetic report',handle(self.ws,{'action':'engine-report','case':self.case,'job_id':jid})['text'])
        self.assertEqual(before,{p.name:digest(p) for p in folder.iterdir()})
        with connect(self.ws,self.case) as (root,db):
            self.assertTrue(verify(root,db)['ok'])
            self.assertEqual(db.execute('SELECT count(*) FROM files WHERE evidence_id=?',(result['evidence_id'],)).fetchone()[0],4)
        # Changing both report and manifest must not bypass the case audit receipt.
        path=job_path(self.root,jid);report=path/'outputs'/'CUSTOMER-42.report.md'
        report.write_text('tampered report')
        manifest=json.loads((path/'output-manifest.json').read_text())
        for item in manifest:
            if item['path']=='outputs/'+report.name:item['sha256']=digest(report)
        atomic_json(path/'output-manifest.json',manifest)
        with self.assertRaisesRegex(UserError,'audit receipt'):
            handle(self.ws,{'action':'engine-report','case':self.case,'job_id':jid})

    def test_import_failed_schema_retains_originals_and_status(self):
        folder=self.external_output()
        with closing(sqlite3.connect(folder/'CUSTOMER-42.db')) as source:
            source.execute('DROP TABLE findings');source.commit()
        result=self.import_output(folder)
        self.assertEqual(result['status'],'failed',result)
        self.assertIn('schema',result['error'])
        with connect(self.ws,self.case) as (root,db):
            self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
            self.assertTrue((root/'evidence'/result['evidence_id']/'CUSTOMER-42.db').is_file())
            self.assertTrue(verify(root,db)['ok'])
        self.assertEqual(self.adapter.get_status(result['id'])['status'],'failed')

    def test_import_rejects_unsafe_ids_versions_links_and_wrong_case(self):
        folder=self.external_output()
        for name,version in (('../CUSTOMER-42',VERSION),('CUSTOMER-42','99.0')):
            with self.assertRaises(UserError):self.import_output(folder,name,version)
        (folder/'linked-secret').symlink_to(self.base/'source'/'record.txt')
        with self.assertRaises(UserError):self.import_output(folder)
        (folder/'linked-secret').unlink()
        with closing(sqlite3.connect(folder/'CUSTOMER-42.db')) as source:
            source.execute("UPDATE case_metadata SET case_id='another-case'")
            source.commit()
        result=self.import_output(folder)
        self.assertEqual(result['status'],'failed')
        self.assertIn('identity',result['error'])

    def test_orphan_window_and_missing_report_are_explicit(self):
        folder=self.external_output()
        (folder/'CUSTOMER-42.report.md').unlink()
        with closing(sqlite3.connect(folder/'CUSTOMER-42.db')) as source:
            source.execute('INSERT INTO windows VALUES(2,999,1,1,NULL,?)',('Orphaned synthetic record',))
            source.commit()
        result=self.import_output(folder)
        self.assertEqual(result['status'],'partial',result)
        self.assertEqual(result['results']['records'],2)
        self.assertTrue(any('no source record' in w for w in result['results']['warnings']))
        self.assertTrue(any('report is missing' in w for w in result['results']['warnings']))
