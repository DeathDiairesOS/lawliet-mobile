"""Actual subprocess death/retry; synthetic transport, never a phone."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from lawliet_mobile.core import connect, create_case, digest, verify
from lawliet_mobile.tools import configure


FIXTURE = r'''
import json, os, shlex, sys, time
from pathlib import Path
root=Path(__file__).parent; args=sys.argv[1:][2:]
if args==['get-state']: print('device'); sys.exit()
if args==['version']: print('synthetic ADB fixture'); sys.exit()
if args[:2]==['shell','getprop']: print('synthetic'); sys.exit()
if args[:2]==['shell','date']: print('2026-10-13T13:00:00-0400'); sys.exit()
q=shlex.split(args[1]); where=q[q.index('--where')+1] if '--where' in q else ''
if where=='0=1': print('No result found.'); sys.exit()
if q[q.index('--projection')+1]=='_id':
 for i in range(1,4): print(f'Row: {i-1} _id={i}')
 sys.exit()
i=int(where.split('=')[1])
if i==2 and not (root/'allow').exists():
 (root/'marker').write_text(json.dumps({'pid':os.getpid()})); time.sleep(60)
values={'thread_id':1,'address':'+12025550100','date':1760000000123,
        'date_sent':0,'type':1,'body':f'SYNTHETIC row {i} 🧪','read':0,'status':-1}
cells=[f'Row: 0 _id={i}']
for field,value in values.items():
 cells += [f'typeof({field})='+('integer' if type(value) is int else 'text'),
           f'hex({field})='+str(value).encode().hex().upper()]
print(', '.join(cells))
'''


@unittest.skipUnless(os.name == 'posix', 'Ownership guardian requires POSIX')
class ProviderRestartTests(unittest.TestCase):
    def test_death_after_collection_before_import_keeps_processing_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);ws=base/'cases';create_case(ws,'A')
            fixture=base/'adb.py';fixture.write_text(FIXTURE);(base/'allow').touch()
            configure(ws,'adb',fixture,python=sys.executable)
            repo=Path(__file__).resolve().parents[1]
            args=['--json','--workspace',str(ws),'collect','android','--case','A',
                  '--serial','SYNTHETIC','--profile','sms-provider','--android-user','0']
            script="""
import sys,time
from pathlib import Path
import lawliet_mobile.provider_sms as provider
from lawliet_mobile.cli import main
marker=Path(sys.argv[1])
def checkpoint(*args,**kwargs):
 marker.touch();time.sleep(60)
provider.import_evidence=checkpoint
sys.argv=[sys.argv[0]]+sys.argv[2:]
raise SystemExit(main())
"""
            with (base/'out').open('w') as out,(base/'err').open('w') as err:
                child=subprocess.Popen([sys.executable,'-c',script,str(base/'import-marker'),*args],cwd=repo,stdout=out,stderr=err)
                try:
                    deadline=time.monotonic()+12
                    while not (base/'import-marker').exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(.05)
                    self.assertTrue((base/'import-marker').exists(),(base/'err').read_text())
                    child.kill();self.assertEqual(child.wait(timeout=5),-9)
                finally:
                    if child.poll() is None:child.kill();child.wait(timeout=5)
            with connect(ws,'A') as (root,db):
                run=db.execute('SELECT * FROM runs').fetchone();old_id=run['id']
                folder=root/'collections'/json.loads(run['detail'])['collection_id']
                manifest=json.loads((folder/'collection.json').read_text())
                self.assertEqual(manifest['collection_status'],'complete')
                self.assertEqual(manifest['processing_state'],'pending')
                self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],0)
                journal_hash=digest(folder/'payload/sms-provider.jsonl')
                self.assertFalse((root/'collections'/(manifest['collection_id']+'-receipt.json')).exists())
            retry=subprocess.run([sys.executable,'-m','lawliet_mobile',*args],cwd=repo,capture_output=True,text=True,timeout=20)
            self.assertEqual(retry.returncode,0,retry.stderr)
            with connect(ws,'A') as (root,db):
                prior=db.execute('SELECT * FROM runs WHERE id=?',(old_id,)).fetchone()
                self.assertEqual(prior['status'],'interrupted');self.assertEqual(prior['records'],0)
                manifest=json.loads((folder/'collection.json').read_text())
                self.assertEqual(manifest['status'],'interrupted')
                self.assertEqual(manifest['processing_state'],'interrupted')
                self.assertEqual(manifest['collection_status'],'complete')
                self.assertEqual(digest(folder/'payload/sms-provider.jsonl'),journal_hash)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],3)
                self.assertTrue(verify(root,db)['ok'])

    def test_hard_parent_death_retains_checkpoint_and_retry_reconciles(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); ws=base/'cases'; create_case(ws,'A')
            fixture=base/'adb.py'; fixture.write_text(FIXTURE)
            configure(ws,'adb',fixture,python=sys.executable)
            argv=[sys.executable,'-m','lawliet_mobile','--json','--workspace',str(ws),
                  'collect','android','--case','A','--serial','SYNTHETIC',
                  '--profile','sms-provider','--android-user','0','--max-sms','10']
            repo=Path(__file__).resolve().parents[1]
            with (base/'stdout').open('w') as out, (base/'stderr').open('w') as err:
                child=subprocess.Popen(argv,cwd=repo,stdout=out,stderr=err)
                try:
                    deadline=time.monotonic()+12
                    while not (base/'marker').exists() and child.poll() is None and time.monotonic()<deadline:
                        time.sleep(.05)
                    self.assertTrue((base/'marker').exists(), (base/'stderr').read_text())
                    worker=json.loads((base/'marker').read_text())['pid']
                    child.kill(); self.assertEqual(child.wait(timeout=5),-9)
                    deadline=time.monotonic()+6
                    while time.monotonic()<deadline:
                        try: os.kill(worker,0)
                        except ProcessLookupError: break
                        time.sleep(.05)
                    else: self.fail('Owned fixture child survived parent death')
                finally:
                    if child.poll() is None: child.kill(); child.wait(timeout=5)
            with connect(ws,'A') as (root,db):
                old=dict(db.execute('SELECT * FROM runs').fetchone())
                self.assertEqual(old['status'],'running'); self.assertIsNone(old['evidence_id'])
                self.assertEqual(old['records'],0)
                detail=json.loads(old['detail']); self.assertEqual(detail['checkpointed_records'],1)
                folder=root/'collections'/detail['collection_id']
                journal=folder/'payload/sms-provider.jsonl'
                rows=[json.loads(x) for x in journal.read_text().splitlines()]
                self.assertEqual(len(rows),1); self.assertEqual(rows[0]['data']['raw_fields']['_id'],1)
                self.assertEqual(digest(folder/'sms-1.txt'),rows[0]['data']['provider']['raw_response_sha256'])
                journal_hash=digest(journal)
            (base/'allow').touch()
            retry=subprocess.run(argv,cwd=repo,capture_output=True,text=True,timeout=20)
            self.assertEqual(retry.returncode,0,retry.stderr)
            with connect(ws,'A') as (root,db):
                runs=list(db.execute('SELECT * FROM runs'))
                self.assertEqual(len(runs),2)
                prior=next(r for r in runs if r['id']==old['id'])
                current=next(r for r in runs if r['id']!=old['id'])
                self.assertEqual(prior['status'],'interrupted'); self.assertEqual(prior['records'],0)
                self.assertEqual(current['status'],'complete'); self.assertEqual(current['records'],3)
                self.assertEqual(json.loads((folder/'collection.json').read_text())['status'],'interrupted')
                self.assertEqual(digest(journal),journal_hash)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],3)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='collection.abandoned'").fetchone()[0],1)
                self.assertTrue(verify(root,db)['ok'])
