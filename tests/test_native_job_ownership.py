"""Native parser lifecycle ownership without changing artifact interpretation."""
import hashlib
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from lawliet_mobile.core import UserError,connect,create_case,import_evidence,verify
from lawliet_mobile.parsers import native_analyze,VERSION
from lawliet_mobile.runner_lease import lease

@unittest.skipUnless(os.name=='posix','POSIX case ownership')
class NativeJobOwnership(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.ws=self.base/'cases';create_case(self.ws,'A')
        self.source=self.base/'sms.db'
        with sqlite3.connect(self.source) as fixture:
            fixture.execute('CREATE TABLE sms(_id INTEGER,address TEXT,body TEXT,date INTEGER,type INTEGER)')
            fixture.execute('INSERT INTO sms VALUES(1,?,?,1700000000000,1)',('seed','NATIVE-RESTART café 東京'))
        self.source_hash=hashlib.sha256(self.source.read_bytes()).hexdigest()
        with connect(self.ws,'A') as (root,db):self.eid=import_evidence(root,db,self.source,'android')[0]

    def test_real_death_concurrent_refusal_and_reanalysis(self):
        ready=self.base/'ready'
        code='''import sys
from pathlib import Path
from lawliet_mobile.core import connect
import lawliet_mobile.parsers as m
real=m.add_artifact
def pause(*a,**kw):
 r=real(*a,**kw);Path(sys.argv[3]).write_text('ready');sys.stdin.read();return r
m.add_artifact=pause
with connect(Path(sys.argv[1]),'A') as (root,db):m.native_analyze(root,db,sys.argv[2])
'''
        p=subprocess.Popen([sys.executable,'-c',code,str(self.ws),self.eid,str(ready)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while not ready.exists():
                if p.poll() is not None:self.fail(p.communicate()[1].decode())
                if time.monotonic()>deadline:self.fail('Native insert not reached')
                time.sleep(.01)
            with connect(self.ws,'A') as (root,db):
                before=[tuple(r) for r in db.execute('SELECT id,status,records FROM runs')]
                with self.assertRaisesRegex(UserError,'still owns'):native_analyze(root,db,self.eid)
                self.assertEqual(before,[tuple(r) for r in db.execute('SELECT id,status,records FROM runs')])
                self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
            p.kill();p.communicate(timeout=5)
            with connect(self.ws,'A') as (root,db):
                result=native_analyze(root,db,self.eid);self.assertEqual(result['new_records'],1)
                self.assertEqual([(r['status'],r['records']) for r in db.execute('SELECT status,records FROM runs ORDER BY rowid')],[('interrupted',0),('complete',1)])
                self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='analysis.abandoned'").fetchone()[0],1)
                artifact=db.execute('SELECT body,parser FROM artifacts').fetchone();self.assertEqual(artifact['body'],'NATIVE-RESTART café 東京');self.assertEqual(artifact['parser'],VERSION)
                self.assertTrue(verify(root,db)['ok'])
                with lease(root,db):pass
            self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(),self.source_hash)
        finally:
            if p.poll() is None:p.kill();p.communicate(timeout=5)

    def test_successful_rerun_preserves_existing_artifact(self):
        with connect(self.ws,'A') as (root,db):
            self.assertEqual(native_analyze(root,db,self.eid)['new_records'],1)
            before=[tuple(r) for r in db.execute('SELECT * FROM artifacts')]
            self.assertEqual(native_analyze(root,db,self.eid)['new_records'],0)
            self.assertEqual(before,[tuple(r) for r in db.execute('SELECT * FROM artifacts')])
            for r in db.execute('SELECT detail FROM runs'):self.assertIn('runner_ownership',json.loads(r['detail']))

    def test_legacy_running_job_not_reclassified(self):
        with connect(self.ws,'A') as (root,db):
            native_analyze(root,db,self.eid);db.execute("UPDATE runs SET status='running',detail='{}'");db.commit()
            before=[tuple(r) for r in db.execute('SELECT * FROM runs')]
            with self.assertRaisesRegex(UserError,'Legacy or unknown'):native_analyze(root,db,self.eid)
            self.assertEqual(before,[tuple(r) for r in db.execute('SELECT * FROM runs')])

    def test_handled_failure_keeps_owner_and_allows_next_job(self):
        with connect(self.ws,'A') as (root,db):
            with patch('lawliet_mobile.parsers.add_artifact',side_effect=RuntimeError('controlled native failure')):
                with self.assertRaisesRegex(RuntimeError,'controlled native failure'):
                    native_analyze(root,db,self.eid)
            # Existing unexpected-error policy remains failed and re-raises.
            row=db.execute('SELECT status,records FROM runs').fetchone()
            self.assertEqual((row['status'],row['records']),('failed',0))
            self.assertIn('runner_ownership',json.loads(db.execute('SELECT detail FROM runs').fetchone()[0]))
            self.assertEqual(native_analyze(root,db,self.eid)['new_records'],1)

    def test_changed_engine_cannot_reuse_audited_native_start(self):
        with connect(self.ws,'A') as (root,db):
            native_analyze(root,db,self.eid)
            db.execute("UPDATE runs SET status='running',engine='native/unknown-version'");db.commit()
            with self.assertRaisesRegex(UserError,'matching audited start'):
                native_analyze(root,db,self.eid)
            self.assertEqual(db.execute('SELECT status FROM runs').fetchone()[0],'running')
