"""Report imports share trusted job ownership and survive real owner death."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from lawliet_mobile.core import UserError, connect, create_case, verify
from lawliet_mobile.parsed_import import import_parsed, import_leapp_folder
from lawliet_mobile.runner_lease import lease


@unittest.skipUnless(os.name == 'posix', 'POSIX case lease')
class ParsedImportOwnership(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve(); self.ws = self.base/'cases'
        create_case(self.ws, 'A')
        self.source = self.base/'seed.jsonl'
        self.source.write_text(json.dumps({'category':'messages','body':'café 東京','data':{}})+'\n')

    def launch(self, folder=False):
        source = self.source
        if folder:
            source = self.base/'reports'; source.mkdir()
            (source/'Unknown.tsv').write_text('A\tB\nseed\tvalue\n')
        ready = self.base/'ready'
        script = '''import sys
from pathlib import Path
from lawliet_mobile.core import connect
import lawliet_mobile.parsed_import as m
original=m.add_artifact
def pause(*args,**kwargs):
    result=original(*args,**kwargs)
    Path(sys.argv[3]).write_text('inserted')
    sys.stdin.read()
    return result
m.add_artifact=pause
with connect(Path(sys.argv[1]),'A') as (root,db):
    m.import_parsed(root,db,Path(sys.argv[2]),'jsonl')
'''
        p = subprocess.Popen([sys.executable,'-c',script,str(self.ws),str(source),str(ready)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if p.poll() is None: p.kill()
            p.communicate(timeout=5)
        self.addCleanup(cleanup)
        deadline = time.monotonic()+5
        while not ready.exists():
            if p.poll() is not None: self.fail(p.communicate()[1].decode())
            if time.monotonic()>deadline: self.fail('Import did not reach controlled insert')
            time.sleep(.01)
        return p, source

    def check_retry(self, folder=False):
        p, source = self.launch(folder)
        expected = {str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in ([source] if source.is_file() else source.rglob('*')) if f.is_file()}
        with connect(self.ws,'A') as (root,db):
            before = [tuple(r) for r in db.execute('SELECT id,status,records FROM runs')]
            with self.assertRaisesRegex(UserError,'still owns'):
                import_parsed(root,db,source,'jsonl')
            self.assertEqual(before,[tuple(r) for r in db.execute('SELECT id,status,records FROM runs')])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
        p.kill(); p.communicate(timeout=5)
        with connect(self.ws,'A') as (root,db):
            result = import_parsed(root,db,source,'jsonl')
            self.assertEqual(result['records'],1)
            rows=list(db.execute('SELECT status,records,detail FROM runs ORDER BY rowid'))
            self.assertEqual([(r['status'],r['records']) for r in rows],[('interrupted',0),('complete',1)])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='parsed_import.abandoned'").fetchone()[0],1)
            for r in rows:self.assertIn('runner_ownership',json.loads(r['detail']))
            self.assertTrue(verify(root,db)['ok'])
            # A later external job can now acquire the same case safely.
            with lease(root,db): pass
        self.assertEqual(expected,{f:hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in expected})

    def test_actual_jsonl_owner_death_concurrent_refusal_and_retry(self):
        self.check_retry()

    def test_actual_folder_owner_death_concurrent_refusal_and_retry(self):
        self.check_retry(folder=True)

    def test_public_folder_and_directory_dispatch_each_use_one_lease(self):
        source=self.base/'reports';source.mkdir();(source/'Other.tsv').write_text('A\tB\nx\ty\n')
        with connect(self.ws,'A') as (root,db):
            self.assertEqual(import_leapp_folder(root,db,source)['records'],1)
            self.assertEqual(import_parsed(root,db,source,'folder')['records'],1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='parsed_import.started'").fetchone()[0],2)

    def test_legacy_running_job_remains_unmodified_and_blocks_before_import(self):
        with connect(self.ws,'A') as (root,db):
            import_parsed(root,db,self.source,'jsonl')
            db.execute("UPDATE runs SET status='running',detail='{}'");db.commit()
            before=[tuple(r) for r in db.execute('SELECT * FROM runs')]
            with self.assertRaisesRegex(UserError,'Legacy or unknown'):import_parsed(root,db,self.source,'jsonl')
            self.assertEqual(before,[tuple(r) for r in db.execute('SELECT * FROM runs')])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],1)

    def test_mismatched_audited_engine_refuses_recovery(self):
        with connect(self.ws,'A') as (root,db):
            import_parsed(root,db,self.source,'jsonl')
            db.execute("UPDATE runs SET status='running',engine='import/tsv'");db.commit()
            with self.assertRaisesRegex(UserError,'matching audited start'):
                import_parsed(root,db,self.source,'jsonl')
            self.assertEqual(db.execute('SELECT status FROM runs').fetchone()[0],'running')

    def test_malformed_import_records_owner_but_rolls_back_artifacts(self):
        self.source.write_text('{"category":"messages","body":"ok","data":{}}\nINVALID\n')
        with connect(self.ws,'A') as (root,db):
            with self.assertRaises(UserError):import_parsed(root,db,self.source,'jsonl')
            row=db.execute('SELECT status,records,detail FROM runs').fetchone()
            self.assertEqual((row['status'],row['records']),('failed',0))
            self.assertIn('runner_ownership',json.loads(row['detail']))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
            with lease(root,db): pass
