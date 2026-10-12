import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from lawliet_mobile.adapters import analyze_file
from lawliet_mobile.core import connect, create_case, import_evidence, select_artifacts, verify, UserError
from lawliet_mobile.sqlite4n6 import normalized_record
from lawliet_mobile.tools import configure


def recovery_fixture(path):
    with closing(sqlite3.connect(path)) as db:
        db.execute('PRAGMA secure_delete=OFF')
        db.execute('CREATE TABLE sms(_id INTEGER PRIMARY KEY,address TEXT,body TEXT,date INTEGER)')
        db.executemany('INSERT INTO sms VALUES(?,?,?,?)',[(i,'+12025550100',f'Synthetic message {i} '+('x'*100),1700000000000+i) for i in range(1,40)])
        db.commit();db.execute('DELETE FROM sms WHERE _id=20');db.commit()


class Sqlite4n6Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.ws=self.base/'cases';create_case(self.ws,'qa')
        source=self.base/'source.db';recovery_fixture(source)
        with connect(self.ws,'qa') as (root,db):
            self.eid=import_evidence(root,db,source,'android')[0]
            self.fid=db.execute('SELECT id FROM files WHERE evidence_id=?',(self.eid,)).fetchone()[0]

    def test_fragment_and_blob_remain_uninterpreted(self):
        row={'kind':'fragment','page':2,'offset':20,'confidence':0.2,'source':'freeblock','missing':2,
             'surviving':[{'column':2,'value':'Synthetic recovered text'}]}
        kind,_,body=normalized_record(row)
        self.assertEqual(kind,'partial_fragment');self.assertIn('Synthetic recovered text',body)
        blob={'page':2,'offset':20,'confidence':0.4,'recovery_source':'freelist-page','values':[{'blob_base64':'AA==','sha256':'fixture'}]}
        self.assertIn('[BLOB;',normalized_record(blob)[2])
        self.assertEqual(blob['values'][0]['blob_base64'],'AA==')
        for invalid in [[],{},dict(blob,confidence=float('nan')),dict(blob,kind='unknown')]:
            with self.assertRaises(UserError):normalized_record(invalid)

    def fake(self,version='sqlite4n6 0.10.1',report='{}\n',exit_code=0):
        path=self.base/'tool.py'
        path.write_text('import sys\nfrom pathlib import Path\n'
                        f'if "--version" in sys.argv: print({version!r})\n'
                        f'else:\n Path(sys.argv[-1]).write_text({report!r})\n sys.exit({exit_code})\n')
        configure(self.ws,'sqlite4n6',path)

    def test_malformed_later_row_rolls_back_all_candidates(self):
        row={'page':2,'offset':20,'confidence':0.4,'recovery_source':'freeblock','values':['Synthetic candidate']}
        self.fake(report=json.dumps(row)+'\nnot JSON\n')
        with connect(self.ws,'qa') as (root,db):
            with self.assertRaises(ValueError):analyze_file(root,db,self.ws,self.fid,'sqlite4n6',20)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifact_runs').fetchone()[0],0)
            run=db.execute('SELECT * FROM runs').fetchone()
            self.assertEqual(run['status'],'failed')
            self.assertIn('not JSON',(root/'runs'/run['id']/'output/carved.jsonl').read_text())
            self.assertTrue(verify(root,db)['ok'])

    def test_unsupported_version_and_nonzero_exit_are_retained_failures(self):
        for version,code in [('sqlite4n6 99.0',0),('sqlite4n6 0.10.1',2)]:
            self.fake(version=version,exit_code=code)
            with connect(self.ws,'qa') as (root,db):
                with self.assertRaises(UserError):analyze_file(root,db,self.ws,self.fid,'sqlite4n6',20)
                self.assertTrue(verify(root,db)['ok'])
                self.assertEqual(db.execute("SELECT COUNT(*) FROM runs WHERE status!='failed'").fetchone()[0],0)

    @unittest.skipUnless(os.environ.get('LAWLIET_SQLITE4N6'),'Set LAWLIET_SQLITE4N6 for the real 0.10.1 binary')
    def test_real_engine_recovers_known_deleted_text_with_provenance(self):
        configure(self.ws,'sqlite4n6',os.environ['LAWLIET_SQLITE4N6'])
        with connect(self.ws,'qa') as (root,db):
            result=analyze_file(root,db,self.ws,self.fid,'sqlite4n6',30)
            rows=select_artifacts(db,run=result['run_id'],category='recovery')
            self.assertEqual(len(rows),1)
            self.assertIn('Synthetic message 20 ',rows[0]['body'])
            self.assertIsNone(rows[0]['timestamp'])
            self.assertEqual(rows[0]['file_id'],self.fid)
            self.assertEqual(rows[0]['data']['tool_version'],'sqlite4n6 0.10.1')
            self.assertEqual(rows[0]['data']['recovery']['classification'],'carved_candidate')
            self.assertEqual(rows[0]['data']['original']['recovery_source'],'freeblock-reconstructed')
            self.assertTrue(verify(root,db)['ok'])
