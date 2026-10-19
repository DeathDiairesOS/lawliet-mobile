"""Compatibility of validated transport with existing artifact identity/membership.

These exercise core contracts, not the still-developing container controller.
"""
import sqlite3
import unittest

from lawliet_mobile import core
from lawliet_mobile import native_container_codec as codec
import test_native_container_codec as fixtures


class CodecPublicationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.CodecTests(); self.fixture.setUp()
        self.db=sqlite3.connect(':memory:'); self.db.row_factory=sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript(core.SCHEMA)
        eid=self.fixture.bindings['evidence_id']
        self.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)',(eid,'Synthetic','ios','fixture','2026-01-01',None,0))
        for f in self.fixture.manifest:
            self.db.execute('INSERT INTO files VALUES(?,?,?,?,?,?)',(f['id'],eid,f['path'],f['logical_path'],f['sha256'],f['bytes']))
        self.db.commit()

    def run_index(self,name):
        self.db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',(name,self.fixture.bindings['evidence_id'],'native/0.1.12','2026-01-01',None,'running',0,'{}'))
        core.begin_run_index(self.db,name)

    def insert(self,row,data,run):
        return core.add_artifact(self.db,row['evidence_id'],row['file_id'],row['category'],row['timestamp'],row['timestamp_raw'],row['title'],row['body'],row['source_ref'],row['parser'],data,run_id=run)

    def test_transport_recreates_exact_existing_artifact_identity_and_rerun_membership(self):
        # BLOB summaries and nonfinite raw representations already produced by
        # native/core are preserved, not replaced with invented transport tags.
        data={'blob_bytes':128,'raw_float':float('inf'),'snow':'雪','empty':'','unknown':None}
        row={**self.fixture.row,'data_json':core.json_text(data)}
        self.run_index('trusted')
        self.assertEqual(self.insert(row,data,'trusted'),1)
        expected=dict(self.db.execute('SELECT * FROM artifacts').fetchone())
        self.db.commit()
        raw=self.fixture.stream(rows=[row])
        validated=codec.validate(raw,self.fixture.bindings,self.fixture.manifest)
        self.run_index('decoded')
        decoded=next(validated.iter_artifacts())
        self.assertEqual(self.insert(decoded,decoded['data'],'decoded'),0)
        self.assertEqual(dict(self.db.execute('SELECT * FROM artifacts').fetchone()),expected)
        self.assertEqual(self.db.execute('SELECT count(*) FROM artifact_runs WHERE run_id=?',('decoded',)).fetchone()[0],1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM artifacts').fetchone()[0],1)
        self.assertEqual(expected['timestamp_raw'],'712345678900000001')
        self.assertEqual(expected['data'],row['data_json'])

    def test_malformed_full_stream_exposes_no_result_for_core_publication(self):
        raw=self.fixture.stream()
        for invalid in (raw[:-2],raw.replace(b'"native_status":"complete"',b'"native_status":"failed"')):
            with self.assertRaises(codec.ValidationError): codec.validate(invalid,self.fixture.bindings,self.fixture.manifest)
        self.assertEqual(self.db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)

if __name__=='__main__':unittest.main()
