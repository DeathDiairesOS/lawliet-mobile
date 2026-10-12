import tempfile
import unittest
from pathlib import Path

from lawliet_mobile.core import (UserError, add_artifact, begin_run_index, connect,
                                create_case, import_evidence, select_artifacts, verify)
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.app_backend import handle
from lawliet_mobile.messages import import_chat


class RunMembershipTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.ws=self.base/'cases';create_case(self.ws,'qa')
        source=self.base/'contacts.vcf';source.write_text('BEGIN:VCARD\nVERSION:3.0\nFN:Synthetic Person\nEND:VCARD\n')
        with connect(self.ws,'qa') as (root,db):self.eid=import_evidence(root,db,source,'android')[0]

    def make_run(self,db,name,engine='native/0.1.0',indexed=True):
        db.execute('INSERT INTO runs(id,evidence_id,engine,status) VALUES(?,?,?,?)',(name,self.eid,engine,'complete'))
        if indexed:begin_run_index(db,name)

    def test_native_rerun_links_existing_records_without_changing_ids(self):
        with connect(self.ws,'qa') as (root,db):
            first=native_analyze(root,db,self.eid)
            records=select_artifacts(db,run=first['run_id'])
            second=native_analyze(root,db,self.eid)
            self.assertEqual(first['new_records'],1);self.assertEqual(second['new_records'],0)
            self.assertEqual(records,select_artifacts(db,run=second['run_id']))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifact_runs').fetchone()[0],2)
            self.assertTrue(verify(root,db)['ok'])
        sources=handle(self.ws,{'action':'overview','case':'qa'})['sources']
        self.assertTrue({first['run_id'],second['run_id']}.issubset({s['id'] for s in sources}))
        result=handle(self.ws,{'action':'records','case':'qa','evidence':self.eid,'run':second['run_id']})
        self.assertEqual(len(result['records']),1)

    def test_membership_excludes_other_run_rows_even_with_matching_path(self):
        with connect(self.ws,'qa') as (root,db):
            for name in ['one','two','empty']:self.make_run(db,name,'aleapp')
            args=(self.eid,None,'external',None,None,'Synthetic','Fixture','runs/one/output/F.tsv:line=2','aleapp',{})
            add_artifact(db,*args,run_id='two')
            self.assertEqual(select_artifacts(db,run='one'),[])
            self.assertEqual(select_artifacts(db,run='empty'),[])
            self.assertEqual(len(select_artifacts(db,run='two')),1)
            self.make_run(db,'legacy','aleapp',False)
            add_artifact(db,self.eid,None,'external',None,None,'Legacy','Fixture','runs/legacy/output/F.tsv:line=2','aleapp',{})
            self.assertEqual(len(select_artifacts(db,run='legacy')),1)

    def test_legacy_native_and_unsupported_index_versions_are_explicit(self):
        with connect(self.ws,'qa') as (root,db):
            self.make_run(db,'legacy',indexed=False)
            with self.assertRaisesRegex(UserError,'legacy run'):select_artifacts(db,run='legacy')
            self.make_run(db,'new')
            db.execute('UPDATE run_artifact_indexes SET schema_version=99 WHERE run_id=?',('new',))
            with self.assertRaisesRegex(UserError,'Unsupported'):select_artifacts(db,run='new')

    def test_invalid_run_link_cannot_insert_an_artifact(self):
        with connect(self.ws,'qa') as (root,db):
            self.make_run(db,'legacy',indexed=False)
            for rid in ['missing','legacy']:
                with self.assertRaises(UserError):
                    add_artifact(db,self.eid,None,'external',None,None,'Fixture','','ref','native',{},run_id=rid)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)

    def test_chat_runs_link_only_their_exact_source_occurrences(self):
        source = self.base / 'chat.txt'
        source.write_text('10/01/26, 09:00 - Jamie: First\n10/01/26, 09:01 - Morgan: Second\n')
        with connect(self.ws, 'qa') as (root, db):
            first = import_chat(root, db, source, 'mdy', 'America/New_York', year_century=2000)
            second = import_chat(root, db, source, 'mdy', 'America/New_York', year_century=2000)
            for result in (first, second):
                rows = select_artifacts(db, run=result['run_id'])
                self.assertEqual(len(rows), 2)
                self.assertEqual({r['evidence_id'] for r in rows}, {result['evidence_id']})
                self.assertEqual([r['body'] for r in rows], ['First', 'Second'])
                self.assertEqual(db.execute('SELECT COUNT(*) FROM artifact_runs WHERE run_id=?',
                                            (result['run_id'],)).fetchone()[0], 2)
                run = db.execute('SELECT * FROM runs WHERE id=?', (result['run_id'],)).fetchone()
                self.assertEqual((run['status'], run['records'], run['engine']),
                                 ('complete', 2, 'whatsapp-export/2'))
                self.assertIsNotNone(run['finished_at'])
            self.assertNotEqual(first['evidence_id'], second['evidence_id'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 4)
            self.assertTrue(verify(root, db)['ok'])

    def test_empty_chat_run_has_explicit_empty_membership(self):
        source = self.base / 'empty.txt'
        source.write_text('Unsupported preamble only\n')
        with connect(self.ws, 'qa') as (root, db):
            result = import_chat(root, db, source, 'mdy')
            self.assertEqual((result['status'], result['records']), ('partial', 0))
            self.assertEqual(select_artifacts(db, run=result['run_id']), [])
            self.assertEqual(db.execute('SELECT schema_version FROM run_artifact_indexes WHERE run_id=?',
                                        (result['run_id'],)).fetchone()[0], 1)
            self.assertTrue(verify(root, db)['ok'])
