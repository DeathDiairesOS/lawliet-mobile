"""Synthetic forensic failure-state and export-boundary acceptance checks."""
import csv
import hashlib
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lawliet_mobile.core import connect, create_case, import_evidence, UserError, select_artifacts
from lawliet_mobile.app_backend import handle
from lawliet_mobile.report import write_export, write_report


def tree_hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}


def sms_database(path, count=2):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE sms(_id INTEGER PRIMARY KEY,address TEXT,body TEXT,date INTEGER,type INTEGER, payload BLOB)')
        db.executemany('INSERT INTO sms VALUES(?,?,?,?,?,?)',
                       ((i, '+12025550100', f'SENTINEL {i}\nUnicode 😀\tquote "', 1700000000000+i, 1, b'\x00\xff') for i in range(count)))
    db.close()


def wal_fixture(root):
    live=root/'live.db'; sms_database(live,20)
    db=sqlite3.connect(live)
    db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
    db.execute('INSERT INTO sms VALUES(20,?, ?,1700000000020,1,NULL)', ('+12025550100','WAL_ONLY_20'))
    db.execute('INSERT INTO sms VALUES(21,?, ?,1700000000021,1,NULL)', ('+12025550100','WAL_ONLY_21'));db.commit()
    for label in ('paired','missing','mismatched'):
        folder=root/label;folder.mkdir()
        shutil.copy2(live,folder/'mmssms.db')
    shutil.copy2(str(live)+'-wal',root/'paired/mmssms.db-wal')
    (root/'mismatched/mmssms.db-wal').write_bytes(b'INVALID WAL FROM ANOTHER SOURCE'*8)
    db.close();live.unlink()
    # A structurally valid WAL from a different same-schema database can be
    # readable without proving it belongs to the supplied main database.
    foreign=root/'foreign.db';sms_database(foreign,20)
    db=sqlite3.connect(foreign);db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA wal_autocheckpoint=0')
    db.execute('INSERT INTO sms VALUES(22, ?, ?,1700000000022,1,NULL)', ('+12025550199','FOREIGN_WAL_SENTINEL'));db.commit()
    folder=root/'foreign';folder.mkdir();shutil.copy2(root/'missing/mmssms.db',folder/'mmssms.db')
    shutil.copy2(str(foreign)+'-wal',folder/'mmssms.db-wal');db.close();foreign.unlink()


class RecoveryExportAcceptanceTests(unittest.TestCase):
    def test_original_and_imported_evidence_and_symlink_export_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); ws=base/'cases';create_case(ws,'A');source=base/'original.db';sms_database(source)
            before=source.read_bytes()
            with connect(ws,'A') as (root,db):
                eid=import_evidence(root,db,source,'android')[0]
                stored=next((root/'evidence'/eid).rglob('original.db'))
                alias=base/'alias';alias.symlink_to(source)
                for path in (source,stored,root/'case.sqlite',alias):
                    with self.subTest(path=str(path)),self.assertRaises(UserError):write_export(root,db,path,'jsonl',[])
            self.assertEqual(source.read_bytes(),before)

    def test_native_intake_maps_uncheckpointed_manifest_rows_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'backup';source.mkdir();ws=base/'cases';create_case(ws,'A')
            live=base/'manifest-live.db';db=sqlite3.connect(live)
            db.execute('CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT)');db.commit()
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
            db.execute("INSERT INTO Files VALUES('aabb','HomeDomain','Library/Safari/History.db')");db.commit()
            shutil.copyfile(live,source/'Manifest.db');shutil.copyfile(str(live)+'-wal',source/'Manifest.db-wal');db.close()
            (source/'aabb').write_bytes(b'payload fixture');before=tree_hashes(source)
            with connect(ws,'A') as (root,case_db):
                eid=import_evidence(root,case_db,source,'ios')[0]
                logical=case_db.execute("SELECT logical_path FROM files WHERE evidence_id=? AND path='aabb'",(eid,)).fetchone()[0]
                self.assertEqual(logical,'HomeDomain/Library/Safari/History.db')
                self.assertEqual(tree_hashes(root/'evidence'/eid),before)
            self.assertEqual(tree_hashes(source),before)

    def test_failed_sqlite_dissect_import_rolls_back_candidates(self):
        from lawliet_mobile.tools import configure
        from lawliet_mobile.recovery import recover_sqlite
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);ws=base/'cases';create_case(ws,'A')
            source=base/'original.db';sms_database(source)
            tool=base/'fake_dissect.py'
            tool.write_text("import sys\nfrom pathlib import Path\nout=Path(sys.argv[sys.argv.index('-d')+1])\n(out/'a.csv').write_text('Operation,Value\\nCarved,partial candidate\\n')\n(out/'b.csv').write_bytes(b'Operation,Value\\nCarved,\\xff\\n')\n")
            configure(ws,'sqlite-dissect',tool)
            with connect(ws,'A') as (root,db):
                eid=import_evidence(root,db,source,'android')[0]
                fid=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
                with self.assertRaises(UnicodeDecodeError):recover_sqlite(root,db,ws,fid,10)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM artifact_runs').fetchone()[0],0)
                self.assertEqual(db.execute('SELECT status FROM runs').fetchone()[0],'failed')
                self.assertTrue(list((root/'runs').glob('*/output/a.csv')))

    def test_case_canaries_and_active_content_are_isolated_and_escaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);ws=base/'cases'
            for case in ('A','B'):
                create_case(ws,case);source=base/(case+'.jsonl')
                source.write_text(json.dumps({'category':'messages','data':{},'body':case+'_CANARY <script>alert(1)</script>','title':'=HYPERLINK("https://example.invalid")'})+'\n')
                handle(ws,{'action':'import','case':case,'path':str(source),'format':'jsonl'})
            with connect(ws,'A') as (root,db):
                self.assertEqual(select_artifacts(db,query='B_CANARY'),[])
                rows=select_artifacts(db);out=base/'review.html';write_report(root,db,out)
                html=out.read_text();self.assertNotIn('B_CANARY',html)
                self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;',html);self.assertNotIn('<script>alert(1)</script>',html)
                csvpath=base/'records.csv';write_export(root,db,csvpath,'csv',rows)
                with csvpath.open(newline='') as f:exported=list(csv.DictReader(f))
                self.assertTrue(exported[0]['title'].startswith("'=HYPERLINK"))


try:
    from mulder.server.tools.phone import _query_android_with_coverage
except ModuleNotFoundError as exc:
    if exc.name != 'mulder':raise
    _query_android_with_coverage=None


@unittest.skipIf(_query_android_with_coverage is None,'Candidate Mulder environment required')
class RecoverySqliteAcceptanceTests(unittest.TestCase):
    def test_failure_states_and_typed_unicode_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);good=root/'sms#literal%20?.db';sms_database(good)
            before=tree_hashes(root)
            lines,cov=_query_android_with_coverage(good,'SELECT address, body, date, type FROM sms LIMIT 1')
            self.assertEqual(cov['state'],'parsed');self.assertEqual(len(lines),2)
            self.assertEqual(json.loads(lines[0])['payload'],{'sqlite_blob_hex':'00ff'})
            self.assertEqual(json.loads(lines[0])['body'],'SENTINEL 1\nUnicode 😀\tquote "')
            self.assertEqual(tree_hashes(root),before)
            bad=root/'corrupt.db';bad.write_bytes(b'not SQLite')
            for path,query,state in ((bad,'SELECT * FROM sms','corrupt'),(root/'absent','SELECT 1','inaccessible'),(good,'SELECT * FROM absent','unsupported_schema'),(good,'SELECT FROM','query_failed'),(good,'SELECT * FROM sms WHERE 0','empty')):
                rows,cov=_query_android_with_coverage(path,query);self.assertEqual(rows,[]);self.assertEqual(cov['state'],state)

    def test_wal_views_are_limited_and_do_not_modify_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);wal_fixture(root)
            for label,count in (('paired',22),('missing',20),('mismatched',20),('foreign',21)):
                folder=root/label;before=tree_hashes(folder)
                rows,cov=_query_android_with_coverage(folder/'mmssms.db','SELECT address, body, date, type FROM sms')
                with self.subTest(label=label):
                    self.assertEqual(cov['state'],'limited');self.assertEqual(len(rows),count)
                    self.assertEqual(cov['wal']['pairing'],'unverified')
                    self.assertEqual(tree_hashes(folder),before)

    def test_ios_query_manifest_and_sqlcipher_wrapper_preserve_source_tree(self):
        from unittest.mock import patch
        from mulder.server.tools.phone import _query_sqlite_safe, _resolve_ios_manifest, _try_sqlcipher
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);wal_fixture(root);folder=root/'paired'
            (folder/'mmssms.db-shm').write_bytes(b'PRESERVE THIS SHM')
            before=tree_hashes(folder)
            rows=_query_sqlite_safe(folder/'mmssms.db','SELECT * FROM sms')
            self.assertEqual(len(rows),23)
            self.assertEqual(tree_hashes(folder),before)
            def mutate_working(path,passwords):
                self.assertNotEqual(path,folder/'mmssms.db')
                self.assertEqual(passwords,['known'])
                path.write_bytes(b'engine changes working database')
                Path(str(path)+'-wal').write_bytes(b'engine changes WAL')
                return ['simulated decoder output']
            with patch('mulder.server.tools.phone._try_sqlcipher_working',side_effect=mutate_working):
                self.assertEqual(_try_sqlcipher(folder/'mmssms.db',['known']),['simulated decoder output'])
            self.assertEqual(tree_hashes(folder),before)
            live=root/'manifest-live.db';db=sqlite3.connect(live)
            db.execute('CREATE TABLE Files(fileID TEXT, relativePath TEXT, domain TEXT)');db.commit()
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
            db.execute("INSERT INTO Files VALUES('aabb','sms.db','HomeDomain')");db.commit()
            shutil.copyfile(live,folder/'Manifest.db');shutil.copyfile(str(live)+'-wal',folder/'Manifest.db-wal')
            db.close();(folder/'aabb').write_bytes(b'fixture')
            before=tree_hashes(folder)
            self.assertEqual(_resolve_ios_manifest(folder),{'aabb':folder/'aabb'})
            self.assertEqual(tree_hashes(folder),before)

    def test_ios_manifest_wal_association_is_same_domain_and_does_not_escape(self):
        from mulder.server.tools.phone import _resolve_ios_manifest
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);root=base/'backup';root.mkdir()
            for name in ('aabb','ccdd','eeff'):(root/name).write_bytes(b'fixture')
            outside=base/'outside';outside.write_bytes(b'not evidence')
            with sqlite3.connect(root/'Manifest.db') as db:
                db.execute('CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT)')
                db.executemany('INSERT INTO Files VALUES(?,?,?)',[
                    ('aabb','HomeDomain','Library/Safari/History.db'),
                    ('ccdd','OtherDomain','Library/Safari/History.db-wal'),
                    ('eeff','HomeDomain','Library/Safari/History.db-wal'),
                    ('../outside','HomeDomain','malicious')])
            db.close();before=tree_hashes(root);coverage=[]
            result=_resolve_ios_manifest(root,coverage)
            self.assertEqual(result['aabb-wal'],root/'eeff')
            self.assertNotIn('../outside',result);self.assertEqual(coverage[0]['state'],'parsed')
            self.assertEqual(tree_hashes(root),before)

    def test_cap_discloses_unindexed_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'large.db';sms_database(path,100001)
            lines,cov=_query_android_with_coverage(path,'SELECT address, body, date, type FROM sms LIMIT 1000')
            self.assertEqual(len(lines),100000);self.assertTrue(cov['truncated']);self.assertEqual(cov['state'],'limited')
            self.assertEqual(json.loads(lines[0])['_id'],100000);self.assertEqual(json.loads(lines[-1])['_id'],1)
