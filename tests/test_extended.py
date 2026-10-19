import base64
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, add_artifact, connect, create_case, import_evidence, select_artifacts, verify
from lawliet_mobile.media import preview
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.private_apps import collect_private_apps
from lawliet_mobile.recovery import recover_sqlite
from lawliet_mobile.signal_backup import decrypt_signal
from lawliet_mobile.tools import configure

PNG=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aDCkAAAAASUVORK5CYII=')


class ExtendedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.workspace=self.base/'cases';create_case(self.workspace,'test')

    def image_fixture(self):
        source=self.base/'extraction';folder=source/'HomeDomain/Library/SMS';folder.mkdir(parents=True)
        media=source/'MediaDomain/Library/SMS/Attachments/a/image.png';media.parent.mkdir(parents=True);media.write_bytes(PNG)
        with closing(sqlite3.connect(folder/'sms.db')) as db:
            db.executescript("CREATE TABLE message(text TEXT,date INTEGER,handle_id INTEGER,is_from_me INTEGER); CREATE TABLE handle(id TEXT); CREATE TABLE attachment(filename TEXT,total_bytes INTEGER); CREATE TABLE message_attachment_join(message_id INTEGER,attachment_id INTEGER); INSERT INTO message VALUES('Image',1,1,0); INSERT INTO handle VALUES('Alex');")
            for i,size in enumerate([len(PNG),len(PNG)+1],1):
                db.execute('INSERT INTO attachment VALUES(?,?)',('~/Library/SMS/Attachments/a/image.png',size));db.execute('INSERT INTO message_attachment_join VALUES(1,?)',(i,))
            db.execute('INSERT INTO attachment VALUES(?,?)',('~/Library/SMS/Attachments/missing.png',123));db.commit()
        return source

    def test_attachment_preview_exact_paths_size_tamper_and_report_claims(self):
        with connect(self.workspace,'test') as (root,db):
            eid=import_evidence(root,db,self.image_fixture(),'ios')[0];native_analyze(root,db,eid)
            attachments=select_artifacts(db,evidence=eid,category='attachments')
            self.assertEqual({r['body'] for r in attachments},{'available','size_mismatch','not_acquired'})
            available=next(r for r in attachments if r['body']=='available')
            result=preview(root,db,available['id']);self.assertEqual(Path(result['path']).read_bytes(),PNG)
            for r in attachments:
                if r['body']!='available':
                    with self.assertRaises(UserError): preview(root,db,r['id'])
            add_artifact(db,eid,None,'media',None,None,'Untrusted report','', 'claimed','import/jsonl',available['data'])
            fake=select_artifacts(db,parser='import/jsonl')[0]
            with self.assertRaises(UserError): preview(root,db,fake['id'])
            self.assertEqual(native_analyze(root,db,eid)['new_records'],0)
            self.assertTrue(verify(root,db)['ok'])
            file=db.execute('SELECT * FROM files WHERE id=?',(available['data']['attachment']['file_id'],)).fetchone()
            (root/'evidence'/eid/file['path']).write_bytes(PNG+b'tamper')
            with self.assertRaisesRegex(UserError,'integrity'): preview(root,db,available['id'])

    def test_signal_private_terminal_does_not_log_secret(self):
        tool=self.base/'decoder.py'
        tool.write_text("import sys,sqlite3,pathlib\nif '--help' in sys.argv: print('source version synthetic --output --stoponerror'); sys.exit(0)\nsecret=input()\nassert secret not in sys.argv\nprint('CIPHERKEY:'+secret)\nprint(secret,file=sys.stderr)\nout=pathlib.Path(sys.argv[sys.argv.index('--output')+1]);c=sqlite3.connect(out/'database.sqlite');c.execute('CREATE TABLE fixture(id INTEGER)');c.commit();c.close()\n")
        configure(self.workspace,'signalbackup-tools',tool,sys.executable)
        source=self.base/'fixture.backup';source.write_bytes(b'encrypted-fixture')
        secret='123456789012345678901234567890'
        with connect(self.workspace,'test') as (root,db):
            r=decrypt_signal(root,db,self.workspace,source,secret,timeout=5)
            self.assertEqual(r['status'],'complete')
            details=' '.join(x[0] for x in db.execute('SELECT detail FROM runs UNION ALL SELECT detail FROM audit'))
            self.assertNotIn(secret,details);self.assertTrue(verify(root,db)['ok'])
            self.assertFalse(list((root/'runs'/r['run_id']).glob('*.log')))
            with self.assertRaises(UserError): decrypt_signal(root,db,self.workspace,source,'wrong')

    def test_private_collection_stops_without_existing_root(self):
        def execute(argv,output,*args,**kwargs):
            Path(output).write_text('');return {'argv':argv,'returncode':1}
        with connect(self.workspace,'test') as (root,db), patch('lawliet_mobile.private_apps.command',return_value=['adb']),patch('lawliet_mobile.private_apps.execute',side_effect=execute) as mock:
            with self.assertRaisesRegex(UserError,'No existing root'): collect_private_apps(root,db,self.workspace,'SERIAL')
            self.assertEqual(mock.call_count,1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],0)
            manifest=json.loads(next((root/'collections').glob('*/collection.json')).read_text());self.assertEqual(manifest['status'],'failed')

    def test_desktop_raw_import_media_and_date_validation(self):
        result=handle(self.workspace,{'action':'import-evidence','case':'test','path':str(self.image_fixture())})
        rows=handle(self.workspace,{'action':'records','case':'test','evidence':result['evidence_id'],'category':'media'})['records']
        self.assertEqual(len(rows),1)
        with self.assertRaises(UserError):handle(self.workspace,{'action':'records','case':'test','since':'bad date'})

    @unittest.skipUnless(os.environ.get('LAWLIET_SQLITE_DISSECT'),'optional SQLite Dissect')
    def test_real_sqlite_dissect_recovers_synthetic_deleted_text(self):
        configure(self.workspace,'sqlite-dissect',os.environ['LAWLIET_SQLITE_DISSECT'])
        source=self.base/'source.db'
        with closing(sqlite3.connect(source)) as c:
            c.execute('PRAGMA secure_delete=OFF');c.execute('CREATE TABLE sms(_id INTEGER PRIMARY KEY,address TEXT,body TEXT,date INTEGER)')
            c.executemany('INSERT INTO sms VALUES(?,?,?,?)',[(i,'+12025550100',f'Synthetic message {i} '+('x'*100),1700000000000+i) for i in range(1,40)]);c.commit();c.execute('DELETE FROM sms WHERE _id=20');c.commit()
        with connect(self.workspace,'test') as (root,db):
            eid=import_evidence(root,db,source,'android')[0];file_id=db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
            r=recover_sqlite(root,db,self.workspace,file_id,30)
            rows=select_artifacts(db,run=r['run_id'],category='recovery',limit=1000)
            self.assertTrue(any('Synthetic message 20 ' in x['body'] for x in rows))
            self.assertTrue(all(x['data']['recovery']['classification']=='carved_candidate' for x in rows))
            self.assertTrue(verify(root,db)['ok'])

    @unittest.skipUnless(os.environ.get('LAWLIET_SIGNAL_TOOL'),'optional signalbackup-tools')
    def test_real_signal_encrypted_backup_roundtrip(self):
        tool=os.environ['LAWLIET_SIGNAL_TOOL'];configure(self.workspace,'signalbackup-tools',tool)
        folder=self.base/'decrypted';folder.mkdir()
        with closing(sqlite3.connect(folder/'database.sqlite')) as c:
            c.executescript("CREATE TABLE recipient(_id INTEGER,e164 TEXT); CREATE TABLE thread(_id INTEGER); CREATE TABLE message(_id INTEGER,thread_id INTEGER,from_recipient_id INTEGER,body TEXT,date_sent INTEGER,type INTEGER); INSERT INTO recipient VALUES(1,'+12025550100'); INSERT INTO thread VALUES(7); INSERT INTO message VALUES(42,7,1,'Synthetic Signal invoice',1700000000000,20);");c.commit()
        (folder/'Header.sbf').write_text('IV:bytes:'+base64.b64encode(bytes(range(16))).decode()+'\nSALT:bytes:'+base64.b64encode(bytes(range(32))).decode()+'\nVERSION:uint32:1\n')
        (folder/'DatabaseVersion.sbf').write_text('VERSION:uint32:215\n');(folder/'End.sbf').write_text('END\n')
        secret='111111111111111111111111111111';encrypted=self.base/'fixture.backup'
        subprocess.run([tool,str(folder),'--output',str(encrypted),'--opassphrase',secret],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        with connect(self.workspace,'test') as (root,db):
            r=decrypt_signal(root,db,self.workspace,encrypted,secret,timeout=30);native_analyze(root,db,r['evidence_id'])
            rows=select_artifacts(db,evidence=r['evidence_id'],app='signal');self.assertEqual(len(rows),1);self.assertEqual(rows[0]['body'],'Synthetic Signal invoice');self.assertEqual(rows[0]['data']['message']['direction'],'incoming');self.assertTrue(verify(root,db)['ok'])
