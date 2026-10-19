"""End-to-end CLI and desktop-bridge review of synthetic customer app sources."""
import base64
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect, create_case, digest, verify

PNG=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aZXkAAAAASUVORK5CYII=')


def fixture_sources(base):
    base.mkdir(parents=True,exist_ok=True)
    whatsapp=base/'WhatsApp export.zip'
    with zipfile.ZipFile(whatsapp,'w') as archive:
        archive.writestr('_chat.txt','[17/10/2026, 10:00:00] Jamie: CASE-ALPHA meeting at noon\n[17/10/2026, 10:01:00] Sam: <attached: photo.png>\n')
        archive.writestr('photo.png',PNG)
    discord=base/'Discord package.zip'
    with zipfile.ZipFile(discord,'w') as archive:
        archive.writestr('Account/user.json',json.dumps({'id':'1200000000000000001','username':'fictional-owner'}))
        archive.writestr('Messages/c1100000000000000001/channel.json',json.dumps({'id':'1100000000000000001','type':1,'recipients':['1200000000000000001','1200000000000000002']}))
        archive.writestr('Messages/c1100000000000000001/messages.json',json.dumps([
            {'ID':'1300000000000000001','Timestamp':'2026-10-17T14:02:00Z','Contents':'CASE-ALPHA confirmed','Attachments':''},
            {'ID':'1300000000000000002','Timestamp':'2026-10-17 14:03:00','Contents':'CASE-ALPHA unknown timezone','Attachments':'https://cdn.discordapp.com/attachments/fixture/photo.png'}]))
    signal=base/'Decoded Signal';signal.mkdir()
    with closing(sqlite3.connect(signal/'database.sqlite')) as db, db:
        db.executescript("CREATE TABLE recipient(_id INTEGER,e164 TEXT); CREATE TABLE thread(_id INTEGER); CREATE TABLE message(_id INTEGER,thread_id INTEGER,from_recipient_id INTEGER,body TEXT,date_sent INTEGER,type INTEGER); INSERT INTO recipient VALUES(1,'+12025550100'); INSERT INTO thread VALUES(7); INSERT INTO message VALUES(42,7,1,'CASE-ALPHA Signal confirmation',1792245840000,20);")
    triage=base/'Android triage';triage.mkdir()
    (triage/'packages.txt').write_text('package:/data/app/fictional/base.apk=com.example.fixture\n')
    (triage/'getprop.txt').write_text('[ro.product.manufacturer]: [Fictional]\n[ro.product.model]: [Test phone]\n[ro.build.version.release]: [16]\n')
    (triage/'logcat.txt').write_text('1792245840.125  100  101 I TestTag: CASE-ALPHA fixture log\n')
    return {'whatsapp':whatsapp,'discord':discord,'signal':signal,'triage':triage}


def ingest(workspace,case,sources):
    def call(action,**kw):return handle(workspace,{'case':case,'action':action,**kw})
    return {'whatsapp':call('import-chat',path=str(sources['whatsapp']),date_order='dmy',timezone='America/New_York'),
            'discord':call('import-discord',path=str(sources['discord'])),
            'signal':call('import-evidence',path=str(sources['signal'])),
            'triage':call('import-evidence',path=str(sources['triage']))}


class CustomerAppWorkflowTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.base=Path(temp.name);self.workspace=self.base/'cases'
        create_case(self.workspace,'A');create_case(self.workspace,'B')
        self.sources=fixture_sources(self.base/'sources')
        self.result=ingest(self.workspace,'A',self.sources)

    def call(self,action='records',**kw):return handle(self.workspace,{'case':'A','action':action,**kw})

    def test_three_apps_reach_same_gui_queries_with_exact_sources(self):
        rows=self.call(category='messages',presentation='investigator')['records']
        self.assertEqual(len(rows),5)
        self.assertEqual({r['data']['message']['app'] for r in rows},{'whatsapp','discord','signal'})
        self.assertTrue(all(r['source_sha256'] and r['source_ref'] for r in rows))
        self.assertEqual(len(self.call(category='messages',query='CASE-ALPHA')['records']),4)
        timed=self.call(category='messages',since='2026-10-17',until='2026-10-18')['records']
        self.assertEqual(len(timed),4)
        self.assertEqual(len(self.call('conversations')),3)
        other=handle(self.workspace,{'case':'B','action':'records'})
        self.assertEqual(other['records'],[])
        overview=self.call('overview')
        for name in ('whatsapp','discord'):
            self.assertTrue(any(s.get('run')==self.result[name]['run_id'] for s in overview['sources']))

    def test_whatsapp_linked_media_and_replay_and_original_archives(self):
        messages=self.call(category='messages',app='whatsapp',presentation='investigator')['records']
        message=next(r for r in messages if 'photo.png' in r['body'])
        fields={f['name']:f['value'] for f in message['display_fields']}
        self.assertEqual(fields['Attachment status'],'available')
        linked=self.call('related-attachments',artifact_id=message['id'])
        self.assertEqual(len(linked),1)
        preview=self.call('preview',artifact_id=linked[0]['id'])
        self.assertEqual(Path(preview['path']).read_bytes(),PNG)
        replay=self.call('import-chat',path=str(self.sources['whatsapp']),date_order='dmy',timezone='America/New_York')
        self.assertEqual(replay['run_id'],self.result['whatsapp']['run_id'])
        with connect(self.workspace,'A') as (root,db):
            for name in ('whatsapp','discord'):
                original=digest(self.sources[name]);files=list(db.execute('SELECT * FROM files WHERE evidence_id=? AND sha256=?',(self.result[name]['evidence_id'],original)))
                self.assertEqual(len(files),1)
                self.assertEqual(digest(root/'evidence'/files[0]['evidence_id']/files[0]['path']),original)
            self.assertTrue(verify(root,db)['ok'])

    def test_native_categories_and_readable_inspector_preserve_source_fields(self):
        stats=self.call('source-stats')
        for category,key in [('apps','Package ID'),('device','Model'),('logs','Process ID')]:
            self.assertEqual(stats['categories'][category],1)
            original=self.call(category=category)['records'][0]
            projected=self.call(category=category,presentation='investigator')['records'][0]
            self.assertIn(key,[f['name'] for f in projected['display_fields']])
            self.assertEqual(original['data'],projected['data'])
            self.assertEqual(original['source_ref'],projected['source_ref'])

    def test_partial_discord_run_remains_selectable(self):
        source=self.base/'partial';folder=source/'Messages'/'c1100000000000000001';folder.mkdir(parents=True)
        (folder/'channel.json').write_text(json.dumps({'id':'1100000000000000001','type':1}))
        (folder/'messages.json').write_text(json.dumps([{'ID':'1300000000000000003','Timestamp':'2026-10-17T14:05:00Z','Contents':'good retained row','Attachments':''},{'bad':'unsupported'}]))
        result=self.call('import-discord',path=str(source))
        self.assertEqual(result['status'],'partial')
        source=next(s for s in self.call('overview')['sources'] if s['id']==result['run_id'])
        self.assertEqual(source['status'],'partial');self.assertIn('partial',source['label'])
        self.assertEqual(len(self.call(run=result['run_id'])['records']),1)

    def test_signal_preflight_refuses_unsupported_before_key_and_decode_partial_propagates(self):
        check=self.call('signal-preflight',path=str(self.sources['signal']))
        self.assertFalse(check['ready']);self.assertIn('already decoded',check['reason'])
        evidence=self.result['signal']['evidence_id']
        with patch('lawliet_mobile.app_backend.decrypt_signal',return_value={'status':'complete','evidence_id':evidence}),patch('lawliet_mobile.app_backend.native_analyze',return_value={'status':'partial','errors':['unsupported fixture']}):
            result=self.call('decrypt-signal',path='synthetic.backup',passphrase='synthetic')
        self.assertEqual(result['decode_status'],'complete');self.assertEqual(result['status'],'partial')
        self.assertEqual(result['message_records'],1)

    def test_cli_discord_import_and_search_and_help(self):
        command=[sys.executable,'-B','-m','lawliet_mobile','--workspace',str(self.workspace),'--json']
        result=subprocess.run(command+['import-discord',str(self.sources['discord']),'--case','B'],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        self.assertEqual(json.loads(result.stdout)['records'],2)
        replay=subprocess.run(command+['import-discord',str(self.sources['discord']),'--case','B'],capture_output=True,text=True,timeout=30)
        self.assertEqual(replay.returncode,0,replay.stderr+replay.stdout)
        self.assertEqual(json.loads(replay.stdout)['status'],'already_imported')
        found=subprocess.run(command+['messages','--case','B','--app','discord','--query','confirmed','--format','json'],capture_output=True,text=True,timeout=30)
        self.assertEqual(found.returncode,0,found.stderr);self.assertIn('CASE-ALPHA confirmed',found.stdout)
        for name in ('import-chat','import-discord','check-signal'):
            help_run=subprocess.run(command+[name,'--help'],capture_output=True,text=True,timeout=30)
            self.assertEqual(help_run.returncode,0,help_run.stderr)


if __name__=='__main__':unittest.main()
