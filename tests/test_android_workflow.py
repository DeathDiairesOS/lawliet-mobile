from contextlib import closing
import contextlib
import io
import json
import os
import sqlite3
import sys
import tarfile
import tempfile
import unittest
import zlib
import zipfile
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

from lawliet_mobile.acquisition import collect_android, case_coverage
from lawliet_mobile.android_backup import inflate, import_backup, unpack_backup
from lawliet_mobile.cli import main
from lawliet_mobile.core import UserError, add_artifact, connect, create_case, digest, import_evidence, select_artifacts, verify
from lawliet_mobile.messages import conversations, import_chat, leapp_message, local_time
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.report import write_report
from lawliet_mobile.tools import configure, command, execute, storage_guard


class AndroidWorkflowTests(unittest.TestCase):
    def test_ileapp_ios_messages_preserve_identity_and_attachment_rows(self):
        row = {'Message Timestamp': '2026-10-10 10:00:00+00:00', 'Message': 'Decoded text',
               'Service': 'iMessage', 'Message Direction': 'Outgoing', 'Message Row ID': '42',
               'Chat ID': '7', 'Sender': '', 'Chat Participants': 'Alex, Sam',
               'Attachment Name': 'photo.jpg'}
        mapped = leapp_message('SMS', row, 'evidence')
        self.assertEqual(mapped[0], 'messages')
        self.assertEqual(mapped[1], '2026-10-10T10:00:00.000000Z')
        self.assertEqual(mapped[4], 'Decoded text')
        self.assertEqual(mapped[5]['message']['app'], 'imessage')
        self.assertEqual(mapped[5]['message']['recipient'], '')
        self.assertEqual(mapped[5]['Attachment Name'], 'photo.jpg')
        second = leapp_message('SMS', {**row, 'Attachment Name': 'other.jpg'}, 'evidence')
        self.assertEqual(mapped[5]['message']['conversation_id'], second[5]['message']['conversation_id'])
        first_unlinked = leapp_message('SMS', {**row, 'Chat ID': ''}, 'evidence')
        other_unlinked = leapp_message('SMS', {**row, 'Chat ID': '', 'Message Row ID': '43'}, 'evidence')
        self.assertNotEqual(first_unlinked[5]['message']['conversation_id'], other_unlinked[5]['message']['conversation_id'])
        self.assertIsNone(leapp_message('SMS', {'Message': 'unknown schema'}, 'evidence'))
        with connect(self.workspace, 'test') as (root, db):
            source = self.base / 'source.txt'
            source.write_text('fixture')
            eid, _, _ = import_evidence(root, db, source, 'ios')
            for parser in ('ileapp', 'native-test'):
                add_artifact(db, eid, None, mapped[0], mapped[1], mapped[2], mapped[3], mapped[4], 'fixture', parser, mapped[5])
            self.assertEqual(len(select_artifacts(db, parser='ileapp')), 1)
            self.assertEqual(conversations(db, parser='ileapp')[0]['records'], 1)
            self.assertEqual(select_artifacts(db, parser='missing'), [])
            report = write_report(root, db, root / 'reports/filtered.html', {'parser': 'ileapp'})
            self.assertEqual(report['records'], 1)
            self.assertIn('Report scope:', Path(report['path']).read_text())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'test')

    def backup(self, compressed=False, name='backup.ab', members=None):
        sms = [{'address': '+12025550100', 'body': 'Invoice <script>alert(1)</script>\nSecond line', 'date': '1791640800000', 'type': '1'}]
        mms = [{'recipients': ['+12025550100'], 'mms_body': 'MMS evidence', 'date': '1791640860', 'msg_box': '2'}]
        members = members if members is not None else {
            'apps/com.android.providers.telephony/d_f/000000_sms_backup': zlib.compress(json.dumps(sms).encode()),
            'apps/com.android.providers.telephony/d_f/000000_mms_backup': zlib.compress(json.dumps(mms).encode())}
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as tar:
            for filename, value in members.items():
                info = tarfile.TarInfo(filename)
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
        payload = zlib.compress(data.getvalue()) if compressed else data.getvalue()
        path = self.base / name
        path.write_bytes(b'ANDROID BACKUP\n5\n' + (b'1\n' if compressed else b'0\n') + b'none\n' + payload)
        return path

    def test_ab_intake_sms_mms_provenance_queries_and_report(self):
        source = self.backup(True)
        hashed = digest(source)
        with connect(self.workspace, 'test') as (root, db):
            result = import_backup(root, db, source)
            eid = result['evidence_id']
            parsed = native_analyze(root, db, eid)
            self.assertEqual(parsed['new_records'], 2)
            self.assertEqual(native_analyze(root, db, eid)['new_records'], 0)
            sms = select_artifacts(db, app='sms', participant='202555', query='invoice')[0]
            self.assertEqual(sms['timestamp'], '2026-10-10T14:00:00.000000Z')
            self.assertIn('<script>', sms['body'])
            self.assertEqual(sms['data']['message']['direction'], 'incoming')
            self.assertTrue(sms['source_sha256'])
            self.assertEqual(select_artifacts(db, app='mms')[0]['timestamp'], '2026-10-10T14:01:00.000000Z')
            groups = conversations(db)
            self.assertEqual(len(groups), 2)
            self.assertEqual(len(select_artifacts(db, conversation=groups[0]['conversation_id'])), 1)
            self.assertEqual(len(select_artifacts(db, category='messages', offset=1)), 1)
            report = write_report(root, db, root / 'reports/messages.html', {'app': 'sms'})
            content = Path(report['path']).read_text()
            self.assertIn('&lt;script&gt;', content)
            self.assertNotIn('MMS evidence', content)
            self.assertIn('report_filters', content)
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(digest(source), hashed)

    def test_ab_encryption_traversal_truncation_and_bomb(self):
        source = self.base / 'encrypted.ab'
        source.write_bytes(b'ANDROID BACKUP\n5\n1\nAES-256\n')
        with connect(self.workspace, 'test') as (root, db):
            with self.assertRaisesRegex(UserError, 'Original retained'):
                import_backup(root, db, source)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 1)
            self.assertTrue(verify(root, db)['ok'])
            disguised = self.base / 'disguised.ab'
            with zipfile.ZipFile(disguised, 'w') as archive:
                archive.writestr('inside.txt', 'wrong container format')
            with self.assertRaisesRegex(UserError, 'Original retained'):
                import_backup(root, db, disguised)
            copied = db.execute("SELECT * FROM files WHERE path='disguised.ab'").fetchone()
            self.assertIsNotNone(copied)
            self.assertEqual(copied['sha256'], digest(disguised))
        source = self.backup(members={'../escape': b'bad'})
        target = self.base / 'output'
        target.mkdir()
        with self.assertRaisesRegex(UserError, 'Unsafe'):
            unpack_backup(source, target)
        self.assertFalse((self.base / 'escape').exists())
        for payload in (zlib.compress(b'A' * 10000), zlib.compress(b'abc')[:-2], zlib.compress(b'abc') + b'extra'):
            with self.assertRaises(UserError):
                inflate(io.BytesIO(payload), io.BytesIO(), 100)

    def test_whatsapp_export_multiline_events_unknown_time_and_scope(self):
        source = self.base / 'chat.txt'
        source.write_text('10/10/2026, 10:00 - Messages are encrypted\n10/10/2026, 10:01 - Alex: invoice\ncontinued\n10/10/2026, 10:02 - Sam: confirmed\n')
        with connect(self.workspace, 'test') as (root, db):
            result = import_chat(root, db, source, 'mdy', 'America/New_York')
            self.assertEqual(result['records'], 3)
            rows = select_artifacts(db, category='messages', app='whatsapp')
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]['body'], 'invoice\ncontinued')
            self.assertEqual(rows[0]['timestamp'], '2026-10-10T14:01:00.000000Z')
            self.assertEqual(rows[0]['source_ref'], 'lines=2-3')
            self.assertEqual(rows[0]['data']['message']['sender'], 'Alex')
            self.assertEqual(len(conversations(db)), 1)
            import_chat(root, db, source, 'mdy')
            self.assertEqual(len(conversations(db)), 2)
            self.assertEqual(sum(r['undated'] for r in conversations(db)), 2)
            self.assertTrue(verify(root, db)['ok'])

    def test_ambiguous_nonexistent_and_two_digit_dates_stay_undated(self):
        zone = ZoneInfo('America/New_York')
        for raw in ['11/01/2026, 01:30', '03/08/2026, 02:30', '10/10/26, 12:30', '02/30/2026, 12:00']:
            self.assertIsNone(local_time(raw, 'mdy', zone)[0], raw)
        self.assertEqual(local_time('10/10/2026, 1:30 PM', 'mdy', zone)[0], '2026-10-10T17:30:00.000000Z')

    def test_leapp_message_mapping_requires_known_schema_and_identity(self):
        signal = {'Date Sent': '2026-10-10T14:00:00+00:00', 'Message': 'hello', 'Thread ID': '7', 'Direction': 'Incoming', 'Sender': 'Alex'}
        mapped = leapp_message('Signal - Messages', signal, 'e1')
        self.assertEqual(mapped[0], 'messages')
        self.assertEqual(mapped[-1]['message']['app'], 'signal')
        self.assertEqual(mapped[-1]['Message'], 'hello')
        self.assertIsNone(leapp_message('Signal - Contacts', signal, 'e1'))
        self.assertIsNone(leapp_message('Signal - Messages', {**signal, 'Thread ID': ''}, 'e1'))
        whatsapp = {'Message Timestamp': '2026-10-10T14:00:00+00:00', 'Message': 'group', 'Group JID': 'one@g.us', 'Message Direction': 'Outgoing', 'Conversation Name': 'Same label'}
        first = leapp_message('WhatsApp - Group Messages', whatsapp, 'e1')
        second = leapp_message('WhatsApp - Group Messages', {**whatsapp, 'Group JID': 'two@g.us'}, 'e1')
        self.assertNotEqual(first[-1]['message']['conversation_id'], second[-1]['message']['conversation_id'])

    def test_collector_counts_payloads_and_keeps_missing_distinct(self):
        backup = self.backup(members={'apps/com.android.providers.telephony/d_f/000000_sms_backup': zlib.compress(b'[]')})
        def fake(argv, output, timeout=300, **kwargs):
            output.write_text('device\n' if argv[-1] == 'get-state' else '')
            output.with_name(output.name + '.stderr').write_text('')
            if 'backup' in argv:
                Path(argv[argv.index('-f') + 1]).write_bytes(backup.read_bytes())
            return {'argv': argv, 'returncode': 0, 'stdout': str(output)}
        with connect(self.workspace, 'test') as (root, db), patch('lawliet_mobile.tools.command', return_value=['adb']), patch('lawliet_mobile.tools.execute', side_effect=fake):
            result = collect_android(root, db, self.workspace, 'TEST')
            states = {r['source']: r['state'] for r in result['coverage']}
            self.assertEqual(states['sms'], 'collected_empty')
            self.assertEqual(states['mms'], 'not_returned')
            self.assertEqual(states['signal'], 'not_attempted')
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(case_coverage(root, db)['acquisitions'][0]['evidence_id'], result['evidence_id'])
            self.assertTrue(verify(root, db)['ok'])

    def test_empty_successful_backup_not_claimed_collected(self):
        def fake(argv, output, timeout=300, **kwargs):
            output.write_text('device\n' if argv[-1] == 'get-state' else '')
            if 'backup' in argv:
                Path(argv[argv.index('-f') + 1]).write_bytes(b'')
            return {'argv': argv, 'returncode': 0}
        with connect(self.workspace, 'test') as (root, db), patch('lawliet_mobile.tools.command', return_value=['adb']), patch('lawliet_mobile.tools.execute', side_effect=fake):
            result = collect_android(root, db, self.workspace, 'TEST')
            self.assertEqual(result['status'], 'partial')
            self.assertTrue(any(x['source'] == 'telephony_backup' and x['state'] == 'failed' for x in result['coverage']))
            self.assertTrue(verify(root, db)['ok'])

    def test_storage_guard_stops_process_and_retains_details(self):
        folder = self.base / 'output'
        folder.mkdir()
        with self.assertRaises(UserError) as caught:
            execute([sys.executable, '-c', "import time; print('x'*10000, flush=True); time.sleep(5)"], folder / 'stdout', 10, guard=storage_guard(folder, 1000, reserve=0))
        self.assertIn('storage budget', caught.exception.tool_result['error'])
        self.assertIsNotNone(caught.exception.tool_result['returncode'])

    def test_isolated_interpreter_and_cli_workflow(self):
        script = self.base / 'engine.py'
        script.write_text('pass')
        configure(self.workspace, 'aleapp', script, sys.executable)
        self.assertEqual(command(self.workspace, 'aleapp'), [str(Path(sys.executable).absolute()), str(script.resolve())])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(['workflow', 'signal', '--json']), 0)
        self.assertIn('Legacy Android Signal backups can be decrypted with a known 30-digit passphrase', out.getvalue())
        self.assertIn('private app acquisition requires existing root', out.getvalue())

    def test_invalid_shared_path_fails_before_collection(self):
        with connect(self.workspace, 'test') as (root, db):
            for remote in ['/data/data', '/sdcard/../data', '/sdcard/a;id']:
                with self.assertRaises(UserError):
                    collect_android(root, db, self.workspace, 'TEST', 'files', [remote])
            self.assertFalse((root / 'collections').exists())

    def test_shared_storage_empty_success_and_spaced_path(self):
        observed = []
        def fake(argv, output, timeout=300, **kwargs):
            observed.append(argv)
            output.write_text('device\n' if argv[-1] == 'get-state' else '4 /sdcard/My Photos\n' if 'du' in argv else '')
            return {'argv': argv, 'returncode': 0}
        with connect(self.workspace, 'test') as (root, db), patch('lawliet_mobile.tools.command', return_value=['adb']), patch('lawliet_mobile.tools.execute', side_effect=fake):
            result = collect_android(root, db, self.workspace, 'TEST', 'files', ['/sdcard/My Photos'])
            self.assertEqual(result['status'], 'complete')
            self.assertEqual(result['coverage'][-1]['state'], 'collected_empty')
            self.assertEqual(next(a for a in observed if 'du' in a)[-1], "'/sdcard/My Photos'")
            self.assertTrue(verify(root, db)['ok'])

    def test_unicode_keyword_search_and_unparsed_encrypted_candidates(self):
        source = self.base / 'data'
        source.mkdir()
        (source / 'signal.db').write_bytes(b'not a readable database')
        (source / 'msgstore.db.crypt15').write_bytes(b'encrypted payload')
        sms = source / 'mmssms.db'
        with closing(sqlite3.connect(sms)) as connection, connection:
            connection.executescript("CREATE TABLE sms(_id INTEGER,date INTEGER,address TEXT,body TEXT,type INTEGER);")
            connection.execute('INSERT INTO sms VALUES(1,1791640800000,?,?,1)', ('Élodie', 'Straße invoice'))
        with connect(self.workspace, 'test') as (root, db):
            eid, _, _ = import_evidence(root, db, source, 'android')
            result = native_analyze(root, db, eid)
            self.assertEqual(len(result['unparsed_candidates']), 2)
            self.assertEqual(len(select_artifacts(db, query='STRASSE', participant='élodie')), 1)

    def test_cli_message_query_and_export(self):
        source = self.backup()
        with connect(self.workspace, 'test') as (root, db):
            result = import_backup(root, db, source)
            native_analyze(root, db, result['evidence_id'])
        output = self.base / 'messages.json'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['messages', '--case', 'test', '--workspace', str(self.workspace),
                '--app', 'sms', '--query', 'invoice', '--format', 'json', '--out', str(output)]), 0)
        rows = json.loads(output.read_text())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['data']['message']['app'], 'sms')


if __name__ == '__main__':
    unittest.main()
