"""Real approved-plan execution against synthetic ADB, never USB or a model.

Collectors, subprocess ownership, intake, native indexing and replay are real.
The configured executable accepts only synthetic serials and fixed commands.
Expected evidence values below are independent of LAWLIET's parser output.
"""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from lawliet_mobile import agent_collection as workflow
from lawliet_mobile.core import connect, create_case, select_artifacts, verify
from lawliet_mobile.tools import configure


PROFILES = ['sms-provider', 'contacts-provider', 'files', 'triage', 'trash-photos']
PULL = '/sdcard/Download/lawliet-seed'
TRASH = '/sdcard/Android/.Trash/com.sec.android.gallery3d/trashed-fixture.png'
MESSAGE_1 = 'Meet at the blue station at noon — café.'
MESSAGE_2 = 'Confirmed. Bring the receipt.'
FIELDS = ('category', 'title', 'body', 'timestamp', 'timestamp_raw',
          'logical_path', 'source_ref', 'parser')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class PortableCollectionExecution(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='lawliet-collection-portable-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.workspace = self.base/'cases'
        create_case(self.workspace, 'SYNTHETIC')
        self.adb = self.base/'synthetic_adb.py'
        shutil.copyfile(Path(__file__).parent/'fixtures/collection_adb.py', self.adb)
        self.tool_hash = sha(self.adb.read_bytes())
        self.calls = self.adb.with_suffix('.calls.jsonl')
        configure(self.workspace, 'adb', self.adb, python=sys.executable)

    def collect(self, profiles, serial='LAWLIET-SYNTHETIC'):
        with connect(self.workspace, 'SYNTHETIC') as (root, db):
            plan = workflow.create_plan(root, db, {
                'objective': 'Synthetic acquisition and native-index qualification',
                'examiner': 'Synthetic QA only', 'authorized': True,
                'serial': serial, 'profiles': profiles,
                'pulls': [PULL] if 'files' in profiles else [], 'android_user': 0,
                'max_records': 10, 'max_bytes': 8*1024**2, 'timeout': 60,
            })
            # Approval persists first; neither configuration nor approval runs ADB.
            self.assertFalse(self.calls.exists())
            result = workflow.execute_plan(root, db, self.workspace, plan['id'])
            self.assertTrue(result['integrity']['ok'], result)
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(sha(self.adb.read_bytes()), self.tool_hash)
        commands = [json.loads(line) for line in self.calls.read_text(encoding='utf-8').splitlines()]
        self.assertTrue(commands)
        self.assertTrue(all(command[:2] == ['-s', serial] for command in commands))
        self.assertFalse(any(command[2] in {'backup', 'install', 'root', 'reboot'}
                             for command in commands))
        return result

    def retained(self, root, db):
        """Check every retained file, not just a collector's success flag."""
        hashes = {}
        for row in db.execute('SELECT evidence_id,path,size,sha256 FROM files'):
            path = root/'evidence'/row['evidence_id']/row['path']
            self.assertFalse(path.is_symlink())
            raw = path.read_bytes()
            self.assertEqual((len(raw), sha(raw)), (row['size'], row['sha256']))
            hashes[(row['evidence_id'], row['path'])] = sha(raw)
        self.assertTrue(hashes)
        return hashes

    def replay(self, result):
        calls_before = self.calls.read_bytes()
        with connect(self.workspace, 'SYNTHETIC') as (root, db):
            before = self.retained(root, db)
            records = select_artifacts(db, limit=None)
            runs = [tuple(row) for row in db.execute('SELECT id,status,records FROM runs ORDER BY id')]
        # Reopen the case: terminal state must persist without another collection.
        with connect(self.workspace, 'SYNTHETIC') as (root, db):
            self.assertEqual(workflow.execute_plan(root, db, self.workspace, result['id']), result)
            self.assertEqual(select_artifacts(db, limit=None), records)
            self.assertEqual([tuple(row) for row in db.execute(
                'SELECT id,status,records FROM runs ORDER BY id')], runs)
            self.assertEqual(self.retained(root, db), before)
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(self.calls.read_bytes(), calls_before)
        self.assertEqual(sha(self.adb.read_bytes()), self.tool_hash)

    def test_all_five_profiles_execute_parse_and_replay_without_recollection(self):
        result = self.collect(PROFILES)
        self.assertEqual(result['status'], 'complete', result)
        self.assertEqual(result['outcome'], 'records_available')
        steps = {step['profile']: step for step in result['steps']}
        self.assertEqual({name: (step['status'], step['records']) for name, step in steps.items()},
                         {'sms-provider': ('complete', 2), 'contacts-provider': ('complete', 1),
                          'files': ('complete', 3), 'triage': ('complete', 3),
                          'trash-photos': ('complete', 1)})
        self.assertEqual(len({step['evidence_id'] for step in steps.values()}), 5)
        self.assertEqual(len({step['run_id'] for step in steps.values()}), 5)
        expected = {
            ('sms-provider', 'payload/sms-provider.jsonl:line=1'):
                ('messages', 'SMS provider · incoming', MESSAGE_1,
                 '2026-10-17T12:00:00.123000Z', '1792238400123',
                 'payload/sms-provider.jsonl', 'payload/sms-provider.jsonl:line=1', 'adb-sms-provider/0.1'),
            ('sms-provider', 'payload/sms-provider.jsonl:line=2'):
                ('messages', 'SMS provider · outgoing', MESSAGE_2,
                 '2026-10-17T12:01:00.123000Z', '1792238460123',
                 'payload/sms-provider.jsonl', 'payload/sms-provider.jsonl:line=2', 'adb-sms-provider/0.1'),
            ('contacts-provider', 'vcard:record=1'):
                ('contacts', 'Alex Fixture',
                 'FN: Alex Fixture · UID: android-provider-user-0-contact-7 · TEL: +12025550123',
                 None, None, 'contacts.vcf', 'vcard:record=1', 'native/0.1.14'),
            ('triage', 'line=2'):
                ('logs', 'I · ActivityManager', 'Synthetic activity resumed',
                 '2026-10-17T12:00:01.250000Z', '1792238401.250',
                 'logcat.txt', 'line=2', 'native/0.1.14'),
            ('files', 'file:shared/0/lab-photo.png'):
                ('media', 'lab-photo.png', 'image/png', None, None,
                 'shared/0/lab-photo.png', 'file:shared/0/lab-photo.png', 'native/0.1.14'),
            ('trash-photos', 'file:photos/0/trashed-fixture.png'):
                ('media', 'trashed-fixture.png', 'image/png', None, None,
                 'photos/0/trashed-fixture.png', 'file:photos/0/trashed-fixture.png', 'native/0.1.14'),
        }
        for profile in ('files', 'triage'):
            expected[(profile, 'line=1')] = (
                'apps', 'com.example.fixture', '/data/app/example/base.apk', None, None,
                'packages.txt', 'line=1', 'native/0.1.14')
            expected[(profile, 'getprop output')] = (
                'device', 'Android system properties', ' Synthetic validation fixture · Android 13',
                None, None, 'getprop.txt', 'getprop output', 'native/0.1.14')
        with connect(self.workspace, 'SYNTHETIC') as (root, db):
            files = self.retained(root, db)
            rows = select_artifacts(db, limit=None)
            by_evidence = {step['evidence_id']: name for name, step in steps.items()}
            actual = {(by_evidence[row['evidence_id']], row['source_ref']):
                      tuple(row[field] for field in FIELDS) for row in rows}
            self.assertEqual(len(rows), len(expected))  # Duplicate keys cannot hide extra rows.
            self.assertEqual(actual, expected)
            for row in rows:
                self.assertEqual(row['source_sha256'], files[(row['evidence_id'], row['logical_path'])])
                self.assertTrue(row['id'])
            sms = sorted((row for row in rows if row['category'] == 'messages'),
                         key=lambda row: row['source_ref'])
            for i, row in enumerate(sms):
                self.assertEqual(row['data']['raw_fields'], {
                    '_id': 41+i, 'thread_id': 7, 'address': '+12025550123',
                    'date': 1792238400123+i*60000, 'date_sent': 0, 'type': 1+i,
                    'body': (MESSAGE_1, MESSAGE_2)[i], 'read': 1, 'status': -1,
                })
                message = row['data']['message']
                self.assertEqual((message['direction'], message['sender'], message['recipient']),
                                 ('incoming', '+12025550123', '') if i == 0
                                 else ('outgoing', '', '+12025550123'))
                self.assertEqual(message['conversation'], 'android-user:0/thread:7')
                provider = row['data']['provider']
                self.assertEqual((provider['android_user'], provider['record_id']), (0, 41+i))
                self.assertEqual(provider['raw_response_sha256'],
                                 files[(row['evidence_id'], f'sms-{41+i}.txt')])
            self.assertEqual(sms[0]['data']['message']['conversation_id'],
                             sms[1]['data']['message']['conversation_id'])
            contact = next(row for row in rows if row['category'] == 'contacts')
            self.assertEqual(contact['data']['properties'],
                             {'FN': ['Alex Fixture'], 'TEL': ['+12025550123'],
                              'UID': ['android-provider-user-0-contact-7']})
            images = {row['title']: row for row in rows if row['category'] == 'media'}
            self.assertEqual(images['lab-photo.png']['source_sha256'],
                             '2142f54f2bd88700b1fdf7eb233fb97568eaba7a4e1d5faa03a8993eaa320b5a')
            self.assertEqual(images['trashed-fixture.png']['source_sha256'],
                             'd281cb3b8f51a9b505e37b8dfc4409391b92c8d7a4008257c5976d83e07b0fd1')
            trash = db.execute('SELECT * FROM media_acquisition_sources').fetchall()
            self.assertEqual(len(trash), 1)
            self.assertEqual((trash[0]['file_id'], trash[0]['remote_path']),
                             (images['trashed-fixture.png']['file_id'], TRASH))
            self.assertEqual(steps['files']['collected_files'], 1)
            self.assertEqual(steps['trash-photos']['collected_files'], 1)
            self.assertEqual(steps['triage']['collected_files'], 6)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0], 5)
        self.replay(result)

    def test_provider_denial_is_retained_and_replay_never_retries(self):
        result = self.collect(['sms-provider', 'contacts-provider'], 'LAWLIET-DENIED')
        self.assertEqual((result['status'], result['outcome']), ('failed', 'no_records'), result)
        self.assertTrue(all(step['status'] == 'failed' and step['records'] == 0
                            and step['error'] and step['evidence_id'] for step in result['steps']))
        with connect(self.workspace, 'SYNTHETIC') as (root, db):
            self.retained(root, db)
            self.assertEqual(select_artifacts(db, limit=None), [])
            for step in result['steps']:
                files = list(db.execute('SELECT path FROM files WHERE evidence_id=?', (step['evidence_id'],)))
                raw = [root/'evidence'/step['evidence_id']/row['path'] for row in files]
                self.assertTrue(any(b'Permission Denial' in path.read_bytes() for path in raw))
                manifest = json.loads((root/'evidence'/step['evidence_id']/'collection.json').read_text(encoding='utf-8'))
                self.assertEqual(manifest['status'], 'failed')
                self.assertTrue(manifest['errors'])
        self.replay(result)

    def test_partial_diagnostics_keep_good_records_and_failure_provenance(self):
        result = self.collect(['triage'], 'LAWLIET-PARTIAL')
        self.assertEqual(result['status'], 'partial', result)
        step = result['steps'][0]
        self.assertEqual((step['status'], step['records'], step['collected_files']), ('partial', 3, 5))
        self.assertTrue(any(row['source'] == 'bugreport' and row['state'] == 'failed'
                            for row in step['coverage']))
        with connect(self.workspace, 'SYNTHETIC') as (root, db):
            self.retained(root, db)
            rows = select_artifacts(db, limit=None)
            self.assertEqual(sorted(row['category'] for row in rows), ['apps', 'device', 'logs'])
            event = next(row for row in rows if row['category'] == 'logs')
            self.assertEqual((event['body'], event['timestamp'], event['source_ref']),
                             ('Synthetic activity resumed', '2026-10-17T12:00:01.250000Z', 'line=2'))
            evidence = root/'evidence'/step['evidence_id']
            self.assertEqual((evidence/'bugreport.log.stderr').read_bytes(),
                             b'Synthetic bugreport collection failure\n')
            self.assertFalse((evidence/'bugreport.zip').exists())
            manifest = json.loads((evidence/'collection.json').read_text(encoding='utf-8'))
            self.assertEqual(manifest['status'], 'partial')
            failed = [command for command in manifest['commands'] if command['returncode'] != 0]
            self.assertEqual(len(failed), 1)
            self.assertEqual(failed[0]['returncode'], 9)
        self.replay(result)
