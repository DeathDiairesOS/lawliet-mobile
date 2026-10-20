"""Authorized collection workflow tests use synthetic evidence, never a phone."""
import json
import shlex
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile import agent_collection as workflow
from lawliet_mobile.core import (UserError, add_artifact, audit, begin_run_index,
                                connect, create_case, import_evidence, now, verify)


class AgentCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'A')
        self.context = connect(self.workspace, 'A')
        self.root, self.db = self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)

    def config(self, **values):
        return dict(objective='Review authorized fixture records', serial='SYNTHETIC-1',
                    profiles=['sms-provider'], examiner='Fixture examiner', authorized=True,
                    android_user=0, max_records=10, max_bytes=1048576, timeout=30, **values)

    def plan(self, config=None):
        return workflow.create_plan(self.root, self.db, config or self.config())

    def run_plan(self, plan):
        return workflow.execute_plan(self.root, self.db, self.workspace, plan['id'])

    def evidence(self, name='fixture.txt', content='retained fixture'):
        folder = self.base / uuid.uuid4().hex
        folder.mkdir()
        (folder / name).write_text(content)
        eid, _, _ = import_evidence(self.root, self.db, folder, 'android', 'Synthetic collection')
        return eid

    def sms_result(self, records=1, status='complete'):
        eid = self.evidence()
        rid = uuid.uuid4().hex[:12]
        self.db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,finished_at,status,records,detail) VALUES(?,?,?,?,?,?,?,?)',
                        (rid, eid, 'adb-sms-provider/1', now(), now(), status, records, '{}'))
        begin_run_index(self.db, rid)
        fid = self.db.execute('SELECT id FROM files WHERE evidence_id=?', (eid,)).fetchone()[0]
        for index in range(records):
            add_artifact(self.db, eid, fid, 'messages', '2026-10-17T12:00:00+00:00', '2026-10-17T12:00:00Z',
                         'Synthetic', 'PRIVATE BODY MUST NOT LEAK', str(index), 'adb-sms-provider/1', {}, run_id=rid)
        self.db.commit()
        return {'collection_id': uuid.uuid4().hex[:12], 'evidence_id': eid, 'run_id': rid, 'status': status, 'records': records, 'errors': []}

    def test_authorization_required_and_bounds_are_strict(self):
        invalid = [dict(authorized=False), dict(authorized=1), dict(examiner=''), dict(objective=''),
                   dict(serial='-s OTHER'), dict(serial='SERIAL;echo'), dict(profiles=[]),
                   dict(profiles=['logical']), dict(profiles=['sms-provider', 'sms-provider']),
                   dict(max_records=True), dict(max_records=10001), dict(max_bytes=20*1024**3+1),
                   dict(timeout=1.5), dict(timeout=901), dict(android_user=True),
                   dict(command=['adb']), dict(pulls=['/sdcard/Download']),
                   dict(profiles=['files']), dict(profiles=['files'], pulls=['/data/data/private']),
                   dict(profiles=['files'], pulls=['/sdcard/../private']),
                   dict(profiles=['files'], pulls=['/sdcard/']),
                   dict(profiles=['files'], pulls=['/sdcard/Download'], android_user=10),
                   dict(profiles=['trash-photos'], android_user=10)]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(UserError):
                workflow.create_plan(self.root, self.db, {**self.config(), **changes})
        self.assertFalse(workflow.list_plans(self.root, self.db))

    def test_saved_authorization_is_authoritative_and_terminal_replay_does_not_collect(self):
        config = self.config()
        plan = self.plan(config)
        config['profiles'].append('files')
        config['serial'] = 'OTHER'
        with patch.object(workflow.provider_sms, 'collect_sms', side_effect=lambda *a, **k: self.sms_result()) as collect:
            result = self.run_plan(plan)
            repeated = self.run_plan(plan)
        self.assertEqual(result, repeated)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['steps'][0]['records'], 1)
        self.assertEqual(result['steps'][0]['source_id'], result['steps'][0]['run_id'])
        self.assertNotIn('PRIVATE BODY', json.dumps(result))
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(collect.call_args.args[3], 'SYNTHETIC-1')
        self.assertEqual(collect.call_args.kwargs, dict(timeout=30, max_bytes=1048576, max_messages=10, user=0))
        self.assertTrue(result['integrity']['ok'])
        self.assertTrue(verify(self.root, self.db)['ok'])

    def test_contacts_collect_then_real_native_parse(self):
        plan = self.plan({**self.config(), 'profiles': ['contacts-provider']})
        def collect(*args, **kwargs):
            eid = self.evidence('contacts.vcf', 'BEGIN:VCARD\nVERSION:3.0\nFN:Fixture Contact\nTEL:+12025550100\nEND:VCARD\n')
            return dict(collection_id='a'*12, status='complete', evidence_id=eid, errors=[])
        with patch.object(workflow.provider_contacts, 'collect_contacts', side_effect=collect) as collect:
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['steps'][0]['records'], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM artifacts WHERE category='contacts'").fetchone()[0], 1)
        self.assertEqual(collect.call_args.kwargs['max_contacts'], 10)
        self.assertTrue(result['steps'][0]['run_id'])

    def test_real_contacts_collector_uses_synthetic_transport_and_indexes(self):
        plan = self.plan({**self.config(), 'profiles': ['contacts-provider']})
        commands = []
        def transport(argv, output, timeout, **kwargs):
            commands.append(argv)
            if argv[-1] == 'get-state':
                text = 'device\n'
            else:
                args = shlex.split(argv[-1])
                column = args[args.index('--projection') + 1]
                where = args[args.index('--where') + 1] if '--where' in args else None
                if column == '_id' and where is None:
                    text = 'Row: 0 _id=7\n'
                elif column == 'display_name':
                    text = 'Row: 0 display_name=Fixture Contact\n'
                elif column == '_id':
                    text = 'Row: 0 _id=11\n' if 'phone_v2' in where else 'No result found.\n'
                else:
                    text = 'Row: 0 data1=+12025550100\n'
            output.write_bytes(text.encode('utf-8'))
            error = Path(str(output) + '.stderr')
            error.write_text('')
            return dict(argv=argv, returncode=0, stdout=str(output), stderr=str(error))
        with patch('lawliet_mobile.provider_contacts.command', return_value=['synthetic-adb']), patch('lawliet_mobile.provider_contacts.execute', side_effect=transport):
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['steps'][0]['records'], 1)
        self.assertTrue(commands)
        self.assertTrue(all(c[:3] == ['synthetic-adb', '-s', 'SYNTHETIC-1'] for c in commands))
        self.assertFalse(any(any(word in ' '.join(c) for word in (' install ', ' grant ', ' root ')) for c in commands))

    def test_files_are_collected_under_runner_lease_and_only_requested_scope(self):
        plan = self.plan({**self.config(), 'profiles': ['files'], 'pulls': ['/sdcard/Download/fixture.txt'], 'timeout': 1})
        def collect(*args, **kwargs):
            from lawliet_mobile.runner_lease import ownership
            self.assertTrue(ownership()['nonce'])
            self.assertEqual(kwargs, dict(timeout=1, max_bytes=1048576, profile='files', pulls=['/sdcard/Download/fixture.txt']))
            return dict(collection_id='b'*12, evidence_id=self.evidence(), status='complete', errors=[],
                        coverage=[dict(source='/sdcard/Download/fixture.txt', state='collected'), dict(source='whatsapp', state='not_attempted')])
        with patch.object(workflow.acquisition, 'collect_android', side_effect=collect):
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['outcome'], 'no_records')
        self.assertTrue(result['steps'][0]['run_id'])

    def test_broader_budget_is_explicit_but_provider_caps_remain_small(self):
        plan = self.plan({**self.config(), 'profiles': ['sms-provider', 'contacts-provider', 'triage', 'trash-photos'],
                          'max_bytes': 20*1024**3})
        with patch.object(workflow.provider_sms, 'collect_sms', side_effect=lambda *a, **k: self.sms_result()) as sms, \
             patch.object(workflow.provider_contacts, 'collect_contacts', return_value=dict(status='complete', evidence_id=self.evidence(), errors=[])) as contacts, \
             patch.object(workflow.acquisition, 'collect_android', return_value=dict(status='failed', errors=[])) as other:
            self.run_plan(plan)
        self.assertEqual(sms.call_args.kwargs['max_bytes'], 64*1024**2)
        self.assertEqual(contacts.call_args.kwargs['max_bytes'], 64*1024**2)
        self.assertEqual([c.kwargs['profile'] for c in other.call_args_list], ['triage', 'trash-photos'])
        self.assertTrue(all(c.kwargs['max_bytes'] == 20*1024**3 for c in other.call_args_list))

    def triage_transport(self, calls, bad_zip=False, empty_properties=False):
        def transport(argv, output, timeout, **kwargs):
            from lawliet_mobile.runner_lease import ownership
            self.assertTrue(ownership()['nonce'])
            calls.append(argv)
            if argv[-1] == 'get-state':
                text = 'device\n'
            elif argv[-1] == 'getprop':
                text = '' if empty_properties else '[ro.product.model]: [Synthetic]\n'
            elif 'packages' in argv:
                text = 'package:/data/app/example/base.apk=org.example.fixture\n'
            elif 'logcat' in argv:
                text = '1792238400.000 100 101 I Fixture: synthetic activity\n'
            elif 'bugreport' in argv:
                if bad_zip:
                    Path(argv[-1]).write_text('not a ZIP')
                else:
                    with zipfile.ZipFile(argv[-1], 'w') as archive:
                        archive.writestr('bugreport.txt', 'synthetic diagnostic content')
                text = 'Bugreport retained\n'
            else:
                text = '2026-10-17T12:00:00+0000\n' if 'date' in argv else 'Android Debug Bridge fixture\n'
            output.write_bytes(text.encode('utf-8'))
            error = Path(str(output)+'.stderr'); error.write_text('')
            return dict(argv=argv, returncode=0, stdout=str(output), stderr=str(error))
        return transport

    def test_real_triage_collects_diagnostics_and_indexes_without_backup_or_device_changes(self):
        plan = self.plan({**self.config(), 'profiles': ['triage']})
        calls = []
        with patch('lawliet_mobile.tools.command', return_value=['synthetic-adb']), \
             patch('lawliet_mobile.tools.execute', side_effect=self.triage_transport(calls)):
            result = self.run_plan(plan)
        step = result['steps'][0]
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(step['collected_files'], 6)
        self.assertGreater(step['retained_files'], step['collected_files'])
        self.assertGreater(step['retained_bytes'], step['collected_bytes'])
        self.assertGreater(step['records'], 0)
        self.assertTrue(step['coverage_manifest_sha256'])
        self.assertTrue((self.root/step['coverage_manifest']).is_file())
        self.assertTrue({'logcat', 'bugreport'} <= {c['source'] for c in step['coverage']})
        self.assertFalse(any(word in {'backup', 'install', 'root', 'grant', 'restore'} for argv in calls for word in argv))
        self.assertTrue(verify(self.root, self.db)['ok'])
        self.assertEqual(self.run_plan(plan), result)

    def test_missing_or_invalid_diagnostics_do_not_claim_complete(self):
        for changes in ({'bad_zip': True}, {'empty_properties': True}):
            with self.subTest(changes=changes):
                plan = self.plan({**self.config(), 'profiles': ['triage']})
                with patch('lawliet_mobile.tools.command', return_value=['synthetic-adb']), \
                     patch('lawliet_mobile.tools.execute', side_effect=self.triage_transport([], **changes)):
                    result = self.run_plan(plan)
                self.assertEqual(result['status'], 'partial')
                self.assertTrue(result['steps'][0]['evidence_id'])
                self.assertTrue(result['steps'][0]['run_id'])
                self.assertTrue(any(c['state'] == 'failed' for c in result['steps'][0]['coverage']))

    def test_missing_triage_coverage_cannot_claim_complete(self):
        plan = self.plan({**self.config(), 'profiles': ['triage']})
        with patch.object(workflow.acquisition, 'collect_android', return_value=dict(status='complete', evidence_id=self.evidence(), errors=[], coverage=[])):
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'failed')

    def test_legacy_backup_is_only_called_when_messages_explicitly_selected(self):
        plan = self.plan({**self.config(), 'profiles': ['messages']})
        calls = []
        transport = self.triage_transport(calls)
        def refuse_backup(argv, output, timeout, **kwargs):
            if 'backup' in argv:
                calls.append(argv); output.write_text('Backup is unsupported on this synthetic device\n')
                return dict(argv=argv, returncode=1, stdout=str(output))
            return transport(argv, output, timeout, **kwargs)
        with patch('lawliet_mobile.tools.command', return_value=['synthetic-adb']), \
             patch('lawliet_mobile.tools.execute', side_effect=refuse_backup):
            result = self.run_plan(plan)
        self.assertEqual(sum('backup' in argv for argv in calls), 1)
        self.assertFalse(any('logcat' in argv or 'bugreport' in argv for argv in calls))
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(any(c['source'] == 'telephony_backup' and c['state'] == 'failed' for c in result['steps'][0]['coverage']))

    def test_file_counts_are_preserved_bytes_not_inventory_records(self):
        plan = self.plan({**self.config(), 'profiles': ['files'], 'pulls': ['/sdcard/Download/fixture.txt']})
        calls = []
        transport = self.triage_transport(calls)
        def file_transport(argv, output, timeout, **kwargs):
            if 'du' in argv:
                output.write_text('4 /sdcard/Download/fixture.txt\n')
                return dict(argv=argv, returncode=0)
            if 'pull' in argv:
                (Path(argv[-1])/'fixture.txt').write_bytes(b'hello')
                output.write_text('copied\n')
                return dict(argv=argv, returncode=0)
            return transport(argv, output, timeout, **kwargs)
        with patch('lawliet_mobile.tools.command', return_value=['synthetic-adb']), \
             patch('lawliet_mobile.tools.execute', side_effect=file_transport):
            result = self.run_plan(plan)
        step = result['steps'][0]
        self.assertEqual(step['collected_files'], 1)
        self.assertEqual(step['collected_bytes'], 5)
        selected = next(c for c in step['coverage'] if c['source'] == '/sdcard/Download/fixture.txt')
        self.assertEqual((selected['files'], selected['bytes']), (1, 5))
        self.assertGreater(step['retained_files'], 1)

    def test_large_coverage_remains_bounded_with_full_manifest_trace(self):
        coverage = [dict(source=f'/sdcard/Android/.Trash/{n}/'+('a'*400), state='collected', detail='d'*400, files=1, bytes=2) for n in range(1000)]
        eid = self.evidence('collection.json', json.dumps({'coverage': coverage}))
        step = dict(profile='trash-photos', evidence_id=eid)
        workflow._retained_summary(self.root, self.db, step)
        self.assertEqual(len(step['coverage']), workflow.MAX_COVERAGE)
        self.assertEqual(step['coverage_total'], 1000)
        self.assertTrue(step['coverage_truncated'])
        self.assertLess(len(json.dumps(step)), 16000)
        self.assertTrue(step['coverage_manifest'])

    def test_six_requested_paths_and_diagnostic_failure_are_visible_before_inventory(self):
        paths = ['/sdcard/'+name for name in ('DCIM', 'Pictures', 'Movies', 'Music', 'Download', 'Documents')]
        coverage = [dict(source=name, state='collected', detail='raw inventory')
                    for name in ('getprop.txt', 'packages.txt', 'device-time.txt', 'adb-version.txt')]
        coverage += [dict(source=name, state='not_attempted') for name in ('whatsapp', 'signal', 'whatsapp_business')]
        coverage += [dict(source=path, state='collected', files=1, bytes=5) for path in paths]
        coverage += [dict(source='bugreport', state='failed', detail='missing returned ZIP')]
        eid = self.evidence('collection.json', json.dumps({'coverage': coverage}))
        step = dict(profile='files', evidence_id=eid)
        workflow._retained_summary(self.root, self.db, step)
        displayed = [row['source'] for row in step['coverage']]
        self.assertEqual(displayed[0], 'bugreport')
        self.assertTrue(set(paths).issubset(displayed))
        self.assertFalse({'whatsapp', 'signal', 'whatsapp_business'} & set(displayed))
        self.assertTrue(step['coverage_truncated'])

    def test_maximum_coverage_state_survives_reload_with_json_escape_characters(self):
        coverage = [dict(source='"\\\x01'*200, state='"\\\x01'*40, detail='"\\\x01'*200,
                         files=1, bytes=2) for _ in range(100)]
        eid = self.evidence('collection.json', json.dumps({'coverage': coverage}))
        plan = self.plan({**self.config(), 'profiles': list(workflow.PROFILES), 'pulls': ['/sdcard/Download']})
        config, state = workflow._load(self.root, self.db, plan['id'])
        for step in state['steps']:
            step['evidence_id'] = eid
            workflow._retained_summary(self.root, self.db, step)
        workflow._save(self.db, plan['id'], state)
        self.assertLess(len(self.db.execute('SELECT state FROM agent_collection_plans WHERE id=?', (plan['id'],)).fetchone()[0]), 65536)
        self.assertEqual(workflow._load(self.root, self.db, plan['id'])[1], state)

    def test_trash_runs_with_lease_and_refuses_symlink_staging(self):
        plan = self.plan({**self.config(), 'profiles': ['trash-photos']})
        def collect(*args, **kwargs):
            from lawliet_mobile.runner_lease import ownership
            self.assertTrue(ownership()['nonce'])
            self.assertEqual(kwargs['profile'], 'trash-photos')
            return dict(status='complete', evidence_id=self.evidence(), coverage=[], errors=[])
        with patch.object(workflow.acquisition, 'collect_android', side_effect=collect):
            self.assertEqual(self.run_plan(plan)['status'], 'complete')
        from lawliet_mobile.trash_collection import collect_trash
        # Test the reused collector independently, without the workflow's scope guard.
        outside = self.base/'outside-trash'; outside.mkdir()
        (self.root/'collections').symlink_to(outside, target_is_directory=True)
        with patch('lawliet_mobile.tools.command', return_value=['synthetic-adb']), \
             patch('lawliet_mobile.tools.execute') as execute, self.assertRaises((OSError, UserError)):
            collect_trash(self.root, self.db, self.workspace, 'SYNTHETIC-1')
        execute.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_failed_requested_pull_cannot_be_reported_complete_even_if_collector_says_complete(self):
        plan = self.plan({**self.config(), 'profiles': ['files'], 'pulls': ['/sdcard/Download/fixture.txt']})
        with patch.object(workflow.acquisition, 'collect_android', return_value=dict(evidence_id=self.evidence(), status='complete', errors=[], coverage=[dict(source='/sdcard/Download/fixture.txt', state='failed')])):
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['steps'][0]['status'], 'failed')
        self.assertTrue(result['steps'][0]['evidence_id'])

    def test_profile_failure_isolated_and_permission_denial_does_not_grant_access(self):
        plan = self.plan({**self.config(), 'profiles': ['sms-provider', 'contacts-provider']})
        with patch.object(workflow.provider_sms, 'collect_sms', side_effect=UserError('Permission denied SECRET')), patch.object(workflow.provider_contacts, 'collect_contacts', return_value=dict(evidence_id=self.evidence(), status='complete', errors=[])) as contacts:
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['steps'][0]['status'], 'failed')
        self.assertEqual(contacts.call_count, 1)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_native_failure_keeps_retained_evidence_and_fails_honestly(self):
        plan = self.plan({**self.config(), 'profiles': ['contacts-provider']})
        with patch.object(workflow.provider_contacts, 'collect_contacts', return_value=dict(evidence_id=self.evidence(), status='complete', errors=[])), patch.object(workflow.parsers, 'native_analyze', side_effect=RuntimeError('SECRET')):
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(result['steps'][0]['evidence_id'])
        self.assertIn('RuntimeError', result['steps'][0]['error'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_zero_records_is_not_evidence_absence(self):
        plan = self.plan()
        with patch.object(workflow.provider_sms, 'collect_sms', side_effect=lambda *a, **k: self.sms_result(records=0)):
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['outcome'], 'no_records')
        self.assertTrue(any('does not establish absence' in text for text in result['limitations']))

    def test_sms_without_index_membership_does_not_claim_processing_completed(self):
        plan = self.plan()
        with patch.object(workflow.provider_sms, 'collect_sms', return_value=dict(evidence_id=self.evidence(), status='complete', errors=[])):
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['steps'][0]['run_id'])

    def test_incomplete_index_uses_existing_parser_source_id(self):
        plan = self.plan()
        with patch.object(workflow.provider_sms, 'collect_sms', side_effect=lambda *a, **k: self.sms_result(status='partial')):
            result = self.run_plan(plan)
        step = result['steps'][0]
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(step['source_id'], step['evidence_id'] + ':adb-sms-provider/1')

    def test_nonblocking_workflow_lock_prevents_reentry_but_status_remains_available(self):
        plan = self.plan()
        def collect(*args, **kwargs):
            self.assertEqual(workflow.get_plan(self.root, self.db, plan['id'])['status'], 'running')
            with self.assertRaisesRegex(UserError, 'owns this case'):
                self.run_plan(plan)
            return self.sms_result()
        with patch.object(workflow.provider_sms, 'collect_sms', side_effect=collect):
            self.assertEqual(self.run_plan(plan)['status'], 'complete')

    def test_abandoned_state_is_interrupted_after_restart_not_reacquired(self):
        plan = self.plan()
        config, state = workflow._load(self.root, self.db, plan['id'])
        state['status'] = 'running'
        state['steps'][0]['status'] = 'running'
        workflow._save(self.db, plan['id'], state)
        with connect(self.workspace, 'A') as (root, db), patch.object(workflow.provider_sms, 'collect_sms') as collect:
            current = workflow.get_plan(root, db, plan['id'])
            self.assertEqual(current['status'], 'interrupted')
            self.assertEqual(workflow.execute_plan(root, db, self.workspace, plan['id'])['status'], 'interrupted')
            collect.assert_not_called()
        self.assertEqual(workflow.list_plans(self.root, self.db)[0]['status'], 'interrupted')

    def test_interrupt_retains_audited_evidence_ids_and_never_reacquires(self):
        plan = self.plan()
        def collect(*args, **kwargs):
            result = self.sms_result()
            audit(self.db, 'collection.started', dict(collection_id=result['collection_id'], serial=plan['serial'], profile='sms-provider'))
            audit(self.db, 'collection.finished', result)
            self.db.commit()
            raise KeyboardInterrupt()
        with patch.object(workflow.provider_sms, 'collect_sms', side_effect=collect) as collect:
            result = self.run_plan(plan)
            self.assertEqual(result['status'], 'interrupted')
            self.assertTrue(result['steps'][0]['evidence_id'])
            self.assertEqual(result['steps'][0]['records'], 1)
            self.run_plan(plan)
            self.assertEqual(collect.call_count, 1)

    def test_restart_reconciles_unique_audited_output_without_recollecting_or_parsing(self):
        plan = self.plan()
        config, state = workflow._load(self.root, self.db, plan['id'])
        state['status'] = 'running'; state['steps'][0]['status'] = 'running'
        state['steps'][0]['audit_after'] = self.db.execute('SELECT MAX(id) FROM audit').fetchone()[0]
        workflow._save(self.db, plan['id'], state)
        result = self.sms_result()
        audit(self.db, 'collection.started', dict(collection_id=result['collection_id'], serial=plan['serial'], profile='sms-provider'))
        audit(self.db, 'collection.finished', result); self.db.commit()
        with patch.object(workflow.provider_sms, 'collect_sms') as collect, patch.object(workflow.parsers, 'native_analyze') as parse:
            resumed = workflow.get_plan(self.root, self.db, plan['id'])
        self.assertEqual(resumed['status'], 'interrupted')
        self.assertEqual(resumed['steps'][0]['evidence_id'], result['evidence_id'])
        self.assertEqual(resumed['steps'][0]['records'], 1)
        collect.assert_not_called(); parse.assert_not_called()

    def test_preexisting_integrity_failure_prevents_device_call(self):
        eid = self.evidence()
        file = self.db.execute('SELECT path FROM files WHERE evidence_id=?', (eid,)).fetchone()[0]
        (self.root / 'evidence' / eid / file).write_text('modified')
        plan = self.plan()
        with patch.object(workflow.provider_sms, 'collect_sms') as collect:
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['integrity']['ok'])
        collect.assert_not_called()

    def test_post_collection_integrity_failure_stops_remaining_profiles(self):
        plan = self.plan({**self.config(), 'profiles': ['sms-provider', 'contacts-provider']})
        def collect(*args, **kwargs):
            result = self.sms_result()
            file = self.db.execute('SELECT path FROM files WHERE evidence_id=?', (result['evidence_id'],)).fetchone()[0]
            (self.root / 'evidence' / result['evidence_id'] / file).write_text('modified')
            return result
        with patch.object(workflow.provider_sms, 'collect_sms', side_effect=collect), patch.object(workflow.provider_contacts, 'collect_contacts') as contacts:
            result = self.run_plan(plan)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['integrity']['ok'])
        contacts.assert_not_called()

    def test_foreign_case_database_workspace_and_plan_are_refused(self):
        plan = self.plan()
        create_case(self.workspace, 'B')
        with connect(self.workspace, 'B') as (root, db):
            with self.assertRaises(UserError):
                workflow.get_plan(root, db, plan['id'])
            with self.assertRaises(UserError):
                workflow.execute_plan(self.root, db, self.workspace, plan['id'])
        with self.assertRaises(UserError):
            workflow.execute_plan(self.root, self.db, self.base, plan['id'])
        for identifier in (True, '../case', 'f'*31):
            with self.assertRaises(UserError):
                workflow.get_plan(self.root, self.db, identifier)

    def test_tampered_scope_and_state_are_not_trusted(self):
        plan = self.plan()
        row = self.db.execute('SELECT config,state FROM agent_collection_plans WHERE id=?', (plan['id'],)).fetchone()
        config = json.loads(row['config']); config['serial'] = 'OTHER'
        self.db.execute('UPDATE agent_collection_plans SET config=? WHERE id=?', (json.dumps(config), plan['id'])); self.db.commit()
        with self.assertRaisesRegex(UserError, 'inconsistent'):
            self.run_plan(plan)
        self.db.execute('UPDATE agent_collection_plans SET config=?,state=? WHERE id=?', (row['config'], json.dumps({**json.loads(row['state']), 'status': 'complete'}), plan['id'])); self.db.commit()
        with self.assertRaisesRegex(UserError, 'inconsistent'):
            workflow.get_plan(self.root, self.db, plan['id'])

    def test_symlink_workflow_lock_refused_before_collection(self):
        plan = self.plan()
        target = self.base / 'target'; target.write_text('untouched')
        (self.root / '.agent-collection.lease').symlink_to(target)
        with self.assertRaises(UserError), patch.object(workflow.provider_sms, 'collect_sms') as collect:
            self.run_plan(plan)
        collect.assert_not_called()
        self.assertEqual(target.read_text(), 'untouched')

    def test_symlinked_collections_refused_before_device_or_outside_write(self):
        plan = self.plan({**self.config(), 'profiles': ['files'], 'pulls': ['/sdcard/Download/fixture.txt']})
        outside = self.base / 'outside'; outside.mkdir()
        (self.root / 'collections').symlink_to(outside, target_is_directory=True)
        with patch.object(workflow.acquisition, 'collect_android') as collect, self.assertRaises(UserError):
            self.run_plan(plan)
        collect.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlinked_evidence_root_refused_before_integrity_reads(self):
        plan = self.plan()
        outside = self.base / 'outside'; outside.mkdir()
        (self.root / 'evidence').symlink_to(outside, target_is_directory=True)
        with patch.object(workflow, 'verify') as integrity, self.assertRaises(UserError):
            self.run_plan(plan)
        integrity.assert_not_called()


if __name__ == '__main__':
    unittest.main()
