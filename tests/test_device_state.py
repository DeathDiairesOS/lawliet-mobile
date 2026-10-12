import json
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path
from lawliet_mobile import device_state
from lawliet_mobile.core import UserError, connect, create_case, verify


class DeviceStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        create_case(self.workspace, 'one')
        create_case(self.workspace, 'two')
        self.value = {'device_reference': 'fictional-phone', 'examiner': 'test operator',
                      'observed_at': '2026-10-11T19:00:00-04:00',
                      'states': {'lock': {'value': 'locked', 'basis': 'observation', 'reference': 'worksheet/photo-1'}}}

    def test_locked_does_not_imply_boot_state_and_reopens_scoped(self):
        with connect(self.workspace, 'one') as (root, db):
            result = device_state.record(db, self.value)
            self.assertEqual(result['states']['boot_state']['value'], 'unknown')
            self.assertTrue(verify(root, db)['ok'])
        with connect(self.workspace, 'one') as (_, db):
            self.assertEqual(device_state.list_records(db)['records'][0]['id'], result['id'])
        with connect(self.workspace, 'two') as (_, db):
            self.assertEqual(device_state.list_records(db)['records'], [])

    def test_afu_retains_inference_and_requires_support(self):
        self.value['states']['boot_state'] = {'value': 'AFU', 'basis': 'inference', 'reference': ''}
        with connect(self.workspace, 'one') as (_, db):
            with self.assertRaises(UserError):
                device_state.record(db, self.value)
            self.assertEqual(device_state.list_records(db)['records'], [])
            self.value['states']['boot_state']['reference'] = 'operator note: earlier unlock observed'
            result = device_state.record(db, self.value)
            self.assertEqual(result['states']['boot_state']['basis'], 'inference')
            self.assertIn('not independently verified', result['verification'])

    def test_invalid_time_state_or_foreign_evidence_rejected(self):
        with connect(self.workspace, 'one') as (_, db):
            for update in [{'observed_at': '2026-10-11T19:00:00'}, {'evidence_id': 'foreign-case'},
                           {'states': {'boot_state': {'value': ['AFU'], 'basis': 'observation', 'reference': 'x'}}}]:
                with self.subTest(update=update), self.assertRaises(UserError):
                    device_state.record(db, {**self.value, **update})
            self.assertEqual(device_state.list_records(db)['records'], [])

    def test_append_only_observations_paginate_and_preserve_conflicts(self):
        with connect(self.workspace, 'one') as (_, db):
            device_state.record(db, self.value)
            other = json.loads(json.dumps(self.value))
            other['states']['lock']['value'] = 'unlocked'
            device_state.record(db, other)
            first = device_state.list_records(db, limit=1)
            second = device_state.list_records(db, after=first['next_cursor'], limit=1)
            self.assertTrue(first['has_more'])
            self.assertEqual(first['records'][0]['states']['lock']['value'], 'locked')
            self.assertEqual(second['records'][0]['states']['lock']['value'], 'unlocked')
            self.assertFalse(second['has_more'])

    def test_stdio_bridge_persists_scoped_worksheet_and_rejects_invalid_input(self):
        def call(action, case='one', **values):
            proc = subprocess.run(
                [sys.executable, '-m', 'lawliet_mobile.app_backend'],
                input=json.dumps({'workspace': str(self.workspace), 'case': case,
                                  'action': action, **values}),
                text=True, capture_output=True, check=False)
            result = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0 if result['ok'] else 1)
            return result

        saved = call('device-state-record', worksheet=self.value)
        self.assertTrue(saved['ok'])
        listed = call('device-state-list', limit=1)['result']
        self.assertEqual(listed['records'][0]['id'], saved['result']['id'])
        self.assertEqual(listed['records'][0]['states']['boot_state']['value'], 'unknown')
        self.assertEqual(call('device-state-list', case='two')['result']['records'], [])
        self.assertFalse(call('device-state-list', after=True)['ok'])
        self.assertFalse(call('device-state-record', worksheet=None)['ok'])
        self.assertEqual(len(call('device-state-list')['result']['records']), 1)
