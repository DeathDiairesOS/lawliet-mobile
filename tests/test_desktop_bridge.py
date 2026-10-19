"""Portable desktop protocol against real synthetic cases; no GUI dependency."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile.desktop import shell_html, synthetic_fixture
from lawliet_mobile.desktop_bridge import DesktopBridge, MAX_REQUEST


class DesktopBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.workspace = self.base/'cases'; self.workspace.mkdir()
        self.fixture = synthetic_fixture(self.base)
        self.bridge = DesktopBridge(self.workspace, timeout=30)
        self.addCleanup(self.bridge._close)

    def call(self, action, **values):
        response = self.bridge.request({'action': action, **values})
        self.assertTrue(response['ok'], response)
        return response['result']

    def create(self):
        self.call('create', id='A', name='Synthetic desktop case', examiner='Test examiner')

    def import_fixture(self):
        self.create()
        self.bridge._grants.add(self.fixture['path'])
        return self.call('import-evidence', case='A', path=self.fixture['path'], platform='android')

    def test_case_import_paginated_search_finding_and_hashes(self):
        original = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(self.fixture['path']).iterdir()}
        result = self.import_fixture()
        self.assertEqual(result['analysis']['status'], 'complete')
        cases = self.call('catalog')['cases']; self.assertEqual([c['id'] for c in cases], ['A'])
        records = self.call('records', case='A', category='messages')['records']
        self.assertEqual(len(records), 2)
        hostile = self.call('records', case='A', query='onerror')['records']
        self.assertEqual(len(hostile), 1)
        self.assertIn('<img', hostile[0]['body'])
        self.call('finding-add', case='A', artifact_id=records[0]['id'], note='Synthetic examiner observation', examiner='Test examiner')
        self.assertTrue(self.call('findings', case='A'))
        self.assertTrue(self.call('verify', case='A')['ok'])
        self.assertEqual(original, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(self.fixture['path']).iterdir()})

    def test_media_is_verified_data_not_a_file_url(self):
        self.import_fixture()
        rows = self.call('records', case='A', category='media')['records']
        response = self.bridge.media({'case': 'A', 'artifact_id': rows[0]['id']})
        self.assertTrue(response['ok'], response)
        result = response['result']; self.assertTrue(result['data_url'].startswith('data:image/png;base64,'))
        data = base64.b64decode(result['data_url'].split(',', 1)[1])
        self.assertEqual(hashlib.sha256(data).hexdigest(), result['sha256'])

    def test_workspace_override_unselected_paths_and_unknown_commands_refused(self):
        self.create()
        for request in (
            {'action': 'records', 'case': 'A', 'workspace': str(self.base)},
            {'action': 'shell', 'command': 'arbitrary'},
            {'action': 'records', 'case': '../A'},
            {'action': 'import-evidence', 'case': 'A', 'path': self.fixture['path']},
            {'action': 'desktop-smoke-fixture'},
            {'action': 'customer-report-approve', 'case': 'A', 'draft_id': 'unreviewed'},
            {'action': 'collect', 'case': 'A', 'platform': 'android', 'serial': 'SYNTHETIC'},
        ):
            with self.subTest(action=request['action']), patch.object(self.bridge, '_invoke', side_effect=AssertionError('must not execute')):
                self.assertFalse(self.bridge.request(request)['ok'])

    def test_busy_and_oversized_requests_do_not_start_another_worker(self):
        self.create()
        key = (str(self.workspace), 'A'); self.bridge._mutations.add(key)
        with patch.object(self.bridge, '_invoke', side_effect=AssertionError('must not execute')):
            response = self.bridge.request({'action':'analyze','case':'A','evidence':'synthetic'})
            self.assertFalse(response['ok']); self.assertIn('already writing', response['error'])
            self.assertFalse(self.bridge.request({'action':'records','case':'A','query':'x'*MAX_REQUEST})['ok'])
        self.assertIn(key, self.bridge._mutations)

    def test_case_profile_conflict_preserves_current_values(self):
        self.create()
        current = self.call('case-management', case='A')['profile']
        self.call('case-update', case='A', values={'client':'Synthetic client'}, revision=current['revision'])
        response = self.bridge.request({'action':'case-update','case':'A','values':{'client':'Stale edit'},'revision':current['revision']})
        self.assertFalse(response['ok'])
        self.assertEqual(self.call('case-management',case='A')['profile']['client'],'Synthetic client')

    def test_packaged_shell_has_no_external_resources_or_html_data_renderer(self):
        html = shell_html()
        self.assertNotIn('<!-- LAWLIET_', html)
        self.assertIn("default-src 'none'", html)
        self.assertIn("connect-src 'none'", html)
        self.assertNotIn('.innerHTML', html)
        self.assertNotIn('document.write(', html)
        self.assertNotIn('<script src=', html)
        self.assertIn('data:image/png;base64,', html)

    def test_smoke_routes_only_available_in_explicit_test_mode(self):
        received = []
        bridge = DesktopBridge(self.workspace, smoke_fixture=self.fixture, smoke_result=received.append)
        self.addCleanup(bridge._close)
        self.assertTrue(bridge.request({'action':'desktop-smoke-fixture'})['ok'])
        self.assertTrue(bridge.request({'action':'desktop-smoke-result','result':{'ok':True}})['ok'])
        self.assertEqual(received,[{'ok':True}])


if __name__ == '__main__': unittest.main()
