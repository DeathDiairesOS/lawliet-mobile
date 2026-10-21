"""Known iPhone inventory values survive native indexing and desktop queries."""
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect, create_case, digest, import_evidence, verify
from lawliet_mobile.parsers import native_analyze


class IOSInventoryReviewTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='lawliet-ios-inventory-review-')
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'IOS')
        create_case(self.workspace, 'OTHER')
        self.source = self.base / 'source'
        self.source.mkdir()
        self.apps = [
            {'CFBundleIdentifier': 'org.example.message', 'CFBundleDisplayName': 'Message 雪',
             'CFBundleShortVersionString': '3.2.1', 'CFBundleVersion': '30201', 'ApplicationType': 'User'},
            {'CFBundleIdentifier': 'org.example.system', 'CFBundleName': 'System Fixture',
             'CFBundleVersion': '91', 'ApplicationType': 'System'},
        ]
        self.device = {'DeviceName': 'Synthetic iPhone', 'ProductType': 'iPhone17,2',
                       'ProductVersion': '26.6.1', 'BuildVersion': '24G101',
                       'UniqueDeviceID': '00000000-0000000000000001'}
        self.write('ios-apps.plist', self.apps)
        self.write('ios-device.plist', self.device)

    def write(self, name, values):
        (self.source / name).write_bytes(plistlib.dumps(values, fmt=plistlib.FMT_XML))

    def ingest(self):
        before = {p.name: digest(p) for p in self.source.iterdir()}
        with connect(self.workspace, 'IOS') as (root, db):
            evidence = import_evidence(root, db, self.source, 'ios')[0]
            result = native_analyze(root, db, evidence)
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(before, {p.name: digest(p) for p in self.source.iterdir()})
        return evidence, result, before

    def query(self, **values):
        return handle(self.workspace, {'action': 'records', 'case': 'IOS', **values})['records']

    def test_names_versions_ids_and_original_values_reach_gui(self):
        evidence, run, hashes = self.ingest()
        self.assertEqual(run['status'], 'complete')
        self.assertEqual(run['new_records'], 3)
        apps = self.query(run=run['run_id'], category='apps', presentation='investigator')
        self.assertEqual(len(apps), 2)
        first = next(row for row in apps if row['title'] == 'org.example.message')
        self.assertEqual(first['display_title'], 'Message 雪')
        self.assertEqual({f['name']: f['value'] for f in first['display_fields']}, {
            'Application': 'Message 雪', 'Bundle ID': 'org.example.message',
            'Version': '3.2.1', 'Build version': '30201', 'Application type': 'User'})
        self.assertEqual(first['data']['original'], self.apps[0])
        self.assertEqual(first['source_ref'], 'plist:array[index=0]')
        self.assertEqual(first['source_sha256'], hashes['ios-apps.plist'])
        self.assertEqual(first['logical_path'], 'ios-apps.plist')
        self.assertEqual(first['evidence_id'], evidence)
        self.assertTrue(all(row['timestamp'] is None for row in apps))
        devices = self.query(run=run['run_id'], category='device', presentation='investigator')
        self.assertEqual(len(devices), 1)
        fields = {f['name']: f['value'] for f in devices[0]['display_fields']}
        self.assertEqual(fields['Device name'], 'Synthetic iPhone')
        self.assertEqual(fields['iOS version'], '26.6.1')
        self.assertEqual(fields['Model identifier'], 'iPhone17,2')
        self.assertEqual(fields['Device identifier'], self.device['UniqueDeviceID'])
        self.assertEqual(devices[0]['data']['original'], self.device)
        self.assertEqual(devices[0]['source_ref'], 'plist:dict')
        self.assertEqual(devices[0]['source_sha256'], hashes['ios-device.plist'])

    def test_search_pagination_case_isolation_and_no_invented_dates(self):
        self.write('ios-apps.plist', self.apps + [
            {'CFBundleIdentifier': f'org.example.fixture{i:03d}'} for i in range(103)])
        _, run, _ = self.ingest()
        self.assertEqual(len(self.query(category='apps', query='3.2.1')), 1)
        self.assertEqual(len(self.query(category='apps', query='Message 雪')), 1)
        self.assertEqual(len(self.query(category='apps', query='org.example.system')), 1)
        first = handle(self.workspace, {'action': 'records', 'case': 'IOS', 'category': 'apps', 'offset': 0})
        second = handle(self.workspace, {'action': 'records', 'case': 'IOS', 'category': 'apps', 'offset': 100})
        self.assertEqual(len(first['records']), 100)
        self.assertEqual(len(second['records']), 5)
        self.assertTrue(first['has_more'])
        self.assertFalse(second['has_more'])
        self.assertFalse({r['id'] for r in first['records']} & {r['id'] for r in second['records']})
        self.assertEqual(self.query(run=run['run_id'], since='2026-10-01', until='2026-11-01'), [])
        self.assertEqual(handle(self.workspace, {'action': 'records', 'case': 'OTHER'})['records'], [])

    def test_malformed_later_app_does_not_index_partial_inventory(self):
        self.write('ios-apps.plist', self.apps + [{'CFBundleIdentifier': 5}])
        _, run, _ = self.ingest()
        self.assertEqual(run['status'], 'partial')
        self.assertEqual(self.query(category='apps'), [])
        self.assertEqual(len(self.query(category='device')), 1)
        self.assertTrue(any(error['source'] == 'ios-apps.plist' for error in run['errors']))

    def test_unknown_filename_does_not_become_inventory(self):
        (self.source / 'ios-apps.plist').rename(self.source / 'other.plist')
        _, run, _ = self.ingest()
        self.assertEqual(run['status'], 'complete')
        self.assertEqual(self.query(category='apps'), [])
        self.assertEqual(len(self.query(category='device')), 1)

    def test_inventory_byte_limit_retains_other_readable_sources(self):
        self.write('ios-apps.plist', [{'CFBundleIdentifier': 'org.example.large',
                                     'CFBundleDisplayName': 'X' * 4096}])
        with patch('lawliet_mobile.ios_apps.MAX_BYTES', 2048):
            _, run, _ = self.ingest()
        self.assertEqual(run['status'], 'partial')
        self.assertEqual(self.query(category='apps'), [])
        self.assertEqual(len(self.query(category='device')), 1)
        self.assertTrue(any('byte limit' in error['error'] for error in run['errors']))

    def test_reanalysis_retains_membership_without_duplicate_records(self):
        evidence, first, _ = self.ingest()
        with connect(self.workspace, 'IOS') as (root, db):
            second = native_analyze(root, db, evidence)
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(second['new_records'], 0)
        self.assertEqual(len(self.query()), 3)
        self.assertEqual({r['id'] for r in self.query(run=first['run_id'])},
                         {r['id'] for r in self.query(run=second['run_id'])})


if __name__ == '__main__':
    unittest.main()
