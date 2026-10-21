"""Desktop collection dispatch uses the device platform and honest stage status."""
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, create_case, import_evidence


class IOSCollectionBridgeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='lawliet-ios-bridge-')
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'QC')
        self.source = self.base / 'acquired'
        self.source.mkdir()
        with closing(sqlite3.connect(self.source / 'sms.db')) as db, db:
            db.executescript("""
                CREATE TABLE handle(id TEXT);
                INSERT INTO handle VALUES ('synthetic-contact');
                CREATE TABLE message(text TEXT, date INTEGER, is_from_me INTEGER,
                    handle_id INTEGER, service TEXT);
                INSERT INTO message VALUES ('Synthetic iPhone message', 813592800,
                    0, 1, 'iMessage');
            """)
        ready = patch('lawliet_mobile.app_backend.preflight', return_value={'ready': True})
        ready.start()
        self.addCleanup(ready.stop)

    def call(self, action='collect', **kwargs):
        return handle(self.workspace, {'action': action, 'case': 'QC', 'platform': 'ios',
            'serial': 'SYNTHETIC', 'max_gib': 1, **kwargs})

    def collected(self, root, db, *_, **kwargs):
        evidence = import_evidence(root, db, self.source, 'ios')[0]
        return {'status': 'complete', 'evidence_id': evidence}

    def test_explicit_iphone_profile_parses_into_gui(self):
        with patch('lawliet_mobile.app_backend.collect', side_effect=self.collected), \
             patch('lawliet_mobile.app_backend.collect_android') as android:
            result = self.call(profile='ios-selected')
        android.assert_not_called()
        self.assertEqual(result['collection_status'], 'complete')
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['analysis']['new_records'], 1)
        records = self.call('records', run=result['analysis']['run_id'])['records']
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['body'], 'Synthetic iPhone message')
        self.assertEqual(records[0]['timestamp'], '2026-10-13T14:00:00.000000Z')
        self.assertTrue(records[0]['source_sha256'])
        self.assertIn('message:rowid=1', records[0]['source_ref'])
        self.assertTrue(self.call('verify')['ok'])

    def test_stale_android_profile_cannot_start_an_iphone_backup(self):
        with patch('lawliet_mobile.app_backend.collect') as collector, \
             patch('lawliet_mobile.app_backend.collect_android') as android:
            with self.assertRaisesRegex(UserError, 'iPhone collection profile'):
                self.call(profile='sms-provider')
        collector.assert_not_called()
        android.assert_not_called()

    def test_corrupt_source_keeps_good_records_and_reports_partial_analysis(self):
        (self.source / 'corrupt.db').write_bytes(b'SQLite format 3\x00' + b'broken' * 24)
        with patch('lawliet_mobile.app_backend.collect', side_effect=self.collected):
            result = self.call(profile='ios-selected')
        self.assertEqual(result['collection_status'], 'complete')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['analysis']['status'], 'partial')
        self.assertEqual(result['analysis']['new_records'], 1)
        self.assertTrue(result['analysis']['errors'])
        self.assertTrue(self.call('verify')['ok'])

    def test_partial_collection_does_not_become_complete_after_parsing(self):
        with patch('lawliet_mobile.app_backend.collect', return_value={'status': 'partial', 'evidence_id': 'fixture'}), \
             patch('lawliet_mobile.app_backend.native_analyze', return_value={'status': 'complete'}):
            result = self.call()
        self.assertEqual(result['collection_status'], 'partial')
        self.assertEqual(result['status'], 'partial')

    def test_failed_collection_without_evidence_is_not_parsed(self):
        with patch('lawliet_mobile.app_backend.collect', return_value={'status': 'failed', 'evidence_id': None}), \
             patch('lawliet_mobile.app_backend.native_analyze') as native:
            result = self.call()
        native.assert_not_called()
        self.assertEqual(result['collection_status'], 'failed')
        self.assertEqual(result['status'], 'failed')

    def test_android_sms_provider_is_not_parsed_twice(self):
        with patch('lawliet_mobile.app_backend.collect_android', return_value={'status': 'complete', 'evidence_id': 'fixture'}), \
             patch('lawliet_mobile.app_backend.native_analyze') as native:
            result = self.call(platform='android', profile='sms-provider')
        native.assert_not_called()
        self.assertEqual(result['collection_status'], 'complete')
        self.assertEqual(result['status'], 'complete')


if __name__ == '__main__':
    unittest.main()
