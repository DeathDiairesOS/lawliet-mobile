"""Independent receipt checks for the native-window qualification controller."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from lawliet_mobile.desktop import (
    _check_export, _check_selected_snapshot, _check_source_inspection,
    _combine_restart, _source_hashes,
)
from lawliet_mobile.core import create_case, connect, import_evidence, select_artifacts
from lawliet_mobile.desktop_smoke import build_fixture
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile import investigation, investigation_report
from lawliet_mobile.package_verification import verify_package


class NativeQualificationReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def exported(self, wrong_record=False):
        fixture = build_fixture(self.root/'inputs')
        workspace = self.root/'cases'
        create_case(workspace, 'SYNTHETIC')
        with connect(workspace, 'SYNTHETIC') as (root, db):
            eid = import_evidence(root, db, fixture['path'], 'android')[0]
            native_analyze(root, db, eid)
            rows = select_artifacts(db, limit=None)
            wanted = next(row for row in rows if row['body'] == '<img src=x onerror="window.evidenceExecuted=true">')
            selected = next(row for row in rows if row['source_ref'] == 'sms:_id=1') if wrong_record else wanted
            self.assertEqual(selected['source_sha256'], wanted['source_sha256'])
            iid = investigation.create(db, 'SYNTHETIC TEST ONLY', [eid])['id']
            investigation.note(db, iid, 'observation', 'Synthetic source citation', [selected['id']])
            draft = investigation_report.build_customer_draft(root, db, iid)
            investigation_report.approve_customer_draft(root, db, draft['draft_id'], 'Synthetic examiner', 'Synthetic only')
            destination = self.root/'synthetic-export'
            release = investigation_report.release_customer_draft(root, db, draft['draft_id'], destination)
        fixture['export_path'] = str(destination)
        outcome = {'selected_finding_snapshot': wanted,
                   'report': {'id': draft['draft_id'], 'manifest_sha256': release['manifest_sha256']}}
        return fixture, outcome

    def test_export_checks_complete_package_exact_bytes_and_review_receipt(self):
        fixture, outcome = self.exported()
        checked = _check_export(fixture, outcome)
        self.assertTrue(checked['ok'])
        self.assertEqual(checked['files_checked'], 7)
        self.assertEqual(checked['selected_source']['source_ref'], 'sms:_id=2')
        (Path(fixture['export_path']) / 'report.txt').write_bytes(b'changed evidence')
        with self.assertRaisesRegex(ValueError, 'size/hash'):
            _check_export(fixture, outcome)

    def test_export_rejects_empty_manifest_with_matching_digest_and_receipt(self):
        destination = self.root/'empty-export'; destination.mkdir()
        manifest = {'format': 'ancalor-customer-bundle-v1', 'review_status': 'draft_unreviewed', 'files': []}
        raw = json.dumps(manifest).encode()
        digest = hashlib.sha256(raw).hexdigest()
        (destination/'manifest.json').write_bytes(raw)
        (destination/'release-receipt.json').write_text(json.dumps({'draft_id': 'synthetic', 'manifest_sha256': digest}))
        with self.assertRaisesRegex(ValueError, 'file count'):
            _check_export({'export_path': str(destination)}, {'report': {'id': 'synthetic', 'manifest_sha256': digest}})

    def test_self_consistent_export_of_wrong_record_in_same_database_rejected(self):
        fixture, outcome = self.exported(wrong_record=True)
        self.assertTrue(verify_package(fixture['export_path'], outcome['report']['manifest_sha256'])['ok'])
        with self.assertRaisesRegex(ValueError, 'citation.*source_ref'):
            _check_export(fixture, outcome)
        wrong = {**outcome['selected_finding_snapshot'], 'source_ref': 'sms:_id=1'}
        with self.assertRaisesRegex(ValueError, 'citation.*source_ref'):
            _check_selected_snapshot(fixture, wrong)

    def test_export_refuses_replaced_manifest_and_wrong_report_receipt(self):
        fixture, outcome = self.exported()
        path = Path(fixture['export_path'])
        (path / 'release-receipt.json').write_text(json.dumps({'draft_id': 'other', 'manifest_sha256': outcome['report']['manifest_sha256']}))
        with self.assertRaisesRegex(ValueError, 'not bound'):
            _check_export(fixture, outcome)
        (path / 'manifest.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'supplied digest'):
            _check_export(fixture, outcome)

    def test_source_view_requires_actual_expected_window_not_only_source_metadata(self):
        fixture = build_fixture(self.root/'inputs')
        record = next(row for row in fixture['oracle']['records'] if row['source_ref'] == 'sms:_id=2')
        raw = (Path(fixture['path'])/record['logical_path']).read_bytes()
        window = raw[:4096]
        result = {'logical_path': record['logical_path'], 'source_sha256': record['source_sha256'],
                  'source_size': len(raw), 'offset': 0, 'end_offset_exclusive': len(window),
                  'bytes_returned': len(window), 'hex': window.hex(),
                  'window_sha256': hashlib.sha256(window).hexdigest()}
        self.assertTrue(_check_source_inspection(fixture, result)['ok'])
        for changed in ({'hex': ''}, {'window_sha256': '0'*64}, {'bytes_returned': 0},
                        {'offset': 4}, {'end_offset_exclusive': 0}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'source bytes'):
                _check_source_inspection(fixture, {**result, **changed})

    def test_source_inventory_is_anchored_to_frozen_manifest(self):
        fixture = build_fixture(self.root/'inputs')
        self.assertEqual(_source_hashes(fixture)['path'], fixture['oracle']['files'])
        source = Path(fixture['path'])
        (source/next(iter(fixture['oracle']['files']))).unlink()
        with self.assertRaisesRegex(ValueError, 'frozen oracle'):
            _source_hashes(fixture)
        with self.assertRaisesRegex(ValueError, 'missing'):
            _source_hashes({'path': str(self.root/'absent')})

    def test_nested_original_hashes_include_wal_and_inventory_changes(self):
        root = self.root / 'evidence' / 'nested'; root.mkdir(parents=True)
        (root / 'messages.db').write_bytes(b'synthetic-main')
        (root / 'messages.db-wal').write_bytes(b'synthetic-wal')
        fixture = {'path': str(root.parent)}
        before = _source_hashes(fixture)
        self.assertEqual(set(before['path']), {'nested/messages.db', 'nested/messages.db-wal'})
        (root / 'messages.db-wal').unlink()
        self.assertNotEqual(_source_hashes(fixture), before)

    def test_restart_requires_new_process_and_identical_persisted_state(self):
        initial = {'ok': True, 'process_id': 100, 'case_id': 'SYNTHETIC',
                   'corpus_sha256': 'corpus', 'field_fingerprint_sha256': 'fields',
                   'report': {'id': 'report', 'manifest_sha256': 'report-bytes'}}
        reopened = {**initial, 'process_id': 101, 'approval_persisted': True,
                    'export_verification': {'ok': True}}
        result = _combine_restart(initial, reopened)
        self.assertTrue(result['new_process'])
        self.assertTrue(result['approval_persisted'])
        for update in ({'process_id': 100}, {'ok': False}, {'case_id': 'different'},
                       {'field_fingerprint_sha256': 'changed'}, {'report': {'id': 'wrong'}}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                _combine_restart(initial, {**reopened, **update})
        self.assertFalse(_combine_restart(initial, {**reopened, 'approval_persisted': False})['approval_persisted'])
