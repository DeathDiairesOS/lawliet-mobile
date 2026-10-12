import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile import custody
from lawliet_mobile.core import UserError, connect, create_case, digest, import_evidence, verify


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / 'cases'
        create_case(self.workspace, 'one')
        create_case(self.workspace, 'two')
        self.source = Path(self.temp.name) / 'fixture.txt'
        self.source.write_text('synthetic evidence\n')
        self.original_hash = digest(self.source)
        self.value = dict(kind='receipt', item_reference='synthetic phone export',
                          occurred_at='2026-10-11T19:00:00-04:00', recorded_by='Founder A',
                          from_handler='Customer (claimed)', to_handler='Founder A',
                          authority_reference='synthetic consent 1', scope_reference='synthetic scope 1',
                          seal_reference='none observed', photo_reference='photo reference not authenticated')

    def receipt(self, root, db):
        eid, _, _ = import_evidence(root, db, self.source)
        return custody.record(root, db, {**self.value, 'evidence_id': eid})

    def later(self, first, kind='transfer', **values):
        value = {k: v for k, v in self.value.items() if k not in {'item_reference'}}
        value.update(kind=kind, item_id=first['item_id'], from_handler='Founder A', to_handler='Founder B',
                     occurred_at='2026-10-11T20:00:00-04:00')
        value.update(values)
        return value

    def test_receipt_transfer_return_reopen_and_manifest(self):
        with connect(self.workspace, 'one') as (root, db):
            first = self.receipt(root, db)
            transfer = custody.record(root, db, self.later(first))
            returned = custody.record(root, db, self.later(first, 'return', from_handler='Founder B',
                                      to_handler='Customer (claimed)', occurred_at='2026-10-11T21:00:00-04:00'))
            self.assertEqual(transfer['previous_event_id'], first['id'])
            self.assertEqual(returned['previous_event_id'], transfer['id'])
            self.assertEqual(first['manifest']['status'], 'matched')
            self.assertEqual(first['manifest']['files'][0]['observed_sha256'], self.original_hash)
            self.assertIn('Pre-receipt custody is unknown.', returned['warnings'])
            self.assertTrue(verify(root, db)['ok'])
        with connect(self.workspace, 'one') as (_, db):
            first_page = custody.list_records(db, limit=1)
            rest = custody.list_records(db, after=first_page['next_cursor'])
            self.assertTrue(first_page['has_more'])
            self.assertEqual([r['kind'] for r in rest['records']], ['transfer', 'return'])
            self.assertEqual(rest['records'][-1]['manifest']['status'], 'matched')
        self.assertEqual(digest(self.source), self.original_hash)

    def test_changed_copy_and_missing_copy_retained_as_limited_receipts(self):
        with connect(self.workspace, 'one') as (root, db):
            first = self.receipt(root, db)
            path = root / 'evidence' / first['evidence_id'] / first['manifest']['files'][0]['path']
            path.chmod(0o600)
            path.write_text('changed working intake')
            changed = custody.record(root, db, self.later(first))
            self.assertEqual(changed['manifest']['status'], 'limited')
            self.assertEqual(changed['manifest']['files'][0]['status'], 'changed')
            path.unlink()
            missing = custody.record(root, db, self.later(first, 'return'))
            self.assertEqual(missing['manifest']['files'][0]['status'], 'unavailable')
            self.assertEqual(custody.list_records(db)['records'][0]['manifest']['status'], 'matched')
        self.assertEqual(digest(self.source), self.original_hash)

    def test_historical_gap_and_conflicting_transfer_are_explicit(self):
        with connect(self.workspace, 'one') as (root, db):
            first = custody.record(root, db, self.value)
            gap = custody.record(root, db, self.later(first, 'historical-gap', gap_reason='No record of overnight handler',
                                 from_handler='', to_handler='', occurred_at='2026-10-10T08:00:00Z'))
            transfer = custody.record(root, db, self.later(first, from_handler='Unknown claimed intermediary'))
            self.assertEqual(gap['gap_reason'], 'No record of overnight handler')
            self.assertTrue(any('precedes' in w for w in gap['warnings']))
            self.assertTrue(any('continuity' in w for w in transfer['warnings']))
            self.assertEqual(first['manifest']['status'], 'not-checked')

    def test_validation_atomic_and_cross_case_isolation(self):
        with connect(self.workspace, 'one') as (root, db):
            first = self.receipt(root, db)
            for patch in ({'occurred_at': '2026-10-11T01:00:00'}, {'evidence_id': 'foreign'},
                          {'kind': []}, {'from_handler': ''}, {'authority_reference': ''},
                          {'prior_custody': 'documented-reference'}, {'unknown': True}):
                with self.subTest(patch=patch), self.assertRaises(UserError):
                    custody.record(root, db, {**self.value, **patch})
            with self.assertRaises(UserError):
                custody.record(root, db, self.later(first, 'historical-gap'))
            self.assertEqual(len(custody.list_records(db)['records']), 1)
        with connect(self.workspace, 'two') as (root, db):
            self.assertEqual(custody.list_records(db)['records'], [])
            with self.assertRaises(UserError):
                custody.record(root, db, self.later(first))
            with self.assertRaises(UserError):
                custody.record(root, db, {**self.value, 'evidence_id': first['evidence_id']})

    def test_tamper_detected_and_item_filter_pagination(self):
        with connect(self.workspace, 'one') as (root, db):
            first = custody.record(root, db, self.value)
            custody.record(root, db, self.value)
            custody.record(root, db, self.later(first))
            page = custody.list_records(db, limit=1, item_id=first['item_id'])
            rest = custody.list_records(db, after=page['next_cursor'], limit=1, item_id=first['item_id'])
            self.assertEqual(rest['records'][0]['kind'], 'transfer')
            self.assertFalse(rest['has_more'])
            db.execute("UPDATE audit SET detail='{}' WHERE action=? AND id=?", (custody.ACTION, page['records'][0]['audit_id']))
            self.assertFalse(verify(root, db)['ok'])
            with self.assertRaisesRegex(UserError, 'audit chain'):
                custody.list_records(db)
            with self.assertRaisesRegex(UserError, 'audit chain'):
                custody.record(root, db, self.value)

    def test_symlink_not_followed_and_item_cannot_be_relinked(self):
        with connect(self.workspace, 'one') as (root, db):
            first = self.receipt(root, db)
            path = root / 'evidence' / first['evidence_id'] / first['manifest']['files'][0]['path']
            path.unlink()
            path.symlink_to(self.source)
            value = self.later(first)
            result = custody.record(root, db, value)
            self.assertIsNone(result['manifest']['files'][0]['observed_sha256'])
            with self.assertRaises(UserError):
                custody.record(root, db, {**value, 'evidence_id': first['evidence_id']})

    def test_evidence_container_symlink_is_not_followed(self):
        with connect(self.workspace, 'one') as (root, db):
            first = self.receipt(root, db)
            evidence = root / 'evidence'
            moved = root / 'relocated-evidence'
            evidence.rename(moved)
            evidence.symlink_to(moved, target_is_directory=True)
            result = custody.record(root, db, self.later(first))
            self.assertEqual(result['manifest']['status'], 'limited')
            self.assertEqual(result['manifest']['files'][0]['status'], 'unavailable')

    def test_stdio_bridge_is_scoped_and_rejects_tampering(self):
        def call(action, case='one', **values):
            proc = subprocess.run([sys.executable, '-m', 'lawliet_mobile.app_backend'],
                input=json.dumps({'workspace': str(self.workspace), 'case': case, 'action': action, **values}),
                text=True, capture_output=True, check=False)
            result = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0 if result['ok'] else 1)
            return result
        saved = call('custody-record', event=self.value)
        self.assertTrue(saved['ok'], saved)
        listed = call('custody-list')['result']
        self.assertEqual(listed['records'][0]['id'], saved['result']['id'])
        self.assertEqual(call('custody-list', case='two')['result']['records'], [])
        self.assertFalse(call('custody-record', event=None)['ok'])
        with connect(self.workspace, 'one') as (_, db):
            db.execute("UPDATE audit SET detail='{}' WHERE action=?", (custody.ACTION,))
        self.assertFalse(call('custody-list')['ok'])
        self.assertFalse(call('custody-record', event=self.value)['ok'])
