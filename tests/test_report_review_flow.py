"""Native report actions stay bound to reviewed bytes and explicit case approval."""
import json
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, connect, digest
from lawliet_mobile import investigation_report as reports
from tests import test_customer_report as fixtures
from tests import test_case_catalog as catalog_fixture


class ReportReviewFlowTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.CustomerReportTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        self.fixture = fixture; self.ws = fixture.ws
        with connect(self.ws, 'A') as (root, db):
            self.draft = reports.build_customer_draft(root, db, fixture.iid)
        self.sha = digest(Path(self.draft['path']) / 'manifest.json')

    def call(self, action, **values):
        return handle(self.ws, {'case':'A', 'action':action, **values})

    def test_readonly_status_requires_exact_manifest_and_case(self):
        path = self.ws / 'A/case.sqlite'; before = path.read_bytes()
        result = self.call('customer-report-review', bundle_id=self.draft['draft_id'], kind='original', expected_manifest_sha256=self.sha)
        self.assertIsNone(result['approval']); self.assertTrue(result['source_integrity_checked'])
        self.assertEqual(path.read_bytes(), before)
        for bad in ('', None, '0'*64):
            with self.assertRaises(UserError):
                self.call('customer-report-review', bundle_id=self.draft['draft_id'], kind='original', expected_manifest_sha256=bad)
        with self.assertRaises(UserError):
            self.call('customer-report-review', case='B', bundle_id=self.draft['draft_id'], kind='original', expected_manifest_sha256=self.sha)

    def test_viewed_byte_mismatch_cannot_approve_or_export(self):
        before = (self.ws/'A/case.sqlite').read_bytes()
        with self.assertRaisesRegex(UserError, 'reviewed bytes'):
            self.call('customer-report-approve', draft_id=self.draft['draft_id'], expected_manifest_sha256='0'*64,
                      reviewer='Synthetic examiner', declaration='Test declaration')
        self.assertEqual((self.ws/'A/case.sqlite').read_bytes(), before)
        target = self.fixture.base/'blocked'
        with self.assertRaises(UserError):
            self.call('customer-report-release', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha, path=str(target))
        self.assertFalse(target.exists())

    def test_approval_status_survives_reopen_and_export_rechecks(self):
        self.call('customer-report-approve', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha,
                  reviewer='Synthetic examiner', declaration='Fixture only: exact unredacted bytes reviewed.')
        result = self.call('customer-report-review', bundle_id=self.draft['draft_id'], kind='original', expected_manifest_sha256=self.sha)
        self.assertEqual(result['approval']['reviewer'], 'Synthetic examiner')
        target = self.fixture.base/'released'
        result = self.call('customer-report-release', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha, path=str(target))
        self.assertEqual(result['manifest_sha256'], self.sha)
        with self.assertRaises(FileExistsError):
            self.call('customer-report-release', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha, path=str(target))

    def test_redacted_derivative_has_separate_approval_and_history(self):
        self.call('customer-report-approve', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha,
                  reviewer='Synthetic examiner', declaration='Original fixture only')
        derivative = self.call('customer-report-redacted-draft', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha, literals=['selected body'])
        common = {'derivative_id':derivative['derivative_id'], 'expected_manifest_sha256':derivative['manifest_sha256']}
        state = self.call('customer-report-review', bundle_id=derivative['derivative_id'], kind='redacted', expected_manifest_sha256=derivative['manifest_sha256'])
        self.assertIsNone(state['approval'])
        target = (self.fixture.base/'redacted-release').resolve()
        with self.assertRaises(UserError): self.call('customer-report-redacted-release', **common, path=str(target))
        self.call('customer-report-redacted-approve', **common, reviewer='Synthetic examiner', declaration='Derivative fixture independently reviewed')
        self.call('customer-report-redacted-release', **common, path=str(target))
        self.assertEqual({p.name for p in target.iterdir()}, {'report.txt','technical-annex.json','investigation.json','exhibits.jsonl','manifest.json'})
        self.assertEqual(digest(Path(self.draft['path'])/'manifest.json'), self.sha)
        history = catalog_fixture.catalog.history(str(self.ws/'A'))
        self.assertEqual({row['kind'] for row in history['items']}, {'original','redacted'})
        self.assertEqual(history['total'], 2)

    def test_changed_sources_invalidate_review_and_recorded_approval(self):
        self.call('customer-report-approve', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha,
                  reviewer='Synthetic examiner', declaration='Fixture declaration')
        with connect(self.ws, 'A') as (root, db):
            row = db.execute('SELECT f.* FROM files f JOIN artifacts a ON a.file_id=f.id WHERE a.id=?', (self.fixture.aid,)).fetchone()
            (root/'evidence'/row['evidence_id']/row['path']).write_text('changed')
        with self.assertRaisesRegex(UserError, 'source integrity'):
            self.call('customer-report-review', bundle_id=self.draft['draft_id'], kind='original', expected_manifest_sha256=self.sha)
        with self.assertRaisesRegex(UserError, 'source integrity'):
            self.call('customer-report-release', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha, path=str(self.fixture.base/'no-copy'))

    def test_source_drift_during_copy_blocks_release_and_cleans_only_new_copy(self):
        self.call('customer-report-approve', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha,
                  reviewer='Synthetic examiner', declaration='Fixture declaration')
        target = self.fixture.base/'source-drift-release'
        neighbor = self.fixture.base/'keep.txt'; neighbor.write_text('KEEP')
        folder = Path(self.draft['path']); before = {p.name:digest(p) for p in folder.iterdir()}
        with connect(self.ws, 'A') as (root, db):
            row = db.execute('SELECT f.* FROM files f JOIN artifacts a ON a.file_id=f.id WHERE a.id=?', (self.fixture.aid,)).fetchone()
            source = root/'evidence'/row['evidence_id']/row['path']
            original = shutil.copyfile; changed = []
            def copy_then_change(src, dst):
                result = original(src, dst)
                if not changed:
                    source.write_text('SYNTHETIC SOURCE DRIFT DURING COPY'); changed.append(True)
                return result
            with patch('shutil.copyfile', side_effect=copy_then_change), self.assertRaisesRegex(UserError, 'source integrity'):
                reports.release_customer_draft(root, db, self.draft['draft_id'], target)
            self.assertTrue(changed)
            self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='customer_report.released'").fetchone()[0], 0)
            self.assertEqual(source.read_text(), 'SYNTHETIC SOURCE DRIFT DURING COPY')
        self.assertFalse(target.exists()); self.assertEqual(neighbor.read_text(), 'KEEP')
        self.assertEqual({p.name:digest(p) for p in folder.iterdir()}, before)

    def test_investigation_drift_during_copy_blocks_release(self):
        from lawliet_mobile import investigation
        self.call('customer-report-approve', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha,
                  reviewer='Synthetic examiner', declaration='Fixture declaration')
        target = self.fixture.base/'investigation-drift-release'
        with connect(self.ws, 'A') as (root, db):
            original = shutil.copyfile; changed = []
            def copy_then_change(src, dst):
                result = original(src, dst)
                if not changed:
                    investigation.note(db, self.fixture.iid, 'question', 'Synthetic new question during export')
                    changed.append(True)
                return result
            with patch('shutil.copyfile', side_effect=copy_then_change), self.assertRaisesRegex(UserError, 'Investigation changed'):
                reports.release_customer_draft(root, db, self.draft['draft_id'], target)
            self.assertTrue(changed)
            self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='customer_report.released'").fetchone()[0], 0)
        self.assertFalse(target.exists())

    def test_new_audited_manifest_during_copy_cannot_reuse_original_approval(self):
        from lawliet_mobile.core import audit
        self.call('customer-report-approve', draft_id=self.draft['draft_id'], expected_manifest_sha256=self.sha,
                  reviewer='Synthetic examiner', declaration='Fixture declaration')
        target = self.fixture.base/'manifest-drift-release'
        manifest = Path(self.draft['path'])/'manifest.json'
        file_count = len(list(manifest.parent.iterdir()))
        with connect(self.ws, 'A') as (root, db):
            original = shutil.copyfile; copied = []
            def copy_then_change(src, dst):
                result = original(src, dst); copied.append(src)
                if len(copied) == file_count:
                    # Change only after every old byte has been copied, and give
                    # the new manifest a valid audit receipt to exercise the
                    # final exact-hash comparison independently of receipt checks.
                    manifest.write_text(manifest.read_text()+'\n')
                    audit(db, 'customer_report.draft_created', {'draft_id':self.draft['draft_id'],
                          'investigation_id':self.fixture.iid, 'manifest_sha256':digest(manifest)})
                return result
            with patch('shutil.copyfile', side_effect=copy_then_change), self.assertRaisesRegex(UserError, 'Draft changed during release copy'):
                reports.release_customer_draft(root, db, self.draft['draft_id'], target)
            self.assertEqual(len(copied), file_count)
            self.assertNotEqual(digest(manifest), self.sha)
            self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='customer_report.released'").fetchone()[0], 0)
        self.assertFalse(target.exists())
