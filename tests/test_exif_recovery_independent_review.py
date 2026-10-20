"""Independent Exif recovery review; synthetic CaseDB, no daemon operations."""
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from tests import test_exif_recovery_registration as fixture
from lawliet_mobile import core, container_runner as cr


class IndependentReview(unittest.TestCase):
    def fixture(self):
        case = fixture.Registration(); case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def ambiguity(self, legacy):
        case = self.fixture(); case.seed(legacy=legacy)
        original = case.settle()
        # Different full terminal claims are ambiguity even if run detail still
        # selects one of them. No audit corruption or daemon call is needed.
        other = {**original, 'container_id': 'e' * 64}
        core.audit(case.db, 'analysis.finished', {'run_id': case.rid, 'container': other})
        case.db.commit()
        self.assertTrue(core.verify(case.root, case.db)['ok'])
        self.assertEqual(case.db.execute("SELECT count(*) FROM audit WHERE action='analysis.finished'").fetchone()[0], 2)
        with patch.object(cr, 'docker', side_effect=AssertionError('Ambiguity must refuse before daemon')):
            with self.assertRaises(core.UserError): case.recover()

    def test_distinct_future_terminal_receipts_refuse(self):
        self.ambiguity(False)

    def test_distinct_legacy_terminal_receipts_refuse(self):
        self.ambiguity(True)

    def test_receipt_hardlink_fifo_oversize_and_wrong_owner_refuse(self):
        case = self.fixture(); marker = case.folder / 'container.json'
        foreign = case.base / 'foreign.json'; foreign.write_text(core.json_text(case.receipt()))
        os.link(foreign, marker)
        with self.assertRaises((core.UserError, OSError)): cr.read_receipt(case.root, case.rid, case.owner, case.cfg)
        marker.unlink()
        if os.name == 'nt': marker.mkdir()  # Actual nonregular Windows object.
        else: os.mkfifo(marker)
        with self.assertRaises((core.UserError, OSError)): cr.read_receipt(case.root, case.rid, case.owner, case.cfg)
        if os.name == 'nt': marker.rmdir()
        else: marker.unlink()
        marker.write_text(core.json_text(case.receipt()) + ' ' * 16384)
        with self.assertRaises(core.UserError): cr.read_receipt(case.root, case.rid, case.owner, case.cfg)
        marker.write_text(core.json_text(case.receipt()))
        with self.assertRaises(core.UserError): cr.read_receipt(case.root, case.rid, {**case.owner, 'nonce': 'f' * 32}, case.cfg)


if __name__ == '__main__': unittest.main()
