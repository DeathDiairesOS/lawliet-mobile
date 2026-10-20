"""Native terminal uniqueness regression; CaseDB/audit real, no daemon calls."""
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from lawliet_mobile import core, native_container as native, parsers
from tests.container_transport_fixtures import move_closed_case


class TerminalUniqueness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve(); self.root = core.create_case(self.workspace, 'case')
        self.db = sqlite3.connect(self.root / 'case.sqlite'); self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.rid = 'a' * 12; self.eid = 'b' * 12
        self.owner = {'protocol': 'ancalor-runner-lease-v1', 'device': 1, 'inode': 2, 'nonce': 'c' * 32}
        self.cfg = {'image': native.IMAGE, 'socket': '/synthetic/socket', 'docker': '/synthetic/docker', 'bootstrap_sha256': core.digest(native.WORKER)}
        self.profile = native.execution_profile()
        self.expected = native.labels(self.root, self.rid, self.owner)
        self.initial = {'runner_ownership': self.owner, 'native_container_config': self.cfg, 'container_execution_profile': self.profile, 'native_container_labels': self.expected}
        self.receipt = {'protocol': native.PROTOCOL, 'container_id': 'd' * 64, 'cfg': self.cfg, 'labels': self.expected, 'state': 'removed_after_verified_stop', 'exit_code': 0, 'OOMKilled': False, 'execution_profile': self.profile}
        self.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)', (self.eid, 'synthetic', 'android', 'fixture', 'now', None, 0))
        self.db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)', (self.rid, self.eid, parsers.VERSION, 'now', 'complete', core.json_text({**self.initial, 'container': self.receipt})))
        core.audit(self.db, 'analysis.started', {'run_id': self.rid, 'evidence_id': self.eid, 'engine': parsers.VERSION, **self.initial})
        core.audit(self.db, 'analysis.finished', {'run_id': self.rid, 'container': self.receipt})
        self.db.commit()

    def no_runtime(self):
        return patch.object(native, 'validate_config', side_effect=AssertionError('Ambiguous or settled history must not probe runtime'))

    def ambiguous(self, *, same=False, action='analysis.finished'):
        receipt = copy.deepcopy(self.receipt)
        if not same: receipt['container_id'] = 'e' * 64
        core.audit(self.db, action, {'run_id': self.rid, 'container': receipt}); self.db.commit()
        self.assertTrue(core.verify(self.root, self.db)['ok'])
        with self.no_runtime(), patch.object(native, 'inventory') as daemon:
            with self.assertRaisesRegex(core.UserError, 'ambiguous'):
                native.recover_before_retry(self.root, self.db)
            daemon.assert_not_called()

    def test_distinct_finished_receipts_refuse_before_runtime(self): self.ambiguous()
    def test_distinct_reconciled_receipts_refuse_before_runtime(self): self.ambiguous(action='analysis.container_reconciled')
    def test_duplicate_identical_finished_receipts_refuse_before_runtime(self): self.ambiguous(same=True)

    def test_unique_full_receipt_preserved_across_status_and_move(self):
        original = self.root; moved = self.workspace / 'moved'
        for status in ('complete', 'partial', 'failed', 'running', 'interrupted'):
            self.db.execute('UPDATE runs SET status=?', (status,)); self.db.commit()
            move_closed_case(self, moved)
            try:
                with self.subTest(status=status), self.no_runtime(): native.recover_before_retry(moved, self.db)
            finally: move_closed_case(self, original)

    def test_nonsettlement_failed_audit_does_not_make_recovery_ambiguous(self):
        core.audit(self.db, 'analysis.finished', {'run_id': self.rid, 'status': 'failed', 'new_records': 0})
        with self.no_runtime(): native.recover_before_retry(self.root, self.db)

    def test_unrelated_other_run_settlement_does_not_create_ambiguity(self):
        core.audit(self.db, 'analysis.finished', {'run_id': 'f' * 12, 'container': self.receipt})
        with self.no_runtime(): native.recover_before_retry(self.root, self.db)

    def test_single_terminal_must_equal_row_for_offline_skip(self):
        value = {**self.initial, 'container': {**self.receipt, 'container_id': 'e' * 64}}
        self.db.execute('UPDATE runs SET detail=?', (core.json_text(value),))
        with patch.object(native, 'validate_config', side_effect=core.UserError('expected unresolved runtime path')) as config:
            with self.assertRaises(core.UserError): native.recover_before_retry(self.root, self.db)
            config.assert_called_once()


if __name__ == '__main__': unittest.main()
