"""Dirfd staging regression review: synthetic files only, no Docker invocation."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from lawliet_mobile import core, native_container as nc, runner_lease


class StagingBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'case'; self.root.mkdir()
        self.eid = 'a' * 12; self.rid = 'b' * 12
        source = self.root / 'evidence' / self.eid; source.mkdir(parents=True)
        (source / 'input.txt').write_bytes(b'selected')
        self.folder = self.root / 'runs' / self.rid; self.folder.mkdir(parents=True)
        self.foreign = self.base / 'foreign'; self.foreign.mkdir()
        self.owner = {'nonce': 'c' * 32}
        self.cfg = {'image': nc.IMAGE, 'bootstrap_sha256': core.digest(nc.WORKER), 'socket': '/synthetic/socket', 'docker': '/synthetic/docker'}
        self.manifest = [{'id': 1, 'path': 'input.txt', 'logical_path': 'input.txt', 'sha256': core.digest(source / 'input.txt'), 'bytes': 8}]
        self.request = {'evidence': {'id': self.eid}, 'package_sha256': nc.package_manifest()}
        self.profile = nc.execution_profile()

    def test_replaced_run_parent_does_not_write_foreign_staging(self):
        self.folder.rename(self.folder.with_name('held'))
        self.folder.symlink_to(self.foreign, target_is_directory=True)
        token = runner_lease.CURRENT.set({'root': str(self.root), 'identity': self.owner})
        try:
            with patch.object(nc, 'validate_config', return_value=self.cfg), patch.object(nc, 'execution_profile', return_value=self.profile), patch.object(nc, 'inventory', return_value=[]), patch.object(nc, 'docker') as daemon:
                with self.assertRaises((OSError, core.UserError)):
                    nc.run(self.root, self.rid, self.owner, self.cfg, self.manifest, self.request, b'{}', self.profile, self.folder)
                daemon.assert_not_called()
            self.assertEqual(list(self.foreign.iterdir()), [], 'staging must not write into a replacement ancestor')
        finally:
            runner_lease.CURRENT.reset(token)

    def test_healthy_staging_reaches_create_with_only_pinned_python(self):
        token = runner_lease.CURRENT.set({'root': str(self.root), 'identity': self.owner})
        try:
            with patch.object(nc, 'validate_config', return_value=self.cfg), patch.object(nc, 'execution_profile', return_value=self.profile), patch.object(nc, 'inventory', return_value=[]), patch.object(nc, 'docker', side_effect=RuntimeError('synthetic create boundary')) as daemon:
                with self.assertRaisesRegex(RuntimeError, 'synthetic create boundary'):
                    nc.run(self.root, self.rid, self.owner, self.cfg, self.manifest, self.request, b'{}', self.profile, self.folder)
                self.assertEqual(daemon.call_args.args[1][0], 'create')
            self.assertEqual((self.folder / 'container-evidence/input.txt').read_bytes(), b'selected')
            package = self.folder / 'container-code/lawliet_mobile'
            self.assertEqual({p.name for p in package.iterdir()}, set(self.request['package_sha256']))
            self.assertEqual((self.folder / 'container-control/request.json').read_bytes(), b'{}')
        finally:
            runner_lease.CURRENT.reset(token)

    def test_write_uses_open_directory_even_if_parent_changes_after_check(self):
        with nc._Staging(self.folder) as staged:
            staged.mkdir('container-evidence')
            actual_check = staged.check
            swapped = False
            def swap_after_check():
                nonlocal swapped
                actual_check()
                if not swapped:
                    self.folder.rename(self.folder.with_name('held'))
                    self.folder.symlink_to(self.foreign, target_is_directory=True)
                    swapped = True
            with patch.object(staged, 'check', side_effect=swap_after_check):
                try:
                    staged.write('container-evidence/input.txt', b'selected')
                except (OSError, core.UserError):
                    pass
            self.assertEqual(list(self.foreign.iterdir()), [])
            with self.assertRaises((OSError, core.UserError)):
                staged.check()

    def test_nested_link_and_existing_leaf_refuse(self):
        with nc._Staging(self.folder) as staged:
            staged.mkdir('container-evidence')
            nested = self.folder / 'container-evidence' / 'nested'
            nested.symlink_to(self.foreign, target_is_directory=True)
            with self.assertRaises((OSError, core.UserError)):
                staged.write('container-evidence/nested/output.txt', b'no')
            self.assertEqual(list(self.foreign.iterdir()), [])
            staged.write('container-evidence/owned', b'first')
            with self.assertRaises((OSError, core.UserError)):
                staged.write('container-evidence/owned', b'replace')
            self.assertEqual((self.folder / 'container-evidence' / 'owned').read_bytes(), b'first')

    def test_staged_reads_refuse_parent_replacement(self):
        with nc._Staging(self.folder) as staged:
            staged.mkdir('container-control')
            staged.write('container-control/request.json', b'{}')
            self.folder.rename(self.folder.with_name('held'))
            self.folder.symlink_to(self.foreign, target_is_directory=True)
            with self.assertRaises((OSError, core.UserError)):
                staged.read('container-control/request.json', 10)


if __name__ == '__main__': unittest.main()


class AuditedRecoveryBoundary(unittest.TestCase):
    """Real audited CaseDB state; daemon responses are explicit synthetic seams."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.root = core.create_case(self.workspace, 'case')
        import sqlite3
        self.db = sqlite3.connect(self.root / 'case.sqlite'); self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.rid = 'd' * 12; self.eid = 'e' * 12
        self.cfg = {'image': nc.IMAGE, 'bootstrap_sha256': 'f' * 64, 'socket': '/synthetic/socket', 'docker': '/synthetic/docker'}
        self.owner = {'protocol': runner_lease.PROTOCOL, 'device': 1, 'inode': 2, 'nonce': 'a' * 32}
        self.profile = {'profile': 'synthetic reviewed binding'}
        self.initial = {'runner_ownership': self.owner, 'native_container_config': self.cfg, 'native_container_labels': nc.labels(self.root, self.rid, self.owner), 'container_execution_profile': self.profile}
        self.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)', (self.eid, 'synthetic', 'android', 'fixture', 'now', None, 0))
        self.db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)', (self.rid, self.eid, 'native/0.1.12', 'now', 'failed', core.json_text(self.initial)))
        self.claim = {'run_id': self.rid, 'evidence_id': self.eid, 'engine': 'native/0.1.12', **self.initial}
        core.audit(self.db, 'analysis.started', self.claim); self.db.commit()
        self.folder = self.root / 'runs' / self.rid; self.folder.mkdir(parents=True)

    def recover(self):
        return nc.recover_before_retry(self.root, self.db)

    def test_missing_detail_binding_refuses_before_daemon(self):
        self.db.execute('UPDATE runs SET detail=?', ('{}',))
        with patch.object(nc, 'inventory') as daemon:
            with self.assertRaisesRegex(core.UserError, 'audited registration'): self.recover()
            daemon.assert_not_called()

    def test_missing_row_refuses_before_daemon(self):
        self.db.execute('DELETE FROM runs')
        with patch.object(nc, 'inventory') as daemon:
            with self.assertRaisesRegex(core.UserError, 'missing'): self.recover()
            daemon.assert_not_called()

    def test_changed_owner_config_profile_or_engine_refuses(self):
        for key in ('runner_ownership', 'native_container_config', 'container_execution_profile', 'native_container_labels'):
            changed = dict(self.initial); changed[key] = {'changed': True}
            self.db.execute('UPDATE runs SET detail=?', (core.json_text(changed),))
            with self.subTest(key=key), patch.object(nc, 'inventory') as daemon:
                with self.assertRaisesRegex(core.UserError, 'audited registration'): self.recover()
                daemon.assert_not_called()
        self.db.execute('UPDATE runs SET detail=?,engine=?', (core.json_text(self.initial), 'foreign/1'))
        with self.assertRaisesRegex(core.UserError, 'audited registration'): self.recover()

    def test_duplicate_start_refuses_even_if_other_claim_mismatches(self):
        core.audit(self.db, 'analysis.started', {**self.claim, 'runner_ownership': {'nonce': 'b' * 32}})
        with patch.object(nc, 'inventory') as daemon:
            with self.assertRaisesRegex(core.UserError, 'unique audited'): self.recover()
            daemon.assert_not_called()

    def test_unaudited_detail_refuses(self):
        self.db.execute("DELETE FROM audit WHERE action='analysis.started'")
        with patch.object(nc, 'inventory') as daemon:
            with self.assertRaisesRegex(core.UserError, 'unique audited'): self.recover()
            daemon.assert_not_called()

    def test_failed_status_live_worker_refuses(self):
        active = {'State': {'Running': True, 'Paused': False, 'Restarting': False, 'Status': 'running'}}
        with patch.object(nc, 'validate_config', return_value=self.cfg), patch.object(nc, 'inventory', return_value=['b' * 64]) as daemon, patch.object(nc, 'owned_state', return_value=active):
            with self.assertRaisesRegex(core.UserError, 'active or uncertain'): self.recover()
            daemon.assert_called_once()

    def test_exact_unique_settlement_skips_fresh_runtime_probes(self):
        receipt = {'protocol': nc.PROTOCOL, 'container_id': 'b' * 64, 'cfg': self.cfg, 'labels': nc.labels(self.root, self.rid, self.owner), 'state': 'removed_after_verified_stop', 'exit_code': 0, 'OOMKilled': False, 'execution_profile': self.profile}
        self.db.execute('UPDATE runs SET detail=?', (core.json_text({**self.initial, 'container': receipt}),))
        core.audit(self.db, 'analysis.finished', {'run_id': self.rid, 'container': receipt})
        with patch.object(nc, 'validate_config') as cfg, patch.object(nc, 'inventory') as daemon:
            self.recover(); cfg.assert_not_called(); daemon.assert_not_called()

    def test_missing_marker_empty_inventory_refuses_even_before_create(self):
        self.assertFalse((self.folder / 'native-container.json').exists())
        with patch.object(nc, 'validate_config', return_value=self.cfg), patch.object(nc, 'inventory', return_value=[]) as daemon:
            with self.assertRaisesRegex(core.UserError, 'outcome uncertain'):
                self.recover()
            daemon.assert_called_once()

    def test_legacy_no_registration_noop(self):
        self.db.execute("DELETE FROM audit WHERE action='analysis.started'")
        self.db.execute('UPDATE runs SET detail=?', ('{}',))
        with patch.object(nc, 'validate_config') as cfg, patch.object(nc, 'inventory') as daemon:
            self.recover(); cfg.assert_not_called(); daemon.assert_not_called()

    def test_moved_root_uses_audited_original_labels_and_refuses_live(self):
        moved = self.workspace / 'moved'
        self.root.rename(moved)
        original_labels = self.initial['native_container_labels']
        self.assertNotEqual(original_labels, nc.labels(moved, self.rid, self.owner))
        active = {'State': {'Running': True, 'Paused': False, 'Restarting': False, 'Status': 'running'}}
        with patch.object(nc, 'validate_config', return_value=self.cfg), patch.object(nc, 'inventory', return_value=['b' * 64]) as daemon, patch.object(nc, 'owned_state', return_value=active):
            with self.assertRaisesRegex(core.UserError, 'active or uncertain'):
                nc.recover_before_retry(moved, self.db)
            daemon.assert_called_once_with(self.cfg, original_labels)

    def test_registered_marker_empty_inventory_and_mismatch_refuse(self):
        marker = {'protocol': nc.PROTOCOL, 'cfg': self.cfg, 'labels': self.initial['native_container_labels'], 'container_id': 'b' * 64, 'state': 'registered_before_start'}
        path = self.folder / 'native-container.json'
        with patch.object(nc, 'validate_config', return_value=self.cfg), patch.object(nc, 'inventory', return_value=[]):
            path.write_text(core.json_text(marker))
            with self.assertRaisesRegex(core.UserError, 'outcome uncertain'): self.recover()
            marker['labels'] = {**marker['labels'], 'lawliet.case': '0' * 64}
            path.write_text(core.json_text(marker))
            with self.assertRaisesRegex(core.UserError, 'differs from audited'): self.recover()

    def test_missing_labels_refuses_and_settled_case_can_move(self):
        changed = dict(self.initial); changed.pop('native_container_labels')
        self.db.execute('UPDATE runs SET detail=?', (core.json_text(changed),))
        with self.assertRaisesRegex(core.UserError, 'audited registration'): self.recover()
        receipt = {'protocol': nc.PROTOCOL, 'container_id': 'b' * 64, 'cfg': self.cfg, 'labels': self.initial['native_container_labels'], 'state': 'removed_after_verified_stop', 'exit_code': 0, 'OOMKilled': False, 'execution_profile': self.profile}
        self.db.execute('UPDATE runs SET detail=?', (core.json_text({**self.initial, 'container': receipt}),))
        core.audit(self.db, 'analysis.finished', {'run_id': self.rid, 'container': receipt})
        moved = self.workspace / 'moved'; self.root.rename(moved)
        with patch.object(nc, 'validate_config') as cfg, patch.object(nc, 'inventory') as daemon:
            nc.recover_before_retry(moved, self.db)
            cfg.assert_not_called(); daemon.assert_not_called()
