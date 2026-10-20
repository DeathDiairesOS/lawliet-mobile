"""Audited SQL recovery controls; synthetic CaseDB/daemon seams, no Docker."""
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from lawliet_mobile import core, sqlite_container as sc, sqlite_workspace as sw, runner_lease
from tests.container_transport_fixtures import move_closed_case


class RecoveryBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.root = core.create_case(self.workspace, 'case')
        self.db = sqlite3.connect(self.root / 'case.sqlite'); self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.rid = 'a' * 12; self.eid = 'b' * 12
        self.owner = {'protocol': runner_lease.PROTOCOL, 'device': 1, 'inode': 2, 'nonce': 'c' * 32}
        self.cfg = {'image': sc.IMAGE, 'socket': '/synthetic/socket', 'docker': '/synthetic/docker', 'bootstrap_sha256': core.digest(sc.WORKER)}
        self.profile = sc.execution_profile()
        self.expected = sc.labels(self.root, self.rid, self.owner)
        self.initial = {'runner_ownership': self.owner, 'sqlite_container_config': self.cfg, 'container_execution_profile': self.profile, 'sqlite_container_labels': self.expected}
        self.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)', (self.eid, 'synthetic', 'android', 'fixture', 'now', None, 0))
        self.db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)', (self.rid, self.eid, sw.VERSION, 'now', 'failed', core.json_text(self.initial)))
        self.claim = {'run_id': self.rid, 'evidence_id': self.eid, 'file_id': 1, 'query_sha256': 'd' * 64, **self.initial}
        core.audit(self.db, 'sqlite_query.started', self.claim); self.db.commit()
        self.folder = self.root / 'runs' / self.rid; self.folder.mkdir(parents=True)
        self.live = {'State': {'Running': True, 'Paused': False, 'Restarting': False, 'Status': 'running'}}

    def recover(self): return sc.recover_before_retry(self.root, self.db)

    def test_historical_registration_paths_use_originating_host_syntax(self):
        for socket, docker in (
            ("/synthetic/daemon.sock", "/synthetic/docker"),
            (r"C:\synthetic\daemon.sock", r"C:\synthetic\docker.exe"),
        ):
            cfg = {**self.cfg, "socket": socket, "docker": docker}
            self.assertTrue(sc._registration_shape(cfg, self.profile, self.owner))
        for value in ("relative", "C:relative", r"\\server\share\daemon", "/a/../daemon",
                      r"C:\daemon:stream", "/socket\ninjected", "\x00", None, True):
            with self.subTest(path=value):
                self.assertFalse(sc._registration_shape(
                    {**self.cfg, "socket": value}, self.profile, self.owner))

    def receipt(self):
        return {'protocol': sc.PROTOCOL, 'container_id': 'e' * 64, 'cfg': self.cfg, 'labels': self.expected, 'state': 'removed_after_verified_stop', 'exit_code': 0, 'OOMKilled': False, 'execution_profile': self.profile}

    def settle(self, receipt=None):
        receipt = self.receipt() if receipt is None else receipt
        self.db.execute('UPDATE runs SET detail=?', (core.json_text({**self.initial, 'container': receipt}),))
        core.audit(self.db, 'sqlite_query.finished', {'run_id': self.rid, 'container': receipt})

    def legacy(self):
        self.initial.pop('sqlite_container_labels'); self.claim.pop('sqlite_container_labels')
        # Construct historical test fixture once; never backfill production audits.
        self.db.execute("DELETE FROM audit WHERE action='sqlite_query.started'")
        core.audit(self.db, 'sqlite_query.started', self.claim)
        self.db.execute('UPDATE runs SET detail=?', (core.json_text(self.initial),))

    def test_missing_or_corrupt_detail_refuses_without_daemon(self):
        for detail in ('{}', 'null', 'broken'):
            self.db.execute('UPDATE runs SET detail=?', (detail,))
            with self.subTest(detail=detail), patch.object(sc, 'inventory') as daemon:
                with self.assertRaises(core.UserError): self.recover()
                daemon.assert_not_called()

    def test_missing_run_refuses_without_daemon(self):
        self.db.execute('DELETE FROM runs')
        with patch.object(sc, 'inventory') as daemon:
            with self.assertRaisesRegex(core.UserError, 'missing'): self.recover()
            daemon.assert_not_called()

    def test_owner_config_profile_labels_evidence_engine_mismatch(self):
        for key in self.initial:
            changed = copy.deepcopy(self.initial); changed[key] = {'changed': True}
            self.db.execute('UPDATE runs SET detail=?', (core.json_text(changed),))
            with self.subTest(key=key), patch.object(sc, 'inventory') as daemon:
                with self.assertRaises(core.UserError): self.recover()
                daemon.assert_not_called()
        self.db.execute('UPDATE runs SET detail=?,engine=?', (core.json_text(self.initial), 'foreign/1'))
        with self.assertRaises(core.UserError): self.recover()
        self.db.execute('UPDATE runs SET engine=?,evidence_id=?', (sw.VERSION, None))
        with self.assertRaises(core.UserError): self.recover()

    def test_duplicate_and_unaudited_starts_refuse(self):
        core.audit(self.db, 'sqlite_query.started', {**self.claim, 'runner_ownership': {'nonce': 'f' * 32}})
        with patch.object(sc, 'inventory') as daemon:
            with self.assertRaisesRegex(core.UserError, 'unique audited'): self.recover()
            daemon.assert_not_called()
        self.db.execute("DELETE FROM audit WHERE action='sqlite_query.started'")
        with self.assertRaisesRegex(core.UserError, 'unique audited'): self.recover()

    def test_failed_status_live_worker_and_moved_case_use_audited_labels(self):
        move_closed_case(self, self.workspace / 'moved')
        self.assertNotEqual(sc.labels(self.root, self.rid, self.owner), self.expected)
        with patch.object(sc, 'validate_config', return_value=self.cfg), patch.object(sc, 'inventory', return_value=['e' * 64]) as daemon, patch.object(sc, 'owned_state', return_value=self.live):
            with self.assertRaisesRegex(core.UserError, 'active or uncertain'): self.recover()
            daemon.assert_called_once_with(self.cfg, self.expected)

    def test_empty_inventory_refuses_missing_or_registered_marker(self):
        for marker in (None, {'state': 'registered_before_start', 'container_id': 'e' * 64}, {'state': 'create_requested'}):
            if marker is not None: (self.folder / 'sqlite-container.json').write_text(core.json_text(marker))
            with self.subTest(marker=marker), patch.object(sc, 'validate_config', return_value=self.cfg), patch.object(sc, 'inventory', return_value=[]):
                with self.assertRaisesRegex(core.UserError, 'empty inventory'): self.recover()

    def test_future_exact_settlement_skips_fresh_probes_after_move(self):
        self.settle()
        move_closed_case(self, self.workspace / 'moved')
        with patch.object(sc, 'validate_config') as config, patch.object(sc, 'inventory') as daemon:
            self.recover(); config.assert_not_called(); daemon.assert_not_called()

    def test_legacy_exact_finished_full_receipt_after_move(self):
        self.legacy(); self.settle()
        before = list(self.db.execute('SELECT detail FROM audit ORDER BY id'))
        move_closed_case(self, self.workspace / 'moved')
        with patch.object(sc, 'validate_config') as config, patch.object(sc, 'inventory') as daemon:
            self.recover(); config.assert_not_called(); daemon.assert_not_called()
        self.assertEqual([row[0] for row in before], [row[0] for row in self.db.execute('SELECT detail FROM audit ORDER BY id')])
        self.assertNotIn('sqlite_container_labels', json.loads(self.db.execute('SELECT detail FROM runs').fetchone()[0]))

    def test_unresolved_legacy_never_guesses_current_path(self):
        self.legacy()
        for receipt in (None, self.receipt()):
            value = {**self.initial, **({'container': receipt} if receipt else {})}
            self.db.execute('UPDATE runs SET detail=?', (core.json_text(value),))
            with patch.object(sc, 'validate_config') as config, patch.object(sc, 'inventory') as daemon:
                with self.assertRaisesRegex(core.UserError, 'legacy'): self.recover()
                config.assert_not_called(); daemon.assert_not_called()

    def test_forged_or_duplicate_legacy_settlement_refuses(self):
        self.legacy()
        original = self.receipt()
        mutations = [('protocol', 'foreign'), ('container_id', 'nothex'), ('cfg', {}), ('execution_profile', {}), ('labels', {**self.expected, 'lawliet.owner': 'f' * 32}), ('labels', {**self.expected, 'lawliet.run': 'f' * 12}), ('labels', {**self.expected, 'lawliet.case': 'bad'}), ('exit_code', True), ('OOMKilled', 0)]
        for key, value in mutations:
            self.db.execute("DELETE FROM audit WHERE action='sqlite_query.finished'")
            receipt = {**original, key: value}; self.settle(receipt)
            with self.subTest(key=key), patch.object(sc, 'inventory') as daemon:
                with self.assertRaises(core.UserError): self.recover()
                daemon.assert_not_called()
        self.db.execute("DELETE FROM audit WHERE action='sqlite_query.finished'")
        self.settle(original)
        core.audit(self.db, 'sqlite_query.finished', {'run_id': self.rid, 'container': original})
        with self.assertRaisesRegex(core.UserError, 'ambiguous'): self.recover()

    def test_future_identical_and_distinct_duplicate_terminals_refuse_before_runtime(self):
        for same in (True, False):
            self.db.execute("DELETE FROM audit WHERE action='sqlite_query.finished'")
            self.settle()
            other = self.receipt()
            if not same: other['container_id'] = 'f' * 64
            core.audit(self.db, 'sqlite_query.finished', {'run_id': self.rid, 'container': other})
            self.db.commit()
            self.assertTrue(core.verify(self.root, self.db)['ok'])
            with self.subTest(same=same), patch.object(sc, 'validate_config', return_value=self.cfg) as config, patch.object(sc, 'inventory', return_value=[]) as daemon:
                with self.assertRaisesRegex(core.UserError, 'ambiguous'): self.recover()
                config.assert_not_called(); daemon.assert_not_called()

    def test_malformed_future_settlement_does_not_bypass_live_check(self):
        self.settle({'state': 'removed_after_verified_stop'})
        with patch.object(sc, 'validate_config', return_value=self.cfg), patch.object(sc, 'inventory', return_value=['e' * 64]), patch.object(sc, 'owned_state', return_value=self.live):
            with self.assertRaisesRegex(core.UserError, 'active or uncertain'): self.recover()

    def test_recovered_stopped_worker_gets_durable_full_audited_settlement(self):
        stopped = {'State': {'Running': False, 'Paused': False, 'Restarting': False, 'Status': 'exited', 'ExitCode': 137, 'OOMKilled': False}}
        with patch.object(sc, 'validate_config', return_value=self.cfg), patch.object(sc, 'inventory', return_value=['e' * 64]), patch.object(sc, 'owned_state', return_value=stopped), patch.object(sc, 'remove_stopped') as remove:
            self.recover(); remove.assert_called_once_with(self.cfg, 'e' * 64, self.expected)
        detail = json.loads(self.db.execute('SELECT detail FROM runs').fetchone()[0])
        self.assertTrue(sc.settled_receipt(detail['container'], self.cfg, self.expected, self.profile))
        end = json.loads(self.db.execute("SELECT detail FROM audit WHERE action='sqlite_query.container_reconciled'").fetchone()[0])
        self.assertEqual(end['container'], detail['container'])
        with patch.object(sc, 'validate_config') as config, patch.object(sc, 'inventory') as daemon:
            self.recover(); config.assert_not_called(); daemon.assert_not_called()

    def test_audited_old_bootstrap_recovery_uses_real_config_validation(self):
        from types import SimpleNamespace
        import stat
        self.cfg['bootstrap_sha256'] = '0' * 64
        self.profile['bootstrap_sha256'] = '0' * 64
        self.db.execute("DELETE FROM audit WHERE action='sqlite_query.started'")
        self.db.execute('UPDATE runs SET detail=?', (core.json_text(self.initial),))
        core.audit(self.db, 'sqlite_query.started', self.claim)
        runtime_cfg = {**self.cfg, **{key: str(Path(self.cfg[key]).resolve())
                                    for key in ('socket', 'docker')}}
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK)), patch.object(sc.os, 'access', return_value=True), patch.dict(sc.os.environ, {'LAWLIET_CONTAINER_SOCKET': self.cfg['socket']}), patch.object(sc, 'inventory', return_value=['e' * 64]) as daemon, patch.object(sc, 'owned_state', return_value=self.live):
            with self.assertRaisesRegex(core.UserError, 'active or uncertain'): self.recover()
            daemon.assert_called_once_with(runtime_cfg, self.expected)

    def test_current_configured_rejects_old_bootstrap_before_runtime_probe(self):
        from lawliet_mobile import tools
        cfg = {**self.cfg, 'bootstrap_sha256': '0' * 64}
        with patch.object(tools, 'configuration', return_value={'sqlite_workspace_container': cfg}), patch.object(sc, 'available') as runtime:
            with self.assertRaisesRegex(core.UserError, 'source pin mismatch'):
                sc.configured(self.root)
            runtime.assert_not_called()

    def test_recovery_config_still_rejects_malformed_hash_and_socket_pin(self):
        from types import SimpleNamespace
        import stat
        for value in ('bad', None, True):
            with self.subTest(value=value), self.assertRaisesRegex(core.UserError, 'source pin mismatch'):
                sc.validate_config({**self.cfg, 'bootstrap_sha256': value}, recovery=True)
        cfg = {**self.cfg, 'bootstrap_sha256': '0' * 64}
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK)), patch.object(sc.os, 'access', return_value=True), patch.dict(sc.os.environ, {'LAWLIET_CONTAINER_SOCKET': '/synthetic/wrong-socket'}):
            with self.assertRaisesRegex(core.UserError, 'explicit endpoint'):
                sc.validate_config(cfg, recovery=True)

    def test_legacy_host_only_noop_without_platform_or_daemon_probes(self):
        self.db.execute("DELETE FROM audit WHERE action='sqlite_query.started'")
        self.db.execute('UPDATE runs SET detail=?', ('{}',))
        with patch.object(sc, 'validate_config') as config, patch.object(sc, 'inventory') as daemon:
            self.recover(); config.assert_not_called(); daemon.assert_not_called()


class FutureQueryRegistration(unittest.TestCase):
    def test_real_query_start_and_terminal_retain_same_audited_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve(); workspace = base / 'cases'; core.create_case(workspace, 'case')
            fixture = base / 'fixture.sqlite'; source = sqlite3.connect(fixture); source.execute('CREATE TABLE seed(x)'); source.execute('INSERT INTO seed VALUES(42)'); source.commit(); source.close()
            cfg = {'image': sc.IMAGE, 'socket': '/synthetic/socket', 'docker': '/synthetic/docker', 'bootstrap_sha256': core.digest(sc.WORKER)}
            with core.connect(workspace, 'case') as (root, db):
                core.import_evidence(root, db, fixture, 'android'); fid = db.execute('SELECT id FROM files').fetchone()[0]
                def worker(root, rid, owner, config, selected, request, folder):
                    expected = sc.labels(root, rid, owner)
                    initial = json.loads(db.execute('SELECT detail FROM runs WHERE id=?', (rid,)).fetchone()[0])
                    started = json.loads(db.execute("SELECT detail FROM audit WHERE action='sqlite_query.started'").fetchone()[0])
                    self.assertEqual(initial['sqlite_container_labels'], expected); self.assertEqual(started['sqlite_container_labels'], expected)
                    (folder / 'container.stderr').write_bytes(b'')
                    receipt = {'protocol': sc.PROTOCOL, 'container_id': 'e' * 64, 'cfg': config, 'labels': expected, 'state': 'removed_after_verified_stop', 'exit_code': 0, 'OOMKilled': False, 'execution_profile': request['container_execution_profile']}
                    return {'metadata': {'state': 'parsed', 'rows_returned': 1, 'columns': ['x'], 'truncated': False}, 'result': b'[42]\n'}, receipt
                with patch.object(sc, 'configured', return_value=cfg), patch.object(sc, 'run', side_effect=worker):
                    result = sw.query(root, db, fid, 'SELECT x FROM seed')
                self.assertEqual(result['preview']['rows'], [[42]])
                final = json.loads(db.execute('SELECT detail FROM runs').fetchone()[0])
                terminal = json.loads(db.execute("SELECT detail FROM audit WHERE action='sqlite_query.finished'").fetchone()[0])
                self.assertEqual(final['sqlite_container_labels'], terminal['sqlite_container_labels'])
                self.assertEqual(final['container']['labels'], terminal['sqlite_container_labels'])
                with patch.object(sc, 'validate_config') as config, patch.object(sc, 'inventory') as daemon:
                    sc.recover_before_retry(root, db); config.assert_not_called(); daemon.assert_not_called()


if __name__ == '__main__': unittest.main()
