"""Worker-only controls; no daemon or claim of mount qualification."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile import native_container_worker as worker
from lawliet_mobile import parsers


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.scratch = self.base / 'scratch'
        self.scratch.mkdir()
        self.code = self.base / 'code'
        package = self.code / 'lawliet_mobile'
        package.mkdir(parents=True)
        for source in Path(worker.__file__).parent.glob('*.py'):
            shutil.copyfile(source, package / source.name)
        self.eid = '123456789abc'
        self.source = self.scratch / 'evidence' / self.eid
        self.source.mkdir(parents=True)
        self.request = {
            'protocol': worker.PROTOCOL,
            'bootstrap_sha256': worker.sha(Path(worker.__file__).read_bytes()),
            # Fixture creation is platform-independent. The actual worker
            # validates the package using Linux nofollow reads when executed.
            'package_sha256': {p.name: worker.sha(p.read_bytes()) for p in package.iterdir()},
            'evidence': {'id': self.eid, 'platform': 'android', 'label': 'tiny', 'input_name': 'fixture', 'encrypted': False},
            'inputs': [],
        }
        self.request_path = self.base / 'request.json'
        self.old_tempdir = tempfile.tempdir
        self.old_syspath = list(sys.path)
        self.old_env = {key: os.environ.get(key) for key in ('TMPDIR', 'SQLITE_TMPDIR')}
        self.addCleanup(self.restore)

    def restore(self):
        tempfile.tempdir = self.old_tempdir
        sys.path[:] = self.old_syspath
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def add(self, name, raw, file_id=1, logical=None):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.request['inputs'].append({'id': file_id, 'path': name, 'logical_path': logical or name, 'sha256': worker.sha(raw), 'bytes': len(raw)})

    def execute(self, raw=None):
        if sys.platform != 'linux':
            self.skipTest('Actual private worker syscalls execute on Linux; host codec tests remain platform-independent.')
        self.request_path.write_bytes(worker.canonical(self.request) if raw is None else raw)
        output = io.BytesIO()
        # Host unit fixtures do not pretend to be root-owned Linux RO mounts.
        with patch.object(worker, 'validate_mount'):
            worker.execute(output, request_path=self.request_path, code_root=self.code, scratch=self.scratch)
        return output.getvalue()

    def frames(self, raw):
        return [worker.strict(line) for line in raw.splitlines()]

    def test_healthy_exact_stream_membership_order_hashes_and_detail(self):
        self.add('packages.txt', b'package:/z=z.package\npackage:/a=a.package\n')
        raw = self.execute(); frames = self.frames(raw)
        self.assertEqual([f['kind'] for f in frames], ['header', 'artifact', 'artifact', 'final'])
        header, first, second, final = frames
        self.assertEqual(set(header), {'kind', 'protocol', 'request_sha256', 'source_manifest_sha256', 'evidence_id', 'native_parser_version', 'package_manifest_sha256', 'bootstrap_sha256'})
        self.assertEqual(first['title'], 'z.package'); self.assertEqual(second['title'], 'a.package')
        self.assertEqual([first['seq'], second['seq']], [1, 2])
        self.assertNotIn('id', first); self.assertNotIn('run_id', first)
        lines = raw.splitlines(keepends=True)[1:-1]
        self.assertEqual(final['artifact_count'], 2)
        self.assertEqual(final['artifact_bytes'], sum(map(len, lines)))
        self.assertEqual(final['artifacts_sha256'], worker.sha(b''.join(lines)))
        self.assertEqual(header['source_manifest_sha256'], worker.sha(worker.canonical(self.request['inputs'])))
        self.assertEqual(header['package_manifest_sha256'], worker.sha(worker.canonical(self.request['package_sha256'])))
        self.assertEqual(header['request_sha256'], worker.sha(self.request_path.read_bytes()))
        self.assertEqual(set(final['runtime']), {'python_version', 'sqlite_version'})
        detail = json.loads(final['native_detail_json'])
        self.assertEqual(detail['status'], 'complete'); self.assertEqual(detail['new_records'], 2)
        from lawliet_mobile.core import json_text
        self.assertEqual(final['native_detail_json'], json_text(detail))
        db = sqlite3.connect(self.scratch / 'case.sqlite')
        try:
            stored = db.execute('SELECT data FROM artifacts ORDER BY rowid').fetchall()
        finally:
            db.close()
        self.assertEqual([first['data_json'], second['data_json']], [row[0] for row in stored])

    def test_sqlite_wal_shm_media_unicode_blob_and_inner_infinity(self):
        database = self.base / 'fixture.db'
        db = sqlite3.connect(database)
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE sms(_id INTEGER,body TEXT,address TEXT,date INTEGER,type INTEGER,raw_value REAL,raw_blob BLOB)')
            db.execute('INSERT INTO sms VALUES(1,?,?,?,?,?,?)', ('café 🐈', '+123', 1700000000123, 1, float('inf'), b'\x00\xff'))
            db.commit()
            self.add('db/mmssms.db', database.read_bytes(), logical='data/mmssms.db')
            self.add('db/mmssms.db-wal', Path(str(database) + '-wal').read_bytes(), file_id=2, logical='data/mmssms.db-wal')
            self.add('db/mmssms.db-shm', Path(str(database) + '-shm').read_bytes(), file_id=3, logical='data/mmssms.db-shm')
        finally:
            db.close()
        self.add('images/picture.png', b'\x89PNG\r\n\x1a\n' + b'0' * 32, file_id=4)
        frames = self.frames(self.execute())
        rows = frames[1:-1]
        message = next(row for row in rows if row['category'] == 'messages')
        media = next(row for row in rows if row['category'] == 'media')
        self.assertEqual(message['body'], 'café 🐈')
        self.assertEqual(message['timestamp_raw'], '1700000000123')
        self.assertIn('Infinity', message['data_json'])
        inner = json.loads(message['data_json'])
        self.assertEqual(inner['raw_blob'], {'blob_bytes': 2})
        self.assertIn('source_sidecars', inner)
        self.assertEqual(json.loads(media['data_json'])['media']['file_id'], 4)
        self.assertEqual(frames[-1]['native_status'], 'complete')

    def test_valid_empty_has_full_footer(self):
        raw = self.execute(); frames = self.frames(raw)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[-1]['artifact_count'], 0)
        self.assertEqual(frames[-1]['artifacts_sha256'], hashlib.sha256(b'').hexdigest())

    def test_partial_preserves_source_errors(self):
        self.add('broken.xml', b'<broken>')
        self.add('packages.txt', b'package:good.app\n', file_id=2)
        frames = self.frames(self.execute())
        self.assertEqual(frames[-1]['native_status'], 'partial')
        detail = json.loads(frames[-1]['native_detail_json'])
        self.assertEqual(detail['errors'][0]['source'], 'broken.xml')
        self.assertEqual(frames[-1]['artifact_count'], 1)

    def test_failed_or_interrupted_never_exports_rows(self):
        original = parsers.native_analyze
        self.add('packages.txt', b'package:good.app\n')
        def failed(*args):
            result = original(*args)
            result['status'] = 'failed'
            return result
        with patch.object(parsers, 'native_analyze', failed):
            with self.assertRaisesRegex(ValueError, 'terminal'):
                self.execute()

    def test_caps_reject_not_prefix_export(self):
        self.add('packages.txt', b'package:good.app\n')
        with patch.object(worker, 'MAX_ARTIFACTS', 1):
            with self.assertRaisesRegex(ValueError, 'output bound'):
                self.execute()

    def test_detail_cap(self):
        with patch.object(worker, 'MAX_DETAIL', 1):
            with self.assertRaisesRegex(ValueError, 'detail bound'):
                self.execute()

    def test_manifest_identity_and_path_refusals(self):
        self.add('packages.txt', b'package:good.app\n')
        base = copy.deepcopy(self.request)
        mutations = [
            lambda r: r['inputs'][0].update(id=True),
            lambda r: r['inputs'][0].update(id=2**63),
            lambda r: r['inputs'][0].update(path='../foreign'),
            lambda r: r['inputs'][0].update(path='/absolute'),
            lambda r: r['inputs'][0].update(path='a//b'),
            lambda r: r['inputs'][0].update(path='.'),
            lambda r: r['inputs'].append(dict(r['inputs'][0])),
            lambda r: r['evidence'].update(encrypted=True),
            lambda r: r['evidence'].update(id='../foreign'),
            lambda r: r.update(extra=1),
        ]
        for change in mutations:
            request = copy.deepcopy(base); change(request)
            with self.subTest(change=mutations.index(change)):
                with self.assertRaises(ValueError): worker.validate_request(request)

    def test_file_manifest_and_aggregate_caps(self):
        with patch.object(worker, 'MAX_FILES', 0):
            self.add('a', b'a')
            with self.assertRaises(ValueError): worker.validate_request(self.request)
        with patch.object(worker, 'MAX_INPUT', 0):
            with self.assertRaises(ValueError): worker.validate_request(self.request)

    def test_linux_worker_manifest_read_cap(self):
        with patch.object(worker, 'MAX_MANIFEST', 1):
            with self.assertRaises(ValueError): self.execute()

    def test_hash_and_extra_file_refused(self):
        self.add('a', b'a')
        (self.source / 'a').write_bytes(b'b')
        with self.assertRaisesRegex(ValueError, 'hash'): self.execute()
        (self.source / 'a').write_bytes(b'a')
        (self.source / 'extra').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'inventory'): self.execute()

    @unittest.skipUnless(sys.platform == 'linux', 'Linux worker filesystem checks')
    def test_symlink_hardlink_fifo_refused_without_read(self):
        foreign = self.base / 'foreign'; foreign.write_bytes(b'a')
        target = self.source / 'a'
        for setup in (lambda: target.symlink_to(foreign), lambda: os.link(foreign, target), lambda: os.mkfifo(target)):
            setup()
            with self.assertRaises(ValueError): worker.verify_inputs(self.source, [], set())
            target.unlink()

    def test_package_or_bootstrap_tampering(self):
        self.request['bootstrap_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'bootstrap'): self.execute()
        self.request['bootstrap_sha256'] = worker.sha(Path(worker.__file__).read_bytes())
        (self.code / 'lawliet_mobile' / '__init__.py').write_text('# changed')
        with self.assertRaisesRegex(ValueError, 'package'): self.execute()

    def test_strict_outer_json(self):
        for raw in (b'\xef\xbb\xbf{}', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'\xff', b'[' * 65 + b']' * 65):
            with self.subTest(raw=raw):
                with self.assertRaises((ValueError, UnicodeError)): worker.strict(raw)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux worker nofollow reads')
    def test_read_refuses_oversize_and_links(self):
        path = self.base / 'small'; path.write_bytes(b'12')
        with self.assertRaises(ValueError): worker.read(path, 1)
        link = self.base / 'link'; link.symlink_to(path)
        with self.assertRaises(OSError): worker.read(link, 10)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux worker UID and mount policy')
    def test_static_mount_uid_and_mode_checks_no_mutation(self):
        with patch.object(worker.os, 'getuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'uid'): worker.validate_mount(self.scratch, self.source)
        with patch.object(worker.os, 'getuid', return_value=65534), patch.object(worker.os, 'geteuid', return_value=65534):
            with self.assertRaisesRegex(ValueError, 'ownership'): worker.validate_mount(self.scratch, self.source)

    def test_existing_scratch_database_not_overwritten(self):
        (self.scratch / 'case.sqlite').write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError, 'already exists'): self.execute()
        self.assertEqual((self.scratch / 'case.sqlite').read_bytes(), b'keep')

    def test_global_elapsed_check(self):
        with patch.object(worker, 'MAX_WALL', -1):
            with self.assertRaisesRegex(ValueError, 'elapsed'): self.execute()


if __name__ == '__main__':
    unittest.main()
