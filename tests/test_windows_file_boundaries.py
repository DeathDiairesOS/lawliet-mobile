"""Windows native file-handle boundaries; no phone or third-party dependencies."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from lawliet_mobile.anchored_output import OutputFiles
from lawliet_mobile.child_output import ChildOutputs
from lawliet_mobile.core import UserError
from lawliet_mobile.windows_files import component, local_path


class WindowsPathValidation(unittest.TestCase):
    def test_device_names_streams_aliases_and_traversal_refused(self):
        for name in ('CON', 'nul.txt', 'COM1.log', 'LPT².csv', 'x:stream', 'x.', 'x ',
                     '..', '.', 'a/b', 'a\\b', 'a\x00b', 'CONOUT$'):
            with self.subTest(name=name), self.assertRaises(UserError):
                component(name)
        self.assertEqual(component('café 東京.jsonl'), 'café 東京.jsonl')

    def test_network_device_and_relative_roots_refused(self):
        for path in ('relative', 'C:relative', r'\\server\share\folder',
                     r'\\?\C:\folder', r'\\.\pipe\device', r'C:\safe\..\outside'):
            with self.subTest(path=path), self.assertRaises(UserError):
                local_path(path)
        self.assertEqual(str(local_path(r'C:\Case files\derived')), r'C:\Case files\derived')


@unittest.skipUnless(os.name == 'nt', 'Windows native handle semantics')
class WindowsFileBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_child_reads_are_bounded_and_hardlinks_refused(self):
        folder = self.root / 'worker'; folder.mkdir()
        (folder / 'rows').write_bytes(b'abc')
        foreign = self.root / 'foreign'; foreign.write_bytes(b'canary')
        os.link(foreign, folder / 'linked')
        with ChildOutputs(folder) as files:
            self.assertEqual(files.read('rows', 3), b'abc')
            self.assertEqual(files.read('rows', 2, prefix=True), b'ab')
            for name, size in [('rows', 2), ('linked', 100), ('rows:stream', 100)]:
                with self.subTest(name=name), self.assertRaises((OSError, UserError)):
                    files.read(name, size)
        self.assertEqual(foreign.read_bytes(), b'canary')

    def test_parent_cannot_be_replaced_while_anchored(self):
        folder = self.root / 'worker'; folder.mkdir(); (folder / 'result').write_bytes(b'good')
        with ChildOutputs(folder) as files:
            with self.assertRaises(OSError):
                folder.rename(self.root / 'displaced')
            self.assertEqual(files.read('result', 4), b'good')
        folder.rename(self.root / 'released')

    def test_directory_junction_is_refused_without_reading_target(self):
        target = self.root / 'target'; target.mkdir(); (target / 'rows').write_bytes(b'foreign')
        link = self.root / 'junction'
        result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(target)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            with self.assertRaises((OSError, UserError)):
                with ChildOutputs(link) as files:
                    files.read('rows', 100)
        finally:
            link.rmdir()
        self.assertEqual((target / 'rows').read_bytes(), b'foreign')

    def test_export_publish_hash_and_unicode_exact_bytes(self):
        path = self.root / 'nested' / 'export.jsonl'
        text = 'café 東京\n'
        with OutputFiles([path]) as files:
            with files.open(path) as stream:
                stream.write(text)
            expected = hashlib.sha256(text.encode()).hexdigest()
            self.assertEqual(files.digest(path), expected)
            files.publish()
            self.assertEqual(files.digest(path), expected)
            with self.assertRaises(OSError):
                path.unlink()
            with self.assertRaises(OSError):
                path.write_text('unowned')
        self.assertEqual(path.read_bytes(), text.encode())
        self.assertEqual(list(path.parent.iterdir()), [path])

    def test_collision_cleans_only_owned_partial_publication(self):
        a, b = self.root / 'rows', self.root / 'receipt'
        with self.assertRaises(FileExistsError):
            with OutputFiles([a, b]) as files:
                for path in (a, b):
                    with files.open(path) as stream:
                        stream.write('derived')
                b.write_text('foreign')
                files.publish()
        self.assertFalse(a.exists())
        self.assertEqual(b.read_text(), 'foreign')
        self.assertEqual(list(self.root.iterdir()), [b])

    def test_native_handle_rename_refuses_existing_target(self):
        from lawliet_mobile.windows_files import WindowsDirectory
        with WindowsDirectory(self.root) as folder:
            stage, fd = folder.new_file()
            target = self.root / 'existing'
            target.write_bytes(b'original')
            try:
                os.write(fd, b'derived')
                with self.assertRaises(FileExistsError):
                    folder.rename(fd, target.name)
                self.assertEqual(target.read_bytes(), b'original')
            finally:
                folder.delete(fd)
                os.close(fd)

    def test_failure_after_publication_removes_owned_files_by_handle(self):
        path = self.root / 'rows'
        with self.assertRaisesRegex(RuntimeError, 'audit failed'):
            with OutputFiles([path]) as files:
                with files.open(path) as stream:
                    stream.write('derived')
                files.publish()
                raise RuntimeError('audit failed')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_destination_and_case_alias_are_refused(self):
        path = self.root / 'rows'; path.write_bytes(b'original')
        with self.assertRaises(FileExistsError):
            with OutputFiles([path]):
                pass
        with self.assertRaises(UserError):
            with OutputFiles([self.root / 'Report', self.root / 'REPORT']):
                pass
        self.assertEqual(path.read_bytes(), b'original')

    def test_generated_manifest_replaces_regular_file_and_refuses_hardlink(self):
        import json
        from lawliet_mobile.provider_sms import _write_manifest
        path = self.root / 'state.json'
        _write_manifest(path, {'state': 'pending'})
        _write_manifest(path, {'state': 'complete', 'text': 'café'})
        self.assertEqual(json.loads(path.read_bytes()), {'state': 'complete', 'text': 'café'})
        alias = self.root / 'linked.json'; os.link(path, alias)
        with self.assertRaises((OSError, UserError)):
            _write_manifest(alias, {'state': 'foreign overwrite'})
        self.assertEqual(json.loads(path.read_bytes())['state'], 'complete')
        self.assertEqual({p.name for p in self.root.iterdir()}, {'state.json', 'linked.json'})

    def test_streamed_fingerprint_and_package_read_use_consistent_handle_identity(self):
        from lawliet_mobile.package_verification import _directory, _read, _close_directory
        path = self.root / 'payload'; content = b'synthetic' * 140000; path.write_bytes(content)
        directory = _directory(self.root)
        try:
            data, identity = _read(directory, path.name)
            result, hashed_identity = directory.fingerprint(path.name, maximum=len(content))
            self.assertEqual(data, content)
            self.assertEqual(identity, hashed_identity)
            self.assertEqual(result, {'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
            with self.assertRaises(UserError):
                directory.fingerprint(path.name, maximum=1)
        finally:
            _close_directory(directory)

    def test_archive_intake_rejects_windows_stream_device_and_alias_members(self):
        import zipfile
        from lawliet_mobile.core import extract_archive
        for index, name in enumerate(('nested/record:stream', 'nested/NUL.txt', 'nested/trailing.')):
            archive = self.root / f'bad{index}.zip'
            with zipfile.ZipFile(archive, 'w') as output:
                output.writestr(name, b'not an ordinary file')
            target = self.root / f'decoded{index}'; target.mkdir()
            with self.subTest(name=name), self.assertRaises(UserError):
                extract_archive(archive, target)
            self.assertEqual(list(target.rglob('*')), [])
