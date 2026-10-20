import bz2
import gzip
import io
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.bounded_archives import extract_bounded
from lawliet_mobile.core import UserError


class BoundedArchivesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / 'output'
        self.destination.mkdir()

    def zipped(self, entries):
        source = self.root / 'input.zip'
        with zipfile.ZipFile(source, 'w') as archive:
            for name, body in entries:
                archive.writestr(name, body)
        return source

    def refused(self, source, **kwargs):
        original = source.read_bytes()
        with self.assertRaises((UserError, OSError, zipfile.BadZipFile, tarfile.TarError)):
            extract_bounded(source, self.destination, **kwargs)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertFalse(list(self.root.glob('.lawliet-archive-*')))

    def test_safe_exact_byte_and_member_cap(self):
        source = self.zipped([('nested/a', b'123'), ('b', b'45')])
        self.assertEqual(extract_bounded(source, self.destination, max_output_bytes=5, max_files=2), ['b', 'nested/a'])
        self.assertEqual((self.destination / 'nested/a').read_bytes(), b'123')

    def test_traversal_after_valid_member_is_atomic_refusal(self):
        source = self.zipped([('first', b'ok'), ('../escape', b'no')])
        self.refused(source)
        self.assertFalse((self.root / 'escape').exists())

    def test_normalized_duplicate_is_not_overwritten(self):
        self.refused(self.zipped([('same', b'first'), ('./same', b'second')]))

    def test_zip_symlink_is_refused(self):
        entry = zipfile.ZipInfo('link')
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.refused(self.zipped([('first', b'ok'), (entry, '../outside')]))

    def test_tar_links_and_special_files_are_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                source = self.root / 'input.tar'
                with tarfile.open(source, 'w') as archive:
                    good = tarfile.TarInfo('first'); good.size = 2
                    archive.addfile(good, io.BytesIO(b'ok'))
                    item = tarfile.TarInfo('link'); item.type = kind; item.linkname = '../outside'
                    archive.addfile(item)
                self.refused(source)

    def test_zip_byte_and_member_overruns_are_visible(self):
        source = self.zipped([('first', b'12'), ('second', b'34')])
        self.refused(source, max_output_bytes=3)
        self.refused(source, max_files=1)

    def test_directory_members_count_toward_cap(self):
        self.refused(self.zipped([('a/', b''), ('b/', b'')]), max_files=1)

    def test_single_streams_are_bounded(self):
        for suffix, encode in (('.gz', gzip.compress), ('.bz2', bz2.compress)):
            with self.subTest(suffix=suffix):
                source = self.root / ('input' + suffix); source.write_bytes(encode(b'A' * 100))
                self.refused(source, max_output_bytes=20)

    def test_tar_gzip_is_decoded_as_members(self):
        source = self.root / 'input.gz'
        with tarfile.open(source, 'w:gz') as archive:
            item = tarfile.TarInfo('actual'); item.size = 3
            archive.addfile(item, io.BytesIO(b'yes'))
        self.assertEqual(extract_bounded(source, self.destination, max_output_bytes=3), ['actual'])
        self.assertEqual((self.destination / 'actual').read_bytes(), b'yes')

    def test_zero_filled_compressed_image_is_not_an_empty_tar(self):
        body = b'\x00' * 4096 + b'FICTIONAL-IMAGE'
        source = self.root / 'image.gz'; source.write_bytes(gzip.compress(body))
        self.assertEqual(extract_bounded(source, self.destination, max_output_bytes=len(body)), ['image'])
        self.assertEqual((self.destination / 'image').read_bytes(), body)

    def test_bookkeeping_collision_is_refused(self):
        self.refused(self.zipped([('.mulder-extraction-complete.json', b'fake')]))

    def test_destination_content_is_never_overwritten(self):
        source = self.zipped([('existing', b'new')])
        (self.destination / 'existing').write_bytes(b'old')
        with self.assertRaises(UserError):
            extract_bounded(source, self.destination)
        self.assertEqual((self.destination / 'existing').read_bytes(), b'old')

    def test_destination_content_added_during_decode_is_preserved(self):
        source = self.zipped([('a', b'decoded')])
        original_open = zipfile.ZipFile.open
        def insert(archive, *args, **kwargs):
            (self.destination/'foreign').write_bytes(b'PRESERVE FOREIGN')
            return original_open(archive, *args, **kwargs)
        with patch.object(zipfile.ZipFile, 'open', insert):
            with self.assertRaisesRegex(UserError, 'destination changed'):
                extract_bounded(source, self.destination)
        self.assertEqual((self.destination/'foreign').read_bytes(), b'PRESERVE FOREIGN')
        self.assertFalse((self.destination/'a').exists())
        self.assertFalse(list(self.root.glob('.lawliet-archive-*')))

    @unittest.skipUnless(os.name == 'nt', 'Requires actual Windows DACL inspection')
    def test_windows_stage_is_private_before_decoding_and_acl_refusal_preserves_folders(self):
        from lawliet_mobile.container_staging import directory_acl
        from lawliet_mobile.windows_files import WindowsDirectory
        def acl(path):
            with WindowsDirectory(path) as directory:
                return directory_acl(directory)
        subprocess.run(['icacls', str(self.root), '/grant', '*S-1-1-0:(OI)(CI)(R)'],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        parent_before = acl(self.root)
        self.assertIn(';;;WD)', parent_before)
        source = self.zipped([('a', b'PRIVATE DECODED BYTES')])
        original_open = zipfile.ZipFile.open
        observed = []
        def inspect(archive, *args, **kwargs):
            # The stage has a DELETE handle now; inspect its retained identity
            # through the helper's security check before that handoff instead.
            self.assertEqual(len(observed), 1)
            return original_open(archive, *args, **kwargs)
        from lawliet_mobile.container_staging import private_directory
        def protect(directory):
            value = private_directory(directory)
            observed.append(directory_acl(directory))
            self.assertEqual(list(directory.path.iterdir()), [])
            return value
        with patch('lawliet_mobile.container_staging.private_directory', side_effect=protect), \
                patch.object(zipfile.ZipFile, 'open', inspect):
            self.assertEqual(extract_bounded(source, self.destination), ['a'])
        published = acl(self.destination)
        self.assertTrue(published.startswith('D:P'), published)
        self.assertEqual(len(re.findall(r'\(([^)]+)\)', published)), 2, published)
        self.assertIn('A;OICI;FA;;;SY', published)
        self.assertNotIn(';;;WD)', published)
        self.assertEqual(published, observed[0])
        self.assertEqual(acl(self.root), parent_before)
        (self.destination/'a').unlink()
        private_before = acl(self.destination)
        with patch('lawliet_mobile.container_staging.private_directory',
                   side_effect=UserError('Synthetic DACL refusal')), \
                patch.object(zipfile.ZipFile, 'open') as decode:
            with self.assertRaisesRegex(UserError, 'Synthetic DACL refusal'):
                extract_bounded(source, self.destination)
            decode.assert_not_called()
        self.assertEqual(acl(self.root), parent_before)
        self.assertEqual(acl(self.destination), private_before)
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertFalse(list(self.root.glob('.lawliet-archive-*')))

    @unittest.skipUnless(os.name == 'posix', 'Windows pins the original directory during decoding')
    def test_replaced_empty_destination_is_detected_before_posix_publication(self):
        source = self.zipped([('a', b'decoded')])
        original_open = zipfile.ZipFile.open
        identities = []
        def replace(archive, *args, **kwargs):
            self.destination.rename(self.root/'original')
            self.destination.mkdir()
            identities.append(self.destination.stat().st_ino)
            return original_open(archive, *args, **kwargs)
        with patch.object(zipfile.ZipFile, 'open', replace):
            with self.assertRaisesRegex(UserError, 'destination changed'):
                extract_bounded(source, self.destination)
        self.assertEqual(self.destination.stat().st_ino, identities[0])
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertTrue((self.root/'original').is_dir())

    @unittest.skipUnless(os.name == 'nt', 'Requires real Windows directory sharing and native rename')
    def test_windows_original_directory_is_pinned_during_decoding(self):
        source = self.zipped([('a', b'decoded')])
        original_open = zipfile.ZipFile.open
        def replace(archive, *args, **kwargs):
            with self.assertRaises(OSError):
                self.destination.rename(self.root/'moved')
            return original_open(archive, *args, **kwargs)
        with patch.object(zipfile.ZipFile, 'open', replace):
            self.assertEqual(extract_bounded(source, self.destination), ['a'])
        self.assertEqual((self.destination/'a').read_bytes(), b'decoded')
        self.assertFalse((self.root/'moved').exists())

    @unittest.skipUnless(os.name == 'nt', 'Requires real Windows handle-based restoration')
    def test_windows_failed_publish_restores_same_original_directory(self):
        from lawliet_mobile.windows_files import WindowsDirectory
        source = self.zipped([('a', b'decoded')])
        original_rename = WindowsDirectory.rename
        identity = self.destination.stat().st_ino
        attempted = []
        def refuse(owner, fd, name, *, replace=False):
            if name == self.destination.name and not attempted:
                attempted.append(True)
                raise OSError('Synthetic publication failure')
            return original_rename(owner, fd, name, replace=replace)
        with patch.object(WindowsDirectory, 'rename', refuse):
            with self.assertRaisesRegex(OSError, 'Synthetic publication failure'):
                extract_bounded(source, self.destination)
        self.assertEqual(self.destination.stat().st_ino, identity)
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertFalse(list(self.root.glob('.lawliet-archive-*')))

    @unittest.skipUnless(os.name == 'nt', 'Requires real Windows no-replace directory publication')
    def test_windows_publication_race_preserves_even_empty_competing_destination(self):
        from lawliet_mobile.windows_files import WindowsDirectory
        source = self.zipped([('a', b'decoded')])
        original_rename = WindowsDirectory.rename
        for populated in (False, True):
            with self.subTest(populated=populated):
                identities = []
                def race(owner, fd, name, *, replace=False):
                    result = original_rename(owner, fd, name, replace=replace)
                    if name.startswith('.lawliet-archive-empty-'):
                        self.destination.mkdir()
                        identities.append(self.destination.stat().st_ino)
                        if populated:
                            (self.destination/'foreign').write_bytes(b'PRESERVE FOREIGN')
                    return result
                with patch.object(WindowsDirectory, 'rename', race):
                    with self.assertRaises(FileExistsError):
                        extract_bounded(source, self.destination)
                self.assertEqual(self.destination.stat().st_ino, identities[0])
                self.assertFalse((self.destination/'a').exists())
                if populated:
                    self.assertEqual((self.destination/'foreign').read_bytes(), b'PRESERVE FOREIGN')
                    (self.destination/'foreign').unlink()
                self.assertEqual(list(self.destination.iterdir()), [])
                self.assertFalse(list(self.root.glob('.lawliet-archive-*')))

    def test_invalid_limits_cannot_disable_guard(self):
        source = self.zipped([('a', b'a')])
        for limits in ({'max_output_bytes': True}, {'max_output_bytes': 0},
                       {'max_output_bytes': 20 * 1024**3 + 1}, {'max_files': 0}, {'max_files': True}):
            with self.subTest(limits=limits):
                self.refused(source, **limits)

    def test_disk_reserve_and_deadline_are_visible(self):
        source = self.zipped([('a', b'a')])
        with patch('lawliet_mobile.bounded_archives.shutil.disk_usage', return_value=type('Usage', (), {'free': 100})()):
            self.refused(source)
        with patch('lawliet_mobile.bounded_archives.time.monotonic', side_effect=[0, 601]):
            self.refused(source)

    def test_unqualified_decoder_fallback_is_refused(self):
        source = self.root / 'input.7z'; source.write_bytes(b'fictional unsupported input')
        self.refused(source)


if __name__ == '__main__':
    unittest.main()
