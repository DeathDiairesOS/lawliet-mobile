import bz2
import gzip
import io
import stat
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
