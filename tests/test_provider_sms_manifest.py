"""Generated manifest boundary controls; no phone or original evidence writes."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.core import UserError
from lawliet_mobile.provider_sms import _write_manifest


@unittest.skipUnless(os.name=='posix','POSIX provider metadata writer')
class ManifestBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.stage=self.base/'stage';self.stage.mkdir()
        self.foreign=self.base/'foreign';self.foreign.mkdir()
        self.protected=self.foreign/'protected';self.protected.write_bytes(b'FOREIGN SENTINEL')

    def test_fixed_temp_link_is_never_followed_or_published(self):
        legacy=self.stage/'collection.tmp';legacy.symlink_to(self.protected)
        destination=self.stage/'collection.json';_write_manifest(destination,{'status':'running'})
        self.assertEqual(self.protected.read_bytes(),b'FOREIGN SENTINEL')
        self.assertTrue(legacy.is_symlink());self.assertFalse(destination.is_symlink())
        self.assertEqual(json.loads(destination.read_text()),{'status':'running'})
        self.assertFalse(list(self.stage.glob('.manifest-*')))

    def test_parent_and_destination_links_are_refused_without_foreign_changes(self):
        parent=self.stage/'linked';parent.symlink_to(self.foreign,target_is_directory=True)
        with self.assertRaises(OSError):_write_manifest(parent/'protected',{'bad':'write'})
        destination=self.stage/'collection.json';destination.symlink_to(self.protected)
        with self.assertRaises(UserError):_write_manifest(destination,{'bad':'write'})
        self.assertTrue(destination.is_symlink())
        self.assertEqual(self.protected.read_bytes(),b'FOREIGN SENTINEL')
        self.assertFalse(list(self.stage.glob('.manifest-*')))

    def test_existing_regular_manifest_replaced_without_mutating_old_inode(self):
        destination=self.stage/'collection.json';destination.write_text('{"status":"running"}')
        with destination.open() as old:
            _write_manifest(destination,{'status':'interrupted'})
            self.assertEqual(json.load(old),{'status':'running'})
        self.assertEqual(json.loads(destination.read_text()),{'status':'interrupted'})
