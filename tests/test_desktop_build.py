"""Verify incremental compilation cannot silently reuse a changed executable."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('native_build',Path(__file__).resolve().parents[1]/'desktop/build.py')
build=importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class NativeBuildCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.source=self.root/'app.swift';self.source.write_text('let value = 1\n')
        self.executable=self.root/'app';self.executable.write_bytes(b'compiled-native-fixture')
        self.identity={'compiler':'Swift test compiler','sdk':'test SDK'}
        self.flags=['-swift-version','5']
        self.key=build.native_key([self.source],self.identity,self.flags)
        self.receipt={'schema_version':1,'native_key':self.key,'native_sha256':build.digest(self.executable.read_bytes())}

    def test_unchanged_native_inputs_reuse_verified_binary(self):
        self.assertTrue(build.can_reuse_native(self.receipt,self.key,self.executable))

    def test_changed_source_even_with_same_size_and_mtime_invalidates(self):
        original=self.source.stat();self.source.write_text('let value = 2\n')
        os.utime(self.source,ns=(original.st_atime_ns,original.st_mtime_ns))
        updated=build.native_key([self.source],self.identity,self.flags)
        self.assertFalse(build.can_reuse_native(self.receipt,updated,self.executable))

    def test_compiler_sdk_flags_and_source_set_changes_invalidate(self):
        extra=self.root/'extra.swift';extra.write_text('let extra = 0\n')
        for sources,identity,flags in [([self.source],{'compiler':'updated'},self.flags),
                                      ([self.source],self.identity,['-swift-version','6']),
                                      ([self.source,extra],self.identity,self.flags)]:
            changed=build.native_key(sources,identity,flags)
            self.assertFalse(build.can_reuse_native(self.receipt,changed,self.executable))

    def test_missing_modified_or_unversioned_binary_cannot_be_reused(self):
        self.assertFalse(build.can_reuse_native({},self.key,self.executable))
        self.executable.write_bytes(b'altered-executable')
        self.assertFalse(build.can_reuse_native(self.receipt,self.key,self.executable))
        self.executable.unlink()
        self.assertFalse(build.can_reuse_native(self.receipt,self.key,self.executable))


class BrandingOutputTests(unittest.TestCase):
    def test_old_application_output_redirects_to_lawliet(self):
        self.assertEqual(build.canonical_output(Path("/Applications/Ancalor Mobile.app")), Path("/Applications/LAWLIET.app"))

    def test_custom_and_current_application_outputs_are_preserved(self):
        for path in [Path("/tmp/LAWLIET.app"), Path("/tmp/DeviceBridgeCheck.app")]:
            self.assertEqual(build.canonical_output(path), path)
