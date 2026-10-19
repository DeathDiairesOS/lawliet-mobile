"""Native MVT display: exact upstream attribution, fallback, and explicit bounds."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'Requires native Swift compiler')
class MVTObservationSummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tmp.cleanup)
        cls.binary=Path(cls.tmp.name)/'mvt-summary';root=Path(__file__).resolve().parents[1]
        result=subprocess.run(['swiftc',str(root/'desktop/MVTObservationSummary.swift'),
                               str(root/'tests/MVTObservationSummaryCheck.swift'),'-o',str(cls.binary)],
                              capture_output=True,text=True,timeout=60)
        if result.returncode:raise AssertionError(result.stderr)

    def check(self, mode):
        result=subprocess.run([str(self.binary),mode],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('passed: '+mode,result.stdout)

    def test_original_message_and_upstream_level_attribution(self):self.check('alert')
    def test_missing_or_wrongly_typed_fields_do_not_invent_summary(self):self.check('fallback')
    def test_unicode_bounds_and_truncation_are_visible(self):self.check('bounds')
