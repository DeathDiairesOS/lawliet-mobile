"""Validate native coverage and date-interpretation models against a saved backend fixture."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'Requires native Swift compiler')
class CoverageReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(__file__).resolve().parents[1]
        cls.fixture = root/'tests/fixtures/coverage-page-v1.json'
        cls.binary = Path(cls.temp.name)/'coverage-review'
        built = subprocess.run(['swiftc', str(root/'desktop/CoverageReview.swift'),
            str(root/'tests/CoverageReviewCheck.swift'), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=60)
        if built.returncode:
            raise AssertionError(built.stderr)

    def check_mode(self, mode):
        result = subprocess.run([str(self.binary), mode, str(self.fixture)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'passed: '+mode)

    def test_counts_keep_collection_parsing_review_verification_independent(self):
        self.check_mode('independent')

    def test_unsupported_inconsistent_or_stale_pages_cannot_be_displayed(self):
        self.check_mode('errors')

    def test_century_is_explicit_optional_and_validated(self):
        self.check_mode('century')
