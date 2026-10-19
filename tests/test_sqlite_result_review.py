"""Native result presentation preserves forensic scalar types and page identity."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'Requires native Swift compiler')
class SQLiteResultReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'sqlite-review-check'
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(['swiftc', str(root/'desktop/SQLiteResultReview.swift'),
                                 str(root/'tests/SQLiteResultReviewCheck.swift'), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stderr)

    def check(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('passed: '+mode, result.stdout)

    def test_int64_unicode_duplicate_columns_and_types(self): self.check('typed')
    def test_nonzero_page_ordinal(self): self.check('page')
    def test_empty_result(self): self.check('empty')
    def test_collection_limit_remains_visible(self): self.check('limited')
    def test_empty_blob_distinct_from_null_and_empty_text(self): self.check('blob-empty')
    def test_real_boundaries_and_negative_zero_round_trip(self): self.check('real-boundaries')
    def test_wrong_run_refused(self): self.check('wrong-run')
    def test_wrong_page_refused(self): self.check('wrong-offset')
    def test_malformed_row_width_refused(self): self.check('row-width')
    def test_boolean_cell_is_not_an_integer(self): self.check('boolean-cell')
    def test_boolean_offset_refused(self): self.check('boolean-count')
    def test_numeric_boolean_flag_refused(self): self.check('numeric-flag')
    def test_inconsistent_total_refused(self): self.check('wrong-total')
    def test_invalid_hash_refused(self): self.check('wrong-hash')
    def test_invalid_blob_refused(self): self.check('invalid-blob')
    def test_unsuccessful_state_not_displayed_as_results(self): self.check('wrong-state')
