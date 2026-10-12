"""Compile and exercise actual Foundation search state used by the native app."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'Requires macOS Swift')
class ReviewContextTests(unittest.TestCase):
    def test_search_identity_filters_and_timestamp_precision(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'review-context'
            built = subprocess.run(['swiftc', str(root/'desktop/ReviewContext.swift'),
                str(root/'tests/ReviewContextCheck.swift'), '-o', str(binary)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('timestamp preservation', result.stdout)
