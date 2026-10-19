"""Pure native briefing generation: no model, tool, filesystem or clipboard side effects."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'Requires native Swift compiler')
class CodexHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'codex-handoff-check'
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(['swiftc', str(root / 'desktop/CodexInvestigationHandoff.swift'),
                                 str(root / 'tests/CodexHandoffCheck.swift'), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stderr)

    def check(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('passed: ' + mode, result.stdout)

    def test_unicode_multiline_exact_values(self): self.check('exact-values')
    def test_scope_identity_and_null_refusals(self): self.check('required-fields')
    def test_utf8_field_limits(self): self.check('utf8-bounds')
    def test_encoded_size_limit_no_truncation(self): self.check('encoded-budget')
    def test_any_binding_or_briefing_change_invalidates_copy(self): self.check('stale-binding')
    def test_no_collection_upload_device_or_release_authority(self): self.check('permissions')
