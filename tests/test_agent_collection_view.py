"""Native collection response binding checks; never opens a phone or model."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("swiftc"), "Requires native Swift compiler")
class AgentCollectionViewTests(unittest.TestCase):
    def test_bound_plan_status_and_failure_display_model(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "agent-collection-view-check"
            # Bound hosted compiler startup separately from the checked program.
            build = subprocess.run([
                "swiftc", "-swift-version", "5",
                str(root / "desktop/LawlietTheme.swift"),
                str(root / "desktop/AgentCollectionView.swift"),
                str(root / "tests/AgentCollectionViewCheck.swift"), "-o", str(binary),
            ], capture_output=True, text=True, timeout=180)
            self.assertEqual(build.returncode, 0, build.stderr)
            checked = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(checked.stdout.count("passed:"), 7, checked.stdout)
