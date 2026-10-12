"""Device-panel async state checks with a fake client; never contacts a phone."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'Requires native Swift compiler')
class DeviceInteractionModelTests(unittest.TestCase):
    def test_polling_actions_errors_disconnection_and_close(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'device-model-check'
            compiled=subprocess.run(['swiftc','-swift-version','5',
                str(root/'desktop/LawlietTheme.swift'),str(root/'desktop/DeviceAuditLog.swift'),str(root/'desktop/DeviceAuditLogView.swift'),str(root/'desktop/DeviceInteractionView.swift'),str(root/'desktop/IPhoneInteractionView.swift'),
                str(root/'tests/DeviceInteractionModelCheck.swift'),'-o',str(binary)],
                capture_output=True,text=True,timeout=60)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual(run.stdout.count('passed:'),7,run.stdout)
