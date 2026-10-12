import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc'),'Requires native Swift compiler')
class DeviceAuditLogTests(unittest.TestCase):
    def test_reader_preserves_logs_and_handles_append_and_tail(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            binary=Path(folder)/'audit-check'
            build=subprocess.run(['swiftc',str(root/'desktop/DeviceAuditLog.swift'),str(root/'tests/DeviceAuditLogCheck.swift'),'-o',str(binary)],capture_output=True,text=True,timeout=60)
            self.assertEqual(build.returncode,0,build.stderr)
            run=subprocess.run([str(binary),folder],capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual(run.stdout.count('passed:'),3,run.stdout)
