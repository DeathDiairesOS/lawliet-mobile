"""Exercise the actual native process transport, including pipe backpressure."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc'),'Native transport checks require macOS and swiftc')
class DesktopProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'process-check'
        root=Path(__file__).resolve().parents[1]
        subprocess.run(['swiftc','-swift-version','5',str(root/'desktop/BackendProcess.swift'),str(root/'tests/BackendProcessCheck.swift'),'-o',str(cls.binary)],check=True,capture_output=True,text=True,timeout=60)

    def check_mode(self,mode):
        result=subprocess.run([str(self.binary),mode,sys.executable],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'passed: '+mode)

    def test_simultaneous_large_input_output_and_stderr_are_drained(self):self.check_mode('flood')
    def test_non_json_crash_retains_bounded_diagnostics(self):self.check_mode('crash')
    def test_verbose_crash_is_drained_and_error_is_bounded(self):self.check_mode('flood_crash')
    def test_nonzero_exit_cannot_claim_success(self):self.check_mode('false_success')
    def test_structured_backend_error_is_preserved(self):self.check_mode('structured_error')
    def test_read_only_listing_deadline_stops_child(self):self.check_mode('timeout')
