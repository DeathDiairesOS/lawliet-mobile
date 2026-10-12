"""Exercise the actual native preview scheduler and verified image decoder."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc'),'Requires macOS Swift/ImageIO')
class InlineMediaTests(unittest.TestCase):
    def test_queue_integrity_case_isolation_retry_and_cache(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder).resolve();binary=base/'inline-media-check'
            built=subprocess.run(['swiftc','-swift-version','5',str(root/'desktop/InlineMediaCache.swift'),str(root/'tests/InlineMediaCheck.swift'),'-o',str(binary),'-framework','AppKit','-framework','ImageIO'],capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stderr)
            result=subprocess.run([str(binary),str(base/'cases'),str(root/'desktop/assets/mobile-icon.png')],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            for check in ['serial execution','unseen queued-image cancellation','late old-case preview','changed preview copy refused','case-path containment']:
                self.assertIn(check,result.stdout)
