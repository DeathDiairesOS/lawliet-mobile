import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc'),'Requires native Swift compiler')
class ReportReviewBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tmp.cleanup)
        cls.binary=Path(cls.tmp.name)/'check';root=Path(__file__).resolve().parents[1]
        result=subprocess.run(['swiftc',str(root/'desktop/DraftReview.swift'),str(root/'desktop/ReportReviewBinding.swift'),
                        str(root/'tests/ReportReviewBindingCheck.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=60)
        if result.returncode:raise AssertionError(result.stderr)
    def check(self,mode):
        result=subprocess.run([str(self.binary),mode],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('passed: '+mode,result.stdout)
    def test_explicit_operator_approval(self):self.check('explicit-approval')
    def test_stale_or_foreign_response_refused(self):self.check('response-binding')
    def test_derivative_action_and_exact_literals(self):self.check('derivative')
