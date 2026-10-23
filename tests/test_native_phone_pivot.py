"""Exercise the production Swift field model used by the native pivot menu."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'),
                     'Native phone pivot checks require macOS and swiftc')
class NativePhonePivotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(prefix='lawliet-phone-pivot-')
        cls.addClassCleanup(tmp.cleanup)
        directory = Path(tmp.name)
        root = Path(__file__).resolve().parents[1]
        source = (root / 'desktop/LawlietMobile.swift').read_text()
        # Compile the actual small production model, avoiding a second App entry
        # point and duplicated parsing logic in a test-only model.
        start = source.index('struct ReportField: Identifiable {')
        end = source.index('\nstruct Artifact:', start)
        model = directory / 'ReportField.swift'
        model.write_text('import Foundation\n' + source[start:end] + '\n')
        main = directory / 'main.swift'
        main.write_text('''import Foundation
let values = ReportField(id:CommandLine.arguments[1],value:CommandLine.arguments[2]).phonePivotValues
print(String(data:try! JSONSerialization.data(withJSONObject:values),encoding:.utf8)!)
''')
        cls.binary = directory / 'phone-pivot'
        built = subprocess.run(['swiftc', '-swift-version', '5', str(model), str(main), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=60)
        if built.returncode:
            raise AssertionError(built.stderr)

    def values(self, text, field='Phone number'):
        result = subprocess.run([str(self.binary), field, text], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_multiline_contact_is_separate_exact_candidates(self):
        self.assertEqual(self.values('+1 (202) 555-0101\n202-555-0102'),
                         ['+1 (202) 555-0101', '202-555-0102'])

    def test_single_number_keeps_single_button_candidate(self):
        self.assertEqual(self.values('+1 (202) 555-0101'), ['+1 (202) 555-0101'])

    def test_crlf_and_blank_lines_do_not_create_empty_menu_choices(self):
        self.assertEqual(self.values('  +12025550101\r\n\r\n202-555-0102 \n'),
                         ['+12025550101', '202-555-0102'])
        self.assertEqual(self.values(' \n\r\n '), [])

    def test_punctuation_labels_and_extensions_are_not_inferred(self):
        for supplied in ('2025550101,2025550102', '2025550101 / 2025550102',
                         'Home: +12025550101', '+12025550101;ext=9'):
            with self.subTest(supplied=supplied):
                self.assertEqual(self.values(supplied), [supplied])

    def test_unrelated_fields_do_not_offer_a_phone_pivot(self):
        self.assertEqual(self.values('+12025550101', field='Email'), [])
        self.assertEqual(self.values('+12025550101', field='Note'), [])

    def test_repeated_values_remain_supplied_lines(self):
        self.assertEqual(self.values('+12025550101\n+12025550101'),
                         ['+12025550101', '+12025550101'])
