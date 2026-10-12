import unittest,tempfile,csv,json
from pathlib import Path
try:
 from mulder.server.tools.phone import _parse_tsv_file,_leapp_artifact_lines
except ModuleNotFoundError as error:
 if error.name != 'mulder':
  raise
 _parse_tsv_file = _leapp_artifact_lines = None

@unittest.skipUnless(_parse_tsv_file, 'Requires the restored Mulder candidate runtime')
class TSVTests(unittest.TestCase):
 def run_fixture(self,text):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'test.tsv';p.write_text(text,encoding='utf-8');return _parse_tsv_file(p)
 def test_exact_multiline(self):
  rows=self.run_fixture('\ufeffID\tMessage\n1\t"First\nSecond 😀\t""quoted"""\n2\tPlain\n');self.assertEqual(len(rows),2);self.assertEqual(rows[0]['Message'],'First\nSecond 😀\t"quoted"');self.assertEqual(json.loads(_leapp_artifact_lines({'data':rows})[1]),rows[0])
 def test_extra_column_explicit_failure(self):
  with self.assertRaisesRegex(ValueError,'column count'):self.run_fixture('A\tB\n1\t2\t3\n')
 def test_missing_column_explicit_failure(self):
  with self.assertRaisesRegex(ValueError,'column count'):self.run_fixture('A\tB\n1\n')
 def test_duplicate_column_explicit_failure(self):
  with self.assertRaisesRegex(ValueError,'duplicate'):self.run_fixture('A\tA\n1\t2\n')
 def test_invalid_quote_explicit_failure(self):
  with self.assertRaises(csv.Error):self.run_fixture('A\n"unterminated\n')
 def test_large_report_preserves_sentinel(self):
  rows=self.run_fixture('ID\tMessage\n'+''.join(str(n)+'\t'+('AFTER_HTML_CAP_SENTINEL' if n==50001 else 'ROW_'+str(n))+'\n' for n in range(1,50002)));self.assertEqual(len(rows),50001);self.assertEqual(rows[-1]['Message'],'AFTER_HTML_CAP_SENTINEL');self.assertEqual(len(_leapp_artifact_lines({'data':rows})),50002)
if __name__=='__main__':unittest.main()
