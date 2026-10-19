"""An imported row must never claim a different report snapshot's hash."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import UserError,create_case,connect,verify
import lawliet_mobile.parsed_import as imported

class ImportReportIdentity(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.base=Path(tmp.name).resolve();self.workspace=self.base/'cases'
 def payload(self,format_name,body):
  return (json.dumps({'category':'external','body':body,'data':{}})+'\n') if format_name=='jsonl' else 'Field\tValue\nLabel\t'+body+'\n'
 def test_changed_source_refused_zero_rows_then_stable_retry_correct(self):
  for format_name in ('jsonl','tsv'):
   with self.subTest(format=format_name):
    case=format_name;create_case(self.workspace,case);source=self.base/('Unknown.'+format_name);source.write_text(self.payload(format_name,'SOURCE-A'));before=hashlib.sha256(source.read_bytes()).hexdigest();original=imported.import_evidence
    def replace_then_intake(*args,**kwargs):
     source.write_text(self.payload(format_name,'SOURCE-B'));return original(*args,**kwargs)
    with connect(self.workspace,case) as (root,db):
     with patch.object(imported,'import_evidence',side_effect=replace_then_intake),self.assertRaisesRegex(UserError,'changed between identity check'):
      imported.import_parsed(root,db,source,format_name)
     self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
     run=db.execute('SELECT status,records FROM runs').fetchone();self.assertEqual(tuple(run),('failed',0))
     retained=db.execute('SELECT sha256 FROM files').fetchone()[0];self.assertNotEqual(retained,before);self.assertEqual(retained,hashlib.sha256(source.read_bytes()).hexdigest());self.assertTrue(verify(root,db)['ok'])
     result=imported.import_parsed(root,db,source,format_name);self.assertEqual(result['records'],1)
     row=db.execute('SELECT body,data FROM artifacts').fetchone();self.assertIn('SOURCE-B',row['body']);self.assertEqual(json.loads(row['data'])['_import_report']['sha256'],retained)
     detail=json.loads(db.execute("SELECT detail FROM runs WHERE status='complete'").fetchone()[0]);self.assertEqual(detail['report_sha256'],retained);self.assertTrue(verify(root,db)['ok'])
 def test_unchanged_single_file_metadata_matches_retained_snapshot(self):
  create_case(self.workspace,'stable');source=self.base/'stable.jsonl';source.write_text(self.payload('jsonl','café 東京'));expected=hashlib.sha256(source.read_bytes()).hexdigest()
  with connect(self.workspace,'stable') as (root,db):
   result=imported.import_parsed(root,db,source,'jsonl');self.assertEqual(result['records'],1)
   row=db.execute('SELECT data FROM artifacts').fetchone();self.assertEqual(json.loads(row['data'])['_import_report']['sha256'],expected)
   self.assertEqual(db.execute('SELECT sha256 FROM files').fetchone()[0],expected);self.assertEqual(imported.import_parsed(root,db,source,'jsonl')['status'],'already_imported')
