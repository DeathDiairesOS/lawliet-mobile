import importlib.util,json,tarfile,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('snapshot_tool',Path(__file__).parents[1]/'tools/create_recovery_snapshot.py')
snapshot=importlib.util.module_from_spec(spec);spec.loader.exec_module(snapshot)
class SnapshotTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.source=self.root/'source';self.source.mkdir();self.validation=self.root/'validation';self.validation.mkdir();self.dest=self.root/'backup'
 def write(self,base,rel,data='data'):
  p=base/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(data);return p
 def test_restore_contains_source_reports_excludes_acquisitions_and_venvs(self):
  self.write(self.source,'module.py','answer=42\n');self.write(self.validation,'acquisition/stream.py');self.write(self.validation,'acquisition/source-inventory.json','{}')
  for rel in ['acquisition/hickman-ios13-backup/receipt.json','acquisition/hickman-android13-selected.quarantine/members.jsonl','acquisition/acquisition-venv/lib/module.py','inputs/small-evidence.json','reports/raw.db','acquisition/ios13-image-creation.txt']:
   self.write(self.validation,rel)
  self.write(self.validation,'custom_runtime/pyvenv.cfg');self.write(self.validation,'custom_runtime/lib/module.py')
  result=snapshot.create_snapshot(self.source,self.validation,self.dest)
  self.assertTrue(result['restore_verified'])
  with tarfile.open(result['archive']) as t:
   names=set(t.getnames());self.assertEqual(names,{'manifest.json','source/module.py','validation/acquisition/stream.py','validation/acquisition/source-inventory.json'})
   self.assertEqual(t.extractfile('source/module.py').read(),b'answer=42\n')
 def test_destination_inside_source_or_validation_rejected(self):
  for dest in [self.source,self.source/'backup',self.validation/'backup']:
   with self.assertRaisesRegex(ValueError,'outside'):snapshot.create_snapshot(self.source,self.validation,dest)
 def test_destination_symlink_resolves_inside_source_and_rejected(self):
  link=self.root/'linked';link.symlink_to(self.source,target_is_directory=True)
  with self.assertRaisesRegex(ValueError,'outside'):snapshot.create_snapshot(self.source,self.validation,link/'nested')
 def test_symlink_input_is_not_followed(self):
  outside=self.write(self.root,'outside/secret.json');(self.validation/'leak.json').symlink_to(outside)
  (self.validation/'linked').symlink_to(outside.parent,target_is_directory=True)
  result=snapshot.create_snapshot(self.source,self.validation,self.dest)
  self.assertEqual(result['files'],0)
if __name__=='__main__':unittest.main()
