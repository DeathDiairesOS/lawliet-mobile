"""Archive reuse must bind source bytes and every decoded output."""
import json,os,tempfile,unittest
from pathlib import Path
from lawliet_mobile.archive_cache import fingerprint,inventory,is_complete,write_completion,MARKER
from lawliet_mobile.core import UserError

class ArchiveCache(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name).resolve();self.source=self.root/'input.zip';self.source.write_bytes(b'archive original');self.dest=self.root/'decoded';self.dest.mkdir();(self.dest/'record').write_bytes(b'ORIGINAL');self.initial=fingerprint(self.source);write_completion(self.dest,self.source,self.initial,1000,10)
 def complete(self):return is_complete(self.dest,self.source,1000,10)
 def test_unchanged_outputs_reuse(self):self.assertTrue(self.complete())
 def test_same_size_changed_source_refused(self):self.source.write_bytes(b'archive modified');self.assertFalse(self.complete())
 def test_same_size_changed_output_refused(self):(self.dest/'record').write_bytes(b'TAMPERED');self.assertFalse(self.complete())
 def test_missing_output_refused(self):(self.dest/'record').unlink();self.assertFalse(self.complete())
 def test_injected_output_refused(self):(self.dest/'extra').write_text('new');self.assertFalse(self.complete())
 def test_injected_empty_directory_refused(self):(self.dest/'empty').mkdir();self.assertFalse(self.complete())
 def test_output_symlink_refused(self):
  (self.dest/'record').unlink();(self.dest/'record').symlink_to(self.source);self.assertFalse(self.complete())
 def test_output_hardlink_refused(self):
  os.link(self.dest/'record',self.root/'alias');self.assertFalse(self.complete())
 def test_marker_symlink_refused_without_read(self):
  marker=self.dest/MARKER;before=marker.read_bytes();target=self.root/'retained';target.write_bytes(before);marker.unlink();marker.symlink_to(target);self.assertFalse(self.complete());self.assertEqual(target.read_bytes(),before)
 def test_legacy_marker_cannot_certify_reuse(self):
  marker=self.dest/MARKER;v=json.loads(marker.read_text());v.pop('source');v.pop('format');marker.write_text(json.dumps(v));self.assertFalse(self.complete())
 def test_changed_source_during_extraction_cannot_get_receipt(self):
  old=(self.dest/MARKER).read_bytes();self.source.write_bytes(b'CHANGED')
  with self.assertRaises(UserError):write_completion(self.dest,self.source,self.initial,1000,10)
  self.assertEqual((self.dest/MARKER).read_bytes(),old)
 def test_smaller_declared_limit_cannot_reuse(self):self.assertFalse(is_complete(self.dest,self.source,1,10))
 def test_implicit_parent_directories_not_counted_as_files(self):
  other=self.root/'nested';(other/'a/b').mkdir(parents=True);(other/'a/b/file').write_bytes(b'X');write_completion(other,self.source,self.initial,1,1);self.assertTrue(is_complete(other,self.source,1,1))
 @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX filesystem FIFOs are not available on Windows; link/reparse protections are checked separately")
 def test_fifo_output_refused_without_open(self):
  os.mkfifo(self.dest/'fifo');self.assertFalse(self.complete())
 def test_receipt_bounds_are_visible(self):
  from unittest.mock import patch
  with patch('lawliet_mobile.archive_cache.RECEIPT_MAX',100):
   self.assertFalse(self.complete())
   with self.assertRaises(UserError):inventory(self.dest,1000,10)

 def test_oversize_sparse_output_refused_before_hashing(self):
  from unittest.mock import patch
  huge=self.dest/'oversize'
  with huge.open('wb') as out:out.truncate(1000000)
  with patch('lawliet_mobile.archive_cache.hashlib.sha256',side_effect=AssertionError('Must not hash oversize')):
   with self.assertRaises(UserError):fingerprint(huge,max_bytes=1000)
 def test_excess_files_refused_before_hashing_extra_file(self):
  from unittest.mock import patch
  (self.dest/'extra').write_bytes(b'NEW')
  original=fingerprint;calls=[]
  def track(*a,**kw):calls.append(a[0]);return original(*a,**kw)
  with patch('lawliet_mobile.archive_cache.fingerprint',side_effect=track):
   with self.assertRaises(UserError):inventory(self.dest,1000,1)
  self.assertEqual(len(calls),1)
 def test_verification_deadline_refuses_before_reading(self):
  from unittest.mock import patch
  with patch('lawliet_mobile.archive_cache.time.monotonic',return_value=601):
   with self.assertRaises(UserError):fingerprint(self.source,deadline=600)
   with self.assertRaises(UserError):inventory(self.dest,1000,10,deadline=600)
 def test_atomic_path_replacement_during_hash_is_refused(self):
  from unittest.mock import patch
  import hashlib
  original=hashlib.sha256
  replacement=self.root/'replacement';replacement.write_bytes(b'REPLACED')
  class Hash:
   def __init__(inner):inner.h=original()
   def update(inner,chunk):
    if os.name=='nt':
     with self.assertRaises(PermissionError):replacement.replace(self.source)
    else:replacement.replace(self.source)
    inner.h.update(chunk)
   def hexdigest(inner):return inner.h.hexdigest()
  with patch('lawliet_mobile.archive_cache.hashlib.sha256',side_effect=Hash):
   if os.name=='nt':
    self.assertEqual(fingerprint(self.source),self.initial)
    self.assertEqual(self.source.read_bytes(),b'archive original');self.assertEqual(replacement.read_bytes(),b'REPLACED')
   else:
    with self.assertRaises(UserError):fingerprint(self.source)
 def test_earlier_output_changed_during_inventory_is_refused(self):
  from unittest.mock import patch
  (self.dest/'second').write_bytes(b'SECOND');original=fingerprint;calls=[]
  def change(*a,**kw):
   value=original(*a,**kw);calls.append(a[0])
   if len(calls)==2:calls[0].write_bytes(b'CHANGED')
   return value
  with patch('lawliet_mobile.archive_cache.fingerprint',side_effect=change):
   with self.assertRaises(UserError):inventory(self.dest,1000,10)
 def test_nested_marker_name_is_evidence_in_inventory(self):
  folder=self.dest/'nested';folder.mkdir();(folder/MARKER).write_bytes(b'EVIDENCE');write_completion(self.dest,self.source,self.initial,1000,10)
  self.assertTrue(self.complete());receipt=json.loads((self.dest/MARKER).read_text());self.assertIn('nested/'+MARKER,[e['path'] for e in receipt['inventory']])
