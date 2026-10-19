"""Mutations of an actual worker-produced fixture transport; daemon not used."""
import copy,hashlib,json,unittest
from unittest.mock import patch
from tests import test_report_container as fixtures
from lawliet_mobile import core,report_container as rc,report_container_codec as codec
class Codec(unittest.TestCase):
 setUp=fixtures.Reports.setUp
 decode=fixtures.Reports.decode
 contained=fixtures.Reports.contained
 def payload(self):
  with core.connect(self.ws,'A') as (root,db):
   result=self.contained(root,db);raw=(root/'runs'/result['run_id']/'report.stdout.jsonl').read_bytes();frames=[json.loads(line) for line in raw.splitlines()];return raw,frames,{k:v for k,v in frames[0].items() if k!='kind'}
 def encoded(self,frames):
  lines=[json.dumps(v,ensure_ascii=True,separators=(',',':')).encode()+b'\n' for v in frames];middle=b''.join(lines[1:-1]);frames[-1].update(artifact_bytes=len(middle),artifacts_sha256=hashlib.sha256(middle).hexdigest());lines[-1]=json.dumps(frames[-1],separators=(',',':')).encode()+b'\n';return b''.join(lines)
 def test_source_locator_sequence_and_provenance_mutations_refuse_even_rehashed(self):
  raw,frames,bindings=self.payload()
  for key,value in [('file_id',999),('source_ref','report:record=999'),('seq',2),('record',False),('parser','native/0.1')]:
   with self.subTest(key=key):
    changed=copy.deepcopy(frames);changed[1][key]=value
    with self.assertRaises(Exception):codec.validate(self.encoded(changed),bindings)
  changed=copy.deepcopy(frames);data=json.loads(changed[1]['data_json']);data['_import_report']['sha256']='f'*64;changed[1]['data_json']=core.json_text(data)
  with self.assertRaises(Exception):codec.validate(self.encoded(changed),bindings)
 def test_truncated_duplicate_final_nonfinite_utf16_and_wrong_header_refuse(self):
  raw,frames,bindings=self.payload()
  for changed in [raw[:-1],b'\n'.join(raw.splitlines()[:-1])+b'\n',raw+raw.splitlines(keepends=True)[-1],raw.decode().encode('utf-16'),raw.replace(b'"seq":1',b'"seq":NaN'),raw.replace(b'"seq":1',b'"seq":1,"seq":1')]:
   with self.subTest(length=len(changed)),self.assertRaises(Exception):codec.validate(changed,bindings)
  changed=copy.deepcopy(frames);changed[0]['evidence_id']='f'*12
  with self.assertRaises(Exception):codec.validate(self.encoded(changed),bindings)
 def test_header_and_trusted_file_id_reject_numeric_aliases(self):
  raw,frames,bindings=self.payload()
  for invalid in (True,False,1.0,0,-1,2**63,'1',None):
   with self.subTest(invalid=invalid):
    bad_bindings={**bindings,'file_id':invalid}
    with self.assertRaises(codec.ValidationError):codec.validate(raw,bad_bindings)
    changed=copy.deepcopy(frames);changed[0]['file_id']=invalid
    with self.assertRaises(codec.ValidationError):codec.validate(self.encoded(changed),bindings)
  self.assertEqual(codec.validate(raw,bindings).count,1)
 def test_provenance_record_rejects_boolean_float_and_shape_aliases(self):
  raw,frames,bindings=self.payload()
  for invalid in (True,False,1.0,'1',None):
   with self.subTest(invalid=invalid):
    changed=copy.deepcopy(frames);data=json.loads(changed[1]['data_json']);data['_import_report']['record']=invalid;changed[1]['data_json']=core.json_text(data)
    with self.assertRaises(codec.ValidationError):codec.validate(self.encoded(changed),bindings)
  for invalid in ({'record':1},[],None):
   changed=copy.deepcopy(frames);data=json.loads(changed[1]['data_json']);data['_import_report']=invalid;changed[1]['data_json']=core.json_text(data)
   with self.assertRaises(codec.ValidationError):codec.validate(self.encoded(changed),bindings)
 def test_terminal_counts_reject_booleans_and_floats(self):
  raw,frames,bindings=self.payload()
  for key in ('artifact_count','artifact_bytes'):
   for invalid in (True,False,float(frames[-1][key])):
    changed=copy.deepcopy(frames);changed[-1][key]=invalid
    # Direct encode preserves deliberately malformed terminal count/byte fields.
    bad=b''.join(json.dumps(frame,separators=(',',':')).encode()+b'\n' for frame in changed)
    with self.assertRaises(codec.ValidationError):codec.validate(bad,bindings)
 def test_entire_output_validated_before_iteration(self):
  raw,frames,bindings=self.payload();frames[-1]['artifact_count']=2
  with self.assertRaises(Exception):codec.validate(self.encoded(frames),bindings)
if __name__=='__main__':unittest.main()
