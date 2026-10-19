"""Strict bounded derived-report transport; never open reports or child databases."""
from dataclasses import dataclass
import hashlib
from .core import json_text
from .native_container_codec import _decode, ValidationError

PROTOCOL='lawliet-report-artifacts/1'
MAX_INPUT=32*1024**2
MAX_STDOUT=18*1024**2
MAX_ARTIFACTS=16*1024**2
MAX_LINE=8*1024**2
MAX_ROWS=100000
BINDINGS={'protocol','request_sha256','source_manifest_sha256','evidence_id','file_id','filename','format_name','parser','report_sha256','package_manifest_sha256','bootstrap_sha256'}
FIELDS={'kind','seq','record','evidence_id','file_id','category','timestamp','timestamp_raw','title','body','source_ref','parser','data_json'}

def require(condition,message):
 if not condition:raise ValidationError(message)

def artifact(value,seq,bindings,previous):
 require(set(value)==FIELDS and value['kind']=='artifact','Invalid report artifact frame.')
 require(type(value['seq']) is int and value['seq']==seq,'Report frame sequence mismatch.')
 record=value['record'];require(type(record) is int and record>previous and record>=(2 if bindings['format_name']=='tsv' else 1),'Invalid report record locator.')
 require(value['evidence_id']==bindings['evidence_id'] and type(value['file_id']) is int and value['file_id']==bindings['file_id'] and value['parser']==bindings['parser'],'Report source identity mismatch.')
 require(all(type(value[k]) is str for k in ('category','title','body','source_ref','data_json')) and all(value[k] is None or type(value[k]) is str for k in ('timestamp','timestamp_raw')),'Invalid report stored field type.')
 require(value['source_ref']==f'report:record={record}','Report locator mismatch.')
 require(len(value['data_json'].encode('utf-8'))<=MAX_LINE,'Report metadata exceeds bound.')
 data=_decode(value['data_json']);require(json_text(data)==value['data_json'],'Report metadata is not canonical stored JSON.')
 expected={'sha256':bindings['report_sha256'],'record':record,'filename':bindings['filename'],'note':'Hash identifies the imported report, not the application database.'}
 provenance=data.get('_import_report') if isinstance(data,dict) else None
 require(type(provenance) is dict and set(provenance)==set(expected) and type(provenance['record']) is int and provenance==expected,'Report provenance mismatch.')
 return {**value,'data':data}

@dataclass(frozen=True)
class Validated:
 raw:bytes
 bindings:dict
 footer:dict
 count:int
 artifact_bytes:int
 def iter_artifacts(self):
  offset=self.raw.index(b'\n')+1;previous=0
  for seq in range(1,self.count+1):
   end=self.raw.index(b'\n',offset)+1
   row=artifact(_decode(self.raw[offset:end].decode('utf-8')),seq,self.bindings,previous)
   previous=row['record'];offset=end;yield row

def validate(raw,bindings):
 require(type(raw) is bytes and len(raw)<=MAX_STDOUT and raw.endswith(b'\n'),'Invalid report transport size/termination.')
 require(type(bindings) is dict and set(bindings)==BINDINGS and type(bindings['file_id']) is int and 0<bindings['file_id']<2**63 and all(type(bindings[k]) is str for k in BINDINGS-{'file_id'}) and bindings['protocol']==PROTOCOL and bindings['format_name'] in ('jsonl','tsv') and bindings['parser']=='import/'+bindings['format_name'],'Invalid trusted report bindings.')
 offset=0;count=size=previous=0;digest=hashlib.sha256();footer=None
 while offset<len(raw):
  end=raw.find(b'\n',offset)
  require(end>=0,'Missing report newline.');end+=1;line=raw[offset:end]
  require(len(line)<=MAX_LINE,'Report frame exceeds line cap.')
  try:value=_decode(line.decode('utf-8'))
  except (UnicodeError,ValueError,RecursionError) as exc:raise ValidationError('Invalid report frame JSON.') from exc
  if offset==0:
   require(len(line)<=8192 and type(value.get('file_id')) is int and value=={'kind':'header',**bindings},'Report header binding mismatch.')
  elif value.get('kind')=='artifact':
   require(footer is None,'Artifact after terminal frame.')
   count+=1;require(count<=MAX_ROWS,'Report row cap exceeded.')
   row=artifact(value,count,bindings,previous);previous=row['record']
   size+=len(line);require(size<=MAX_ARTIFACTS,'Report normalized output exceeds16MiB.')
   digest.update(line)
  else:
   require(footer is None and set(value)=={'kind','protocol','request_sha256','source_manifest_sha256','status','artifact_count','artifact_bytes','artifacts_sha256','runtime'} and value['kind']=='final' and value['status']=='complete','Invalid report terminal frame.')
   require(all(value[k]==bindings[k] for k in ('protocol','request_sha256','source_manifest_sha256')),'Report footer source mismatch.')
   require(type(value['artifact_count']) is int and value['artifact_count']==count and type(value['artifact_bytes']) is int and value['artifact_bytes']==size and value['artifacts_sha256']==digest.hexdigest(),'Report terminal count/hash mismatch.')
   require(isinstance(value['runtime'],dict) and set(value['runtime'])=={'python_version','sqlite_version'} and all(type(x) is str and 0<len(x)<=128 for x in value['runtime'].values()),'Invalid report runtime metadata.')
   require(end==len(raw),'Data after report terminal frame.');footer=value
  offset=end
 require(footer is not None and (count>0 or bindings['format_name']=='tsv'),'Report did not complete or JSONL has no records.')
 return Validated(raw,dict(bindings),footer,count,size)
