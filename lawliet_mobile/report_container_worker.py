"""Fixed-path stdlib report decoder. No host CaseDB, FD, socket or home."""
import hashlib,json,math,os,re,sqlite3,stat,sys,tempfile,time,shutil
from pathlib import Path
MAX_DEPTH=64
MAX_INPUT=32*1024**2
MAX_ROWS=100000
MAX_ARTIFACTS=16*1024**2
MAX_LINE=8*1024**2
PROTOCOL='lawliet-report-artifacts/1'
HASH=re.compile(r'[0-9a-f]{64}\Z')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(',', ':')).encode('utf-8')

def read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError('file bound/type')
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        named = os.stat(path, follow_symlinks=False)
        if len(raw) != before.st_size or identity(before) != identity(after) or identity(after) != identity(named):
            raise ValueError('file changed')
        return bytes(raw)
    finally:
        os.close(fd)

def strict(raw):
    # Bound structural depth before the recursive decoder, ignoring string text.
    text = raw.decode('utf-8')
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError('JSON depth')
        elif char in ']}':
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def number(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError('nonfinite JSON')
        return parsed
    def constant(value):
        raise ValueError('nonfinite JSON')
    return json.loads(text, object_pairs_hook=pairs, parse_float=number, parse_constant=constant)

def package_hashes(package):
    result = {}
    for path in package.iterdir():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.py', path.name):
            raise ValueError('unexpected package entry')
        result[path.name] = sha(read(path, 2 * 1024**2))
    return result

def mount_checks(scratch):
 value=scratch.lstat()
 if os.getuid()!=65534 or os.geteuid()!=65534 or not stat.S_ISDIR(value.st_mode) or value.st_uid!=0 or stat.S_IMODE(value.st_mode)!=0o1777:raise ValueError('report worker uid/scratch')

def execute(output,*,request_path=Path('/control/request.json'),code_root=Path('/code'),source_path=Path('/input/report'),scratch=Path('/scratch')):
 started=time.monotonic()
 def deadline():
  if time.monotonic()-started>90:raise ValueError('report worker elapsed limit')
 raw=read(request_path,2*1024**2);request=strict(raw)
 if not isinstance(request,dict) or set(request)!={'protocol','bootstrap_sha256','package_sha256','source'} or request['protocol']!=PROTOCOL:raise ValueError('request schema')
 if request['bootstrap_sha256']!=sha(read(__file__,1024**2)):raise ValueError('bootstrap SHA')
 actual=package_hashes(code_root/'lawliet_mobile')
 if actual!=request['package_sha256']:raise ValueError('package SHA')
 source=request['source']
 if not isinstance(source,dict) or set(source)!={'evidence_id','file_id','filename','format_name','sha256','bytes'}:raise ValueError('report source schema')
 if (not isinstance(source['evidence_id'],str) or not re.fullmatch('[0-9a-f]{12}',source['evidence_id']) or type(source['file_id']) is not int or not 0<source['file_id']<2**63 or source['format_name'] not in ('jsonl','tsv') or not isinstance(source['filename'],str) or not source['filename'] or Path(source['filename']).name!=source['filename'] or '\\' in source['filename'] or len(source['filename'].encode('utf-8'))>4096 or not isinstance(source['sha256'],str) or not HASH.fullmatch(source['sha256']) or type(source['bytes']) is not int or not 0<=source['bytes']<=MAX_INPUT):raise ValueError('report source identity')
 mount_checks(scratch)
 data=read(source_path,MAX_INPUT)
 if len(data)!=source['bytes'] or sha(data)!=source['sha256']:raise ValueError('report source SHA')
 del data
 os.environ['TMPDIR']=str(scratch);os.environ['SQLITE_TMPDIR']=str(scratch);tempfile.tempdir=str(scratch);sys.path.insert(0,str(code_root))
 from lawliet_mobile.parsed_import import iter_report_records
 from lawliet_mobile.core import json_text
 from lawliet_mobile.report_container_codec import validate
 bindings={'protocol':PROTOCOL,'request_sha256':sha(raw),'source_manifest_sha256':sha(canonical(source)),'evidence_id':source['evidence_id'],'file_id':source['file_id'],'filename':source['filename'],'format_name':source['format_name'],'parser':'import/'+source['format_name'],'report_sha256':source['sha256'],'package_manifest_sha256':sha(canonical(actual)),'bootstrap_sha256':request['bootstrap_sha256']}
 def frame(value):return json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('utf-8')+b'\n'
 with tempfile.TemporaryFile(dir=scratch) as spool:
  size=count=0;digest=hashlib.sha256()
  for record,mapped in iter_report_records(source_path,source['format_name'],source['evidence_id'],source['sha256'],source['filename']):
   deadline();category,when,original,title,body,metadata=mapped;count+=1
   line=frame({'kind':'artifact','seq':count,'record':record,'evidence_id':source['evidence_id'],'file_id':source['file_id'],'category':str(category),'timestamp':when,'timestamp_raw':str(original) if original is not None else None,'title':str(title),'body':str(body),'source_ref':f'report:record={record}','parser':bindings['parser'],'data_json':json_text(metadata)})
   if count>MAX_ROWS or len(line)>MAX_LINE or size+len(line)>MAX_ARTIFACTS:raise ValueError('report normalized output cap')
   size+=len(line);digest.update(line);spool.write(line)
  if count==0 and source['format_name']!='tsv':raise ValueError('No records found in this report.')
  if sha(read(source_path,MAX_INPUT))!=source['sha256'] or actual!=package_hashes(code_root/'lawliet_mobile'):raise ValueError('report source/package changed')
  deadline()
  header=frame({'kind':'header',**bindings})
  footer=frame({'kind':'final','protocol':PROTOCOL,'request_sha256':bindings['request_sha256'],'source_manifest_sha256':bindings['source_manifest_sha256'],'status':'complete','artifact_count':count,'artifact_bytes':size,'artifacts_sha256':digest.hexdigest(),'runtime':{'python_version':sys.version.split()[0],'sqlite_version':sqlite3.sqlite_version}})
  spool.seek(0);transport=header+spool.read()+footer
  validate(transport,bindings)
  output.write(transport)

def main():
 try:
  if len(sys.argv)!=1:raise ValueError('report worker arguments refused')
  execute(sys.stdout.buffer);return 0
 except Exception as exc:
  sys.stderr.write('contained report refused: '+type(exc).__name__+'\n');return 125

if __name__=='__main__':raise SystemExit(main())
