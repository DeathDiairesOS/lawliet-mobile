"""Validation-only same-process SQLite bootstrap. No Docker/host launcher here."""
import base64
import contextlib
import hashlib
import io
import json
import math
import os
from pathlib import Path
import runpy
import stat
import sys

INPUT_PROTOCOL='lawliet-python-sqlite-input/1'
OUTPUT_PROTOCOL='lawliet-python-sqlite-output/1'
MAX_INPUT=64*1024**2
MAX_METADATA=1024**2
MAX_ROWS=16*1024**2
MAX_REQUEST=2*1024**2
MAX_CODE=1024**2
MAX_ENVELOPE=24*1024**2
NAMES={'database.sqlite','database.sqlite-wal','database.sqlite-journal'}

class Refusal(ValueError):pass

def strict_json(raw):
    text=raw.decode('utf-8') if isinstance(raw,bytes) else raw
    depth=0;quoted=False;escape=False
    for c in text:
        if quoted:
            if escape:escape=False
            elif c=='\\':escape=True
            elif c=='"':quoted=False
        elif c=='"':quoted=True
        elif c in '[{':
            depth+=1
            if depth>64:raise Refusal('JSON depth limit exceeded')
        elif c in ']}':depth-=1
    def pairs(items):
        d={}
        for k,v in items:
            if k in d:raise Refusal('Duplicate JSON key')
            d[k]=v
        return d
    def constant(v):raise Refusal('Nonfinite JSON number')
    def number(v):
        value=float(v)
        if not math.isfinite(value):raise Refusal('Nonfinite JSON number')
        return value
    try:return json.loads(text,object_pairs_hook=pairs,parse_constant=constant,parse_float=number)
    except (ValueError,RecursionError,UnicodeError) as exc:raise Refusal('Invalid strict JSON') from exc

def directory(path):
    path=Path(path).absolute()
    if '..' in path.parts:raise Refusal('Unsafe directory path')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=new
        return fd
    except BaseException:os.close(fd);raise

def fingerprint(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)

def bounded_read(parent,name,limit):
    if '/' in name or name in ('','.','..'):raise Refusal('Unsafe file name')
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>limit:raise Refusal('Unsafe or oversized regular file')
        chunks=[];remaining=limit+1
        while remaining:
            data=os.read(fd,min(65536,remaining))
            if not data:break
            chunks.append(data);remaining-=len(data)
        raw=b''.join(chunks)
        if len(raw)>limit or len(raw)!=before.st_size or fingerprint(os.fstat(fd))!=fingerprint(before):raise Refusal('File changed or exceeded bound')
        return raw
    finally:os.close(fd)

def input_transfer(parent,name,expected_size,expected_hash,destination=None):
    """Hash/copy in 64KiB chunks without retaining a64MiB input in RAM."""
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    out=None
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size!=expected_size:raise Refusal('Unsafe input file or size mismatch')
        if destination is not None:out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=destination)
        count=0;digest=hashlib.sha256()
        while True:
            chunk=os.read(fd,min(65536,expected_size-count+1))
            if not chunk:break
            count+=len(chunk)
            if count>expected_size:raise Refusal('Input grew beyond declared bound')
            digest.update(chunk)
            if out is not None:
                view=memoryview(chunk)
                while view:
                    n=os.write(out,view)
                    if n<=0:raise Refusal('Input copy made no progress')
                    view=view[n:]
        value=digest.hexdigest()
        if count!=expected_size or value!=expected_hash or fingerprint(os.fstat(fd))!=fingerprint(before):raise Refusal('Input integrity mismatch')
        return value
    finally:
        os.close(fd)
        if out is not None:os.close(out)

def exclusive_write(parent,name,data):
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
    try:
        view=memoryview(data)
        while view:
            count=os.write(fd,view)
            if count<=0:raise Refusal('Write made no progress')
            view=view[count:]
    finally:os.close(fd)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def hash_value(v):return isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v)

def validate_request(r):
    keys={'protocol','worker_source_sha256','query','parameters','row_limit','max_output_bytes','timeout_seconds','inputs'}
    if not isinstance(r,dict) or set(r)!=keys or r['protocol']!=INPUT_PROTOCOL:raise Refusal('Unsupported request schema')
    if not hash_value(r['worker_source_sha256']):raise Refusal('Worker hash required')
    if not isinstance(r['query'],str) or not r['query'].strip() or len(r['query'].encode('utf-8'))>32768:raise Refusal('Invalid query')
    if not isinstance(r['parameters'],list) or len(r['parameters'])>128:raise Refusal('Invalid parameters')
    for v in r['parameters']:
        if type(v) not in (str,int,float,type(None)) or type(v) is float and not math.isfinite(v):raise Refusal('Invalid parameter value')
        if type(v) is int and not -(2**63)<=v<2**63:raise Refusal('Integer parameter exceeds signed64')
    if len(json.dumps(r['parameters']).encode())>1024**2:raise Refusal('Parameter byte limit exceeded')
    if type(r['timeout_seconds']) not in (int,float) or not math.isfinite(r['timeout_seconds']) or not 0.05<=r['timeout_seconds']<=30:raise Refusal('Invalid timeout')
    for k,low,high in [('row_limit',1,100000),('max_output_bytes',1024,MAX_ROWS)]:
        if type(r[k]) is not int or not low<=r[k]<=high:raise Refusal('Invalid query limit')
    if not isinstance(r['inputs'],list) or not 1<=len(r['inputs'])<=3:raise Refusal('Invalid input inventory')
    names=set();total=0
    for item in r['inputs']:
        if not isinstance(item,dict) or set(item)!={'name','bytes','sha256'} or item['name'] not in NAMES or item['name'] in names:raise Refusal('Invalid input name')
        if type(item['bytes']) is not int or item['bytes']<0 or not hash_value(item['sha256']):raise Refusal('Invalid input size/hash')
        names.add(item['name']);total+=item['bytes']
    if 'database.sqlite' not in names or total>MAX_INPUT:raise Refusal('Input bundle exceeds bound or lacks database')

class QuietOutput(io.TextIOBase):
    def write(self,text):
        if text:raise Refusal('Unexpected worker stdout')
        return 0

def validate_outputs(metadata,rows,max_output,row_limit):
    if not isinstance(metadata,dict):raise Refusal('Metadata must be an object')
    state=metadata.get('state');columns=metadata.get('columns');count=metadata.get('rows_returned')
    states={'parsed','empty','limited','denied','timed-out','corrupt','unsupported-or-corrupt','unsupported-schema','resource-limited','query-failed'}
    if state not in states or not isinstance(columns,list) or len(columns)>256 or any(not isinstance(c,str) for c in columns):raise Refusal('Invalid metadata fields')
    if type(count) is not int or not 0<=count<=row_limit or type(metadata.get('truncated')) is not bool or type(metadata.get('bytes_written')) is not int:raise Refusal('Invalid metadata counts')
    if len(rows)>max_output or metadata['bytes_written']!=len(rows):raise Refusal('Output byte count mismatch')
    try:text=rows.decode('utf-8')
    except UnicodeError as exc:raise Refusal('Invalid row UTF8') from exc
    n=0
    for line in text.splitlines():
        row=strict_json(line)
        if not isinstance(row,list) or len(row)!=len(columns):raise Refusal('Invalid row width')
        for value in row:
            if type(value) in (str,int,float,type(None)):continue
            if isinstance(value,dict) and len(value)==1:
                if set(value)=={'sqlite_blob_hex'} and isinstance(value['sqlite_blob_hex'],str) and len(value['sqlite_blob_hex'])%2==0 and all(c in '0123456789abcdef' for c in value['sqlite_blob_hex']):continue
                if set(value)=={'sqlite_nonfinite_float'} and value['sqlite_nonfinite_float'] in ('inf','-inf','nan'):continue
            raise Refusal('Invalid row cell')
        n+=1
    if n!=count or state=='empty' and n or state=='parsed' and not n:raise Refusal('Row count/state mismatch')
    if not isinstance(metadata.get('denied_operations'),list):raise Refusal('Invalid denied-operation list')

def execute(request_path,code_path,input_root,scratch_root):
    request_path=Path(request_path);code_path=Path(code_path);scratch_root=Path(scratch_root).absolute()
    with contextlib.ExitStack() as stack:
        def opened(path):
            fd=directory(path);stack.callback(os.close,fd);return fd
        requestfd=opened(request_path.parent);codefd=opened(code_path.parent);inputfd=opened(input_root);scratchfd=opened(scratch_root)
        request_bytes=bounded_read(requestfd,request_path.name,MAX_REQUEST);request=strict_json(request_bytes);validate_request(request)
        source=bounded_read(codefd,code_path.name,MAX_CODE)
        if sha(source)!=request['worker_source_sha256']:raise Refusal('Worker source hash mismatch')
        # A fresh private child prevents old sidecars/output from influencing a rerun.
        os.mkdir('work',0o700,dir_fd=scratchfd);work=scratch_root/'work';workfd=opened(work)
        input_hashes={}
        for item in request['inputs']:
            input_hashes[item['name']]=input_transfer(inputfd,item['name'],item['bytes'],item['sha256'],workfd)
        worker_request={k:request[k] for k in ('query','parameters','row_limit','max_output_bytes','timeout_seconds','worker_source_sha256')}
        worker_request.update(database_path=str(work/'database.sqlite'),output_path=str(work/'rows.jsonl'))
        exclusive_write(workfd,'request.json',json.dumps(worker_request,allow_nan=False).encode())
        with contextlib.redirect_stdout(QuietOutput()):
            namespace=runpy.run_path(str(code_path),run_name='lawliet_validation_sqlite_worker')
            namespace['_worker'](str(work/'request.json'),str(work/'metadata.json'))
        if sha(bounded_read(codefd,code_path.name,MAX_CODE))!=request['worker_source_sha256']:raise Refusal('Worker source changed')
        for item in request['inputs']:
            try:input_transfer(inputfd,item['name'],item['bytes'],input_hashes[item['name']])
            except Refusal as exc:raise Refusal('Original input changed') from exc
        metadata=strict_json(bounded_read(workfd,'metadata.json',MAX_METADATA))
        if not isinstance(metadata,dict):raise Refusal('Metadata must be an object')
        # Failed queries before output creation legitimately have no row file.
        try:rows=bounded_read(workfd,'rows.jsonl',request['max_output_bytes'])
        except FileNotFoundError:
            if metadata.get('state') in ('parsed','empty','limited') or metadata.get('rows_returned')!=0 or metadata.get('bytes_written')!=0:raise Refusal('Expected rows missing')
            rows=b''
        validate_outputs(metadata,rows,request['max_output_bytes'],request['row_limit'])
        result={'protocol':OUTPUT_PROTOCOL,'request_sha256':sha(request_bytes),'worker_source_sha256':request['worker_source_sha256'],'inputs_sha256':input_hashes,'metadata':metadata,'result_base64':base64.b64encode(rows).decode('ascii'),'result_sha256':sha(rows),'result_bytes':len(rows)}
        encoded=json.dumps(result,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('utf-8')+b'\n'
        if len(encoded)>MAX_ENVELOPE:raise Refusal('Envelope exceeds transport bound')
        return encoded

def main():
    try:
        payload=execute('/control/request.json','/code/sqlite_workspace.py','/input','/scratch')
        sys.stdout.buffer.write(payload);sys.stdout.buffer.flush();return 0
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,UnicodeError,MemoryError) as exc:
        # Diagnostics describe type only, avoiding evidence/query content in stderr.
        sys.stderr.write('SQLite validation bootstrap refused: '+type(exc).__name__+'\n');return 125

if __name__=='__main__':raise SystemExit(main())
