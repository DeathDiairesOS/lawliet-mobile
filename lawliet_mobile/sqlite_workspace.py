"""Recorded, bounded SQLite queries on disposable copies of retained evidence.

This module also runs as a stdlib-only isolated worker. No database result is
promoted to a message, timestamp interpretation, deletion or examiner finding.
"""
import contextlib
import hashlib
import json
import math
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

VERSION='sqlite-workspace/1'
MAX_INPUT_BYTES=512*1024**2
MAX_OUTPUT_BYTES=16*1024**2
MAX_WORKER_METADATA_BYTES=1024**2
MAX_RESULT_VIEW_RECEIPT_BYTES=2*1024**2
MAX_RESULT_VIEW_QUERY_BYTES=2*1024**2
FUNCTIONS=frozenset(('abs round min max sum avg count total coalesce ifnull nullif typeof length '
    'octet_length substr substring hex quote lower upper trim ltrim rtrim replace instr unicode '
    'char like glob date time datetime julianday unixepoch strftime json json_valid json_type '
    'json_extract json_array_length json_quote json_array json_object json_group_array '
    'json_group_object json_each json_tree').split())
SCHEMA_QUERY="SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','view','index') ORDER BY type,name"


def _cell(value):
    if isinstance(value,bytes):return {'sqlite_blob_hex':value.hex()}
    if isinstance(value,float) and not math.isfinite(value):return {'sqlite_nonfinite_float':str(value)}
    return value


def _worker_json(data):
    if isinstance(data,bytes):data=data.decode('utf-8')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate JSON key')
            result[key]=value
        return result
    def constant(value):raise ValueError('nonfinite JSON number')
    def number(value):
        parsed=float(value)
        if not math.isfinite(parsed):raise ValueError('nonfinite JSON number')
        return parsed
    return json.loads(data,object_pairs_hook=pairs,parse_constant=constant,parse_float=number)


def _validate_result(data,detail):
    """Validate the bounded child stream before recording completion."""
    from .core import UserError
    count=0
    try:
        for line in data.splitlines():
            row=_worker_json(line)
            if not isinstance(row,list) or len(row)!=len(detail['columns']):raise ValueError('row width')
            for value in row:
                if type(value) in (str,int,type(None)):continue
                if type(value) is float and math.isfinite(value):continue
                if isinstance(value,dict) and len(value)==1:
                    if set(value)=={'sqlite_blob_hex'} and isinstance(value['sqlite_blob_hex'],str):
                        encoded=value['sqlite_blob_hex']
                        if len(encoded)%2==0 and all(c in '0123456789abcdef' for c in encoded):continue
                    if set(value)=={'sqlite_nonfinite_float'} and value['sqlite_nonfinite_float'] in ('inf','-inf','nan'):continue
                raise ValueError('cell type')
            count+=1
        if count!=detail['rows_returned']:raise ValueError('row count')
        if detail['state']=='empty' and count or detail['state']=='parsed' and not count:raise ValueError('state/count')
    except (ValueError,TypeError,RecursionError) as exc:
        raise UserError('Invalid SQLite worker result rows.') from exc


def _worker(request_path,metadata_path):
    """Private child process: only copied SQLite inputs and bounded output."""
    request=json.loads(Path(request_path).read_text())
    started=time.monotonic();deadline=started+request['timeout_seconds'];denied=[]
    result={'state':'query-failed','columns':[],'rows_returned':0,'truncated':False,
            'sqlite_version':sqlite3.sqlite_version,'python_version':sys.version.split()[0],
            'authorizer_policy':'SELECT/READ/recursive CTE and explicit scalar/aggregate function allowlist; main database only',
            'resource_policy':{'sqlite_heap_bytes':64*1024**2,'field_bytes':1024**2,'sql_bytes':32768,'columns':256,'compiled_vm_operations':1000000,'wall_seconds':request['timeout_seconds']}}
    output=Path(request['output_path']);bytes_written=0
    def authorize(action,arg1,arg2,database,trigger):
        allowed=(action in {sqlite3.SQLITE_SELECT,getattr(sqlite3,'SQLITE_RECURSIVE',33)} or
                 action==sqlite3.SQLITE_READ and database in (None,'main') or
                 action==sqlite3.SQLITE_FUNCTION and str(arg2 or arg1).lower() in FUNCTIONS)
        if not allowed and len(denied)<20:denied.append({'action':action,'object':arg1,'detail':arg2,'database':database})
        return sqlite3.SQLITE_OK if allowed else sqlite3.SQLITE_DENY
    try:
        with contextlib.closing(sqlite3.connect(Path(request['database_path']).as_uri()+'?mode=ro',uri=True,timeout=0.1)) as db:
            db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA temp_store=MEMORY')
            heap=db.execute('PRAGMA hard_heap_limit=67108864').fetchone()
            if not heap or not 0<heap[0]<=64*1024**2:raise RuntimeError('SQLite heap limit could not be established')
            for name,value in [('SQLITE_LIMIT_LENGTH',1024**2),('SQLITE_LIMIT_SQL_LENGTH',32768),('SQLITE_LIMIT_COLUMN',256),('SQLITE_LIMIT_EXPR_DEPTH',100),('SQLITE_LIMIT_COMPOUND_SELECT',20),('SQLITE_LIMIT_VARIABLE_NUMBER',128),('SQLITE_LIMIT_VDBE_OP',1000000),('SQLITE_LIMIT_ATTACHED',0)]:
                db.setlimit(getattr(sqlite3,name),value)
            with contextlib.suppress(AttributeError):db.enable_load_extension(False)
            db.set_authorizer(authorize)
            db.set_progress_handler(lambda: 1 if time.monotonic()>deadline else 0,1000)
            cursor=db.execute(request['query'],request['parameters'])
            if cursor.description is None:raise RuntimeError('Query did not return a read-only result table')
            result['columns']=[column[0] for column in cursor.description]
            with output.open('x',encoding='utf-8') as stream:
                for row in cursor:
                    if time.monotonic()>deadline:raise TimeoutError('SQLite query deadline reached')
                    encoded=json.dumps([_cell(value) for value in row],ensure_ascii=True,allow_nan=False)+'\n'
                    size=len(encoded.encode('utf-8'))
                    if result['rows_returned']>=request['row_limit'] or bytes_written+size>request['max_output_bytes']:
                        result['truncated']=True;result['limit_reason']='row_limit' if result['rows_returned']>=request['row_limit'] else 'output_bytes';break
                    stream.write(encoded);bytes_written+=size;result['rows_returned']+=1
            result['state']='limited' if result['truncated'] else 'parsed' if result['rows_returned'] else 'empty'
    except (sqlite3.Error,ValueError,RuntimeError,TimeoutError,MemoryError,OSError,OverflowError) as exc:
        code=(getattr(exc,'sqlite_errorcode',0) or 0)&0xff
        state=('denied' if denied else 'timed-out' if isinstance(exc,TimeoutError) or time.monotonic()>deadline else
               'corrupt' if code==sqlite3.SQLITE_CORRUPT else 'unsupported-or-corrupt' if code==sqlite3.SQLITE_NOTADB else
               'unsupported-schema' if 'no such table' in str(exc) or 'no such column' in str(exc) else
               'resource-limited' if isinstance(exc,MemoryError) or code in {sqlite3.SQLITE_TOOBIG,sqlite3.SQLITE_NOMEM} else 'query-failed')
        result.update(state=state,error=str(exc),sqlite_errorcode=getattr(exc,'sqlite_errorcode',None),partial_rows_unverified=result['rows_returned'])
    result.update(denied_operations=denied,bytes_written=bytes_written,elapsed_seconds=time.monotonic()-started)
    Path(metadata_path).write_text(json.dumps(result,ensure_ascii=True,indent=2)+'\n')


def _inputs(root,db,file_id):
    from .core import UserError,digest
    row=db.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone()
    if not row:raise UserError('Unknown retained SQLite file ID in this case.')
    selected=[('',dict(row))]
    for suffix in ('-wal','-shm','-journal'):
        rows=list(db.execute('SELECT * FROM files WHERE evidence_id=? AND (path=? OR logical_path=?)',(row['evidence_id'],row['path']+suffix,row['logical_path']+suffix)))
        if len(rows)>1:raise UserError('Ambiguous SQLite companion association.')
        if rows:selected.append((suffix,dict(rows[0])))
        physical=root/'evidence'/row['evidence_id']/(row['path']+suffix)
        if (physical.exists() or physical.is_symlink()) and not rows:raise UserError('Untracked SQLite companion; intake reconciliation required.')
    if sum(item['size'] for _,item in selected)>MAX_INPUT_BYTES:raise UserError('SQLite inputs exceed512MiB working-copy limit.')
    for suffix,item in selected:
        base=root/'evidence'/item['evidence_id'];path=base/item['path']
        if any(p.is_symlink() for p in [path,*path.parents] if p!=root.parent) or not path.is_file() or not path.resolve().is_relative_to(base.resolve()):raise UserError('Unsafe retained SQLite source.')
        if path.stat().st_size!=item['size'] or digest(path)!=item['sha256']:raise UserError('Retained SQLite source integrity mismatch.')
        item['retained_path']=str(path)
    return selected


def _validate_query(file_id,sql,parameters,row_limit,max_output_bytes,timeout_seconds):
    from .core import UserError
    if type(file_id) is not int or file_id<1:raise UserError('Positive retained file ID required.')
    if not isinstance(sql,str) or not sql.strip() or len(sql.encode())>32768:raise UserError('Query must contain1–32768 UTF8 bytes.')
    if not isinstance(parameters,(list,tuple)) or len(parameters)>128 or any(type(x) not in (str,int,float,type(None)) for x in parameters):raise UserError('At most128 scalar JSON parameters required.')
    if any(type(x) is int and not -(2**63)<=x<2**63 for x in parameters):raise UserError('Integer parameters must fit signed64-bit SQLite values.')
    if any(type(x) is float and not math.isfinite(x) for x in parameters) or len(json.dumps(parameters).encode())>1024**2:raise UserError('Invalid or oversized query parameters.')
    if type(row_limit) is not int or not 1<=row_limit<=100000:raise UserError('Row limit must be1–100000.')
    if type(max_output_bytes) is not int or not 1024<=max_output_bytes<=MAX_OUTPUT_BYTES:raise UserError('Output budget must be1024–16777216 bytes.')
    if type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or not 0.05<=timeout_seconds<=30:raise UserError('Timeout must be0.05–30 seconds.')


def query(root,db,file_id,sql,parameters=(),row_limit=1000,max_output_bytes=8*1024**2,timeout_seconds=5):
    from .core import UserError
    from .runner_lease import CURRENT,lease
    _validate_query(file_id,sql,parameters,row_limit,max_output_bytes,timeout_seconds)
    _inputs(root,db,file_id)  # Preserve source/scope refusal before lease mutation.
    context=CURRENT.get()
    if context is not None:
        if context['root']!=str(root):raise UserError('SQLite query belongs to a different runner case.')
        return _query_owned(root,db,file_id,sql,parameters,row_limit,max_output_bytes,timeout_seconds)
    with lease(root,db):
        return _query_owned(root,db,file_id,sql,parameters,row_limit,max_output_bytes,timeout_seconds)


def _query_owned(root,db,file_id,sql,parameters=(),row_limit=1000,max_output_bytes=8*1024**2,timeout_seconds=5):
    """Record a scoped read-only query and result receipt, including failures.

    Returns metadata plus at most100 preview rows. Full bounded output is a
    hashed JSONL array stream; columns are a separate ordered list so duplicate
    names, NULLs, BLOBs and numeric values are not silently collapsed.
    """
    from .core import UserError,audit,digest,json_text,now
    selected=_inputs(root,db,file_id);eid=selected[0][1]['evidence_id']
    from .sqlite_container import configured,MAX_INPUT,execution_profile
    container_cfg=configured(root)
    import os
    if os.environ.get('LAWLIET_MCP_PROFILE')=='sqlite-container' and container_cfg is None:raise UserError('SQLite container endpoint requires isolation; no host fallback.')
    container_profile=execution_profile() if container_cfg is not None else None
    if container_cfg is not None and sum(item['size'] for suffix,item in selected if suffix!='-shm')>MAX_INPUT:raise UserError('SQLite container input bundle exceeds64MiB; no host fallback.')
    if shutil.disk_usage(root).free<sum(item['size'] for _,item in selected)+64*1024**2:raise UserError('Insufficient free space for SQLite working copies and reserve.')
    runs=root/'runs'
    if any(p.is_symlink() for p in [runs,*runs.parents]) or not runs.resolve().is_relative_to(root.resolve()):raise UserError('Unsafe query output directory.')
    from .container_runner import create_run_directory
    from .runner_lease import ownership
    owner=ownership();rid=uuid.uuid4().hex[:12];folder=create_run_directory(root,rid)
    container_labels=None
    if container_cfg is not None:
        from .sqlite_container import labels
        container_labels=labels(root,rid,owner)
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)',(rid,eid,VERSION,now(),'running',json_text({'runner_ownership':owner,**({'sqlite_container_config':container_cfg,'container_execution_profile':container_profile,'sqlite_container_labels':container_labels} if container_cfg is not None else {})})))
    input_receipt=[{'suffix':suffix,'file_id':item['id'],'logical_path':item['logical_path'],'sha256':item['sha256'],'bytes':item['size']} for suffix,item in selected]
    request={'query':sql,'parameters':list(parameters),'row_limit':row_limit,'max_output_bytes':max_output_bytes,'timeout_seconds':timeout_seconds,'worker_source_sha256':digest(Path(__file__)),'source_file_id':file_id,'inputs':input_receipt,'scope':'Supplied retained SQLite view only; query semantics are examiner supplied.'}
    if container_cfg is not None:request['container_execution_profile']=container_profile
    (folder/'query.json').write_text(json.dumps(request,ensure_ascii=True,indent=2)+'\n')
    audit(db,'sqlite_query.started',{'run_id':rid,'evidence_id':eid,'file_id':file_id,'query_sha256':digest(folder/'query.json'),'runner_ownership':owner,**({'sqlite_container_config':container_cfg,'container_execution_profile':container_profile,'sqlite_container_labels':container_labels} if container_cfg is not None else {})});db.commit()
    detail={};status='failed';outputs=None;container_receipt=None
    try:
        from .child_output import ChildOutputs
        outputs=ChildOutputs(folder).__enter__()
        with tempfile.TemporaryDirectory(prefix='lawliet-query-',dir=folder) as tmp:
            working=Path(tmp)/'source.db'
            for suffix,item in selected:
                if suffix=='-shm':continue # Rebuild working SHM; preserve supplied SHM untouched.
                target=Path(str(working)+suffix);shutil.copyfile(item['retained_path'],target)
                if digest(target)!=item['sha256']:raise UserError('SQLite working-copy integrity mismatch.')
            header=working.read_bytes()[:20] if working.stat().st_size<4096 else None
            if header is None:
                with working.open('rb') as stream:header=stream.read(20)
            wal_present=any(suffix=='-wal' for suffix,_ in selected)
            warnings=[]
            if len(header)>=20 and header[18:20]==b'\x02\x02':warnings.append('WAL pairing unverified; readable rows do not prove companion provenance.' if wal_present else 'WAL companion missing; only checkpointed view may be available.')
            elif wal_present:warnings.append('Supplied WAL pairing unverified; SQLite may ignore an incompatible companion.')
            worker_request={**request,'database_path':str(working),'output_path':str(folder/'result.jsonl')}
            worker_path=Path(tmp)/'worker-request.json';worker_path.write_text(json.dumps(worker_request))
            try:
                from .tools import execute
                if container_cfg is None:
                    process=execute([sys.executable,'-I',str(Path(__file__).resolve()),'--worker',str(worker_path),str(folder/'worker-result.json')],folder/'worker.stdout',timeout_seconds+2,cwd=tmp)
                else:
                    from .sqlite_container import run as run_container
                    try:decoded,container_receipt=run_container(root,rid,owner,container_cfg,selected,request,folder)
                    except BaseException as exc:
                        container_receipt=getattr(exc,'tool_result',{}).get('container');raise
                    from .anchored_output import OutputFiles
                    paths=[folder/'worker-result.json',folder/'result.jsonl',folder/'worker.stdout.stderr']
                    with OutputFiles(paths) as publication:
                        for target,data in zip(paths,[json.dumps(decoded['metadata']).encode(),decoded['result'],outputs.read('container.stderr',65536)]):
                            with publication.open(target) as stream:stream.buffer.write(data)
                        publication.publish()
                    process={'returncode':0}
                from .anchored_output import OutputFiles
                retained_errors=folder/'worker.stderr'
                error_bytes=outputs.read('worker.stdout.stderr',65536,prefix=True)
                with OutputFiles([retained_errors]) as publication:
                    with publication.open(retained_errors) as stream:stream.buffer.write(error_bytes)
                    publication.publish()
                if process['returncode'] or not (folder/'worker-result.json').is_file():detail={'state':'worker-failed','error':'Isolated SQLite worker did not complete','returncode':process['returncode']}
                else:
                    try:detail=_worker_json(outputs.read('worker-result.json',MAX_WORKER_METADATA_BYTES))
                    except (ValueError,RecursionError) as exc:raise UserError('Invalid SQLite worker metadata.') from exc
                    if (not isinstance(detail,dict) or not isinstance(detail.get('state'),str)
                        or type(detail.get('rows_returned')) is not int or not 0<=detail['rows_returned']<=row_limit
                        or not isinstance(detail.get('columns'),list) or len(detail['columns'])>256
                        or any(not isinstance(c,str) for c in detail['columns']) or type(detail.get('truncated')) is not bool):
                        detail={}
                        raise UserError('Invalid SQLite worker metadata.')
                    detail.pop('result_sha256',None);detail.pop('result_path',None)
            except subprocess.TimeoutExpired:
                detail={'state':'timed-out','error':'Isolated worker wall-clock deadline exceeded'}
            if digest(Path(__file__))!=request['worker_source_sha256']:raise UserError('SQLite worker source changed during execution; result not promoted.')
            detail.update(worker_source_sha256=request['worker_source_sha256'],run_id=rid,inputs=input_receipt,warnings=warnings,wal_pairing='unverified' if wal_present else 'not-supplied',source_file_id=file_id,query_sha256=digest(folder/'query.json'),query_path=str(folder/'query.json'))
            _inputs(root,db,file_id) # Source and supplied sidecars still exactly match intake hashes.
            detail['originals_unchanged']=True
            if (folder/'result.jsonl').exists() or (folder/'result.jsonl').is_symlink():
                result_bytes=outputs.read('result.jsonl',max_output_bytes)
                if detail['state'] in {'parsed','empty','limited'}:_validate_result(result_bytes,detail)
                detail.update(result_path=str(folder/'result.jsonl'),result_sha256=hashlib.sha256(result_bytes).hexdigest())
            if detail['state'] in {'parsed','empty','limited'}:
                if 'result_sha256' not in detail:raise UserError('SQLite worker result is missing.')
                if warnings:detail['state']='limited'
                status='complete'
    except BaseException as exc:
        status='interrupted' if isinstance(exc,KeyboardInterrupt) else 'failed'
        detail.update(state=status,error=str(exc));raise
    finally:
        try:
            if outputs is not None:outputs.check_directory()
            detail['runner_ownership']=owner
            if container_cfg is not None:
                detail['sqlite_container_config']=container_cfg
                detail['sqlite_container_labels']=container_labels
                detail['container_execution_profile']=container_profile
                if container_receipt is not None:detail['container']=container_receipt
            from .anchored_output import OutputFiles
            receipt=folder/'receipt.json'
            with OutputFiles([receipt]) as publication:
                with publication.open(receipt) as stream:stream.write(json.dumps(detail,ensure_ascii=True,indent=2)+'\n')
                receipt_sha256=publication.digest(receipt)
                publication.publish()
            db.execute('UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?',(now(),status,detail.get('rows_returned',0) if status=='complete' else 0,json_text(detail),rid))
            audit(db,'sqlite_query.finished',{'run_id':rid,'status':status,'receipt_sha256':receipt_sha256,'result_sha256':detail.get('result_sha256'),**({'container':container_receipt} if container_receipt is not None else {}),**({'sqlite_container_labels':container_labels} if container_cfg is not None else {})});db.commit()
        finally:
            if outputs is not None:outputs.__exit__()
    return {**detail,'receipt_path':str(receipt),'status':status,'preview':read_result(root,db,rid,limit=min(row_limit,100)) if status=='complete' else None}


def schema(root,db,file_id,**limits):
    return query(root,db,file_id,SCHEMA_QUERY,**limits)


def read_result(root,db,run_id,offset=0,limit=100):
    """Page verified retained bytes; never execute SQL or open a child database.

    Receipt/query view caps deliberately refuse oversized legacy metadata. The
    current producer permits1MiB worker metadata/parameters plus bounded query
    and provenance, so2MiB per control file is conservative. This verifies the
    bytes read, not an atomic snapshot of evidence or later filesystem changes.
    """
    from .core import UserError,json_text
    from .child_output import ChildOutputs
    if type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=1000:raise UserError('Result page requires nonnegative offset and limit1–1000.')
    if not isinstance(run_id,str) or len(run_id)!=12 or any(c not in '0123456789abcdef' for c in run_id):raise UserError('Invalid SQLite query run ID.')
    run=db.execute('SELECT * FROM runs WHERE id=? AND engine=?',(run_id,VERSION)).fetchone()
    if not run or run['status']!='complete':raise UserError('No completed SQLite query in this case.')
    previous='0'*64;finished=[];started=[]
    try:
        for event in db.execute('SELECT * FROM audit ORDER BY id'):
            expected=hashlib.sha256(json_text([event['at'],event['action'],event['detail'],previous]).encode()).hexdigest()
            if event['previous_hash']!=previous or event['hash']!=expected:raise UserError('SQLite audit chain integrity mismatch.')
            previous=event['hash']
            if event['action'] in ('sqlite_query.started','sqlite_query.finished'):
                if not isinstance(event['detail'],str) or len(event['detail'].encode('utf-8'))>MAX_RESULT_VIEW_RECEIPT_BYTES:raise ValueError('audit metadata bound')
                item=_worker_json(event['detail'])
                if not isinstance(item,dict):raise ValueError('audit metadata shape')
                if item.get('run_id')==run_id:(started if event['action'].endswith('started') else finished).append(item)
        if len(started)!=1 or len(finished)!=1 or finished[0].get('status')!='complete':raise UserError('SQLite query receipt missing or ambiguous.')
        folder=Path(root)/'runs'/run_id
        with ChildOutputs(folder) as outputs:
            receipt_bytes=outputs.read('receipt.json',MAX_RESULT_VIEW_RECEIPT_BYTES)
            request_bytes=outputs.read('query.json',MAX_RESULT_VIEW_QUERY_BYTES)
            receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest()
            query_sha256=hashlib.sha256(request_bytes).hexdigest()
            if receipt_sha256!=finished[0].get('receipt_sha256') or query_sha256!=started[0].get('query_sha256'):raise UserError('SQLite receipt integrity mismatch.')
            detail=_worker_json(receipt_bytes)
            request=_worker_json(request_bytes)
            if not isinstance(run['detail'],str) or len(run['detail'].encode('utf-8'))>MAX_RESULT_VIEW_RECEIPT_BYTES:raise ValueError('run metadata bound')
            stored_detail=_worker_json(run['detail'])
            if (not isinstance(detail,dict) or detail!=stored_detail or detail.get('run_id')!=run_id
                    or detail.get('result_sha256')!=finished[0].get('result_sha256')
                    or detail.get('query_sha256')!=query_sha256):raise UserError('SQLite run integrity mismatch.')
            if not isinstance(request,dict):raise ValueError('query metadata shape')
            if (detail.get('state') not in {'parsed','empty','limited'}
                    or type(detail.get('rows_returned')) is not int or not 0<=detail['rows_returned']<=100000
                    or type(run['records']) is not int or run['records']!=detail['rows_returned']
                    or not isinstance(detail.get('columns'),list) or len(detail['columns'])>256
                    or any(not isinstance(column,str) for column in detail['columns'])
                    or type(detail.get('truncated')) is not bool):raise ValueError('result metadata shape')
            result_bytes=outputs.read('result.jsonl',MAX_OUTPUT_BYTES)
            result_sha256=hashlib.sha256(result_bytes).hexdigest()
            if result_sha256!=detail.get('result_sha256'):raise UserError('SQLite result integrity mismatch.')
            _validate_result(result_bytes,detail)
            rows=[]
            for number,line in enumerate(result_bytes.splitlines()):
                if number<offset:continue
                if len(rows)>=limit:break
                rows.append(_worker_json(line))
            outputs.check_directory()
    except (OSError,ValueError,TypeError,RecursionError) as exc:
        raise UserError('SQLite retained result is unsafe, oversized or invalid.') from exc
    return {'columns':detail['columns'],'rows':rows,'offset':offset,
            'has_more':offset+len(rows)<detail['rows_returned'],'query_truncated':detail['truncated'],'state':detail['state'],
            'run_id':run_id,'total_rows':detail['rows_returned'],'result_sha256':result_sha256,
            'integrity_scope':'Verified retained receipt/query/result bytes against this case audit and run metadata; query output only, not independent source verification or evidence completeness.'}

if __name__=='__main__':
    if len(sys.argv)!=4 or sys.argv[1]!='--worker':raise SystemExit('Private SQLite worker invocation required')
    _worker(sys.argv[2],sys.argv[3])
