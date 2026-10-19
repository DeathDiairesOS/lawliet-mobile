"""Staged bounded container result decoder; not wired into LAWLIET."""
import base64
import binascii
import hashlib
import json
from .core import UserError
from .sqlite_workspace import _worker_json, _validate_result, MAX_OUTPUT_BYTES

PROTOCOL='lawliet-python-sqlite-output/1'
MAX_FRAME=32*1024**2
MAX_METADATA=1024**2
STATES={'parsed','empty','limited','denied','timed-out','corrupt',
        'unsupported-or-corrupt','unsupported-schema','resource-limited','query-failed'}
FIELDS={'state','columns','rows_returned','truncated','sqlite_version','python_version',
        'authorizer_policy','resource_policy','denied_operations','bytes_written',
        'elapsed_seconds','error','sqlite_errorcode','partial_rows_unverified','limit_reason'}


def _structure(raw):
    depth=tokens=0;quoted=escaped=False
    for byte in raw:
        if quoted:
            if escaped:escaped=False
            elif byte==92:escaped=True
            elif byte==34:quoted=False
        elif byte==34:
            quoted=True;tokens+=1
        elif byte in (123,91):
            depth+=1;tokens+=1
            if depth>16:raise UserError('Container envelope nesting limit exceeded.')
        elif byte in (125,93):
            depth-=1
            if depth<0:raise UserError('Malformed container envelope.')
        elif byte in (44,58):tokens+=1
        if tokens>10000:raise UserError('Container envelope structure limit exceeded.')
    if depth or quoted:raise UserError('Incomplete container envelope.')


def decode(raw,request,*,request_sha256):
    if not isinstance(raw,bytes) or len(raw)>MAX_FRAME:raise UserError('Container envelope exceeds byte limit.')
    maximum=request['max_output_bytes'];row_limit=request['row_limit']
    if type(maximum) is not int or not 1024<=maximum<=MAX_OUTPUT_BYTES or type(row_limit) is not int or not 1<=row_limit<=100000:
        raise UserError('Invalid trusted output budget.')
    _structure(raw)
    try:
        frame=_worker_json(raw)
        if (not isinstance(frame,dict) or set(frame)!={'protocol','metadata','result_base64','result_sha256','result_bytes','request_sha256','worker_source_sha256','inputs_sha256'}
            or frame['protocol']!=PROTOCOL):raise ValueError('envelope schema')
        expected_inputs={i['name']:i['sha256'] for i in request['inputs']}
        if (not isinstance(request_sha256,str) or len(request_sha256)!=64 or any(c not in '0123456789abcdef' for c in request_sha256)
            or frame['request_sha256']!=request_sha256 or frame['worker_source_sha256']!=request['worker_source_sha256']
            or frame['inputs_sha256']!=expected_inputs):raise ValueError('request/source binding')
        encoded=frame['result_base64']
        if not isinstance(encoded,str) or len(encoded)>4*((maximum+2)//3):raise ValueError('base64 bound')
        data=base64.b64decode(encoded,validate=True)
        if (len(data)>maximum or type(frame['result_bytes']) is not int or frame['result_bytes']!=len(data)
            or frame['result_sha256']!=hashlib.sha256(data).hexdigest()):raise ValueError('result identity')
        meta=frame['metadata']
        if (not isinstance(meta,dict) or not set(meta)<=FIELDS or meta.get('state') not in STATES
            or type(meta.get('rows_returned')) is not int or not 0<=meta['rows_returned']<=row_limit
            or not isinstance(meta.get('columns'),list) or len(meta['columns'])>256
            or any(not isinstance(c,str) for c in meta['columns']) or type(meta.get('truncated')) is not bool
            or type(meta.get('bytes_written')) is not int or meta['bytes_written']!=len(data)
            or len(json.dumps(meta,ensure_ascii=True,allow_nan=False).encode())>MAX_METADATA):raise ValueError('metadata schema/bound')
        line_count=data.count(b'\n')+data.count(b'\r')-data.count(b'\r\n')
        if data and not data.endswith((b'\n',b'\r')):line_count+=1
        if line_count!=meta['rows_returned']:raise ValueError('row line count')
        _validate_result(data,meta)
        return {'metadata':meta,'result':data,'result_sha256':hashlib.sha256(data).hexdigest()}
    except (ValueError,TypeError,KeyError,binascii.Error,RecursionError) as exc:
        raise UserError('Invalid container result envelope; no result promoted.') from exc
