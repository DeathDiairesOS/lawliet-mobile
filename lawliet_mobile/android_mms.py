"""Narrow raw Android MMS schema; no payload fetching or inferred identity."""
import json
import math
import sqlite3
from collections import Counter,defaultdict
from datetime import datetime,timedelta,timezone
from pathlib import PurePosixPath
from .messages import metadata

SCHEMA='android-pdu-part-addr/1'
REQUIRED={'pdu':{'_id','thread_id','date','msg_box','m_type'},
          'part':{'_id','mid','seq','ct','text','_data','chset'},
          'addr':{'_id','msg_id','address','type','charset'}}
LIMIT=100000
MAX_VALUE_BYTES=1024*1024
MAX_RAW_TABLE_BYTES=32*1024*1024


def _raw(row):
    return {key:({'sqlite_blob_hex':value.hex()} if isinstance(value,bytes) else
                 {'sqlite_nonfinite_float':str(value)} if isinstance(value,float) and not math.isfinite(value) else value)
            for key,value in row.items()}


def _time(value):
    # Declared raw provider timestamps are integer seconds, never guessed units.
    if type(value) is not int:return None
    try:
        dt=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(seconds=value)
        return dt.isoformat(timespec='microseconds').replace('+00:00','Z') if 1990<=dt.year<=2200 else None
    except (ValueError,OverflowError):return None


def _payload(part,files):
    path=part.get('_data')
    result={'recorded_path':_raw({'path':path})['path'],'status':'no-file-reference','file_id':None}
    if path is None or path=='':return result
    if not isinstance(path,str) or '..' in PurePosixPath(path).parts:
        result['status']='unsupported-path';return result
    # Full recorded path only. No CE/DE, profile, basename or directory alias guess.
    logical=path[1:] if path.startswith('/') else path
    matches=[dict(f) for f in files if f['logical_path'] in {path,logical}]
    result['status']='not-acquired'
    if len(matches)>1:result['status']='ambiguous-path'
    elif matches:
        f=matches[0];result.update(status='exact-retained-path-reference',file_id=f['id'],logical_path=f['logical_path'],sha256=f['sha256'],bytes=f['size'])
    result['payload_decoded']=False
    return result


def decode(db,logical_path,files=(),platform='unknown'):
    """Return bounded artifact tuples and residual limitations from copied SQLite."""
    names={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not names.intersection({'pdu','part','addr'}):return [],[],False
    def warning(reason,**extra):return {'source':logical_path,'state':'unsupported','reason':reason,**extra}
    if platform!='android' or PurePosixPath(logical_path).name.lower()!='mmssms.db':
        return [],[warning('MMS candidate schema outside declared Android mmssms.db scope; raw tables retained.')],False
    for table,cols in REQUIRED.items():
        actual={r[1] for r in db.execute(f'PRAGMA table_info("{table}")')} if table in names else set()
        if {'__source_rowid__','rowid'} & {name.lower() for name in actual}:
            return [],[warning('Reserved source-rowid alias collision; no reliable row citation emitted.',table=table)],False
        if not cols<=actual:return [],[warning('Unknown MMS schema: required columns missing; no guessed field/unit mapping.',table=table,missing_columns=sorted(cols-actual))],False
    rows={};warnings=[];serialized_bytes=0
    prior_limit=db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
    # SQLite rejects oversized values/rows before Python materializes their BLOBs.
    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,min(prior_limit,MAX_VALUE_BYTES))
    try:
        for table in REQUIRED:
            cursor=db.execute(f'SELECT rowid AS __source_rowid__,* FROM "{table}" ORDER BY rowid')
            columns=[c[0] for c in cursor.description];values=[]
            for row in cursor:
                if len(values)>=LIMIT:
                    return [],[warning('MMS table exceeds bounded row budget; no partial success claim.',table=table,row_limit=LIMIT,state='resource-limited')],False
                value=dict(zip(columns,row))
                size=len(json.dumps(_raw(value),ensure_ascii=True,allow_nan=False).encode('utf-8'))
                serialized_bytes+=size
                if serialized_bytes>MAX_RAW_TABLE_BYTES:
                    return [],[warning('MMS serialized raw-table byte budget exceeded; no partial success claim.',table=table,raw_table_budget=MAX_RAW_TABLE_BYTES,state='resource-limited')],False
                values.append(value)
            rows[table]=values
    except sqlite3.DataError:
        return [],[warning('MMS SQLite value/row exceeds bounded input bytes; no partial success claim.',value_bytes=MAX_VALUE_BYTES,state='resource-limited')],False
    finally:
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,prior_limit)
    counts=Counter(p['_id'] for p in rows['pdu'] if type(p['_id']) is int)
    part_links=defaultdict(list);addr_links=defaultdict(list);orphans=[]
    for table,key,target in [('part','mid',part_links),('addr','msg_id',addr_links)]:
        for row in rows[table]:
            parent=row[key]
            if type(parent) is int and counts.get(parent)==1:target[parent].append(row)
            else:orphans.append((table,row,'ambiguous-parent' if counts.get(parent,0)>1 else 'missing-parent'))
    output=[]
    for pdu in rows['pdu']:
        pid=pdu['_id'];unique=type(pid) is int and counts[pid]==1
        parts=part_links[pid] if unique else [];addresses=addr_links[pid] if unique else []
        seqs=[p['seq'] for p in parts]
        ordering_known=all(type(seq) is int for seq in seqs) and len(set(seqs))==len(seqs)
        parts=sorted(parts,key=lambda p:(p['seq'] if ordering_known else 0,p['__source_rowid__']))
        address_data=[];from_values=[];to_values=[]
        for address in addresses:
            value=address['address'];role={137:'from',151:'to',130:'cc',129:'bcc'}.get(address['type'],'unknown') if type(address['type']) is int else 'unknown'
            usable=isinstance(value,str) and value not in ('','insert-address-token') and address['charset'] in (None,106)
            address_data.append({'raw':_raw(address),'role':role,'usable_text':usable,'source_ref':f"addr:rowid={address['__source_rowid__']}"})
            if usable and role=='from':from_values.append(value)
            if usable and role=='to':to_values.append(value)
        bodies=[];part_data=[];limited=not unique or not parts or len(from_values)!=1 or not ordering_known
        for part in parts:
            charset_known=part['chset'] in (None,106)
            text_ok=part['ct']=='text/plain' and isinstance(part['text'],str) and charset_known
            if text_ok:bodies.append(part['text'])
            state='inline-text-retained' if text_ok else 'smil-not-decoded' if part['ct']=='application/smil' else 'unsupported-or-binary-part'
            if not text_ok:limited=True
            part_data.append({'raw':_raw(part),'source_ref':f"part:rowid={part['__source_rowid__']}",'state':state,'payload':_payload(part,files)})
        ordinary=type(pdu['m_type']) is int and pdu['m_type'] in (128,132) and unique
        direction={1:'incoming',2:'outgoing',3:'draft',4:'outbox',5:'failed'}.get(pdu['msg_box'],'unknown') if type(pdu['msg_box']) is int else 'unknown'
        when=_time(pdu['date']);ref=f"pdu:rowid={pdu['__source_rowid__']};_id={pid}"
        data={'mms_schema':SCHEMA,'raw_pdu':_raw(pdu),'parts':part_data,'addresses':address_data,
              'source_database':logical_path,'timestamp_semantics':'Declared Android provider pdu.date integer Unix seconds; raw date_sent retained separately, not substituted.',
              'support_state':'limited-development-schema','independent_review':'pending',
              'record_state':'content-pdu' if ordinary else 'control-or-unsupported-pdu',
              'part_ordering':'source-seq' if ordering_known else 'unknown',
              'body_composition':'Supported text/plain parts joined with newline; original boundaries and seq retained in parts.' if ordering_known else 'Unknown part order; no aggregate message body emitted.',
              'source_locator':{'table':'pdu','rowid':pdu['__source_rowid__'],'key':_raw({'id':pid})['id']}}
        if ordinary:
            sender=from_values[0] if len(from_values)==1 else ''
            recipient=to_values[0] if len(to_values)==1 else ''
            data['message']=metadata('mms',pdu['thread_id'] if pdu['thread_id'] is not None else 'unlinked:'+ref,sender,recipient,direction,
                recipients=to_values,participants=[x['raw']['address'] for x in address_data if x['usable_text']],sender_state='single-source-address' if len(from_values)==1 else 'unknown-or-ambiguous',attachment_status='reference-only',timestamp_field='pdu.date')
        if not ordinary or limited or when is None or any(not a['usable_text'] or a['role']=='unknown' for a in address_data):
            warnings.append(warning('MMS record contains unsupported/control/ambiguous metadata or undecoded parts; raw rows retained, no completeness claim.',table='pdu',source_ref=ref))
        output.append(('messages' if ordinary else 'mms_candidates',when,_raw({'date':pdu['date']})['date'],('MMS' if ordinary else 'Undecoded MMS PDU')+' · '+direction,'\n'.join(bodies) if ordinary and ordering_known else '',ref,data))
    for table,row,state in orphans:
        data={'mms_schema':SCHEMA,'record_state':state,'raw_record':_raw(row),'source_database':logical_path,
              'source_locator':{'table':table,'rowid':row['__source_rowid__'],'key':_raw({'id':row['_id']})['id']}}
        if table=='part':data['payload']=_payload(row,files)
        ref=f"{table}:rowid={row['__source_rowid__']}"
        output.append(('mms_candidates',None,None,'Unlinked MMS '+table,'',ref,data))
        warnings.append(warning('Unlinked MMS child retained without parent time, identity or message attribution.',table=table,source_ref=ref))
    return output,warnings,True
