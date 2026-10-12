"""Append-only examiner findings, separate from acquired and parsed records."""
from pathlib import Path
import hashlib
import json
import uuid
import unicodedata
from .core import UserError, audit, json_text, now, digest
from .report import safe_output

SCHEMA='''CREATE TABLE IF NOT EXISTS findings(
 id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, created_at TEXT NOT NULL,
 examiner TEXT NOT NULL, note TEXT NOT NULL, snapshot TEXT NOT NULL,
 sha256 TEXT NOT NULL)'''


def exists(db):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='findings'").fetchone() is not None


def checksum(value):
    return hashlib.sha256(json_text(value).encode('utf-8')).hexdigest()


def add_finding(db, artifact_id, note, examiner=''):
    if not isinstance(note,str) or not note.strip() or len(note)>20000:
        raise UserError('Enter a finding note of 1–20,000 characters.')
    if not isinstance(examiner,str) or len(examiner)>200:
        raise UserError('Examiner label must be at most 200 characters.')
    row=db.execute('SELECT a.*,f.logical_path,f.sha256 AS source_sha256 FROM artifacts a LEFT JOIN files f ON f.id=a.file_id WHERE a.id=?',(artifact_id,)).fetchone()
    if row is None:raise UserError('Unknown artifact in this case.')
    snapshot=dict(row);snapshot['data']=json.loads(snapshot['data'])
    value={'id':uuid.uuid4().hex[:16],'artifact_id':artifact_id,'created_at':now(),
           'examiner':examiner,'note':note,'snapshot':snapshot}
    sha=checksum(value)
    db.execute(SCHEMA)
    db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?)',(value['id'],artifact_id,value['created_at'],examiner,note,json_text(snapshot),sha))
    audit(db,'finding.created',{'finding_id':value['id'],'artifact_id':artifact_id,'sha256':sha})
    return {**value,'sha256':sha}


def check_inventory(db):
    receipts={}
    for row in db.execute("SELECT detail FROM audit WHERE action='finding.created'"):
        try:
            receipt=json.loads(row['detail']);identifier=receipt['finding_id']
            if not isinstance(identifier,str) or identifier in receipts:
                raise ValueError('Duplicate or invalid finding ID')
            receipts[identifier]=receipt
        except (ValueError,KeyError,TypeError) as exc:
            raise UserError('Saved finding audit inventory is malformed.') from exc
    actual={r['id'] for r in db.execute('SELECT id FROM findings')} if exists(db) else set()
    if set(receipts)!=actual:
        raise UserError('Saved finding inventory mismatch: '+str(len(set(receipts)-actual))+' missing, '+str(len(actual-set(receipts)))+' without creation receipts.')
    return receipts


def checked_value(row,receipts):
    value=dict(row);sha=value.pop('sha256')
    try:value['snapshot']=json.loads(value['snapshot'])
    except (ValueError,TypeError) as exc:raise UserError('Saved finding snapshot is malformed: '+value['id']) from exc
    if checksum(value)!=sha:raise UserError('Saved finding integrity mismatch: '+value['id'])
    receipt={'finding_id':value['id'],'artifact_id':value['artifact_id'],'sha256':sha}
    if receipts.get(value['id'])!=receipt:
        raise UserError('Saved finding has no matching audit receipt: '+value['id'])
    return {**value,'sha256':sha}


def verify_findings(db):
    receipts=check_inventory(db)
    if receipts:
        for row in db.execute('SELECT * FROM findings'):checked_value(row,receipts)
    return len(receipts)


def list_findings(db, limit=100, offset=0):
    if not isinstance(limit,int) or not 1<=limit<=1000 or not isinstance(offset,int) or offset<0:
        raise UserError('Invalid findings page; limit must be 1–1,000 and offset nonnegative.')
    receipts=check_inventory(db)
    if not exists(db):return {'findings':[],'total':0,'offset':offset,'has_more':False}
    values=[]
    for row in db.execute('SELECT * FROM findings ORDER BY created_at,id LIMIT ? OFFSET ?',(limit,offset)):
        values.append(checked_value(row,receipts))
    total=db.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
    return {'findings':values,'total':total,'offset':offset,'has_more':offset+len(values)<total}


def readable(value):
    """Visible control characters for human review; JSONL retains exact values."""
    text=str(value if value is not None else '')
    return ''.join(c if c in '\n\t' or unicodedata.category(c) not in {'Cc','Cf'} else '\\u'+format(ord(c),'04x') for c in text)


def text_finding(finding,number):
    record=finding['snapshot']
    def block(label,value):
        return label+'\n'+'\n'.join('  | '+line for line in readable(value).split('\n'))+'\n'
    output='\n'+'='*72+'\nFINDING '+str(number)+' — '+finding['id']+'\n'
    output+=block('Examiner label (not authenticated):',finding['examiner'] or '[unspecified]')
    output+='Saved at: '+finding['created_at']+'\n'
    output+=block('EXAMINER NOTE — interpretation, not original evidence:',finding['note'])
    output+=block('SAVED RECORD TITLE:',record.get('title'))
    output+=block('SAVED RECORD BODY:',record.get('body'))
    for label,key in [('Artifact ID','id'),('Evidence ID','evidence_id'),('Category','category'),('Record timestamp','timestamp'),('Parser','parser'),('Source reference','source_ref'),('Logical path','logical_path'),('Stored source SHA-256','source_sha256')]:
        output+=block(label+':',record.get(key) if record.get(key) is not None else '[not available]')
    output+='Saved finding checksum: '+finding['sha256']+'\n'
    return output


def export_findings(root,db,destination,format_name='jsonl'):

    # Hold one database snapshot across inventory checking, pagination and
    # receipt creation, even when another CLI/app instance has the case open.
    if format_name not in {'jsonl','text'}:raise UserError('Findings export format must be jsonl or text.')
    created=[]
    db.execute('SAVEPOINT findings_export')
    try:
        result=_export_findings(root,db,destination,format_name,created)
        db.execute('RELEASE SAVEPOINT findings_export')
        return result
    except BaseException:
        try:
            db.execute('ROLLBACK TO SAVEPOINT findings_export')
            db.execute('RELEASE SAVEPOINT findings_export')
        finally:
            for item in reversed(created):item.unlink(missing_ok=True)
        raise


def _export_findings(root,db,destination,format_name,created):
    requested=Path(destination).expanduser()
    raw_paths=[requested,Path(str(requested)+'.coverage.json'),Path(str(requested)+'.receipt.json')]
    if any(item.is_symlink() for item in raw_paths):
        raise UserError('Findings output, coverage and receipt must not be symlinks.')
    path,coverage_path,receipt_path=[safe_output(root,db,item) for item in raw_paths]
    if any(item.exists() for item in (path,coverage_path,receipt_path)):
        raise FileExistsError('Choose a new findings export filename; output or receipt already exists.')
    # Check all findings before creating a deliverable, then stream a second pass.
    count=0;coverage_eids=set();coverage_pairs=set()
    while True:
        page=list_findings(db,offset=count);count+=len(page['findings'])
        for finding in page['findings']:
            snapshot=finding['snapshot']
            if snapshot.get('evidence_id'):coverage_eids.add(snapshot['evidence_id'])
            if snapshot.get('evidence_id') and snapshot.get('logical_path'):coverage_pairs.add((snapshot['evidence_id'],snapshot['logical_path']))
        if not page['has_more']:break
    with path.open('x',encoding='utf-8') as out:
        created.append(path)
        if format_name=='text':
            meta=dict(db.execute('SELECT key,value FROM meta'))
            out.write('LAWLIET MOBILE — SAVED FINDINGS\nCase ID: '+readable(meta.get('case_id'))+'\nCase name: '+readable(meta.get('name'))+'\nFindings: '+str(count)+'\n\nExaminer notes and saved parsed-record summaries. Full original fields are available in the JSONL export. Control/format characters are shown as Unicode escapes in this text report.\nSource bytes were not reverified during export. Saved record timestamps are not finding-creation times. Neither report counts nor local hashes establish complete phone acquisition or independently authenticated authorship.\n')
        offset=0
        while True:
            page=list_findings(db,offset=offset)
            for index,finding in enumerate(page['findings'],start=offset+1):
                out.write(json_text(finding)+'\n' if format_name=='jsonl' else text_finding(finding,index))
            offset+=len(page['findings'])
            if not page['has_more']:break
    from .coverage_ledger import portable_summary
    from .acquisition import case_coverage
    from .portable_coverage import bounded_json
    sha=digest(path)
    coverage=portable_summary(case_coverage(root,db)['ledger'],
        {'format':format_name,'records':count,'evidence_ids':list(coverage_eids),'source_pairs':coverage_pairs})
    coverage['export_sha256']=sha
    encoded=bounded_json(coverage)
    with coverage_path.open('x',encoding='utf-8') as out:
        created.append(coverage_path)
        out.write(encoded)
    head=db.execute('SELECT hash FROM audit ORDER BY id DESC LIMIT 1').fetchone()
    receipt={'format':'ancalor-findings-export-v1','document_format':format_name,'created_at':now(),
             'case_id':dict(db.execute('SELECT key,value FROM meta')).get('case_id'),
             'filename':path.name,'records':count,'bytes':path.stat().st_size,'sha256':sha,
             'audit_head_before_export':head['hash'] if head else None,'coverage_file':Path(coverage_path).name,'coverage_sha256':digest(Path(coverage_path)),
             'scope':'Examiner notes and saved indexed-record snapshots. Source bytes were not reverified during export. Local hashes are not independent signatures.'}
    with receipt_path.open('x',encoding='utf-8') as out:
        created.append(receipt_path)
        out.write(json_text(receipt)+'\n')
    audit(db,'findings.exported',{'path':str(path),'records':count,'format':format_name,'sha256':sha,
                                 'receipt':str(receipt_path),'receipt_sha256':digest(receipt_path),
                                 'coverage_path':str(coverage_path),'coverage_sha256':receipt['coverage_sha256']})
    return {'path':str(path),'records':count,'sha256':sha,'receipt_path':str(receipt_path),'coverage_path':str(coverage_path)}
