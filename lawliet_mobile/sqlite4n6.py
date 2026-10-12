"""Version-checked sqlite4n6 JSONL recovery on disposable database copies."""
import json
import math
import shutil
import tempfile
import uuid
from pathlib import Path

from .core import UserError, add_artifact, audit, begin_run_index, digest, json_text, now, verify
from .tools import command, execute, storage_guard

SUPPORTED_VERSION='sqlite4n6 0.10.1'


def normalized_record(row):
    if not isinstance(row,dict):raise UserError('sqlite4n6 JSONL record must be an object.')
    for key in ('page','offset'):
        if type(row.get(key)) is not int or row[key]<0:raise UserError('Unsupported sqlite4n6 record coordinates.')
    confidence=row.get('confidence')
    if type(confidence) not in (int,float) or not math.isfinite(confidence) or not 0<=confidence<=1:
        raise UserError('Unsupported sqlite4n6 confidence field.')
    fragment=row.get('kind')=='fragment'
    values=row.get('surviving' if fragment else 'values')
    method=row.get('source' if fragment else 'recovery_source')
    if not isinstance(values,list) or not isinstance(method,str) or not method:
        raise UserError('Unsupported sqlite4n6 recovery schema; original output retained.')
    if row.get('kind') not in (None,'fragment'):raise UserError('Unknown sqlite4n6 record kind.')
    classification='partial_fragment' if fragment else 'carved_candidate'
    # No column-name/type/time inference from the values. BLOB content stays in
    # the complete original JSON object; keep the review summary bounded.
    parts=[]
    for value in values[:100]:
        if isinstance(value,dict) and 'blob_base64' in value:parts.append('[BLOB; see original output]')
        else:parts.append(str(value)[:2000])
    return classification,method,' · '.join(parts)[:12000]


def recover(root,db,workspace,file_id,timeout=900):
    source=db.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone()
    if not source:raise UserError('Select an imported SQLite file.')
    if not verify(root,db)['ok']:raise UserError('Evidence integrity check failed.')
    original=root/'evidence'/source['evidence_id']/source['path']
    with original.open('rb') as stream:
        if stream.read(16)!=b'SQLite format 3\x00':raise UserError('Recovery requires a plaintext SQLite header.')
    cmd=command(workspace,'sqlite4n6');rid=uuid.uuid4().hex[:12]
    folder=root/'runs'/rid;output=folder/'output';output.mkdir(parents=True)
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES(?,?,?,?,?)',
               (rid,source['evidence_id'],'sqlite4n6',now(),'running'))
    begin_run_index(db,rid)
    detail={'adapter_version':1,'source_sha256':source['sha256'],'executable_sha256':digest(cmd[-1]),'source_sidecars':[]}
    audit(db,'recovery.started',{'run_id':rid,'engine':'sqlite4n6','file_id':file_id,**detail});db.commit()
    count=0;status='failed'
    db.execute('SAVEPOINT sqlite4n6_records')
    try:
        version=execute(cmd+['--version'],folder/'version.log',min(timeout,20),guard=storage_guard(folder,2*1024**3))
        detail['version_command']=version
        with (folder/'version.log').open('r',encoding='utf-8') as stream:version_text=stream.read(4096).strip()
        detail['tool_version']=version_text
        if version['returncode'] or version_text!=SUPPORTED_VERSION:
            raise UserError('Unsupported sqlite4n6 version; this adapter is validated for 0.10.1 only.')
        with tempfile.TemporaryDirectory(prefix='lawliet-sqlite4n6-') as tmp:
            work=Path(tmp)/'source.db';shutil.copyfile(original,work)
            for suffix in ('-wal','-shm','-journal'):
                rows=list(db.execute('SELECT * FROM files WHERE evidence_id=? AND (path=? OR logical_path=?)',
                    (source['evidence_id'],source['path']+suffix,source['logical_path']+suffix)))
                if len(rows)>1:raise UserError('Ambiguous SQLite sidecar association.')
                if rows:
                    row=rows[0];shutil.copyfile(root/'evidence'/row['evidence_id']/row['path'],Path(str(work)+suffix))
                    detail['source_sidecars'].append({'logical_path':row['logical_path'],'sha256':row['sha256']})
            report=output/'carved.jsonl'
            result=execute(cmd+['carve',str(work),'-f','jsonl','-o',str(report)],folder/'recovery.log',timeout,
                           cwd=tmp,guard=storage_guard(folder,2*1024**3))
            detail['execution']=result
            if result['returncode']:raise UserError('sqlite4n6 failed; output and logs retained.')
            if not report.is_file() or report.is_symlink():raise UserError('sqlite4n6 returned no safe JSONL report.')
            report_hash=digest(report);detail['report_sha256']=report_hash
            with report.open('rb') as stream:
                number=0
                while raw:=stream.readline(8*1024**2+1):
                    number+=1
                    if len(raw)>8*1024**2:raise UserError('sqlite4n6 record exceeds 8 MiB; output retained.')
                    row=json.loads(raw.decode('utf-8'));classification,method,body=normalized_record(row)
                    data={'original':row,'normalization_version':1,'tool_version':version_text,
                          'recovery':{'classification':classification,'method':method,'tool_confidence':row['confidence'],
                                      'note':'Tool-reported confidence is not an Lawliet probability. Corroborate candidates; no user deletion, message identity or timestamp is inferred.'},
                          'source_sidecars':detail['source_sidecars'],'report_sha256':report_hash,'report_record':number}
                    count+=add_artifact(db,source['evidence_id'],source['id'],'recovery',None,None,
                        f'{classification.replace("_"," ")} · page {row["page"]} offset {row["offset"]}',body,
                        f'runs/{rid}/output/carved.jsonl:line={number}','sqlite4n6',data,run_id=rid)
        if not verify(root,db)['ok']:raise UserError('Post-analysis evidence integrity check failed.')
        status='complete';detail['integrity_after']='passed'
    except BaseException as exc:
        db.execute('ROLLBACK TO sqlite4n6_records');count=0
        detail['error']=str(exc);detail.update(getattr(exc,'tool_result',{}))
        status='interrupted' if isinstance(exc,KeyboardInterrupt) else 'failed'
        raise
    finally:
        db.execute('RELEASE sqlite4n6_records')
        db.execute('UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?',(now(),status,count,json_text(detail),rid))
        audit(db,'recovery.finished',{'run_id':rid,'engine':'sqlite4n6','status':status,'candidates':count});db.commit()
    return {'run_id':rid,'status':status,'candidates':count,'engine':'sqlite4n6',
            'note':'Recovery observations only. Zero candidates does not establish that nothing was deleted.'}
