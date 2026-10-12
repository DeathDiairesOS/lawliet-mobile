"""Optional SQLite Dissect analysis; candidates remain separate from messages."""
import csv
import json
import shutil
import tempfile
import uuid
from pathlib import Path
from .core import begin_run_index, UserError, add_artifact, audit, digest, json_text, now, verify
from .tools import command, execute, storage_guard


def recover_sqlite(root,db,workspace,file_id,timeout=900):
    source=db.execute('SELECT * FROM files WHERE id=?',(int(file_id),)).fetchone()
    if not source: raise UserError('Select an imported SQLite file ID.')
    if not verify(root,db)['ok']: raise UserError('Evidence integrity check failed.')
    original=root/'evidence'/source['evidence_id']/source['path']
    with original.open('rb') as f:
        if f.read(16)!=b'SQLite format 3\x00': raise UserError('Recovery requires a decrypted SQLite database.')
    cmd=command(workspace,'sqlite-dissect');rid=uuid.uuid4().hex[:12]
    folder=root/'runs'/rid;folder.mkdir(parents=True);output=folder/'output';output.mkdir()
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES(?,?,?,?,?)',(rid,source['evidence_id'],'sqlite-dissect',now(),'running'))
    begin_run_index(db,rid)
    audit(db,'recovery.started',{'run_id':rid,'file_id':file_id,'executable_sha256':digest(cmd[-1])});db.commit()
    detail={};count=0;status='failed'
    db.execute('SAVEPOINT dissect_records')
    try:
        with tempfile.TemporaryDirectory(prefix='lawliet-recovery-') as tmp:
            work=Path(tmp)/'source.db';shutil.copyfile(original,work);sidecars=[]
            for suffix in ('-wal','-shm','-journal'):
                row=db.execute('SELECT * FROM files WHERE evidence_id=? AND (path=? OR logical_path=?)',(source['evidence_id'],source['path']+suffix,source['logical_path']+suffix)).fetchone()
                if row:
                    shutil.copyfile(root/'evidence'/source['evidence_id']/row['path'],Path(str(work)+suffix));sidecars.append({'logical_path':row['logical_path'],'sha256':row['sha256']})
            detail=execute(cmd+[str(work),'-d',str(output),'-e','csv','--carve','--carve-freelists'],folder/'recovery.log',timeout,guard=storage_guard(folder,2*1024**3))
            if detail['returncode']!=0: raise UserError('SQLite Dissect failed; its run log is retained.')
            for report in sorted(output.rglob('*.csv')):
                hashed=digest(report)
                with report.open(encoding='utf-8-sig',newline='') as f:
                    for number,row in enumerate(csv.DictReader(f),2):
                        operation=row.get('Operation','')
                        if operation not in {'Carved','Deleted'}: continue
                        data={'original':row,'recovery':{'classification':'carved_candidate' if operation=='Carved' else 'historical_deleted_row',
                              'note':'Requires examiner corroboration. A carved candidate is not a confirmed deleted message; WAL deletion describes database history.'},
                              'source_sidecars':sidecars,'report_sha256':hashed,'report_record':number}
                        count+=add_artifact(db,source['evidence_id'],source['id'],'recovery',None,None,operation+' · '+report.stem,
                            ' · '.join(str(v) for v in row.values() if v),f'runs/{rid}/output/{report.relative_to(output)}:record={number}','sqlite-dissect',data,run_id=rid)
            detail.update(candidates=count,source_sha256=source['sha256'],source_sidecars=sidecars)
            status='complete'
    except BaseException as exc:
        db.execute('ROLLBACK TO dissect_records');count=0
        detail['error']=str(exc);raise
    finally:
        db.execute('RELEASE dissect_records')
        db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?',(status,now(),count,json_text(detail),rid))
        audit(db,'recovery.finished',{'run_id':rid,'status':status,'candidates':count});db.commit()
    return {'run_id':rid,'status':status,'candidates':count,'note':'Zero candidates does not prove no data was deleted.'}
