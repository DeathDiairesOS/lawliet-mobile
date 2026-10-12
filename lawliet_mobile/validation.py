"""Repeatable, scoped case checks. Never turns acquisition gaps into completeness."""
import json
import shutil
import sqlite3
import tempfile
import uuid
import time
from contextlib import contextmanager, closing
from pathlib import Path

from .core import UserError, audit, digest, json_text, now, iter_artifacts, verify
from .parsers import timestamp
from .media import attachment_rows, resolve_attachment
from .tools import doctor
from .report_validation import reconcile_reports


@contextmanager
def working_sqlite(root, evidence, file, files):
    with tempfile.TemporaryDirectory(prefix='lawliet-validate-') as temp:
        target=Path(temp)/'source.db'
        shutil.copyfile(root/'evidence'/evidence/file['path'],target)
        sidecars=[]
        for suffix in ('-wal','-shm','-journal'):
            matches=[f for f in files if f['logical_path']==file['logical_path']+suffix]
            if len(matches)>1: raise UserError('Ambiguous SQLite sidecar paths.')
            if matches:
                f=matches[0];shutil.copyfile(root/'evidence'/evidence/f['path'],Path(str(target)+suffix))
                sidecars.append({'path':f['logical_path'],'sha256':f['sha256']})
        with closing(sqlite3.connect(target)) as c:
            c.row_factory=sqlite3.Row
            c.execute("PRAGMA query_only=ON")
            deadline=time.monotonic()+60
            c.set_progress_handler(lambda:1 if time.monotonic()>deadline else 0,10000)
            yield c,sidecars


def preflight(workspace, platform, max_bytes):
    if platform not in {'ios','android'} or max_bytes<=0: raise UserError('Invalid acquisition scope or storage budget.')
    free=shutil.disk_usage(workspace).free
    required=2*max_bytes+1024**3
    required_tools=['idevice_id','idevicebackup2'] if platform=='ios' else ['adb']
    inventory=doctor(workspace)['tools']
    missing=[name for name in required_tools if not any(t['tool']==name and t['available'] for t in inventory)]
    return {'platform':platform,'free_bytes':free,'budget_bytes':max_bytes,'required_bytes':required,
            'storage_ready':free>=required,'missing_tools':missing,'ready':free>=required and not missing,
            'note':'Reserves acquisition plus evidence-copy budget and 1 GiB headroom. Budget is not an estimate of phone contents. Device authorization and actual backup size still need assessment.'}


def validate_case(root, db, workspace, evidence_id, parser=None, run=None):
    if not db.execute('SELECT 1 FROM evidence WHERE id=?',(evidence_id,)).fetchone():raise UserError('Unknown evidence.')
    integrity=verify(root,db)
    if not integrity['ok']:raise UserError('Case integrity failed; validation stopped. Run verify for details.')
    files=[dict(r) for r in db.execute('SELECT * FROM files WHERE evidence_id=?',(evidence_id,))]
    def indexed_rows():
        return iter_artifacts(db,evidence=evidence_id,parser=parser,run=run,limit=None)
    categories={}
    for r in indexed_rows():categories[r['category']]=categories.get(r['category'],0)+1
    result={'created_at':now(),'evidence_id':evidence_id,'parser':parser,'run':run,
            'integrity':integrity,'indexed_categories':categories,'indexed_rows':sum(categories.values()),
            'files':len(files),'checks':[],'limitations':[
                'Checks concern acquired evidence only, not completeness of the phone.',
                'Parsed report imports cannot independently authenticate original databases or authorship.',
                'Carving results require examiner corroboration; absence of recoverable data is inconclusive.']}
    reports={};report_failures=[]
    for row in indexed_rows():
        provenance=row['data'].get('_ancalor_report')
        if row['parser'] not in {'aleapp','ileapp'} or not isinstance(provenance,dict):continue
        reference=row['source_ref'].rsplit(':line=',1)[0]
        reports.setdefault(reference,set()).add(provenance.get('sha256'))
    for reference,hashes in reports.items():
        path=root/reference
        if not path.resolve().is_relative_to((root/'runs').resolve()) or path.is_symlink() or not path.is_file():
            report_failures.append({'report':reference,'reason':'Missing or unsafe report path'})
        elif len(hashes)!=1 or digest(path) not in hashes:
            report_failures.append({'report':reference,'reason':'Upstream report hash mismatch'})
    result['checks'].append({'check':'upstream_report_integrity','status':'needs_review' if report_failures else ('pass' if reports else 'not_available'),
                             'reports_checked':len(reports),'failures':report_failures})
    result['checks'].append(reconcile_reports(root,db,evidence_id,indexed_rows(),parser,run))
    # Assess the actual backup bookkeeping and declared payload inventory.
    manifests=[f for f in files if Path(f['logical_path']).name=='Manifest.db']
    if not manifests:
        result['checks'].append({'check':'ios_backup_inventory','status':'not_available','reason':'No Manifest.db in selected evidence; backup completeness cannot be checked.'})
    for manifest in manifests:
        parent=Path(manifest['path']).parent
        status_path=root/'evidence'/evidence_id/parent/'Status.plist'
        manifest_plist=root/'evidence'/evidence_id/parent/'Manifest.plist'
        import plistlib
        try:
            state=plistlib.loads(status_path.read_bytes())
            info=plistlib.loads(manifest_plist.read_bytes())
            if info.get('IsEncrypted'):
                result['checks'].append({'check':'ios_backup_inventory','status':'encrypted','reason':'Manifest decryption is required before checking payload inventory.'});continue
            missing=[];declared=0;invalid=0
            with working_sqlite(root,evidence_id,manifest,files) as (c,_):
                for row in c.execute('SELECT fileID,domain,relativePath FROM Files WHERE flags=1'):
                    fid=row['fileID'];declared+=1
                    if not isinstance(fid,str) or len(fid)!=40 or any(x not in '0123456789abcdef' for x in fid.lower()):invalid+=1;continue
                    candidates=[parent/fid[:2]/fid,parent/fid]
                    if not any((root/'evidence'/evidence_id/p).is_file() for p in candidates):
                        missing.append({'file_id':fid,'logical_path':str(row['domain'])+'/'+str(row['relativePath'])})
            result['checks'].append({'check':'ios_backup_inventory','status':'pass' if state.get('SnapshotState')=='finished' and not missing and not invalid else 'incomplete',
                'snapshot_state':state.get('SnapshotState'),'declared_files':declared,'missing_count':len(missing),'missing':missing,'invalid_file_ids':invalid,
                'note':'Manifest presence and payload inventory do not establish inclusion of cloud-only or excluded application data.'})
        except (OSError,ValueError,sqlite3.Error) as exc:
            result['checks'].append({'check':'ios_backup_inventory','status':'not_checked','reason':str(exc)})
    sms=[f for f in files if Path(f['logical_path']).name.lower()=='sms.db']
    if len(sms)!=1:
        result['checks'].append({'check':'ios_messages_reconciliation','status':'not_available','reason':'Requires exactly one source sms.db in selected evidence.'})
    else:
        source=sms[0]
        try:
            with working_sqlite(root,evidence_id,source,files) as (c,sidecars):
                source_rows={str(r['rowid']):dict(r) for r in c.execute('SELECT rowid,text,date FROM message')}
                observed={};unlinked=0
                for r in indexed_rows():
                    if r['category']!='messages':continue
                    data=r['data']
                    if r['parser'].startswith('native/') and r['file_id']==source['id']:identifier=data.get('__rowid__')
                    elif r['parser']=='ileapp':identifier=data.get('message',{}).get('source_row_id')
                    else:identifier=None
                    if identifier is None:unlinked+=1;continue
                    observed.setdefault(str(identifier),[]).append({key:r[key] for key in ('id','body','timestamp','parser')})
                mismatches=[];text_checked=0;time_checked=0;decoded=0;precision_loss=0;precision_examples=[]
                for identifier,records in observed.items():
                    original=source_rows.get(identifier)
                    if original is None:continue
                    raw=original['date'];expected=timestamp(raw,'apple','nanoseconds' if isinstance(raw,(int,float)) and abs(raw)>10**12 else 'seconds')
                    if not original['text'] and any(r['body'] for r in records):decoded+=1
                    for r in records:
                        reasons=[]
                        if original['text']:
                            text_checked+=1
                            if r['body']!=original['text']:reasons.append('plaintext')
                        if expected:
                            time_checked+=1
                            if r['timestamp']!=expected:
                                if r['parser']=='ileapp' and r['timestamp']==expected[:19]+'.000000Z':
                                    precision_loss+=1
                                    if len(precision_examples)<20:precision_examples.append({'source_row_id':identifier,'artifact_id':r['id'],'source_utc':expected,'reported_utc':r['timestamp']})
                                else:reasons.append('timestamp')
                        if reasons:mismatches.append({'source_row_id':identifier,'artifact_id':r['id'],'fields':reasons})
                missing=sorted(set(source_rows)-set(observed));extra=sorted(set(observed)-set(source_rows))
                result['checks'].append({'check':'ios_messages_reconciliation','status':('pass_with_precision_loss' if precision_loss else 'pass') if observed and not missing and not extra and not mismatches else 'needs_review',
                    'source_sha256':source['sha256'],'sidecars':sidecars,'source_rows':len(source_rows),'distinct_indexed_source_rows':len(observed),
                    'missing_source_row_ids':missing,'unexpected_source_row_ids':extra,'mismatches':mismatches,'plaintext_comparisons':text_checked,
                    'timestamp_comparisons':time_checked,'timestamp_precision_loss_rows':precision_loss,'precision_loss_examples':precision_examples,'rows_with_additional_decoded_body':decoded,'unlinked_report_rows':unlinked,
                    'duplicate_report_rows':sum(max(0,len(v)-1) for v in observed.values()),
                    'note':'Additional decoded bodies are counted, not independently decoded or validated by this comparison.'})
                statuses={}
                for attachment in attachment_rows(c):
                    resolution=resolve_attachment(attachment,files)
                    state=resolution['status'];statuses[state]=statuses.get(state,0)+1
                result['checks'].append({'check':'ios_attachment_paths','status':'assessed','counts':statuses,
                    'note':'Exact logical path and byte-size association; media rendering and semantic attachment contents are not validated.'})
        except (sqlite3.Error,ValueError,KeyError) as exc:
            result['checks'].append({'check':'ios_messages_reconciliation','status':'not_checked','reason':str(exc)})
    native_checks=[]
    if parser and parser.startswith('native/'):
        for file in files:
            path=root/'evidence'/evidence_id/file['path']
            with path.open('rb') as f: is_sqlite=f.read(16)==b'SQLite format 3\x00'
            if not is_sqlite or Path(file['logical_path']).name=='Manifest.db':continue
            try:
                with working_sqlite(root,evidence_id,file,files) as (c,sidecars):
                    names={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    specs=[('calls','calls'),('ZCALLRECORD','calls'),('ABPerson','contacts'),('data','contacts'),('history_visits','browser'),('urls','browser'),('sms','messages')]
                    for table,category in specs:
                        if table not in names:continue
                        # Restrict checks to files where the selected native parser actually emitted this category.
                        indexed=sum(1 for r in indexed_rows() if r['file_id']==file['id'] and r['category']==category)
                        if not indexed:continue
                        expected=c.execute('SELECT COUNT(*) FROM "'+table+'"').fetchone()[0]
                        native_checks.append({'source':file['logical_path'],'table':table,'category':category,'source_rows':expected,
                            'indexed_rows':indexed,'status':'pass' if expected==indexed else 'needs_review','source_sha256':file['sha256'],'sidecars':sidecars})
            except sqlite3.Error as exc:
                native_checks.append({'source':file['logical_path'],'status':'not_checked','reason':str(exc)})
    result['checks'].append({'check':'native_table_counts','status':'needs_review' if any(c['status']!='pass' for c in native_checks) else ('pass' if native_checks else 'not_available'),
                             'tables':native_checks,'note':'Row counts for supported native tables that emitted records. Count equality does not validate each field; unparsed sources remain outside this check.'})
    result['checks'].append({'check':'evidence_integrity','status':'pass','note':f"SHA-256 checked for {integrity['files_checked']} acquired files; local audit chain verified. This includes imported report files, not authentication of their original-device claims."})
    tools=doctor(workspace)
    for t in tools['tools']:
        if t['available']:t['entrypoint_sha256']=digest(t['path'])
    result['tools']=tools
    result['status']='needs_review' if any(c['status'] in {'needs_review','incomplete','not_checked','pass_with_precision_loss'} for c in result['checks']) else 'checks_completed_with_limitations'
    folder=root/'reports'/('validation-'+uuid.uuid4().hex[:12]);folder.mkdir(parents=True)
    output=folder/'validation.json';output.write_text(json_text(result)+'\n')
    summary=folder/'summary.txt'
    summary.write_text('LAWLIET CASE VALIDATION\n'+result['status']+'\nEvidence: '+evidence_id+'\n\n'+'\n'.join(c['check']+': '+c['status'] for c in result['checks'])+'\n\n'+'\n'.join(result['limitations'])+'\n')
    audit(db,'validation.created',{'evidence_id':evidence_id,'parser':parser,'run':run,'report':str(output.relative_to(root)),'sha256':digest(output),'status':result['status']});db.commit()
    return {'status':result['status'],'path':str(output),'summary_path':str(summary),'checks':result['checks'],'indexed_categories':categories}
