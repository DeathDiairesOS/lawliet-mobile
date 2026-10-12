"""LEAPP-first processing of acquired evidence; no device acquisition implied."""
import json
from pathlib import Path
from .core import UserError, audit
from .tools import command
from .adapters import analyze as adapter_analyze


def process_evidence(root,db,workspace,evidence_id,engine='auto',timeout=900):
    evidence=db.execute('SELECT * FROM evidence WHERE id=?',(evidence_id,)).fetchone()
    if not evidence:raise UserError('Unknown evidence.')
    if engine not in {'auto','native','aleapp','ileapp'}:raise UserError('Choose auto, native, ALEAPP or iLEAPP.')
    selected=engine
    if selected=='auto':selected={'ios':'ileapp','android':'aleapp'}.get(evidence['platform'])
    paths=[r[0] for r in db.execute('SELECT logical_path FROM files WHERE evidence_id=?',(evidence_id,))]
    # Supplied contact/message exports use the existing small import readers.
    if engine=='auto' and paths and all(Path(p).suffix.lower() in {'.vcf','.xml'} for p in paths):selected='native'
    if engine=='auto' and any(Path(p).name=='contacts.vcf' for p in paths):
        for row in db.execute("SELECT path FROM files WHERE evidence_id=? AND logical_path='collection.json'",(evidence_id,)):
            manifest=root/'evidence'/evidence_id/row['path']
            if manifest.stat().st_size<=4*1024**2:
                try:
                    value=json.loads(manifest.read_text())
                    if isinstance(value,dict) and value.get('profile')=='contacts-provider':selected='native'
                except (ValueError,OSError):pass
    result={'evidence_id':evidence_id,'engine':selected,'status':'needs_platform','source_id':evidence_id+':unparsed',
            'message':'Evidence retained. Choose Android/ALEAPP or iOS/iLEAPP; platform could not be established from the input.'}
    if selected:
        try:
            if selected=='native':
                analysis=adapter_analyze(root,db,workspace,evidence_id,'native',timeout)
                result.update(analysis=analysis,source_id=evidence_id+':'+analysis['engine'],
                              status=analysis['status'],message=f"Imported app export: {analysis['new_records']} new records. Check Sources for parsing errors.")
            else:
                command(workspace,selected)
                analysis=adapter_analyze(root,db,workspace,evidence_id,selected,timeout)
                result.update(analysis=analysis,source_id=analysis['run_id'],status='complete' if analysis['new_records'] else 'no_records',
                              message=f"{selected.upper()}: {analysis['new_records']} indexed rows. All returned TSV reports are available in All artifacts.")
                diagnostics=analysis['detail'].get('diagnostics',{})
                if diagnostics.get('failed_artifacts') or diagnostics.get('error_lines'):
                    result['status']='needs_review';result['message']+=' Engine diagnostics contain failures or errors; inspect Sources.'
                if not analysis['new_records']:result['message']+=' No parsed rows were returned; this does not establish absence on the phone.'
        except Exception as exc:
            result.update(status='processing_failed',message=f'Evidence retained. Processing needs attention: {exc}')
    audit(db,'pipeline.finished',{k:v for k,v in result.items() if k!='analysis'});db.commit()
    return result
