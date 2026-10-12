"""Documentary method-specific training/practice/review claims, not certification."""
import json
import uuid
from .core import UserError,audit,now
from .investigation import verify_ledger

ACTION='competency.recorded'
LIMITATIONS=['All identities, references, outcomes and independence declarations are operator-supplied claims.',
             'No identity, certification, reviewer independence or examiner competence is authenticated.',
             'Training, practice success and reviewer sign-off never automatically establish qualification.',
             'No role, case-release or tool-execution permission is granted by these records.']


def _text(value,label,required=True,limit=4000):
    if not isinstance(value,str) or len(value)>limit or (required and not value.strip()):
        raise UserError(label+' must be '+('nonempty ' if required else '')+'bounded text.')
    return value


def _events(db):
    verify_ledger(db)
    for row in db.execute('SELECT id,detail FROM audit WHERE action=? ORDER BY id',(ACTION,)):
        try:
            event=json.loads(row['detail'])
            if event['schema_version']!=1:raise ValueError()
            yield {'audit_id':row['id'],**event}
        except (KeyError,TypeError,ValueError) as exc:raise UserError('Malformed competency record.') from exc


def record(db,value):
    if not isinstance(value,dict) or set(value)-{'examiner','method','method_version','kind','recorded_by','description','references','file_ids','reviewed_event_ids','reviewer','review_outcome','declaration','independence','supersedes_event_id','change_reason'}:
        raise UserError('Unsupported competency fields.')
    if not db.in_transaction:db.execute('BEGIN IMMEDIATE')
    else:db.execute('UPDATE audit SET id=id WHERE 0')
    base={key:_text(value.get(key),key,limit=1000) for key in ('examiner','method','method_version','recorded_by')}
    kind=value.get('kind')
    if not isinstance(kind,str) or kind not in ('training','practice','review'):raise UserError('Kind must be training, practice or review.')
    description=_text(value.get('description'),'description',limit=8000)
    refs=value.get('references')
    if not isinstance(refs,list) or not 1<=len(refs)<=50:raise UserError('Supply 1–50 documentary/test references.')
    refs=[_text(ref,'reference') for ref in refs]
    file_ids=value.get('file_ids',[])
    if not isinstance(file_ids,list) or len(file_ids)>100 or any(type(fid) is not int or fid<1 for fid in file_ids):raise UserError('Invalid case-local file references.')
    sources=[]
    for fid in sorted(set(file_ids)):
        row=db.execute('SELECT id,evidence_id,path,logical_path,size,sha256 FROM files WHERE id=?',(fid,)).fetchone()
        if not row:raise UserError('Source file is not in this case.')
        sources.append(dict(row))
    links=value.get('reviewed_event_ids',[])
    if not isinstance(links,list) or len(links)>100 or any(not isinstance(i,str) for i in links):raise UserError('Invalid reviewed event references.')
    supersedes=value.get('supersedes_event_id')
    if supersedes is not None and not isinstance(supersedes,str):raise UserError('Invalid superseded event reference.')
    wanted=set(links)|({supersedes} if supersedes else set());found={}
    for event in _events(db):
        if event['event_id'] in wanted:found[event['event_id']]=event
    if set(found)!=wanted:raise UserError('Referenced competency event is not in this case.')
    for event in found.values():
        if any(event[k]!=base[k] for k in ('examiner','method','method_version')):raise UserError('Reference must concern the same examiner and exact method/version.')
    reason=_text(value.get('change_reason',''),'change reason',required=bool(supersedes))
    if supersedes and found[supersedes]['kind']!=kind:raise UserError('Corrections must retain record kind.')
    reviewer=outcome=declaration=independence=None
    if kind=='review':
        reviewer=_text(value.get('reviewer'),'reviewer',limit=1000)
        outcome=value.get('review_outcome');independence=value.get('independence','unknown')
        if not isinstance(outcome,str) or outcome not in ('sign-off-recorded','needs-more-practice','not-assessed','withdrawn'):raise UserError('Unsupported review outcome.')
        if not isinstance(independence,str) or independence not in ('claimed','not-claimed','unknown'):raise UserError('Unsupported independence declaration.')
        declaration=_text(value.get('declaration'),'review declaration')
        if not links:raise UserError('Review must cite existing method-specific records.')
        if independence=='claimed' and reviewer.strip().casefold()==base['examiner'].strip().casefold():raise UserError('A self-review cannot claim reviewer independence.')
    elif links or any(k in value for k in ('reviewer','review_outcome','declaration','independence')):
        raise UserError('Training/practice cannot carry reviewer sign-off fields.')
    result={**base,'schema_version':1,'event_id':uuid.uuid4().hex,'recorded_at':now(),'kind':kind,
            'description':description,'references':refs,'sources':sources,'reviewed_event_ids':sorted(set(links)),
            'reviewer':reviewer,'review_outcome':outcome,'declaration':declaration,'independence':independence,
            'supersedes_event_id':supersedes,'change_reason':reason,
            'competency_status':'not-assessed-by-software','authenticated':False,'limitations':LIMITATIONS}
    audit(db,ACTION,result);return result


def history(db,after=0,limit=100,examiner=None,method=None):
    if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=100:raise UserError('Use nonnegative cursor and limit1–100.')
    for label,value in [('examiner',examiner),('method',method)]:
        if value is not None:_text(value,label,limit=1000)
    rows=[]
    for event in _events(db):
        if event['audit_id']>after and (examiner is None or event['examiner']==examiner) and (method is None or event['method']==method):
            rows.append(event)
            if len(rows)>limit:break
    page=rows[:limit]
    return {'events':page,'has_more':len(rows)>limit,'next_cursor':page[-1]['audit_id'] if page else after,
            'competency_status':'not-assessed-by-software','authenticated':False,'limitations':LIMITATIONS}
