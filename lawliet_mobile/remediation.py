"""Operator-recorded preservation and remediation handoff; executes no actions."""
import json
import uuid
from .core import UserError, audit, now
from . import investigation

ACTION = 'remediation.recorded'
LIMITATIONS = [
    'Operator-supplied claims and references are not independently authenticated.',
    'Recording a recommendation does not perform it; recording completion does not verify it.',
    'No account, device, network or remote action is executed.',
    'Preservation agreements are supplied references, not proof of consent or legal authority.',
]


def _text(value, name, required=False, limit=4000):
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise UserError(name + ' must be ' + ('nonempty ' if required else '') + 'text within the size limit.')
    return value


def _events(db):
    investigation.verify_ledger(db)
    for row in db.execute('SELECT id,detail FROM audit WHERE action=? ORDER BY id', (ACTION,)):
        try:
            value = json.loads(row['detail'])
            if value['schema_version'] != 1:
                raise ValueError()
            yield {'audit_id': row['id'], **value}
        except (ValueError, KeyError, TypeError) as exc:
            raise UserError('Malformed remediation event.') from exc


def record(db, value):
    """Append an operator claim; latest_event_id prevents stale action revisions."""
    # Hold the write reservation before checking source scope or latest event.
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    else:
        # A caller may have opened a deferred transaction; reserve writes before reads.
        db.execute('UPDATE audit SET id=id WHERE 0')
    allowed = {'actor','description','category','status','file_ids','investigation_id',
               'supporting_reference','preservation_agreement_reference','action_id',
               'latest_event_id','change_reason'}
    if not isinstance(value, dict) or set(value) - allowed:
        raise UserError('Unsupported remediation fields.')
    actor = _text(value.get('actor'), 'Actor', True, 1000)
    description = _text(value.get('description'), 'Description', True, 8000)
    category, status = value.get('category'), value.get('status')
    if category not in ('preservation','remediation'):
        raise UserError('Category must be preservation or remediation.')
    if not isinstance(status,str) or status not in ({'preserved','unknown'} if category == 'preservation' else {'recommended','completed','unknown'}):
        raise UserError('Status must distinguish preservation from remediation recommendations and completion.')
    supporting = _text(value.get('supporting_reference',''), 'Supporting reference')
    agreement = _text(value.get('preservation_agreement_reference',''), 'Preservation agreement reference')
    if status in ('preserved','completed') and not supporting.strip():
        raise UserError('Recorded preservation/completion needs an explicit supporting reference.')
    if category == 'remediation' and status == 'completed' and not agreement.strip():
        raise UserError('Recorded completion requires an agreed preservation reference.')
    file_ids = value.get('file_ids',[])
    if not isinstance(file_ids,list) or len(file_ids)>100 or any(type(i) is not int or i<1 for i in file_ids):
        raise UserError('Supply at most 100 positive case-local file IDs.')
    iid = value.get('investigation_id')
    if iid is not None and not isinstance(iid,str):raise UserError('Invalid investigation reference.')
    scope = investigation.get(db,iid)['scope']['evidence_ids'] if iid else None
    sources=[]
    for fid in sorted(set(file_ids)):
        row=db.execute('SELECT id,evidence_id,path,logical_path,size,sha256 FROM files WHERE id=?',(fid,)).fetchone()
        if not row:raise UserError('Source file is not in this case.')
        if scope is not None and row['evidence_id'] not in scope:raise UserError('Source file is outside investigation scope.')
        sources.append(dict(row))
    if not sources and not iid:raise UserError('A case-local source or investigation reference is required.')
    previous=None;action_id=value.get('action_id')
    for event in _events(db):
        if event['action_id']==action_id:previous=event
    reason=_text(value.get('change_reason',''),'Change reason')
    if action_id is not None:
        if not isinstance(action_id,str) or previous is None:raise UserError('Unknown remediation action in this case.')
        if value.get('latest_event_id')!=previous['event_id']:raise UserError('Stale remediation action; reload latest event.')
        if not reason.strip():raise UserError('Action revisions require a change reason.')
        if category!=previous['category'] or iid!=previous['investigation_id'] or sources!=previous['sources']:
            raise UserError('Action category and source scope cannot change; record a separate action.')
    elif value.get('latest_event_id') is not None:raise UserError('A new action cannot supersede an event.')
    result={'schema_version':1,'event_id':uuid.uuid4().hex,'action_id':action_id or uuid.uuid4().hex,
            'previous_event_id':previous['event_id'] if previous else None,'recorded_at':now(),
            'actor':actor,'description':description,'category':category,'status':status,
            'sources':sources,'investigation_id':iid,'supporting_reference':supporting,
            'preservation_agreement_reference':agreement,'change_reason':reason,
            'verification':'operator-recorded; independently unverified',
            'execution':'not-executed-by-tool','limitations':LIMITATIONS}
    audit(db,ACTION,result)
    return result


def history(db, after=0, limit=100, action_id=None):
    if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=100:
        raise UserError('History requires nonnegative cursor and limit 1–100.')
    if action_id is not None and not isinstance(action_id,str):raise UserError('Invalid action ID.')
    rows=[]
    for event in _events(db):
        if event['audit_id']>after and (action_id is None or event['action_id']==action_id):
            rows.append(event)
            if len(rows)>limit:break
    page=rows[:limit]
    return {'events':page,'has_more':len(rows)>limit,'next_cursor':page[-1]['audit_id'] if page else after,
            'view':'append-only history; later events explicitly supersede earlier claims',
            'limitations':LIMITATIONS}
