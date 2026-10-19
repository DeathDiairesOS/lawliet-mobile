"""Independent coverage observations projected from retained case records.

Parsing, collection, decryption and examiner decisions never promote each other.
Explicit observations live in the existing audit chain, not a second state store.
"""
import json
import hashlib
import uuid
import unicodedata
from pathlib import Path
from .core import UserError, audit, now, select_artifacts, json_text

STATE_AXIS = {'requested':'acquisition','collected':'acquisition','excluded':'acquisition',
              'inaccessible':'acquisition','collection-unresolved':'acquisition','unsupported':'parsing','parser-failed':'parsing',
              'parsed':'parsing','parsed-empty':'parsing','unresolved':'parsing','reviewed':'review',
              'verified':'examiner-verification','searched-with-no-finding':'search',
              'decryption-succeeded':'decryption','decryption-failed':'decryption'}
DIMENSIONS=('source','category','profile','schema','input_tier','tool_version','device_build','device_state','validation_basis')
LIMITATIONS=['Coverage observations are independent: collection does not imply decryption, parsing, review or examiner verification.',
             'Missing, inaccessible, unsupported, empty and failed inputs never establish no evidence or no activity.',
             'A search without findings applies only to the declared indexed scope and query; uncollected/unparsed data is outside it.',
             'Imported files establish possession of supplied bytes, not complete acquisition of a device.',
             'Hash integrity is separate from examiner verification; vendor claims and local tests are not interchangeable.']


def _entry(state, reason, **values):
    return {'state':state,'axis':STATE_AXIS[state],**{key:'unknown' for key in DIMENSIONS},
            'reason':reason,'evidence_id':None,'run_id':None,'origin':'derived',**values}


EXPECTATION_KIND = 'retained-logical-file-v1'
EXPECTED_REASONS = frozenset({'expected_file_not_in_inventory', 'expected_file_mapping_ambiguous'})


class _ExpectedSourceGap(dict):
    """In-memory provenance marker; only the audited inventory projection emits it."""


class _EncryptedInputRefusal(dict):
    """Typed projection of the controlled preflight refusal, never evidence prose."""


def _verify_audit(db):
    previous = '0' * 64
    for receipt in db.execute('SELECT * FROM audit ORDER BY id'):
        hashed = hashlib.sha256(json_text([receipt['at'], receipt['action'], receipt['detail'], previous]).encode()).hexdigest()
        if receipt['previous_hash'] != previous or receipt['hash'] != hashed:
            raise UserError('Coverage audit chain integrity mismatch.')
        previous = receipt['hash']


def _check_expectation(db, values):
    if values.get('expectation_kind') != EXPECTATION_KIND or values.get('state') != 'requested':
        raise UserError('Expected logical files require the retained-logical-file-v1 requested state.')
    eid = values.get('evidence_id')
    if not isinstance(eid, str) or not eid or not db.execute('SELECT 1 FROM evidence WHERE id=?', (eid,)).fetchone():
        raise UserError('Expected logical files require existing case-local evidence.')
    source = values.get('source')
    if (not isinstance(source, str) or not source or len(source) > 4000
            or '\\' in source or ':' in source
            or any(part in {'', '.', '..'} for part in source.split('/'))
            or any(unicodedata.category(char).startswith('C') for char in source)):
        raise UserError('Expected source must be a bounded canonical relative logical file path.')


def record_observation(db, values):
    if not isinstance(values,dict):raise UserError('Coverage observation must be an object.')
    allowed=set(DIMENSIONS)|{'state','reason','actor','evidence_id','run_id','query','since','until','reference','expectation_kind'}
    if set(values)-allowed:raise UserError('Unknown coverage observation fields.')
    state=values.get('state')
    if state not in STATE_AXIS:raise UserError('Unknown coverage state.')
    for key in ('source','category','reason','actor'):
        if not isinstance(values.get(key),str) or not values[key].strip() or len(values[key])>4000:raise UserError(f'Coverage {key} is required and bounded to4000 characters.')
    for key in set(DIMENSIONS)|{'reference'}:
        if key in values and (not isinstance(values[key],str) or not values[key].strip() or len(values[key])>4000):raise UserError('Invalid coverage dimension/reference.')
    if values.get('validation_basis','unknown') not in {'unknown','vendor-documented','locally-tested'}:raise UserError('Unknown validation basis.')
    if values.get('validation_basis') in {'vendor-documented','locally-tested'} and not values.get('reference'):raise UserError('Validation basis requires a supporting source/test reference.')
    if 'expectation_kind' in values:
        _check_expectation(db, values)
        _verify_audit(db)
    eid=values.get('evidence_id');rid=values.get('run_id')
    if eid and not db.execute('SELECT 1 FROM evidence WHERE id=?',(eid,)).fetchone():raise UserError('Unknown coverage evidence.')
    if rid:
        run=db.execute('SELECT evidence_id FROM runs WHERE id=?',(rid,)).fetchone()
        if not run or (eid and run['evidence_id']!=eid):raise UserError('Coverage run does not belong to evidence.')
    if state in {'reviewed','verified'} and not values.get('reference'):raise UserError('Examiner review/verification requires a supporting reference.')
    row=_entry(state,values['reason'],**{k:v for k,v in values.items() if k not in {'state','reason'}},origin='explicit',id=uuid.uuid4().hex,recorded_at=now())
    if state=='searched-with-no-finding':
        if not eid or not isinstance(values.get('query'),str) or not values['query'].strip():raise UserError('Negative search requires an evidence ID and explicit query.')
        if select_artifacts(db,evidence=eid,run=rid,category=None if values['category']=='all' else values['category'],query=values['query'],since=values.get('since'),until=values.get('until'),limit=1):raise UserError('Search contains indexed findings; negative-search state rejected.')
        row['search_scope']='Indexed records only; no assertion about unparsed or uncollected inputs.'
    audit(db,'coverage.recorded',row)
    return row


def _iter_entries(root, db, acquisition=None):
    """Read existing inventory, run details and explicit audited observations."""
    _verify_audit(db)
    for file in db.execute('SELECT evidence_id,path,logical_path FROM files ORDER BY evidence_id,path'):
        yield _entry('collected','Supplied file retained in evidence inventory; acquisition completeness unknown.',source=file['logical_path'],evidence_id=file['evidence_id'],input_tier='supplied-files',reference=file['path'])
    # Count memberships, not new-record deltas: reparsing can add zero new rows.
    for row in db.execute('SELECT a.evidence_id,a.file_id,a.category,a.parser,f.logical_path,COUNT(*) AS count FROM artifacts a LEFT JOIN files f ON a.file_id=f.id GROUP BY a.evidence_id,a.file_id,a.category,a.parser,f.logical_path ORDER BY a.evidence_id,a.file_id,a.category,a.parser,f.logical_path'):
        yield _entry('parsed','Indexed artifact rows exist; this does not imply complete source parsing or examiner review.',source=row['logical_path'] or 'imported-records',category=row['category'],tool_version=row['parser'] or 'unknown',evidence_id=row['evidence_id'],records=row['count'])
    for run in db.execute('SELECT id,evidence_id,engine,status,detail FROM runs ORDER BY started_at,id'):
        common={'evidence_id':run['evidence_id'],'run_id':run['id'],'tool_version':run['engine'],'source':'run:'+run['id'],'scope_level':'run'}
        try:detail=json.loads(run['detail'] or '{}')
        except (ValueError,TypeError):detail={'error':'Unreadable retained run details.'}
        if not isinstance(detail,dict):detail={'error':'Unsupported retained run detail shape.'}
        if run['status'] in {'failed','interrupted','partial'} or detail.get('error'):
            entry = _entry('decryption-failed' if 'decrypt' in run['engine'].lower() else 'parser-failed',str(detail.get('error') or 'Run '+run['status']+'; inspect retained diagnostics.'),**common)
            from .analysis_refusal import ENCRYPTED_INPUT
            if detail.get('preflight_refusal') == ENCRYPTED_INPUT and detail.get('execution_started') is False:
                entry = _EncryptedInputRefusal(entry, reason_code=ENCRYPTED_INPUT,
                                              execution_started=False)
            yield entry
        if 'decrypt' in run['engine'].lower() and run['status']=='complete':yield _entry('decryption-succeeded','Decryption run completed; parsing and examiner verification remain independent.',**common)
        for item in detail.get('errors',[]):
            item=item if isinstance(item,dict) else {'error':str(item)}
            yield _entry('decryption-failed' if 'decrypt' in run['engine'].lower() else 'parser-failed',str(item.get('error') or item.get('reason') or item),**{**common,'source':item.get('source',common['source']),'scope_level':'source' if item.get('source') else 'run'})
        for item in detail.get('unparsed_candidates',[]):
            if not isinstance(item,dict):continue
            state = item['state'] if item.get('state') in {'unsupported', 'parsed-empty'} else 'unresolved'
            dimensions = {key:item[key] for key in DIMENSIONS if key in item}
            observations = {key:item[key] for key in ('table','rows_observed','count_state','records') if key in item}
            yield _entry(state,str(item.get('reason') or 'Parser support/emptiness not established.'),
                         **{**common,**dimensions,**observations,'source':item.get('source',common['source']),'scope_level':'source'})
    acquisition=acquisition or {}
    for attempt in acquisition.get('collection_attempts',[])+acquisition.get('acquisitions',[]):
        for item in attempt.get('coverage',[]):
            if not isinstance(item,dict):continue
            original=item.get('state','unknown')
            state={'access_denied':'inaccessible','not_returned':'inaccessible','failed':'inaccessible','unsupported':'unsupported','excluded':'excluded','collected':'collected','complete':'collected','not_requested':'excluded','not_attempted':'excluded','collected_empty':'collected','requested':'requested'}.get(original,'collection-unresolved')
            yield _entry(state,str(item.get('detail') or item.get('reason') or 'Collection state: '+original),source=str(item.get('source','unknown')),category=str(item.get('category',item.get('source','unknown'))),profile=str(attempt.get('profile','unknown')),input_tier=str(attempt.get('method','collection-log')),evidence_id=attempt.get('evidence_id'),collection_state=original,reference=attempt.get('manifest_path','collection manifest'))
    for row in db.execute("SELECT detail FROM audit WHERE action='coverage.recorded' ORDER BY id"):
        try:value=json.loads(row[0])
        except (ValueError,TypeError):raise UserError('Unreadable coverage audit observation.')
        if not isinstance(value,dict) or value.get('state') not in STATE_AXIS:raise UserError('Invalid coverage audit observation.')
        if 'expectation_kind' in value:
            _check_expectation(db, value)
        yield value
        if value.get('expectation_kind') == EXPECTATION_KIND:
            # Inventory identity only: no filename heuristics, filesystem probes,
            # current-byte verification, or device acquisition completeness claim.
            matches = db.execute('SELECT COUNT(*) FROM files WHERE evidence_id=? AND logical_path=?',
                (value['evidence_id'], value['source'])).fetchone()[0]
            if matches != 1:
                code = 'expected_file_not_in_inventory' if matches == 0 else 'expected_file_mapping_ambiguous'
                yield _ExpectedSourceGap(_entry('collection-unresolved',
                    'Declared expected logical file has no inventory match.' if matches == 0 else 'Declared expected logical file has multiple inventory mappings.',
                    **{key: value.get(key, 'unknown') for key in DIMENSIONS},
                    evidence_id=value['evidence_id'], expectation_kind=EXPECTATION_KIND,
                    expectation_id=value.get('id'), reason_code=code, module_role='expected',
                    inventory_matches=matches))


def build_ledger(root, db, acquisition=None, export_scope=None):
    return {'schema_version':1,'entries':list(_iter_entries(root,db,acquisition)),
            'limitations':LIMITATIONS,'export_scope':export_scope or {'scope':'case coverage; not a completeness assertion'},
            'independent_examiner_signoff':False}


def ledger_page(root, db, acquisition=None, offset=0, limit=100, filters=None):
    """Bound response memory while computing whole-case and filtered counts.

    The summary still scans the projection and verifies the complete audit chain.
    Full exports intentionally retain their separate complete-ledger contract.
    """
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 0 <= limit <= 100:
        raise UserError('Coverage offset must be nonnegative and limit must be 0–100.')
    filters = {} if filters is None else filters
    allowed = set(DIMENSIONS) | {'state', 'axis', 'evidence_id', 'run_id'}
    if not isinstance(filters, dict) or set(filters) - allowed:
        raise UserError('Unsupported coverage filters.')
    if any(not isinstance(v, str) or not v or len(v) > 4000 for v in filters.values()):
        raise UserError('Coverage filters require nonempty strings of at most 4000 characters.')
    entries=[];total=0;matched=0
    states={state:0 for state in STATE_AXIS};axes={axis:0 for axis in STATE_AXIS.values()}
    filtered_states=dict(states);filtered_axes=dict(axes)
    for entry in _iter_entries(root,db,acquisition):
        total+=1;states[entry['state']]+=1;axes[entry['axis']]+=1
        if any(entry.get(k) != v for k,v in filters.items()):
            continue
        if offset <= matched < offset+limit:
            entries.append(entry)
        matched+=1;filtered_states[entry['state']]+=1;filtered_axes[entry['axis']]+=1
    return {'schema_version':1,'entries':entries,'limitations':LIMITATIONS,
            'independent_examiner_signoff':False,'offset':offset,'limit':limit,
            'filters':filters,'total':total,'filtered_total':matched,
            'has_more':offset+len(entries)<matched,
            'next_offset':offset+len(entries) if limit and offset+len(entries)<matched else None,
            'summary':{'state_counts':states,'axis_counts':axes},
            'filtered_summary':{'state_counts':filtered_states,'axis_counts':filtered_axes},
            'count_unit':'observations; independent axes may describe the same source',
            'pagination_note':'Stable ordering for unchanged case. Refresh from offset zero after changes. Summary verifies audit chain and scans retained projection.'}


def source_pairs(records):
    """Internal selection identity; independent evidence/path sets lose pairing."""
    return {(record.get('evidence_id'),record.get('logical_path')) for record in records
            if record.get('evidence_id') and record.get('logical_path')}


def portable_summary(ledger, export_scope=None):
    """No free-text/source/profile/query fields in portable scoped metadata."""
    scope={} if export_scope is None else export_scope
    if not isinstance(scope,dict):raise UserError('Coverage export scope must be an object.')
    def identifiers(key):
        values=scope.get(key,[])
        if not isinstance(values,(list,tuple,set,frozenset)) or len(values)>10000 or any(not isinstance(v,str) or not v for v in values):
            raise UserError('Coverage '+key+' requires a bounded collection of identifiers.')
        return set(values)
    eids=identifiers('evidence_ids')
    pairs=set()
    values=scope.get('source_pairs',[])
    if not isinstance(values,(list,tuple,set,frozenset)) or len(values)>10000:
        raise UserError('Coverage source scope requires exact evidence/source pairs.')
    for pair in values:
        if not isinstance(pair,(list,tuple)) or len(pair)!=2 or any(not isinstance(v,str) or not v for v in pair):
            raise UserError('Coverage source scope requires exact evidence/source pairs.')
        pairs.add(tuple(pair))
    pair_scope_known='source_pairs' in scope
    from .portable_coverage import Context, run_selected
    run_ids=identifiers('run_ids') if 'run_ids' in scope else None
    context=Context(pairs,identifiers('coverage_evidence_ids'),run_ids)
    counts={}
    for entry in ledger['entries']:
        if not run_selected(entry,run_ids):continue
        # Only actual retained run projections receive run-wide treatment.
        # A caller-authored source beginning "run:" is still a source label.
        run_wide=(entry.get('origin')=='derived' and entry.get('scope_level')=='run'
                  and bool(entry.get('run_id')))
        context.add(entry,run_wide)
        if entry.get('evidence_id') not in eids:
            continue
        if not pair_scope_known:continue
        if not run_wide and (entry.get('evidence_id'),entry.get('source')) not in pairs:
            continue
        state=entry['state'];counts[state]=counts.get(state,0)+1
    result={'schema_version':1,'state_counts':counts,'limitations':LIMITATIONS,
            'detail_withheld':True,'scope_sufficient_for_state_counts':bool(eids) and pair_scope_known,
            'source_scope_known':pair_scope_known,
            'coverage_context':context.result(),
            'note':'Detailed source/reason/profile/query observations are internal case metadata and are omitted from portable exports. Counts are observations, not evidence counts or completeness.',
            'export_scope':{key:scope[key] for key in ('format','records','preview_limit','truncated') if key in scope},
            'independent_examiner_signoff':False}
    from .portable_coverage import bounded_json
    bounded_json(result)
    return result


def export_ledger(root, db, destination, export_scope=None):
    from .report import safe_output
    from .acquisition import case_coverage
    path=safe_output(root,db,Path(str(destination)+'.coverage.json'))
    data=portable_summary(case_coverage(root,db)['ledger'],export_scope)
    from .portable_coverage import bounded_json
    encoded=bounded_json(data)
    with path.open('x',encoding='utf-8') as stream:
        stream.write(encoded)
    return str(path)
