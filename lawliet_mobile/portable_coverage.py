"""Bounded coverage context without exporting unselected source labels or prose."""
import json
from .core import UserError

CATEGORIES=frozenset({'messages','attachments','contacts','calls','browser','media','accounts','calendar','locations','network','system','applications','files','notifications','unknown'})
MODULES={'native':'native','aleapp':'aleapp','ileapp':'ileapp','leapp':'leapp',
         'import/jsonl':'import','import/tsv':'import','import/leapp':'import',
         'mvt':'mvt','mvt-ios':'mvt','sqlite-dissect':'sqlite-dissect','exiftool':'exiftool'}
REASONS={'requested':'requested_scope','collected':'supplied_bytes_retained','excluded':'excluded_scope',
         'inaccessible':'source_not_accessible','collection-unresolved':'collection_state_unknown',
         'unsupported':'unsupported_input','parser-failed':'processing_error','parsed':'indexed_records','parsed-empty':'recognized_empty_supplied_view',
         'unresolved':'parsing_state_unknown','reviewed':'operator_review_recorded',
         'verified':'operator_verification_recorded','searched-with-no-finding':'indexed_search_no_match',
         'decryption-succeeded':'decryption_completed','decryption-failed':'decryption_error'}
MAX_ROWS=10000
MAX_BYTES=4*1024**2


def bounded_json(value):
    encoded=json.dumps(value,ensure_ascii=False,indent=2)+'\n'
    if len(encoded.encode('utf-8'))>MAX_BYTES:
        raise UserError('Portable coverage exceeds metadata byte budget; narrow evidence scope.')
    return encoded


def run_selected(entry, run_ids):
    if run_ids is None:return True
    rid=entry.get('run_id')
    if rid is not None and rid not in run_ids:return False
    if entry.get('origin')=='explicit' and rid not in run_ids:return False
    if rid is None and entry.get('axis')=='parsing':return False
    return True


def checked_scope(db, filters):
    """Only explicit, current-case evidence/run selectors expand context."""
    result={}
    if filters is None:return result
    if not isinstance(filters,dict):raise UserError('Coverage selection must be an object.')
    evidence=filters.get('evidence');run=filters.get('run')
    if evidence is not None:
        if not isinstance(evidence,str) or not evidence or not db.execute('SELECT 1 FROM evidence WHERE id=?',(evidence,)).fetchone():
            raise UserError('Unknown coverage evidence scope.')
        result['coverage_evidence_ids']={evidence}
    if run is not None:
        if not isinstance(run,str) or not run:raise UserError('Unknown coverage run scope.')
        row=db.execute('SELECT evidence_id FROM runs WHERE id=?',(run,)).fetchone()
        if not row or (evidence is not None and evidence!=row['evidence_id']):
            raise UserError('Coverage run does not belong to selected evidence.')
        result['coverage_evidence_ids']={row['evidence_id']};result['run_ids']={run}
    return result


class Context:
    """Local aliases, controlled vocabulary and strict output budgets."""
    def __init__(self,pairs,evidence_ids,run_ids=None):
        self.pairs=pairs;self.eids=set(evidence_ids);self.runs=run_ids
        self.represented_eids={pair[0] for pair in pairs}
        self.aliases={};self.rows={};self.bytes=0

    def add(self,entry,run_wide=False):
        eid=entry.get('evidence_id');pair=(eid,entry.get('source'))
        if eid is None or (pair not in self.pairs and eid not in self.eids and not (run_wide and eid in self.represented_eids)):return
        rid=entry.get('run_id')
        if not run_selected(entry,self.runs):return
        alias_key=(eid,entry.get('source'),rid if run_wide else None)
        if alias_key not in self.aliases:
            if len(self.aliases)>=MAX_ROWS:raise UserError('Portable coverage exceeds source budget; narrow evidence scope.')
            self.aliases[alias_key]='S'+str(len(self.aliases)+1)
        module='unknown';tool=entry.get('tool_version')
        if isinstance(tool,str):
            for prefix,value in MODULES.items():
                if tool==prefix or tool.startswith(prefix+'/'):module=value;break
        category=entry.get('category');category=category if isinstance(category,str) and category in CATEGORIES else 'unknown'
        represented=pair in self.pairs and not run_wide
        row={'source_ref':self.aliases[alias_key],'evidence_id':eid,
             'source_relation':'represented' if represented else 'selected-evidence-context',
             'category':category,'module':module,'axis':entry['axis'],'state':entry['state'],
             'reason_code':REASONS[entry['state']],
             'origin':'operator-recorded' if entry.get('origin')=='explicit' else 'derived',
             'applies_to':'run' if run_wide else 'source','observation_count':1}
        from .coverage_ledger import _ExpectedSourceGap, EXPECTED_REASONS, EXPECTATION_KIND
        from .coverage_ledger import _EncryptedInputRefusal
        from .analysis_refusal import ENCRYPTED_INPUT
        if isinstance(entry, _EncryptedInputRefusal) and entry.get('execution_started') is False:
            row['reason_code'] = ENCRYPTED_INPUT
            row['execution_started'] = False
        if (isinstance(entry, _ExpectedSourceGap) and entry.get('origin') == 'derived'
                and entry.get('state') == 'collection-unresolved'
                and entry.get('expectation_kind') == EXPECTATION_KIND
                and entry.get('reason_code') in EXPECTED_REASONS):
            row['reason_code'] = entry['reason_code']
            row['module_role'] = 'expected'
        elif (entry.get('origin') == 'explicit' and entry.get('state') == 'requested'
                and entry.get('expectation_kind') == EXPECTATION_KIND):
            row['module_role'] = 'expected'
        if represented:row['source_path']=entry['source']
        if run_wide:row['selected_source_impact']='unknown'
        key=json.dumps({k:v for k,v in row.items() if k!='observation_count'},sort_keys=True,ensure_ascii=True)
        if key in self.rows:self.rows[key]['observation_count']+=1;return
        self.bytes+=len(json.dumps(row,ensure_ascii=True).encode())
        if len(self.rows)>=MAX_ROWS or self.bytes>MAX_BYTES:
            raise UserError('Portable coverage exceeds metadata budget; narrow evidence scope.')
        self.rows[key]=row

    def result(self):
        result={'schema_version':1,'observations':list(self.rows.values()),
                'scope':'selected-run-with-acquisition-context' if self.runs is not None else 'explicit-selected-evidence-context' if self.eids else 'represented-sources-only',
                'detail_withheld':True,'independent_examiner_signoff':False,
                'limitations':[
                    'Coverage context is separate from exported matching records; parsing and acquisition completeness are not asserted.',
                    'Unrepresented source labels use local aliases. Raw reasons, profiles, schemas, queries, actors and version strings are withheld.',
                    'Unbound and out-of-scope observations are withheld; their absence is not an absence-of-evidence claim.',
                    'Expected-file gap codes compare explicitly declared case-local logical paths with retained inventory only; they do not probe files, verify current bytes or establish device completeness. Other reason codes describe recorded states.',
                    'Module names describe retained tool labels; module_role=expected marks a declared expectation, not a tool execution. Capabilities and versions require internal source-linked review.',
                    'Reviewed and verified states are recorded operator assertions, not independent examiner approval.',
                    'Run-level errors have unknown impact on individual selected sources.',
                    'Run filters withhold parsing observations that lack a run link; artifact membership remains in the exported records.',
                    'This metadata scope control is not content redaction or authorization for customer release.']}
        bounded_json(result)
        return result
