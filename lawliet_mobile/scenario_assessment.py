"""Read-only customer-question assessment of retained case metadata.

This projects the existing index and coverage ledger. It never acquires evidence,
runs parsers, opens original files, or treats available records as an answer.
"""
import json
import re
import sqlite3
import uuid
from collections import Counter

from .analysis_refusal import ENCRYPTED_INPUT
from .core import UserError, run_scope
from .coverage_ledger import (EXPECTED_REASONS, STATE_AXIS, _EncryptedInputRefusal,
                              _ExpectedSourceGap, _iter_entries)
from .portable_coverage import REASONS, checked_scope, run_selected
from .report_sort import sort_value
from .workflows import SCENARIOS

MAX_SAMPLES = 5
MAX_ITEMS = 20
MAX_TEXT = 1024
MAX_OUTPUT = 128 * 1024
REQUIREMENTS = {
    'messages': (('messages', 'Messages', None), ('attachments', 'Message attachment observations', None),
                 ('contacts', 'Contact context', None), ('calls', 'Call context', None)),
    'whatsapp': (('messages', 'WhatsApp messages', 'whatsapp'),),
    'signal': (('messages', 'Signal messages', 'signal'),),
    'files': (('media', 'Media observations', None), ('files', 'File observations', None)),
    'incident': (('applications', 'Application observations', None), ('system', 'System observations', None),
                 ('network', 'Network observations', None), ('browser', 'Browser activity', None),
                 ('messages', 'Message context', None)),
    'deleted': (('recovery', 'Database recovery candidates', None),),
}
GAP_STATES = frozenset({'requested', 'excluded', 'inaccessible', 'collection-unresolved',
                        'unsupported', 'parser-failed', 'unresolved', 'decryption-failed'})
LIMITATIONS = [
    'This assessment describes retained index and metadata, not whether the customer question is answered or the case is ready for release.',
    'Counts are indexed observations, not unique messages, people, files or events. Multiple parsers and runs may overlap.',
    'No relevant indexed records does not establish no activity, no messages, no compromise or no deleted data on the device.',
    'Observed date bounds describe only explicitly zoned indexed timestamps. Undated or unresolved timestamps do not establish a complete history.',
    'Recorded hashes and source links are metadata, not fresh integrity verification or authentication of source claims. Report-only rows do not authenticate original device records.',
    'Collection, parsing, search, review and examiner verification remain independent. Recorded review states are operator claims.',
    'Coverage comes from inventory, retained analysis metadata and audited observations. Operational or acquired collection-manifest files are not read by this assessment.',
    'Run-level failures have unknown impact on individual source files or artifact categories. Unbound observations are excluded from a selected run where required.',
    'Samples contain references only, never message bodies. Open the underlying record for values and detailed provenance.',
    'No device, parser, model, external service or original evidence file is accessed. Suggested actions require a separate deliberate invocation.',
]


def _selector(value, name, optional=False):
    if optional and value is None:
        return
    if not isinstance(value, str) or not value.strip() or len(value) > 256 or '\x00' in value:
        raise UserError('Select a nonempty bounded ' + name + '.')


def _safe_text(value):
    """Omit an oversized reference instead of turning a clipped path into a citation."""
    if not isinstance(value, str):
        return None
    try:
        return value if len(value.encode('utf-8')) <= MAX_TEXT else None
    except UnicodeError:
        return None


def _utc(value):
    result = sort_value(value, 'timestamp')
    return result.replace('+00:00', 'Z') if result else None


def _hash(value):
    return int(isinstance(value, str) and re.fullmatch(r'[0-9a-fA-F]{64}', value) is not None)


def _requirement(db, clause, params, category, label, app):
    where = clause + ' AND a.category=?'
    args = [*params, category]
    # CASE protects JSON access even for malformed historical imported metadata.
    data = "CASE WHEN json_valid(a.data) THEN a.data ELSE '{}' END"
    if app:
        where += ' AND json_extract(' + data + ", '$.message.app')=?"
        args.append(app)
    reference = "(typeof(a.source_ref)='text' AND length(trim(a.source_ref))>0)"
    derived = "(a.parser IN ('aleapp','ileapp','leapp','import/leapp','import/tsv','import/jsonl') OR a.parser LIKE 'import/%')"
    report = ('(' + reference + ' AND (assessment_hash(json_extract(' + data + ", '$._ancalor_report.sha256'))=1"
              ' OR (' + derived + ' AND assessment_hash(f.sha256)=1)))')
    base = ' FROM artifacts a LEFT JOIN files f ON f.id=a.file_id AND f.evidence_id=a.evidence_id WHERE ' + where
    row = db.execute('SELECT COUNT(*) AS total,COUNT(assessment_utc(a.timestamp)) AS dated,'
                     'MIN(assessment_utc(a.timestamp)) AS first,MAX(assessment_utc(a.timestamp)) AS last,'
                     'COALESCE(SUM(' + reference + '),0) AS refs,'
                     'COALESCE(SUM(assessment_hash(f.sha256)),0) AS hashes,'
                     'COALESCE(SUM(' + report + '),0) AS reports,'
                     'COALESCE(SUM(' + derived + '),0) AS derived,'
                     'COALESCE(SUM(a.file_id IS NOT NULL AND f.id IS NULL),0) AS invalid_links' + base, args).fetchone()
    samples = []
    for source in db.execute('SELECT a.id AS artifact_id,a.evidence_id,a.source_ref,a.parser,f.id AS file_id,'
                             'f.logical_path,f.sha256 AS source_sha256,' + report + ' AS report_link' + base +
                             ' ORDER BY a.id LIMIT ?', [*args, MAX_SAMPLES]):
        if not _safe_text(source['artifact_id']) or source['evidence_id'] is None:
            continue
        sample = {}
        omitted = []
        for key in ('artifact_id', 'evidence_id', 'source_ref', 'parser', 'logical_path', 'source_sha256'):
            sample[key] = _safe_text(source[key])
            if source[key] is not None and sample[key] is None:
                omitted.append(key)
        sample['file_id'] = source['file_id']
        sample['source_kind'] = ('retained-report-reference' if source['report_link'] else
                                 'retained-file-reference' if source['file_id'] is not None else 'unresolved-reference')
        sample['omitted_fields'] = omitted
        samples.append(sample)
    return {'id': category + (':' + app if app else ''), 'label': label, 'category': category, 'application': app,
            'record_count': row['total'], 'dated_count': row['dated'], 'undated_count': row['total'] - row['dated'],
            'first_utc': row['first'], 'last_utc': row['last'],
            'provenance': {'with_source_reference': row['refs'], 'without_source_reference': row['total'] - row['refs'],
                           'with_recorded_file_hash': row['hashes'], 'with_retained_report_reference': row['reports'],
                           'derived_report_rows': row['derived'], 'invalid_file_links': row['invalid_links']},
            'samples': samples, 'samples_truncated': row['total'] > len(samples),
            'sample_fields_omitted': any(s['omitted_fields'] for s in samples)}


def _runs(db, evidence, run):
    clause, args = 'evidence_id=?', [evidence]
    if run:
        clause += ' AND id=?'
        args.append(run)
    total = db.execute('SELECT COUNT(*) FROM runs WHERE ' + clause, args).fetchone()[0]
    items = []
    for row in db.execute('SELECT id,engine,status,started_at,finished_at,records FROM runs WHERE ' + clause +
                          ' ORDER BY started_at DESC,id DESC LIMIT ?', [*args, MAX_ITEMS]):
        if not _safe_text(row['id']):
            continue
        item = {key: _safe_text(row[key]) for key in ('id', 'engine', 'status', 'started_at', 'finished_at')}
        item['records'] = row['records'] if type(row['records']) is int and row['records'] >= 0 else 0
        item['record_count_meaning'] = 'Retained run counter; may count newly inserted rows, not membership.'
        item['fields_omitted'] = [key for key in item if key in row.keys() and row[key] is not None and item[key] is None]
        for key in ('engine', 'status'):
            if item[key] is None:
                item[key] = 'unknown'
        items.append(item)
    return {'items': items, 'total': total, 'truncated': total > len(items)}


def _coverage(root, db, evidence, run):
    states = Counter({state: 0 for state in STATE_AXIS})
    axes = Counter({axis: 0 for axis in STATE_AXIS.values()})
    gaps, count = [], 0
    runs = {run} if run else None
    try:
        for entry in _iter_entries(root, db):
            if entry.get('evidence_id') != evidence or not run_selected(entry, runs):
                continue
            state, axis = entry['state'], entry['axis']
            states[state] += 1
            axes[axis] += 1
            if state not in GAP_STATES:
                continue
            count += 1
            if len(gaps) >= MAX_ITEMS:
                continue
            reason = REASONS[state]
            if isinstance(entry, _ExpectedSourceGap) and entry.get('reason_code') in EXPECTED_REASONS:
                reason = entry['reason_code']
            if isinstance(entry, _EncryptedInputRefusal) and entry.get('execution_started') is False:
                reason = ENCRYPTED_INPUT
            gap = {'state': state, 'axis': axis, 'reason_code': reason,
                   'evidence_id': evidence, 'run_id': _safe_text(entry.get('run_id')),
                   'source': _safe_text(entry.get('source')), 'category': _safe_text(entry.get('category')),
                   'reference': _safe_text(entry.get('reference')), 'expectation_id': _safe_text(entry.get('expectation_id')),
                   'origin': 'operator-recorded' if entry.get('origin') == 'explicit' else 'derived',
                   'scope_level': 'run' if entry.get('scope_level') == 'run' else 'source',
                   'impact_on_selected_records': 'unknown'}
            if reason == ENCRYPTED_INPUT:
                gap['execution_started'] = False
            gap['fields_omitted'] = [key for key in ('source', 'reference', 'category', 'run_id', 'expectation_id')
                                     if entry.get(key) is not None and gap[key] is None]
            gaps.append(gap)
    except (TypeError, ValueError, AttributeError, sqlite3.Error) as exc:
        raise UserError('Retained coverage metadata could not be assessed; inspect the coverage ledger.') from exc
    return {'state_counts': dict(states), 'axis_counts': dict(axes), 'gaps': gaps,
            'gap_count': count, 'truncated': count > len(gaps),
            'scope': 'selected-evidence-with-run-filter' if run else 'selected-evidence',
            'count_unit': 'coverage observations; independent axes may describe the same source',
            'independent_examiner_signoff': False}


def _actions(case, evidence, run, requirements, coverage):
    scope = {'case': case, 'evidence': evidence}
    if run:
        scope['run'] = run
    actions = []
    for item in requirements:
        if not item['record_count']:
            continue
        request = {'action': 'records', **scope, 'category': item['category']}
        argv = ['lawliet', 'timeline', '--case', case, '--evidence', evidence, '--category', item['category']]
        if item['application']:
            request['app'] = item['application']
            argv += ['--app', item['application']]
        if run:
            argv += ['--run', run]
        actions.append({'id': 'review:' + item['id'], 'label': 'Review ' + item['label'].lower(),
                        'request': request, 'cli_argv': argv})
    filters = {'evidence_id': evidence}
    if coverage['gap_count']:
        actions.append({'id': 'coverage', 'label': 'Inspect evidence-wide coverage and retained processing limitations',
                        'request': {'action': 'coverage-ledger', 'case': case, 'filters': filters}, 'cli_argv': []})
    if any(not item['record_count'] for item in requirements):
        actions.append({'id': 'analysis-plan', 'label': 'Review compatible analysis for the selected evidence',
                        'request': {'action': 'analysis-plan', 'case': case, 'evidence': evidence, 'profile': 'standard'},
                        'cli_argv': ['lawliet', 'analysis-plan', '--case', case, '--evidence', evidence]})
    actions.extend([
        {'id': 'inventory', 'label': 'Inspect retained evidence inventory',
         'request': {'action': 'file-inventory', 'case': case, 'evidence': evidence},
         'cli_argv': ['lawliet', 'evidence', '--case', case, '--evidence', evidence]},
        {'id': 'verify', 'label': 'Run fresh case integrity verification',
         'request': {'action': 'verify', 'case': case}, 'cli_argv': ['lawliet', 'verify', '--case', case]},
    ])
    return actions


def _bound_output(value):
    """Bound retained samples and gap details without altering aggregate counts."""
    def size():
        return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8'))
    if size() > MAX_OUTPUT:
        value['truncated'] = True
        for item in reversed(value['requirements']):
            while item['samples'] and size() > MAX_OUTPUT:
                item['samples'].pop()
                item['samples_truncated'] = True
        for group, key in ((value['coverage'], 'gaps'), (value['analysis_runs'], 'items')):
            while group[key] and size() > MAX_OUTPUT:
                group[key].pop()
                group['truncated'] = True
    if size() > MAX_OUTPUT:
        raise UserError('Assessment metadata exceeds its output budget.')
    return value


def assess(root, db, evidence, scenario='messages', run=None):
    """Return one consistent, bounded assessment without persistent case writes."""
    _selector(evidence, 'evidence ID')
    _selector(run, 'run ID', optional=True)
    if not isinstance(scenario, str) or scenario not in SCENARIOS or scenario not in REQUIREMENTS:
        raise UserError('Choose a supported customer scenario.')
    # A savepoint nests safely inside an existing caller transaction and holds a
    # consistent SQLite read snapshot; release does not commit caller writes.
    savepoint = 'assessment_' + uuid.uuid4().hex
    db.execute('SAVEPOINT ' + savepoint)
    try:
        checked_scope(db, {'evidence': evidence, **({'run': run} if run else {})})
        db.create_function('assessment_utc', 1, _utc, deterministic=True)
        db.create_function('assessment_hash', 1, _hash, deterministic=True)
        case = db.execute("SELECT value FROM meta WHERE key='case_id'").fetchone()
        if not case or not isinstance(case[0], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', case[0]):
            raise UserError('Case identifier metadata is invalid.')
        case = case[0]
        clause, params = 'a.evidence_id=?', [evidence]
        if run:
            selected, arguments = run_scope(db, run, 'a.')
            clause += ' AND ' + selected
            params += arguments
        requirements = [_requirement(db, clause, params, *spec) for spec in REQUIREMENTS[scenario]]
        inventory = db.execute('SELECT COUNT(*),COALESCE(SUM(size),0),COALESCE(SUM(assessment_hash(sha256)),0) '
                               'FROM files WHERE evidence_id=?', (evidence,)).fetchone()
        coverage = _coverage(root, db, evidence, run)
        runs = _runs(db, evidence, run)
        result = {'schema_version': 1, 'case_id': case, 'evidence_id': evidence, 'run': run,
                  'scenario': scenario, 'objective': SCENARIOS[scenario]['customer'],
                  'status': 'records_available_for_review' if any(r['record_count'] for r in requirements) else 'no_relevant_indexed_records',
                  'assessment_scope': 'retained index and metadata; no fresh integrity check',
                  'requirements': requirements,
                  'inventory': {'files': inventory[0], 'bytes': inventory[1], 'hashes_recorded': inventory[2]},
                  'analysis_runs': runs, 'coverage': coverage,
                  'next_actions': _actions(case, evidence, run, requirements, coverage),
                  'limitations': LIMITATIONS + SCENARIOS[scenario]['blind_spots'],
                  'truncated': runs['truncated'] or coverage['truncated']
                      or any(item['fields_omitted'] for item in runs['items'])
                      or any(item['fields_omitted'] for item in coverage['gaps'])
                      or any(r['samples_truncated'] or r['sample_fields_omitted'] for r in requirements)}
        return _bound_output(result)
    finally:
        db.execute('ROLLBACK TO ' + savepoint)
        db.execute('RELEASE ' + savepoint)
