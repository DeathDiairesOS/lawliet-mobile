"""Bounded, repeatable message-review handoff using existing case evidence."""
import csv
import json
import uuid
from collections import Counter

from .acquisition import case_coverage
from .core import UserError, audit, digest, iter_artifacts, now, verify
from .messages import conversations
from .parsers import VERSION
from .report import write_report
from .adapters import analyze as adapter_analyze


def review(root, db, workspace, evidence_id, engine='native', run=None,
           reanalyze=False, preview_limit=500, timeout=900):
    evidence = db.execute('SELECT * FROM evidence WHERE id=?', (evidence_id,)).fetchone()
    if not evidence:
        raise UserError(f'Unknown evidence: {evidence_id}')
    if not 1 <= preview_limit <= 10000:
        raise UserError('Preview limit must be between 1 and 10,000.')
    integrity = verify(root, db)
    if not integrity['ok']:
        raise UserError('Evidence integrity check failed; run verify before review.')
    if run and reanalyze:
        raise UserError('Choose an existing --run or --reanalyze, not both.')
    selected = None
    if run:
        selected = db.execute('SELECT * FROM runs WHERE id=? AND evidence_id=?', (run, evidence_id)).fetchone()
        if not selected or selected['engine'] not in {'ileapp', 'aleapp'} or selected['status'] != 'complete':
            raise UserError('Choose a completed LEAPP run belonging to this evidence.')
        engine = selected['engine']
    elif not reanalyze:
        selected = db.execute("SELECT * FROM runs WHERE evidence_id=? AND engine=? AND status='complete' ORDER BY started_at DESC,rowid DESC LIMIT 1", (evidence_id, VERSION if engine == 'native' else engine)).fetchone()
    if selected is None:
        result = adapter_analyze(root, db, workspace, evidence_id, engine, timeout)
        if result['status'] != 'complete':
            raise UserError('Analysis did not complete; inspect coverage and run details before review.')
        selected = db.execute('SELECT * FROM runs WHERE id=?', (result['run_id'],)).fetchone()
    filters = {'evidence': evidence_id, 'category': 'messages',
               'parser': VERSION if engine == 'native' else engine}
    if engine != 'native':
        filters['run'] = selected['id']
    folder = root / 'reports' / ('review-' + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    counts, undated, rows, ids = Counter(), 0, 0, set()
    # Stream the complete export; HTML remains small even for large cases.
    fields = ['id', 'timestamp', 'app', 'direction', 'sender', 'recipient', 'body', 'source_ref', 'parser']
    def cell(value):
        value = str(value or '')
        return "'" + value if value.startswith(('=', '+', '-', '@', '\t', '\r')) else value
    with (folder / 'messages.jsonl').open('w', encoding='utf-8') as output, (folder / 'messages.csv').open('w', encoding='utf-8', newline='') as flat:
        writer = csv.DictWriter(flat, fieldnames=fields)
        writer.writeheader()
        for record in iter_artifacts(db, limit=None, **filters):
            output.write(json.dumps(record, ensure_ascii=False) + '\n')
            message = record['data'].get('message', {})
            writer.writerow({k: cell(message.get(k, record.get(k))) for k in fields})
            counts[message.get('app', 'unknown')] += 1
            rows += 1
            undated += record['timestamp'] is None
            if engine == 'ileapp' and message.get('source_row_id'):
                ids.add(str(message['source_row_id']))
    groups = conversations(db, evidence=evidence_id, parser=filters['parser'], run=filters.get('run'))
    (folder / 'conversations.json').write_text(json.dumps(groups, indent=2, ensure_ascii=False) + '\n')
    report = write_report(root, db, folder / 'preview.html', filters, preview_limit=preview_limit)
    coverage = case_coverage(root, db)
    (folder / 'coverage.json').write_text(json.dumps(coverage, indent=2, ensure_ascii=False) + '\n')
    integrity = verify(root, db)
    summary = {'created_at': now(), 'status': 'ready_for_review' if rows and integrity['ok'] else 'no_messages' if integrity['ok'] else 'integrity_failure',
               'evidence_id': evidence_id, 'evidence_label': evidence['label'], 'analysis_run': selected['id'],
               'engine': engine, 'filters': filters, 'message_rows': rows, 'rows_by_app': dict(counts),
               'undated_rows': undated, 'conversations': len(groups),
               'distinct_ileapp_message_row_ids': len(ids) if ids else None,
               'integrity': integrity, 'preview': report,
               'case_collection_statuses': [a.get('status', 'unknown') for a in coverage['collection_attempts']],
               'limitations': ['Review readiness does not establish acquisition completeness; read coverage.json and the evidence label.',
                   'Counts are report rows; attachments can repeat message IDs. Distinct iLEAPP row IDs assume a single source Messages database.',
                   'Native review includes current-parser artifacts across idempotent runs; LEAPP review selects exactly one completed run.',
                   'Attachment references are not proof that attachment bytes were acquired or validated.',
                   'HTML searches only its displayed preview; use CLI queries or messages.jsonl for all rows.'],
               'files': {name: {'sha256': digest(folder / name), 'bytes': (folder / name).stat().st_size}
                         for name in ['messages.jsonl', 'messages.csv', 'conversations.json', 'coverage.json', 'preview.html']}}
    (folder / 'summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    audit(db, 'review.created', {'folder': str(folder), 'summary_sha256': digest(folder / 'summary.json'),
          'analysis_run': selected['id'], 'message_rows': rows, 'status': summary['status']})
    return {'status': summary['status'], 'folder': str(folder), 'summary': str(folder / 'summary.json'),
            'preview': report['path'], 'message_rows': rows, 'rows_by_app': dict(counts),
            'analysis_run': selected['id'], 'preview_rows': report['records'], 'integrity_ok': integrity['ok']}
