"""Bind explicitly selected saved findings to an unreviewed investigation draft."""
import json

from . import findings, investigation
from .core import UserError, audit, verify


def from_findings(root, db, objective, finding_ids):
    if (not isinstance(finding_ids, list) or not 1 <= len(finding_ids) <= 100 or
            any(not isinstance(i, str) or not i or len(i) > 64 for i in finding_ids) or
            len(set(finding_ids)) != len(finding_ids)):
        raise UserError('Select 1–100 distinct saved finding IDs in this case.')
    if not isinstance(objective, str) or not objective.strip() or len(objective) > 16000:
        raise UserError('Supply an explicit report investigation objective of 1–16000 characters.')
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    else:
        db.execute('UPDATE audit SET id=id WHERE 0')
    checked = verify(root, db)
    if not checked['ok']:
        raise UserError('Case integrity must pass before binding saved findings.')
    receipts = findings.check_inventory(db)
    selected = []
    for identifier in finding_ids:
        row = db.execute('SELECT * FROM findings WHERE id=?', (identifier,)).fetchone() if receipts else None
        if row is None:
            raise UserError('Selected saved finding is not in this case.')
        finding = findings.checked_value(row, receipts)
        current = db.execute('''SELECT a.*,f.logical_path,f.sha256 AS source_sha256 FROM artifacts a
                                LEFT JOIN files f ON f.id=a.file_id WHERE a.id=?''',
                             (finding['artifact_id'],)).fetchone()
        if current is None:
            raise UserError('Saved finding source artifact is unavailable.')
        snapshot = dict(current)
        snapshot['data'] = json.loads(snapshot['data'])
        if findings.checksum(snapshot) != findings.checksum(finding['snapshot']):
            raise UserError('Saved finding snapshot differs from the retained artifact; review the change first.')
        text = ('Saved finding ' + identifier + '; original examiner label: ' + finding['examiner'] +
                '. Unreviewed operator interpretation; source linkage does not verify its conclusion.\n' + finding['note'])
        if len(text) > 16000:
            raise UserError('Selected finding exceeds the investigation note bound; narrow it explicitly.')
        selected.append((finding, text))
    db.execute('SAVEPOINT report_findings_binding')
    try:
        result = investigation.create(db, objective, sorted({f['snapshot']['evidence_id'] for f, _ in selected}))
        entries = []
        for finding, text in selected:
            entry = investigation.note(db, result['id'], 'interpretation', text, [finding['artifact_id']])
            entries.append({'finding_id': finding['id'], 'finding_sha256': finding['sha256'],
                            'artifact_id': finding['artifact_id'], 'entry_id': entry['entry_id']})
        audit(db, 'investigation.findings_bound', {'investigation_id': result['id'], 'selected': entries,
                                                  'review_status': 'unreviewed'})
        db.execute('RELEASE SAVEPOINT report_findings_binding')
    except BaseException:
        db.execute('ROLLBACK TO SAVEPOINT report_findings_binding')
        db.execute('RELEASE SAVEPOINT report_findings_binding')
        raise
    return {'investigation_id': result['id'], 'selected': entries, 'scope': result['scope'],
            'review_status': 'unreviewed', 'source_integrity_checked': True,
            'limitations': ['Only explicitly selected saved findings were bound.',
                            'Finding text remains an operator interpretation, not an independently verified fact.',
                            'No draft approval, release, external delivery or new parser execution occurred.']}
