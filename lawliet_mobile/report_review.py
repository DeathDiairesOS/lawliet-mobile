"""Read-only, case-audited bindings for native examiner review controls."""
import hmac
import json

from .core import UserError
from .investigation_report import _checked_draft, _checked_redacted_customer_draft


def checked_binding(root, db, bundle_id, kind, expected_manifest_sha256):
    if kind not in ('original', 'redacted'):
        raise UserError('Select an original or redacted report bundle.')
    expected = expected_manifest_sha256
    if not isinstance(expected, str) or len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
        raise UserError('The manifest hash of the reviewed bundle is required.')
    check = _checked_redacted_customer_draft if kind == 'redacted' else _checked_draft
    folder, manifest, checksum = check(root, db, bundle_id)
    if not hmac.compare_digest(expected, checksum):
        raise UserError('The selected bundle differs from the reviewed bytes. Reopen and review it before continuing.')
    return folder, manifest, checksum


def review_bundle(root, db, bundle_id, kind, expected_manifest_sha256):
    folder, manifest, checksum = checked_binding(root, db, bundle_id, kind, expected_manifest_sha256)
    id_key = 'derivative_id' if kind == 'redacted' else 'draft_id'
    action = 'customer_report.redacted_approved' if kind == 'redacted' else 'customer_report.approved'
    approval = None
    for row in db.execute('SELECT detail FROM audit WHERE action=? ORDER BY id DESC', (action,)):
        value = json.loads(row[0])
        if value.get(id_key) == bundle_id and value.get('manifest_sha256') == checksum:
            approval = {key: value.get(key) for key in ('reviewer', 'approved_at', 'manifest_sha256')}
            break
    return {'schema_version': 1, 'case_id': root.name, 'bundle_id': bundle_id, 'kind': kind,
            'path': str(folder), 'manifest_sha256': checksum, 'source_integrity_checked': True,
            'approval': approval, 'release_requires_recorded_approval': True,
            'limitations': ['Approval records an operator declaration; examiner identity and qualifications are not authenticated.',
                            'Export creates a local copy only. No delivery, upload or report-content modification occurs.',
                            'Verification is a point-in-time check; approval and export recheck source and bundle integrity.']}
