"""Bounded, read-only recipient checks for versioned references-only packages.

No case database, evidence paths, URLs, model or examiner identity is consulted.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_FILE = 32 * 1024**2
MAX_TOTAL = 64 * 1024**2
BASE_FILES = {'report.txt', 'technical-annex.json', 'investigation.json', 'exhibits.jsonl'}
FORMATS = {'ancalor-customer-bundle-v1', 'ancalor-customer-redacted-bundle-v1'}
SHA = re.compile(r'[0-9a-f]{64}\Z')
ENTRY_KINDS = ('task', 'hypothesis', 'question', 'observation', 'interpretation')


class PackageError(ValueError):
    pass


def _json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise PackageError('Duplicate JSON key.')
            value[key] = item
        return value
    def constant(_):
        raise PackageError('Nonfinite JSON number.')
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PackageError('Invalid or excessively nested package JSON.') from exc


def _directory(path):
    """Anchor every directory component without following symbolic links."""
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise PackageError('This platform lacks the required no-follow directory API.')
    path = Path(path).absolute()
    if '..' in path.parts:
        raise PackageError('Parent traversal is not accepted.')
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(fd, name):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    file_fd = os.open(name, flags, dir_fd=fd)
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PackageError('Package members must be regular, single-link files.')
        if before.st_size > MAX_FILE:
            raise PackageError('Package member exceeds the 32 MiB verification limit.')
        with os.fdopen(file_fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_FILE + 1)
        after = os.fstat(file_fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if len(data) > MAX_FILE or identity(before) != identity(after) or identity(after) != identity(current):
            raise PackageError('Package member changed during verification.')
        return data, identity(after)
    finally:
        os.close(file_fd)


def _cross_document_entries(investigation, annex):
    """Compare retained declarations; never authenticate or replay a ledger."""
    entries, snapshots, action_keys = [], {}, set()
    for kind in ENTRY_KINDS:
        events = investigation.get(kind + '_entries')
        if not isinstance(events, list):
            raise PackageError('Missing or invalid investigation entry section.')
        for event in events:
            if not isinstance(event, dict):
                raise PackageError('Invalid investigation entry.')
            key = event.get('action_key')
            request, result = event.get('request'), event.get('result')
            if not isinstance(key, str) or not key or key in action_keys:
                raise PackageError('Duplicate or invalid investigation entry identity.')
            if (not isinstance(request, dict) or not isinstance(result, dict)
                    or not isinstance(request.get('text'), str)
                    or not isinstance(result.get('citations'), list)):
                raise PackageError('Invalid investigation entry request/citations.')
            if (event.get('kind') != 'analyst.' + kind or request.get('kind') != kind
                    or event.get('investigation_id') != investigation['investigation']['id']):
                raise PackageError('Investigation entry kind/identity disagree.')
            refs = []
            for snapshot in result['citations']:
                if not isinstance(snapshot, dict) or not isinstance(snapshot.get('id'), str) or not snapshot['id']:
                    raise PackageError('Invalid investigation citation snapshot.')
                aid = snapshot['id']
                if aid in snapshots and snapshots[aid] != snapshot:
                    raise PackageError('Investigation citation snapshots disagree.')
                refs.append(aid)
                snapshots[aid] = snapshot
            if request.get('artifact_ids') != refs:
                raise PackageError('Investigation entry request and citations disagree.')
            action_keys.add(key)
            entries.append({'kind': kind, 'entry_id': key,
                            'text': request['text'], 'artifact_ids': refs})
    if entries != annex['entries']:
        raise PackageError('Annex and investigation entries disagree.')
    if snapshots != {c['artifact_id']: c['snapshot'] for c in annex['citations']}:
        raise PackageError('Annex and investigation citation snapshots disagree.')


def verify_package(path, expected_manifest_sha256=None):
    """Return self-consistency observations; an optional digest is an external anchor.

    An external digest is useful only if the caller obtained it independently.
    A passing result never authenticates evidence, authorship or approval.
    """
    if expected_manifest_sha256 is not None and not SHA.fullmatch(expected_manifest_sha256):
        raise PackageError('Expected manifest SHA-256 must be 64 lowercase hexadecimal characters.')
    fd = _directory(path)
    try:
        inventory = set(os.listdir(fd))
        if len(inventory) > 7:
            raise PackageError('Unexpected package inventory.')
        raw, manifest_identity = _read(fd, 'manifest.json')
        manifest_sha = hashlib.sha256(raw).hexdigest()
        if expected_manifest_sha256 is not None and manifest_sha != expected_manifest_sha256:
            raise PackageError('Manifest does not match the independently supplied digest.')
        manifest = _json(raw)
        if not isinstance(manifest, dict) or manifest.get('format') not in FORMATS:
            raise PackageError('Unsupported package format/version.')
        redacted = manifest['format'] == 'ancalor-customer-redacted-bundle-v1'
        if manifest.get('review_status') != ('unreviewed_redacted_derivative' if redacted else 'draft_unreviewed'):
            raise PackageError('Unsupported recorded review status.')
        required = BASE_FILES if redacted else BASE_FILES | {'investigation.json.receipt.json'}
        files = manifest.get('files')
        if not isinstance(files, list) or len(files) != len(required):
            raise PackageError('Unexpected manifest file count.')
        payloads, identities = {}, {'manifest.json': manifest_identity}
        total = len(raw)
        for entry in files:
            if not isinstance(entry, dict):
                raise PackageError('Invalid manifest member.')
            name = entry.get('path')
            if not isinstance(name, str) or name not in required or name in payloads:
                raise PackageError('Unsafe, duplicate or unsupported manifest member.')
            if type(entry.get('bytes')) is not int or entry['bytes'] < 0 or not isinstance(entry.get('sha256'), str) or not SHA.fullmatch(entry['sha256']):
                raise PackageError('Invalid manifest size/hash.')
            data, identity = _read(fd, name)
            if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
                raise PackageError('Package member size/hash mismatch.')
            total += len(data)
            if total > MAX_TOTAL:
                raise PackageError('Package exceeds the 64 MiB verification limit.')
            payloads[name], identities[name] = data, identity
        allowed = required | {'manifest.json'}
        # Unredacted local releases add an unmanifested receipt. It is checked for
        # internal digest binding, never treated as a trusted examiner signature.
        release_receipt = None
        if not redacted and 'release-receipt.json' in inventory:
            data, identities['release-receipt.json'] = _read(fd, 'release-receipt.json')
            total += len(data)
            if total > MAX_TOTAL:
                raise PackageError('Package exceeds the 64 MiB verification limit.')
            release_receipt = _json(data)
            if not isinstance(release_receipt, dict) or release_receipt.get('manifest_sha256') != manifest_sha:
                raise PackageError('Release receipt does not bind this manifest.')
            allowed.add('release-receipt.json')
        if inventory != allowed or set(os.listdir(fd)) != inventory:
            raise PackageError('Missing or unexpected package members.')
        annex = _json(payloads['technical-annex.json'])
        if not isinstance(annex, dict) or annex.get('format') != 'ancalor-customer-annex-v1':
            raise PackageError('Unsupported annex format/version.')
        exhibits = [_json(line) for line in payloads['exhibits.jsonl'].splitlines() if line.strip()]
        if annex.get('citations') != exhibits:
            raise PackageError('Annex and exhibit citations disagree.')
        ids = []
        incomplete_locators = 0
        tiers = {}
        for citation in exhibits:
            if not isinstance(citation, dict) or not isinstance(citation.get('artifact_id'), str) or not citation['artifact_id']:
                raise PackageError('Invalid citation identity.')
            ids.append(citation['artifact_id'])
            tier = citation.get('source_tier')
            if tier not in {'supplied-file; acquisition tier unverified', 'derived-tool-report', 'supplied-text-export'}:
                raise PackageError('Unsupported citation source tier.')
            tiers[tier] = tiers.get(tier, 0) + 1
            locator = citation.get('source_locator')
            if not isinstance(locator, dict) or not isinstance(citation.get('snapshot'), dict):
                raise PackageError('Missing citation snapshot/locator.')
            snapshot = citation['snapshot']
            if snapshot.get('id') != citation['artifact_id']:
                raise PackageError('Citation and snapshot identities disagree.')
            mappings = {'retained_logical_path': 'logical_path',
                        'record_table_key_or_offset': 'source_ref',
                        'recorded_source_sha256': 'source_sha256'}
            if any(locator.get(k) != snapshot.get(v) for k, v in mappings.items()):
                raise PackageError('Citation locator and retained snapshot disagree.')
            if any(not locator.get(k) for k in mappings):
                incomplete_locators += 1
            # Locators are data only: never resolve these against the host.
        entries = annex.get('entries')
        chronology = annex.get('chronology_artifact_ids')
        counts = manifest.get('counts')
        if len(set(ids)) != len(ids) or not isinstance(chronology, list) or len(chronology) != len(ids) or set(chronology) != set(ids):
            raise PackageError('Duplicate or inconsistent chronology/citation identities.')
        if not isinstance(entries, list) or not isinstance(counts, dict) or type(counts.get('entries')) is not int or type(counts.get('unique_cited_artifacts')) is not int or counts != {'entries': len(entries), 'unique_cited_artifacts': len(ids)}:
            raise PackageError('Manifest and annex counts disagree.')
        referenced = set()
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get('artifact_ids'), list) or any(not isinstance(i, str) or i not in ids for i in entry['artifact_ids']):
                raise PackageError('Entry has an unresolved citation.')
            referenced.update(entry['artifact_ids'])
        if referenced != set(ids):
            raise PackageError('Unreferenced exhibit citation.')
        investigation = _json(payloads['investigation.json'])
        if not isinstance(investigation, dict) or investigation.get('format') != 'ancalor-investigation-report-v1' or not isinstance(investigation.get('investigation'), dict) or investigation['investigation'].get('id') != annex.get('investigation_id'):
            raise PackageError('Investigation and annex identities disagree.')
        investigation_id = investigation['investigation'].get('id')
        case_id = investigation.get('case_id')
        if not isinstance(investigation_id, str) or not investigation_id.strip() or not isinstance(case_id, str) or not case_id.strip():
            raise PackageError('Missing or invalid investigation/case identity.')
        _cross_document_entries(investigation, annex)
        if not redacted:
            # The redacted manifest deliberately omits investigation_id and its
            # original export receipt; require these only in the original format.
            if manifest.get('investigation_id') != investigation_id:
                raise PackageError('Manifest and investigation identities disagree.')
            receipt = _json(payloads['investigation.json.receipt.json'])
            if not isinstance(receipt, dict) or receipt.get('sha256') != hashlib.sha256(payloads['investigation.json']).hexdigest() or receipt.get('bytes') != len(payloads['investigation.json']):
                raise PackageError('Investigation receipt does not bind the retained JSON.')
            if receipt.get('format') != 'ancalor-investigation-export-receipt-v1' or receipt.get('filename') != 'investigation.json':
                raise PackageError('Unsupported investigation export receipt.')
            if receipt.get('investigation_id') != investigation_id or receipt.get('case_id') != case_id:
                raise PackageError('Export receipt and investigation identities disagree.')
        for name, identity in identities.items():
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) != identity:
                raise PackageError('Package changed during verification.')
        return {'ok': True, 'format': manifest['format'], 'manifest_sha256': manifest_sha,
                'anchor': 'matches_supplied_digest' if expected_manifest_sha256 else 'self_consistency_only',
                'files_checked': len(identities), 'bytes_checked': total, 'counts': counts,
                'cross_document_entries_and_snapshots_match': True,
                'source_tiers': tiers, 'recorded_review_status': manifest.get('review_status'),
                'citations_with_incomplete_recorded_locators': incomplete_locators,
                'release_receipt_present': release_receipt is not None,
                'limitations': ['No original evidence or originating case database was consulted.',
                               'No claim of evidence authenticity, conclusion accuracy, redaction sufficiency or examiner approval.',
                               'A supplied digest must come through an independently trusted channel.',
                               'Reference paths and URLs were not opened; no network or model was used.']}
    finally:
        os.close(fd)
