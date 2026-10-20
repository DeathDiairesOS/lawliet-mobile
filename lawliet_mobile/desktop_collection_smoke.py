"""Synthetic collector-to-desktop checks; never contacts a real device.

The transport script is supplied explicitly from the test checkout. Expected
content below comes from its fixed seed values, not production parser results.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from .desktop_smoke import canonical_sha256

PROFILES = ['sms-provider', 'contacts-provider', 'files', 'triage', 'trash-photos']
MESSAGE = 'Meet at the blue station at noon — café.'
NOTE = 'SYNTHETIC COLLECTION ONLY: meeting message and retained provider record reviewed.'
FIELDS = ('category', 'body', 'title', 'timestamp', 'timestamp_raw', 'logical_path', 'source_ref')
EXPECTED = [
    ('messages', MESSAGE, 'SMS provider · incoming', '2026-10-17T12:00:00.123000Z',
     '1792238400123', 'payload/sms-provider.jsonl', 'payload/sms-provider.jsonl:line=1'),
    ('messages', 'Confirmed. Bring the receipt.', 'SMS provider · outgoing',
     '2026-10-17T12:01:00.123000Z', '1792238460123',
     'payload/sms-provider.jsonl', 'payload/sms-provider.jsonl:line=2'),
    ('contacts', 'FN: Alex Fixture · UID: android-provider-user-0-contact-7 · TEL: +12025550123',
     'Alex Fixture', None, None, 'contacts.vcf', 'vcard:record=1'),
    ('logs', 'Synthetic activity resumed', 'I · ActivityManager',
     '2026-10-17T12:00:01.250000Z', '1792238401.250', 'logcat.txt', 'line=2'),
    ('media', 'image/png', 'lab-photo.png', None, None,
     'shared/0/lab-photo.png', 'file:shared/0/lab-photo.png'),
    ('media', 'image/png', 'trashed-fixture.png', None, None,
     'photos/0/trashed-fixture.png', 'file:photos/0/trashed-fixture.png'),
] + [
    ('apps', '/data/app/example/base.apk', 'com.example.fixture', None, None, 'packages.txt', 'line=1'),
    ('device', ' Synthetic validation fixture · Android 13', 'Android system properties',
     None, None, 'getprop.txt', 'getprop output'),
] * 2


def prepare(workspace, directory, transport):
    from .tools import configure
    directory = Path(directory)
    script = directory / 'synthetic-adb.py'
    script.write_bytes(Path(transport).read_bytes())
    # Device discovery normally checks both platforms. Override both so even
    # discovery cannot contact a real phone during an explicit synthetic run.
    ios = directory / 'synthetic-ios-empty.py'
    ios.write_bytes(b'import sys\nraise SystemExit(0 if sys.argv[1:] == ["-l"] else 2)\n')
    configure(workspace, 'adb', str(script), sys.executable)
    configure(workspace, 'idevice_id', str(ios), sys.executable)
    return {'case_id': 'DESKTOP-COLLECTION', 'serial': 'LAWLIET-SYNTHETIC',
            'profiles': PROFILES, 'pull': '/sdcard/Download/lawliet-seed',
            'script': str(script), 'script_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
            'export_path': str(directory / 'collection-report-export'),
            'message': MESSAGE, 'note': NOTE}


def check_records(rows):
    actual = [tuple(row.get(key) for key in FIELDS) for row in rows]
    if Counter(actual) != Counter(EXPECTED):
        raise ValueError('Collected record fields differ from the fixed synthetic device seed')
    return canonical_sha256(sorted(actual, key=lambda row: json.dumps(row, ensure_ascii=False)))


def check(workspace, config, result):
    from .core import connect, verify
    from .package_verification import verify_package
    if result.get('case_id') != config['case_id']:
        raise ValueError('Collection results belong to a different case')
    steps = result.get('collections', [])
    if [s.get('profile') for s in steps] != PROFILES or any(
            s.get('result', {}).get('status') != 'complete' for s in steps):
        raise ValueError('Not all five synthetic collection methods completed')
    rows = result.get('records', [])
    fingerprint = check_records(rows)
    with connect(workspace, config['case_id']) as (root, db):
        integrity = verify(root, db)
        if not integrity['ok']:
            raise ValueError('Collected evidence failed integrity verification')
        for row in rows:
            entry = db.execute('SELECT path,sha256,evidence_id FROM files WHERE id=?',
                               (row['file_id'],)).fetchone()
            if not entry or entry['evidence_id'] != row['evidence_id']:
                raise ValueError('Collected artifact lost its case source file')
            digest = hashlib.sha256((root/'evidence'/entry['evidence_id']/entry['path']).read_bytes()).hexdigest()
            if digest != entry['sha256'] or digest != row['source_sha256']:
                raise ValueError('Collected source hash differs from displayed provenance')
    chosen = result.get('selected', {})
    if tuple(chosen.get(key) for key in FIELDS) != EXPECTED[0]:
        raise ValueError('Collection finding does not identify the expected incoming message')
    # The searchable view adds a mutable review_note, which is intentionally
    # absent from the immutable original-record snapshot.
    if not any(row.get('id') == chosen.get('id') and
               {key: row.get(key) for key in chosen} == chosen for row in rows):
        raise ValueError('Collection finding is not a retained collected record')
    export = Path(config['export_path'])
    report = result['report']
    verified = verify_package(export, report['manifest_sha256'])
    annex = json.loads((export/'technical-annex.json').read_text(encoding='utf-8'))
    citations = annex['citations']
    cited = dict(citations[0]['snapshot']) if len(citations) == 1 else {}
    # The technical annex retains the database JSON text; the viewer decodes it.
    if isinstance(cited.get('data'), str):
        cited['data'] = json.loads(cited['data'])
    if len(citations) != 1 or cited != chosen or citations[0]['artifact_id'] != chosen['id']:
        raise ValueError('Collection report lost its exact source record')
    receipt = json.loads((export/'release-receipt.json').read_text(encoding='utf-8'))
    if (receipt['draft_id'] != report['id'] or receipt['manifest_sha256'] != report['manifest_sha256']
            or verified['files_checked'] != 7):
        raise ValueError('Collection report release is not bound to its complete package')
    script = Path(config['script'])
    if hashlib.sha256(script.read_bytes()).hexdigest() != config['script_sha256']:
        raise ValueError('Synthetic device transport changed during validation')
    calls = script.with_suffix('.calls.jsonl').read_bytes()
    return {'ok': True, 'case_id': config['case_id'], 'profiles': PROFILES,
            'records_checked': len(rows), 'field_fingerprint_sha256': fingerprint,
            'source_hashes_verified': True, 'report_verified': True,
            'transport_sha256': config['script_sha256'],
            'transport_calls_sha256': hashlib.sha256(calls).hexdigest(),
            'transport': 'synthetic subprocess; no physical USB', 'report': report}
