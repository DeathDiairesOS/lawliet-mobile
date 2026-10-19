"""Durable, examiner-authorized Android collection plans for existing collectors.

This is a bounded workflow, not an agent or a device-access bypass. Callers may
execute a saved plan by ID; execution never accepts replacement scope or commands.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path, PurePosixPath

from . import acquisition, parsers, provider_contacts, provider_sms
from .core import UserError, audit, has_run_index, json_text, now, run_scope, verify

PROFILES = ('sms-provider', 'contacts-provider', 'files', 'triage', 'trash-photos', 'messages')
PROVIDER_MAX_BYTES = 64 * 1024**2
MAX_BYTES = 20 * 1024**3
MAX_COVERAGE = 8
TERMINAL = {'complete', 'partial', 'failed', 'interrupted'}
LIMITATIONS = [
    'Authorization covers only the saved serial, profiles, paths and limits. No permission grants, app installation, root or security-setting changes are performed.',
    'SMS provider access does not include MMS, RCS or private application messages; contacts and shared files cover only accessible data.',
    'Triage collects device properties, application inventory, logcat and a bug report. Diagnostic files are retained; not every diagnostic field becomes an indexed artifact.',
    'Legacy telephony backup is separately selected as messages and may require on-device confirmation or be unsupported. Triage never requests a backup.',
    'Trash photos covers the accessible Samsung shared-storage Trash path only, not permanently deleted recovery. Shared files and Trash use owner-user storage paths.',
    'Live reads may be logged by the device and are not an atomic device snapshot. Zero indexed records does not establish absence.',
    'The byte limit applies separately to each profile; SMS and contacts remain capped at 64 MiB. Live storage checks are polling stop conditions and may overshoot. Timeout bounds the provider collection phase or each other collection command, not parsing or the whole workflow.',
    'Interrupted workflows are not automatically reacquired. Inspect retained collection and analysis history before authorizing a new plan.',
    'Completion describes execution and indexing only. Source interpretation and examiner review remain separate.',
]


def _text(value, label, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 and c not in '\n\t' for c in value):
        raise UserError(f'{label} must be nonempty text, at most {maximum} characters, without control characters.')
    return value.strip()


def _integer(value, label, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise UserError(f'{label} must be an integer between {minimum} and {maximum}; booleans are refused.')
    return value


def _config(config):
    allowed = {'objective', 'serial', 'profiles', 'pulls', 'android_user', 'max_records', 'max_bytes', 'timeout', 'examiner', 'authorized'}
    if not isinstance(config, dict) or set(config) - allowed:
        raise UserError('Collection configuration contains unsupported fields.')
    if config.get('authorized') is not True:
        raise UserError('Explicit examiner authorization is required before saving a collection plan.')
    value = {key: _text(config.get(key), key, cap) for key, cap in [('objective', 2000), ('examiner', 160), ('serial', 128)]}
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.:-]*', value['serial']):
        raise UserError('Select one explicit valid Android serial; shell arguments are not accepted.')
    profiles = config.get('profiles')
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= len(PROFILES) or any(p not in PROFILES for p in profiles) or len(set(profiles)) != len(profiles):
        raise UserError(f'Select one to {len(PROFILES)} distinct supported collection profiles.')
    pulls = config.get('pulls', [])
    if not isinstance(pulls, list) or len(pulls) > 10 or any(not isinstance(p, str) or len(p) > 512 for p in pulls):
        raise UserError('Provide at most ten explicit shared-storage paths.')
    for path in pulls:
        parts = PurePosixPath(path)
        if not path.startswith(('/sdcard/', '/storage/emulated/0/')) or '..' in parts.parts or not re.fullmatch(r'[\w /().@+-]+', path) or parts.as_posix() != path or path in {'/sdcard/', '/storage/emulated/0/'}:
            raise UserError('Pull paths must name explicit shared-storage items under /sdcard/ or /storage/emulated/0/ without traversal.')
    if len(set(pulls)) != len(pulls) or bool(pulls) != ('files' in profiles):
        raise UserError('Explicit distinct pull paths are required only for the files profile.')
    user = config.get('android_user')
    if user is not None:
        _integer(user, 'Android user', 0, 2147483647)
        if {'files', 'trash-photos'} & set(profiles) and user != 0:
            raise UserError('Shared files and Trash support owner-user paths only; use a separate provider-only plan for another Android user.')
    value.update(profiles=list(profiles), pulls=list(pulls), android_user=user, authorized=True,
                 max_records=_integer(config.get('max_records', 1000), 'Record cap', 1, 10000),
                 max_bytes=_integer(config.get('max_bytes', PROVIDER_MAX_BYTES), 'Per-profile byte cap', 1, MAX_BYTES),
                 timeout=_integer(config.get('timeout', 900), 'Per-command timeout', 1, 900))
    return value


def _scope(root, db):
    root = Path(root)
    if not root.is_absolute() or any(p.is_symlink() for p in (root, *root.parents)) or not root.is_dir():
        raise UserError('Collection requires an existing absolute case directory without symlinks.')
    for name in ('collections', 'evidence', 'runs'):
        child = root / name
        if child.is_symlink() or (child.exists() and not child.is_dir()):
            raise UserError('Collection requires safe case-owned evidence, collections and runs directories.')
    path = root / 'case.sqlite'
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise UserError('Collection case database path is unsafe.')
    database = next((r[2] for r in db.execute('PRAGMA database_list') if r[1] == 'main'), '')
    if not database or not Path(database).is_absolute() or not os.path.samefile(database, path):
        raise UserError('Collection database and selected case do not match.')
    meta = dict(db.execute("SELECT key,value FROM meta WHERE key IN ('case_id','created_at')"))
    if meta.get('case_id') != root.name or not meta.get('created_at'):
        raise UserError('Collection case identity is missing or inconsistent.')
    return root, meta


@contextlib.contextmanager
def _lock(root):
    """Independent, nonblocking workflow lock; nested collectors own runner leases."""
    if os.name != 'posix':
        raise UserError('Authorized collection ownership requires a POSIX host.')
    import fcntl
    path = root / '.agent-collection.lease'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except OSError as exc:
        raise UserError('Cannot safely open the collection workflow lock.') from exc
    try:
        info = os.fstat(fd)
        current = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise UserError('Collection workflow lock identity is unsafe.')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
        else:
            yield True
    finally:
        os.close(fd)


def _exists(db):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_collection_plans'").fetchone() is not None


def _hash(value):
    return hashlib.sha256(json_text(value).encode()).hexdigest()


def _load(root, db, plan_id):
    # State and its audit receipt must come from one SQLite read snapshot while
    # another process streams durable progress.
    db.execute('SAVEPOINT collection_plan_read')
    try:
        return _load_snapshot(root, db, plan_id)
    finally:
        db.execute('RELEASE collection_plan_read')


def _load_snapshot(root, db, plan_id):
    if not isinstance(plan_id, str) or not re.fullmatch(r'[a-f0-9]{32}', plan_id):
        raise UserError('Invalid collection plan identifier.')
    if not _exists(db):
        raise UserError('Unknown collection plan in this case.')
    row = db.execute('SELECT config,state FROM agent_collection_plans WHERE id=?', (plan_id,)).fetchone()
    if not row or any(len(raw) > 65536 for raw in row):
        raise UserError('Unknown or oversized collection plan in this case.')
    try:
        config, state = (json.loads(raw) for raw in row)
        meta = dict(db.execute('SELECT key,value FROM meta'))
        if config['case_id'] != meta['case_id'] or config['case_path'] != str(root) or config['case_created_at'] != meta['created_at']:
            raise ValueError('case identity')
        approved = db.execute("SELECT detail FROM audit WHERE action='agent_collection.authorized' AND json_extract(detail,'$.plan_id')=? ORDER BY id DESC LIMIT 1", (plan_id,)).fetchone()
        latest = db.execute("SELECT detail FROM audit WHERE action='agent_collection.state' AND json_extract(detail,'$.plan_id')=? ORDER BY id DESC LIMIT 1", (plan_id,)).fetchone()
        if not approved or json.loads(approved[0])['config_sha256'] != _hash(config) or not latest or json.loads(latest[0])['state_sha256'] != _hash(state):
            raise ValueError('authorization or state receipt')
        if state['status'] not in TERMINAL | {'authorized', 'running'}:
            raise ValueError('state')
    except (KeyError, TypeError, ValueError) as exc:
        raise UserError('Saved collection authorization or state is inconsistent; execution refused.') from exc
    return config, state


def _save(db, plan_id, state):
    state['updated_at'] = now()
    try:
        db.execute('BEGIN IMMEDIATE')
        db.execute('UPDATE agent_collection_plans SET state=? WHERE id=?', (json_text(state), plan_id))
        audit(db, 'agent_collection.state', {'plan_id': plan_id, 'status': state['status'], 'steps': state['steps'], 'state_sha256': _hash(state)})
        db.commit()
    except BaseException:
        db.rollback()
        raise


def _public(plan_id, config, state):
    return {**{k: v for k, v in config.items() if k != 'case_created_at'}, **state, 'id': plan_id, 'schema_version': 1, 'limitations': list(LIMITATIONS)}


def create_plan(root, db, config):
    root, meta = _scope(root, db)
    value = _config(config)
    if db.in_transaction:
        raise UserError('Finish the current database transaction before authorizing collection.')
    value.update(case_id=meta['case_id'], case_path=str(root), case_created_at=meta['created_at'], authorized_at=now())
    plan_id = uuid.uuid4().hex
    state = {'status': 'authorized', 'updated_at': now(), 'started_at': None, 'finished_at': None,
             'outcome': 'not_run', 'integrity': None, 'steps': [dict(profile=p, status='pending', evidence_id=None,
             run_id=None, source_id=None, collection_id=None, records=0, retained_files=0, retained_bytes=0,
             collected_files=0, collected_bytes=0, coverage=[], coverage_total=0, coverage_truncated=False,
             coverage_manifest=None, error=None) for p in value['profiles']]}
    try:
        db.execute('BEGIN IMMEDIATE')
        db.execute('CREATE TABLE IF NOT EXISTS agent_collection_plans(id TEXT PRIMARY KEY,config TEXT NOT NULL,state TEXT NOT NULL)')
        db.execute('INSERT INTO agent_collection_plans VALUES(?,?,?)', (plan_id, json_text(value), json_text(state)))
        audit(db, 'agent_collection.authorized', {'plan_id': plan_id, 'config_sha256': _hash(value), 'examiner': value['examiner'], 'serial': value['serial'], 'profiles': value['profiles'], 'pulls': value['pulls']})
        audit(db, 'agent_collection.state', {'plan_id': plan_id, 'status': 'authorized', 'steps': state['steps'], 'state_sha256': _hash(state)})
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return _public(plan_id, value, state)


def _interrupted(db, plan_id, config, state):
    state.update(status='interrupted', finished_at=now())
    for step in state['steps']:
        if step['status'] == 'running':
            try:
                _recover_references(db, config, step)
            except (UserError, TypeError, ValueError):
                pass
            step.update(status='interrupted', error='The workflow owner stopped. Retained case history may contain additional output; automatic reacquisition is refused.')
    state['outcome'] = 'records_available' if any(s['records'] for s in state['steps']) else 'no_records'
    _save(db, plan_id, state)


def get_plan(root, db, plan_id):
    root, _ = _scope(root, db)
    with _lock(root) as acquired:
        config, state = _load(root, db, plan_id)
        if acquired and state['status'] == 'running':
            _interrupted(db, plan_id, config, state)
    return _public(plan_id, config, state)


def list_plans(root, db):
    root, _ = _scope(root, db)
    if not _exists(db):
        return []
    ids = [r[0] for r in db.execute('SELECT id FROM agent_collection_plans ORDER BY rowid DESC LIMIT 100')]
    return [get_plan(root, db, identifier) for identifier in ids]


def _integrity(root, db, state):
    result = verify(root, db)
    state['integrity'] = {'ok': result['ok'], 'checked_at': now(), 'files_checked': result['files_checked'], 'failure_count': len(result['failures'])}
    return result['ok']


def _references(db, step, result):
    eid = result.get('evidence_id', step['evidence_id'])
    if eid is not None and (not isinstance(eid, str) or not db.execute('SELECT 1 FROM evidence WHERE id=?', (eid,)).fetchone()):
        raise UserError('Collector returned an unknown evidence identifier.')
    step['evidence_id'] = eid
    cid = result.get('collection_id')
    if cid is not None:
        if not isinstance(cid, str) or not re.fullmatch(r'[a-f0-9]{12,32}', cid):
            raise UserError('Collector returned an invalid collection identifier.')
        step['collection_id'] = cid
    rid = result.get('run_id', step['run_id'])
    if rid:
        row = db.execute('SELECT evidence_id,engine,status FROM runs WHERE id=?', (rid,)).fetchone()
        if not row or row['evidence_id'] != eid or not has_run_index(db, rid):
            raise UserError('Analysis returned no verifiable evidence/run membership.')
        clause, args = run_scope(db, rid)
        step['records'] = db.execute('SELECT COUNT(*) FROM artifacts WHERE evidence_id=? AND '+clause, [eid, *args]).fetchone()[0]
        step['run_id'] = rid
        step['source_id'] = rid if row['status'] == 'complete' else eid + ':' + row['engine'] if step['records'] else eid + ':unparsed'
    elif eid:
        step['source_id'] = eid + ':unparsed'


def _recover_references(db, config, step):
    """Only a uniquely matched audited attempt can supply post-exception IDs."""
    after = step.get('audit_after')
    if type(after) is not int:
        return
    starts = db.execute("SELECT detail FROM audit WHERE id>? AND action='collection.started' AND json_extract(detail,'$.serial')=? AND json_extract(detail,'$.profile')=? LIMIT 2", (after, config['serial'], step['profile'])).fetchall()
    if len(starts) != 1:
        return
    cid = json.loads(starts[0][0]).get('collection_id')
    row = db.execute("SELECT detail FROM audit WHERE id>? AND action='collection.finished' AND json_extract(detail,'$.collection_id')=? ORDER BY id DESC LIMIT 1", (after, cid)).fetchone()
    if row:
        _references(db, step, json.loads(row[0]))
        _retained_summary(Path(config['case_path']), db, step)


def _retained_summary(root, db, step, result=None):
    """Count preserved bytes separately from indexed rows; keep coverage bounded."""
    eid = step.get('evidence_id')
    if not eid:
        return
    row = db.execute('SELECT COUNT(*),COALESCE(SUM(size),0) FROM files WHERE evidence_id=?', (eid,)).fetchone()
    step.update(retained_files=row[0], retained_bytes=row[1])
    profile = step['profile']
    if profile == 'files':
        predicate, parameters = "path LIKE 'shared/%'", []
    elif profile == 'trash-photos':
        predicate, parameters = "path LIKE 'photos/%'", []
    elif profile == 'sms-provider':
        predicate, parameters = 'path=?', ['payload/sms-provider.jsonl']
    elif profile == 'contacts-provider':
        predicate, parameters = 'path=?', ['contacts.vcf']
    elif profile == 'messages':
        # The .ab is acquired; telephony/* is its derived unpacking, not another acquisition.
        predicate, parameters = 'path=?', ['telephony.ab']
    else:
        predicate = 'path IN (?,?,?,?,?,?)'
        parameters = ['getprop.txt', 'packages.txt', 'device-time.txt', 'adb-version.txt', 'logcat.txt', 'bugreport.zip']
    row = db.execute('SELECT COUNT(*),COALESCE(SUM(size),0) FROM files WHERE evidence_id=? AND '+predicate, [eid, *parameters]).fetchone()
    step.update(collected_files=row[0], collected_bytes=row[1])
    coverage = (result or {}).get('coverage')
    manifest_row = db.execute("SELECT path,size,sha256 FROM files WHERE evidence_id=? AND path='collection.json'", (eid,)).fetchone()
    if manifest_row:
        step['coverage_manifest'] = f'evidence/{eid}/collection.json'
        step['coverage_manifest_sha256'] = manifest_row['sha256']
        if coverage is None and manifest_row['size'] <= 4 * 1024**2:
            try:
                coverage = json.loads((root / 'evidence' / eid / 'collection.json').read_text()).get('coverage', [])
            except (OSError, ValueError, AttributeError):
                coverage = []
    coverage = coverage if isinstance(coverage, list) else []
    step['coverage_total'] = len(coverage)
    step['coverage_truncated'] = len(coverage) > MAX_COVERAGE
    summary = []
    failure_states = {'failed', 'access_denied', 'unsupported', 'not_returned'}
    def priority(item):
        source = str(item.get('source', ''))
        if item.get('state') in failure_states:
            return 0
        if source.startswith(('/sdcard/', '/storage/')) or source in {'logcat', 'bugreport', 'sms', 'mms', 'telephony_backup'}:
            return 1
        return 3 if item.get('state') == 'not_attempted' else 2
    ordered = sorted((item for item in coverage if isinstance(item, dict)),
                     key=priority)
    for item in ordered[:MAX_COVERAGE]:
        # Raw diagnostics remain in the manifest. Remove controls from this small
        # display projection so JSON escaping cannot exceed the durable-state cap.
        entry = {key: ''.join(c if ord(c) >= 32 and ord(c) != 127 else ' ' for c in str(item.get(key, ''))[:cap])
                 for key, cap in [('source', 256), ('state', 32), ('detail', 192)]}
        for key in ('files', 'bytes', 'records'):
            if type(item.get(key)) is int and item[key] >= 0:
                entry[key] = item[key]
        summary.append(entry)
    step['coverage'] = summary


def _collect(root, db, workspace, config, profile):
    args = (root, db, workspace, config['serial'])
    kw = dict(timeout=config['timeout'], max_bytes=min(config['max_bytes'], PROVIDER_MAX_BYTES))
    if profile == 'sms-provider':
        return provider_sms.collect_sms(*args, **kw, max_messages=config['max_records'], user=config['android_user'])
    if profile == 'contacts-provider':
        return provider_contacts.collect_contacts(*args, **kw, max_contacts=config['max_records'], user=config['android_user'])
    # These existing collectors have no runner lease of their own.
    from .runner_lease import lease
    with lease(root, db):
        return acquisition.collect_android(*args, timeout=config['timeout'], max_bytes=config['max_bytes'],
                                           profile=profile, pulls=config['pulls'] if profile == 'files' else ())


def execute_plan(root, db, workspace, plan_id):
    root, meta = _scope(root, db)
    if Path(workspace).expanduser().resolve() / meta['case_id'] != root:
        raise UserError('Collection workspace does not contain the authorized case.')
    if db.in_transaction:
        raise UserError('Finish the current database transaction before collection.')
    with _lock(root) as acquired:
        if not acquired:
            raise UserError('Another collection workflow owns this case; execution was not started.')
        config, state = _load(root, db, plan_id)
        if state['status'] == 'running':
            _interrupted(db, plan_id, config, state)
        if state['status'] in TERMINAL:
            return _public(plan_id, config, state)
        state.update(status='running', started_at=now())
        _save(db, plan_id, state)
        try:
            if not _integrity(root, db, state):
                raise UserError('Case integrity check failed before collection.')
            for step in state['steps']:
                step['status'] = 'running'
                step['audit_after'] = db.execute('SELECT COALESCE(MAX(id),0) FROM audit').fetchone()[0]
                _save(db, plan_id, state)
                try:
                    result = _collect(root, db, workspace, config, step['profile'])
                    _references(db, step, result)
                    _retained_summary(root, db, step, result)
                    if step['profile'] == 'sms-provider' and not step['run_id']:
                        raise UserError('SMS collection returned no indexed analysis run.')
                    status = result.get('status')
                    if status not in TERMINAL:
                        raise UserError('Collector returned an unsupported execution status.')
                    if result.get('errors') and status == 'complete':
                        status = 'partial'
                    if step['profile'] == 'files':
                        coverage = {r.get('source'): r.get('state') for r in result.get('coverage', []) if isinstance(r, dict)}
                        failed = [p for p in config['pulls'] if coverage.get(p) not in {'collected', 'collected_empty'}]
                        if failed:
                            status = 'failed' if len(failed) == len(config['pulls']) else 'partial'
                    elif step['profile'] == 'triage':
                        coverage = {r.get('source'): r.get('state') for r in result.get('coverage', []) if isinstance(r, dict)}
                        required = {'getprop.txt', 'packages.txt', 'device-time.txt', 'adb-version.txt', 'logcat', 'bugreport'}
                        collected = {name for name in required if coverage.get(name) in {'collected', 'collected_empty'}}
                        if collected != required:
                            status = 'partial' if collected else 'failed'
                    step['status'] = status
                    if status != 'complete':
                        step['error'] = 'Collection was incomplete; inspect the retained collection logs and coverage.'
                    _save(db, plan_id, state)  # Retain IDs before parsing, including failed acquisitions.
                    if not _integrity(root, db, state):
                        raise UserError('Case integrity failed after collection; parsing was refused.')
                    if step['evidence_id'] and step['profile'] != 'sms-provider' and status != 'interrupted':
                        parsed = parsers.native_analyze(root, db, step['evidence_id'])
                        _references(db, step, parsed)
                        if not step['run_id']:
                            raise UserError('Native parsing returned no indexed analysis run.')
                        if parsed.get('status') != 'complete':
                            step.update(status='partial' if step['records'] else 'failed', error='Native parsing was incomplete; inspect the retained analysis run.')
                    if not step['evidence_id']:
                        step.update(status='failed', error='Collection produced no retained evidence identifier.')
                except Exception as exc:
                    db.rollback()
                    _recover_references(db, config, step)
                    step.update(status='failed', error=f'{type(exc).__name__}: collection or parsing failed; inspect case processing history. No automatic retry.')
                if not _integrity(root, db, state):
                    step.update(status='failed', error='Case integrity verification failed; remaining collection was stopped.')
                    _save(db, plan_id, state)
                    break
                _save(db, plan_id, state)
                if step['status'] == 'interrupted':
                    break
            statuses = [s['status'] for s in state['steps']]
            state['status'] = ('interrupted' if 'interrupted' in statuses else 'complete' if all(s == 'complete' for s in statuses)
                               else 'partial' if any(s in {'complete', 'partial'} for s in statuses) or any(s['records'] for s in state['steps']) else 'failed')
            if not state['integrity']['ok']:
                state['status'] = 'failed'
        except BaseException as exc:
            db.rollback()
            state['status'] = 'interrupted' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'failed'
            for step in state['steps']:
                if step['status'] == 'running':
                    try:
                        _recover_references(db, config, step)
                    except (UserError, TypeError, ValueError):
                        pass
                    step.update(status=state['status'], error=f'{type(exc).__name__}: workflow stopped; inspect retained case history before creating a new plan.')
            state['error'] = f'{type(exc).__name__}: workflow stopped; inspect case integrity and processing history.'
            try:
                _integrity(root, db, state)
            except Exception:
                state['integrity'] = {'ok': False, 'checked_at': now(), 'files_checked': 0, 'failure_count': 1}
        state.update(finished_at=now(), outcome='records_available' if any(s['records'] for s in state['steps']) else 'no_records')
        _save(db, plan_id, state)
        return _public(plan_id, config, state)
