"""Scoped Android collection and evidence-based coverage, without device modification helpers."""
import json
import re
import shutil
import shlex
import subprocess
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from .android_backup import backup_rows, unpack_backup
from .core import UserError, audit, digest, import_evidence, json_text, now

APPS = {'whatsapp': 'com.whatsapp', 'whatsapp_business': 'com.whatsapp.w4b', 'signal': 'org.thoughtcrime.securesms'}


def collect_android(root, db, workspace, serial, profile='messages', pulls=(), timeout=900, max_bytes=20 * 1024**3):
    from .tools import command, execute, storage_guard
    if profile == 'trash-photos':
        if pulls: raise UserError('Trash profile uses a fixed shared-storage discovery path; no custom pulls.')
        from .trash_collection import collect_trash
        return collect_trash(root, db, workspace, serial, timeout, max_bytes)
    if profile == 'contacts-provider':
        if pulls:raise UserError('Contacts profile does not accept shared-storage paths.')
        from .provider_contacts import collect_contacts
        return collect_contacts(root,db,workspace,serial,timeout,min(max_bytes,64*1024**2))
    if not serial or serial.startswith('-') or any(c.isspace() or c in '/\\' for c in serial):
        raise UserError('Supply a valid serial from devices.')
    if profile not in {'messages', 'logical', 'files'}:
        raise UserError('Unknown Android collection profile.')
    if profile == 'files' and not pulls:
        raise UserError('The files profile requires at least one --pull shared-storage path.')
    for remote in pulls:
        parts = PurePosixPath(remote)
        if not remote.startswith(('/sdcard/', '/storage/emulated/0/')) or '..' in parts.parts or not re.fullmatch(r'[\w /().@+-]+', remote):
            raise UserError('Pull paths must be explicit shared-storage paths under /sdcard/ or /storage/emulated/0/, without traversal or shell characters.')
    cmd = command(workspace, 'adb') + ['-s', serial]
    run_id = uuid.uuid4().hex[:12]
    folder = root / 'collections' / run_id
    folder.mkdir(parents=True)
    coverage, commands, errors = [], [], []
    evidence_id, status = None, 'failed'
    started = now()
    audit(db, 'collection.started', {'collection_id': run_id, 'serial': serial, 'platform': 'android', 'profile': profile,
          'requested_paths': list(pulls), 'device_changes': 'Live ADB commands and optional Android backup prompt; no app installation or clock correction.'})
    db.commit()

    def attempt(args, name, seconds=None):
        try:
            result = execute(cmd + args, folder / name, seconds or timeout, guard=storage_guard(folder, max_bytes))
        except (subprocess.TimeoutExpired, OSError, UserError) as exc:
            result = getattr(exc, 'tool_result', {'argv': cmd + args, 'returncode': None, 'error': str(exc)})
        commands.append(result)
        return result

    def item(source, state, detail, **extra):
        value = {'source': source, 'state': state, 'detail': detail, **extra}
        coverage.append(value)
        if state in {'failed', 'access_denied', 'unsupported', 'not_returned'}:
            errors.append(value)
        return value

    try:
        state = attempt(['get-state'], 'device-state.txt', 20)
        if state.get('returncode') != 0 or (folder / 'device-state.txt').read_text().strip() != 'device':
            raise UserError('Device is unavailable or unauthorized. Unlock and approve this host on the selected phone.')
        for args, name in [(['shell', 'getprop'], 'getprop.txt'), (['shell', 'pm', 'list', 'packages', '-f'], 'packages.txt'),
                           (['shell', 'date', '+%Y-%m-%dT%H:%M:%S%z'], 'device-time.txt'), (['version'], 'adb-version.txt')]:
            before = now()
            result = attempt(args, name, 30)
            item(name, 'collected' if result.get('returncode') == 0 else 'failed', 'Raw output retained; acquisition time is recorded separately.')
            if name == 'device-time.txt':
                (folder / 'clock-observation.json').write_text(json_text({'host_before_utc': before, 'host_after_utc': now(),
                    'device_output': (folder / name).read_text(errors='replace') if (folder / name).exists() else None,
                    'note': 'No target clock change or timestamp correction performed.'}) + '\n')
        packages = (folder / 'packages.txt').read_text(errors='replace') if (folder / 'packages.txt').exists() else ''
        package_names = {line.rsplit('=', 1)[-1].removeprefix('package:').strip() for line in packages.splitlines()}
        for app, package in APPS.items():
            item(app, 'not_attempted', 'Private chat acquisition is not available through this profile. Supply an app export or a supported extraction with required keys.',
                 package=package, listed_in_package_inventory=package in package_names, parsing='not_assessed')
        if profile == 'logical':
            for args, name in [(['logcat', '-d', '-v', 'epoch'], 'logcat.txt'), (['bugreport', str(folder / 'bugreport.zip')], 'bugreport.log')]:
                result = attempt(args, name)
                okay = result.get('returncode') == 0
                if args[0] == 'bugreport':
                    okay = okay and zipfile.is_zipfile(folder / 'bugreport.zip')
                item(args[0], 'collected' if okay else 'failed', 'Diagnostic triage, not private app history.')
        if profile in {'messages', 'logical'}:
            backup = folder / 'telephony.ab'
            result = attempt(['backup', '-f', str(backup), '-noapk', '-nocompress', 'com.android.providers.telephony'], 'telephony.log')
            if result.get('returncode') != 0:
                item('telephony_backup', 'failed', 'Backup command failed or timed out. Any returned bytes and logs are retained.')
            else:
                payload = folder / 'telephony'
                payload.mkdir()
                try:
                    detail = unpack_backup(backup, payload, max_bytes)
                    (folder / 'backup-derivation.json').write_text(json_text({'original_sha256': digest(backup), **detail}) + '\n')
                    for kind in ('sms', 'mms'):
                        files = list(payload.rglob(f'*_{kind}_backup'))
                        if not files:
                            item(kind, 'not_returned', 'No matching payload returned; this does not prove the phone has no such messages.')
                            continue
                        count = sum(len(backup_rows(file)) for file in files)
                        item(kind, 'collected' if count else 'collected_empty', 'Returned backup records counted; device-wide completeness not established.', records=count, parsing='ready_for_native')
                except Exception as exc:
                    item('telephony_backup', 'failed', str(exc))
        for index, remote in enumerate(pulls):
            estimate = attempt(['shell', 'du', '-sk', shlex.quote(remote)], f'pull-{index}-size.txt', 30)
            try:
                size = int((folder / f'pull-{index}-size.txt').read_text().split()[0]) * 1024
            except (ValueError, IndexError, OSError):
                size = None
            if estimate.get('returncode') != 0 or size is None:
                item(remote, 'failed', 'Cannot establish source size/access; no pull performed. See size command logs.')
                continue
            used = sum(p.stat().st_size for p in folder.rglob('*') if p.is_file())
            if size + used > max_bytes or size > shutil.disk_usage(folder).free // 2:
                item(remote, 'failed', 'Source exceeds collection budget or available disk reserve; no pull performed.')
                continue
            destination = folder / 'shared' / str(index)
            destination.mkdir(parents=True)
            result = attempt(['pull', '-a', remote, str(destination)], f'pull-{index}.log')
            file_count = sum(p.is_file() for p in destination.rglob('*'))
            item(remote, ('collected' if file_count else 'collected_empty') if result.get('returncode') == 0 else 'failed',
                 'Accessible shared storage only; files may change during live copying. Host hashes are recorded at intake.',
                 local_path=str(destination.relative_to(folder)), files=file_count, estimated_bytes=size)
        status = 'partial' if errors else 'complete'
    except BaseException as exc:
        status = 'interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed'
        if hasattr(exc, 'tool_result'):
            commands.append(exc.tool_result)
        errors.append({'error': str(exc)})
        raise
    finally:
        manifest = {'collection_id': run_id, 'platform': 'android', 'serial': serial, 'profile': profile,
                    'started_at_host_utc': started, 'finished_at_host_utc': now(), 'status': status,
                    'coverage': coverage, 'commands': commands, 'errors': errors,
                    'scope': 'Status describes the requested profile only. No full filesystem, deleted recovery, cloud, or private-app completeness claim.'}
        (folder / 'collection.json').write_text(json_text(manifest) + '\n')
        # Preserve even failed attempts, including any partial backup/file bytes.
        try:
            evidence_id, _, _ = import_evidence(root, db, folder, 'android', f'Android {profile} collection', max_bytes)
        except Exception as exc:
            errors.append({'intake_error': str(exc), 'retained_path': str(folder)})
            status = 'failed'
            manifest.update(status=status, errors=errors)
            (folder / 'collection.json').write_text(json_text(manifest) + '\n')
        audit(db, 'collection.finished', {'collection_id': run_id, 'status': status, 'evidence_id': evidence_id, 'errors': errors})
        db.commit()
    return {'collection_id': run_id, 'status': status, 'evidence_id': evidence_id, 'path': str(folder), 'coverage': coverage, 'errors': errors}


def case_coverage(root, db, ledger_options=None, include_ledger=True):
    acquisitions = []
    attempts = []
    for path in sorted((root / 'collections').glob('*/collection.json')):
        try:
            value = json.loads(path.read_text())
            if isinstance(value, dict):
                attempts.append({**value, 'manifest_path': str(path.relative_to(root)),
                                 'provenance_note': 'Operational collection log; may not be imported or covered by evidence-file verification.'})
        except (ValueError, OSError):
            attempts.append({'manifest_path': str(path.relative_to(root)), 'status': 'unreadable'})
    for row in db.execute("SELECT * FROM files WHERE path LIKE '%collection.json' ORDER BY evidence_id,path"):
        path = root / 'evidence' / row['evidence_id'] / row['path']
        try:
            value = json.loads(path.read_text())
            if isinstance(value, dict) and 'commands' in value:
                acquisitions.append({**value, 'evidence_id': row['evidence_id'], 'source_sha256': row['sha256']})
        except (ValueError, OSError):
            pass
    runs = [dict(row) for row in db.execute('SELECT id,evidence_id,engine,status,records,detail FROM runs ORDER BY started_at')]
    result={'acquisitions': acquisitions, 'collection_attempts': attempts, 'analysis_runs': runs,
            'note': 'Acquisition and parsing are separate. Zero records and missing payloads do not establish absence. Older/imported evidence may have no acquisition coverage manifest.'}
    if include_ledger:
        from .coverage_ledger import build_ledger, ledger_page
        result['ledger'] = (build_ledger(root,db,result) if ledger_options is None
                            else ledger_page(root,db,result,**ledger_options))
    return result
