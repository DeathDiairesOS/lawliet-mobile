"""Small, explicitly selected iOS app inventory; never a backup or app-data pull."""
from __future__ import annotations

import hashlib
import plistlib
import re
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path
from xml.parsers.expat import ExpatError

from .child_output import ChildOutputs
from .core import UserError, audit, digest, import_evidence, now

VERSION = 'ios-app-inventory/1'
MAX_BYTES = 16 * 1024**2
MAX_APPS = 10000
FILENAMES = {'ios-apps.plist', 'ios-device.plist'}
SCOPE = ('Observed installation-service inventory and device metadata only. No messages, contacts, '
         'private app contents, deleted apps or historical installation times are collected. '
         'An empty response does not establish device-wide absence.')


def _json_values(value, depth=0, counter=None):
    counter = [0] if counter is None else counter
    counter[0] += 1
    if depth > 32 or counter[0] > 200000:
        raise ValueError('iOS inventory structure exceeds its review limit.')
    if isinstance(value, bytes):
        return {'blob_bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
    if isinstance(value, datetime):
        return {'plist_date_original': value.isoformat()}
    if isinstance(value, list):
        return [_json_values(v, depth + 1, counter) for v in value]
    if isinstance(value, dict):
        return {k: _json_values(v, depth + 1, counter) for k, v in value.items()}
    return value


def _records(raw, name):
    if name not in FILENAMES or len(raw) > MAX_BYTES:
        raise ValueError('Unsupported or oversized iOS inventory input.')
    try:
        value = plistlib.loads(raw, fmt=plistlib.FMT_XML)
        original = _json_values(value)
    except (ValueError, TypeError, OverflowError, RecursionError, ExpatError, plistlib.InvalidFileException) as exc:
        raise ValueError('Invalid iOS inventory property list.') from exc
    common = {'format': 'iOS XML property-list inventory', 'parser_version': VERSION, 'scope': SCOPE}
    if name == 'ios-device.plist':
        if not isinstance(value, dict) or not any(isinstance(value.get(k), str) and value[k]
                                                for k in ('ProductType', 'ProductVersion', 'DeviceName')):
            raise ValueError('Device inventory lacks recognizable device metadata.')
        text = ' · '.join(str(value[k]) for k in ('DeviceName', 'ProductType', 'ProductVersion') if value.get(k))
        return [('device', None, None, 'iOS device information', text, 'plist:dict',
                 {**common, 'original': original})]
    if not isinstance(value, list) or len(value) > MAX_APPS:
        raise ValueError('App inventory must be a bounded array of application dictionaries.')
    records = []
    for index, app in enumerate(value):
        if (not isinstance(app, dict) or not isinstance(app.get('CFBundleIdentifier'), str)
                or not app['CFBundleIdentifier'] or len(app['CFBundleIdentifier']) > 1024):
            raise ValueError('App inventory contains a record without a valid bundle identifier.')
        for key in ('CFBundleDisplayName', 'CFBundleName', 'CFBundleShortVersionString',
                    'CFBundleVersion', 'ApplicationType'):
            if key in app and not isinstance(app[key], str):
                raise ValueError('App inventory display fields must be strings.')
        name_value = app.get('CFBundleDisplayName') or app.get('CFBundleName')
        version = app.get('CFBundleShortVersionString') or app.get('CFBundleVersion')
        body = ' · '.join(v for v in (name_value, 'Version ' + version if version else None,
                                      app.get('ApplicationType')) if v)
        records.append(('apps', None, None, app['CFBundleIdentifier'], body,
                        f'plist:array[index={index}]', {**common, 'original': original[index]}))
    return records


def inventory_records(path):
    """Normalize retained bytes; caller supplies the normal file/run provenance."""
    path = Path(path)
    with ChildOutputs(path.parent) as outputs:
        return _records(outputs.read(path.name, MAX_BYTES), path.name)


def _publish_bytes(path, raw):
    from .anchored_output import OutputFiles
    with OutputFiles([path]) as output:
        with output.open(path) as stream:
            stream.buffer.write(raw)
        if output.digest(path) != hashlib.sha256(raw).hexdigest():
            raise UserError('Inventory working-copy hash mismatch.')
        output.publish()


def collect_apps(root, db, workspace, serial, timeout=120, max_bytes=MAX_BYTES):
    """Collect through configured utilities. Caller obtains examiner authorization."""
    from .iphone_connection import UDID, require_local_usb_environment
    from .runner_lease import lease
    if not isinstance(serial, str) or not UDID.fullmatch(serial):
        raise UserError('Select an explicit iPhone UDID from device discovery.')
    if (type(timeout) not in (int, float) or not 0 < timeout <= 900
            or type(max_bytes) is not int or not 1024 <= max_bytes <= MAX_BYTES):
        raise UserError('App inventory requires a positive timeout up to 900 seconds and a 1 KiB–16 MiB budget.')
    require_local_usb_environment()
    with lease(root, db):
        return _collect_owned(root, db, workspace, serial, timeout, max_bytes)


def _collect_owned(root, db, workspace, serial, timeout, max_bytes):
    from .provider_contacts import _create_collection
    from .provider_sms import _write_manifest
    from .tools import command, execute, storage_guard
    cid = uuid.uuid4().hex[:12]
    folder = _create_collection(root, cid)
    started, deadline = now(), time.monotonic() + timeout
    commands, errors, coverage, tools = [], [], [], {}
    evidence_id, status = None, 'failed'
    audit(db, 'collection.started', {'collection_id': cid, 'platform': 'ios', 'profile': 'apps',
        'serial': serial, 'max_bytes': max_bytes, 'timeout': timeout,
        'device_changes': 'Live USB service queries may create device logs or require Trust; no install, uninstall, backup or clock command.'})
    db.commit()

    def error(source, kind, detail):
        errors.append({'source': source, 'kind': kind, 'detail': str(detail)[:1000]})

    with ChildOutputs(folder) as outputs:
        def attempt(tool, args, name, limit):
            argv = tools[tool]['argv_prefix'] + args
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                result = execute(argv, folder / name, remaining, guard=storage_guard(folder, max_bytes))
                commands.append(result)
                if result['returncode'] != 0:
                    error(name, 'command_failed', f"Tool exited with {result['returncode']}; retained stdout/stderr contain diagnostics.")
                    return None
                raw = outputs.read(name, limit)
                if digest(Path(tools[tool]['argv_prefix'][-1])) != tools[tool]['executable_sha256']:
                    error(name, 'tool_changed', 'Configured tool bytes changed; output is not indexed.')
                    return None
                return raw
            except (OSError, UserError, subprocess.TimeoutExpired) as exc:
                if getattr(exc, 'tool_result', None) not in commands and hasattr(exc, 'tool_result'):
                    commands.append(exc.tool_result)
                kind = 'timeout' if isinstance(exc, subprocess.TimeoutExpired) else 'resource_or_output_refusal' if isinstance(exc, UserError) else 'execution_error'
                error(name, kind, exc)
                return None

        try:
            ready = True
            for name in ('ideviceinstaller', 'ideviceinfo'):
                try:
                    argv = command(workspace, name)
                    tools[name] = {'argv_prefix': argv, 'executable_sha256': digest(Path(argv[-1]))}
                    if len(argv) > 1:
                        tools[name]['interpreter_sha256'] = digest(Path(argv[0]))
                except (UserError, OSError) as exc:
                    error(name, 'missing_dependency', exc); ready = False; continue
                raw = attempt(name, ['--version'], name + '-version.txt', 16384)
                version = raw.decode('utf-8', errors='replace').strip() if raw is not None else ''
                tools[name]['version'] = version
                match = re.fullmatch(re.escape(name) + r' (1)\.(\d+)\.(\d+)(?:[-+][\w.]+)?', version)
                if not match or (name == 'ideviceinstaller' and int(match[2]) < 2):
                    error(name, 'unsupported_version', 'This adapter requires ideviceinstaller 1.2+ within major 1 and ideviceinfo major 1. No device command issued.')
                    ready = False
            if ready:
                for tool, args, raw_name, parsed_name in (
                    ('ideviceinfo', ['-u', serial, '--simple', '--xml'], 'device.stdout', 'ios-device.plist'),
                    ('ideviceinstaller', ['-u', serial, 'list', '--all', '--xml'], 'apps.stdout', 'ios-apps.plist')):
                    raw = attempt(tool, args, raw_name, min(max_bytes, MAX_BYTES))
                    if raw is None:
                        coverage.append({'source': parsed_name, 'state': 'failed', 'records': None}); continue
                    try:
                        rows = _records(raw, parsed_name)
                        if parsed_name == 'ios-device.plist':
                            observed = rows[0][-1]['original'].get('UniqueDeviceID')
                            if observed is not None and observed != serial:
                                error(parsed_name, 'device_mismatch', 'Returned device UDID differs from the requested device; app query refused.')
                                coverage.append({'source': parsed_name, 'state': 'failed', 'records': None})
                                break
                        storage_guard(folder, max_bytes)()
                        # Raw output and its exact validated working copy both count.
                        used = sum(p.stat().st_size for p in folder.iterdir() if p.is_file())
                        if used + len(raw) > max_bytes:
                            raise ValueError('No budget remains for the validated inventory working copy.')
                        _publish_bytes(folder / parsed_name, raw)
                        coverage.append({'source': parsed_name, 'state': 'collected' if rows else 'collected_empty',
                            'records': len(rows), 'raw_output': raw_name, 'sha256': hashlib.sha256(raw).hexdigest(),
                            'bytes': len(raw), 'derivation': 'Byte-identical validated stdout copy; no fields rewritten.'})
                    except (ValueError, OSError, UserError) as exc:
                        error(parsed_name, 'invalid_or_bounded_output', exc)
                        coverage.append({'source': parsed_name, 'state': 'failed', 'records': None})
            observed = sum(c['state'] in {'collected', 'collected_empty'} for c in coverage)
            status = 'complete' if observed == 2 and not errors else 'partial' if observed else 'failed'
        except BaseException as exc:
            status = 'interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed'
            error('collection', 'interrupted' if status == 'interrupted' else 'unexpected_failure', exc)
            raise
        finally:
            manifest = {'collection_id': cid, 'platform': 'ios', 'profile': 'apps', 'serial': serial,
                'started_at_host_utc': started, 'finished_at_host_utc': now(), 'status': status,
                'tools': tools, 'commands': commands, 'coverage': coverage, 'errors': errors, 'scope': SCOPE,
                'resource_policy': {'maximum_bytes': max_bytes, 'timeout_seconds': timeout,
                    'enforcement': 'Periodic process stop threshold; output can overshoot between checks. Bounded reads before indexing.'}}
            try:
                outputs.check_directory()
                _write_manifest(folder / 'collection.json', manifest)
                evidence_id = import_evidence(root, db, folder, 'ios', 'iOS app inventory', max_bytes=max_bytes)[0]
            except (OSError, UserError) as exc:
                status = 'failed'; error('collection', 'receipt_or_intake_failure', exc)
            audit(db, 'collection.finished', {'collection_id': cid, 'status': status,
                'evidence_id': evidence_id, 'errors': errors, 'coverage': coverage})
            db.commit()
    return {'collection_id': cid, 'status': status, 'evidence_id': evidence_id, 'path': str(folder),
            'coverage': coverage, 'errors': errors, 'scope': SCOPE}
