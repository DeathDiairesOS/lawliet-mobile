"""Launch the three-tool, host-approved Android collection endpoint.

The selected LAWLIET case is fixed for this process. Models cannot authorize
plans, choose devices, change collection settings or select another case.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys

# A direct launch may omit -B. Never write import caches into the signed app.
sys.dont_write_bytecode = True

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lawliet_mobile.mulder_runtime import (RuntimeQualificationError, inspect_runtime,
                                          resolve_launcher, verify_launcher_identity,
                                          verify_source_identity)

BINDING_KEY = 'lawliet.collection.binding.v1'
PROFILE = 'android-workflow'
TOOLS = {'get_lawliet_collection', 'run_lawliet_collection', 'query_lawliet_collection'}


def case_binding(case_path):
    requested = Path(case_path).expanduser().absolute()
    if any(p.is_symlink() for p in (requested, *requested.parents)) or not requested.is_dir():
        raise ValueError('Select a regular existing LAWLIET case directory.')
    root = requested.resolve(strict=True)
    path = root / 'case.sqlite'
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('The selected case must contain a regular case.sqlite.')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 65536)
        rows = list(db.execute("SELECT key,value FROM meta WHERE key IN ('case_id','created_at') LIMIT 3"))
        if len(rows) != 2:
            raise ValueError('LAWLIET case identity is missing or duplicated.')
        values = dict(rows)
    if values.get('case_id') != root.name or not values.get('created_at'):
        raise ValueError('LAWLIET case identity does not match its selected directory.')
    return {'case_path': str(root), 'case_id': values['case_id'], 'created_at': values['created_at'],
            'root_identity': [root.stat().st_dev, root.stat().st_ino],
            'database_identity': [path.stat().st_dev, path.stat().st_ino]}


def parent_location(binding):
    root = Path(binding['case_path'])
    db_dir = root / 'analyses' / 'agent-collection' / 'mulder'
    identity = json.dumps(binding, sort_keys=True, separators=(',', ':'))
    return db_dir, 'collection-' + hashlib.sha256(identity.encode()).hexdigest()[:24]


def initialize_parent(case_path):
    """Run under the selected Mulder interpreter; never use the shared MCP case."""
    from lawliet_mobile.agent_collection import _lock
    binding = case_binding(case_path)
    with _lock(Path(binding['case_path'])) as acquired:
        if not acquired:
            raise ValueError('Collection case is busy; retry endpoint setup after its active operation.')
        return _initialize_parent_locked(binding)


def _initialize_parent_locked(binding):
    from mulder.db import CaseDB
    if case_binding(binding['case_path']) != binding:
        raise ValueError('Collection case changed during parent initialization.')
    db_dir, case_id = parent_location(binding)
    root = Path(binding['case_path'])
    current = root
    for part in db_dir.relative_to(root).parts:
        current = current / part
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise ValueError('Unsafe collection parent directory.')
        current.mkdir(exist_ok=True, mode=0o700)
    path = db_dir / (case_id + '.db')
    audit_path = db_dir / (case_id + '.audit.jsonl')
    for retained in (path, audit_path):
        if retained.is_symlink() or (retained.exists() and
                (not retained.is_file() or retained.stat().st_nlink != 1)):
            raise ValueError('Collection parent database and audit must be regular unlinked files.')
    encoded = json.dumps(binding, sort_keys=True)
    if path.exists():
        with CaseDB.open(case_id, db_dir) as db:
            metadata = db.get_case_metadata()
            if (metadata.case_id != case_id or metadata.evidence_root != str(root)
                    or db.get_kv(BINDING_KEY) != encoded):
                raise ValueError('Collection parent belongs to a different case identity.')
    else:
        with CaseDB.create(case_id, str(root), db_dir) as db:
            db.set_kv(BINDING_KEY, encoded)
    return {'db_dir': str(db_dir), 'case_id': case_id, 'binding': binding}


def launch(case_path, mulder_launcher):
    binding = case_binding(case_path)
    db_dir, case_id = parent_location(binding)
    spec = resolve_launcher(mulder_launcher)
    env = spec['environment']
    for key in ('PYTHONHOME','PYTHONSTARTUP','ADB_SERVER_SOCKET','ANDROID_SERIAL',
                'ANDROID_ADB_SERVER_ADDRESS','ANDROID_ADB_SERVER_PORT',
                'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):
        env.pop(key, None)
    paths = env.get('PYTHONPATH', '').split(os.pathsep)
    if any(not value or not Path(value).is_absolute() for value in paths):
        raise RuntimeQualificationError('A pinned absolute Mulder source path is required.')
    backend = str(Path(__file__).resolve().parent.parent)
    # Retain the selected Mulder source, replacing any stale backend path with
    # this actual packaged application. Never import a second LAWLIET checkout.
    env['PYTHONPATH'] = os.pathsep.join([paths[0], backend])
    if not stat.S_ISCHR(os.stat('/dev/null').st_mode):
        raise RuntimeQualificationError('Source-only execution requires /dev/null.')
    env.update(LAWLIET_MCP_PROFILE=PROFILE, LAWLIET_COLLECTION_CASE=binding['case_path'],
               LAWLIET_COLLECTION_BINDING=json.dumps(binding, sort_keys=True),
               ADB_SERVER_SOCKET='tcp:127.0.0.1:5037', PYTHONDONTWRITEBYTECODE='1',
               PYTHONPYCACHEPREFIX='/dev/null/lawliet-source-only')
    identity = inspect_runtime(spec)
    if identity.get('errors'):
        raise RuntimeQualificationError('Selected Mulder runtime cannot import the collection profile.')
    app = Path(identity.get('modules', {}).get('mulder.server.app', {}).get('path', ''))
    package = Path(identity.get('modules', {}).get('mulder', {}).get('path', ''))
    source = Path(paths[0]).resolve()
    if (not app.is_file() or app.resolve() != source/'mulder/server/app.py'
            or package.resolve() != source/'mulder/__init__.py'
            or '_LAWLIET_WORKFLOW_TOOLS' not in app.read_text()):
        raise RuntimeQualificationError('Selected Mulder runtime lacks the collection profile.')
    contract = Path(__file__).resolve().parent.parent
    if not (contract/'setup/mobile-macos-arm64.json').is_file():
        contract = Path(__file__).resolve().parent/'_mulder_contract'
    try:
        manifest = json.loads((contract/'setup/mobile-macos-arm64.json').read_text())
    except (OSError, ValueError) as exc:
        raise RuntimeQualificationError('The packaged Mulder source qualification contract is missing or invalid.') from exc
    verify_source_identity(identity, contract, manifest)
    sandbox = Path('/usr/bin/sandbox-exec')
    if not sandbox.is_file():
        raise RuntimeQualificationError('This endpoint currently requires the macOS local-ADB network policy.')
    python = [spec['python'], '-B', '-P']
    probe = ('import json,sys; from pathlib import Path; '
             'import lawliet_mobile.agent_collection_endpoint as endpoint; '
             'assert Path(endpoint.__file__).resolve()==Path(sys.argv[2]).resolve(); '
             'print(json.dumps(endpoint.initialize_parent(sys.argv[1])))')
    try:
        result = subprocess.run([*python, '-c', probe, binding['case_path'], str(Path(__file__).resolve())], env=env,
                                cwd=binding['case_path'], capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeQualificationError('Collection parent initialization failed or timed out.') from exc
    if result.returncode or len(result.stdout) > 32768:
        raise RuntimeQualificationError('Collection parent initialization failed; no collector was started.')
    initialized = json.loads(result.stdout)
    if initialized != {'db_dir':str(db_dir), 'case_id':case_id, 'binding':binding}:
        raise RuntimeQualificationError('Collection parent identity changed during initialization.')
    verify_launcher_identity(spec)
    policy = '(version 1) (allow default) (deny network*) (allow network-outbound (remote tcp "localhost:5037"))'
    return [str(sandbox), '-p', policy, *python, '-m', 'mulder.cli', 'serve',
            '--case-id', case_id, '--db-dir', str(db_dir), '--transport', 'stdio', '--workers', '1'], env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-path', required=True)
    parser.add_argument('--mulder-launcher', required=True)
    args = parser.parse_args()
    try:
        argv, env = launch(args.case_path, args.mulder_launcher)
    except (OSError, ValueError, sqlite3.Error, RuntimeQualificationError) as exc:
        parser.error(str(exc))
    os.execve(argv[0], argv, env)


if __name__ == '__main__':
    main()
