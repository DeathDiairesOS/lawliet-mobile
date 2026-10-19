"""Read-only qualification of a known Mulder launcher, source tree and MCP schema.

This checks an installed build, not model behavior, parser fidelity, phone access
or an already-running server. Unsupported/opaque launchers fail closed.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import tempfile
import time


class RuntimeQualificationError(RuntimeError):
    pass


PROFILE_TOOLS = {
    'android-workflow': {'get_lawliet_collection', 'run_lawliet_collection', 'query_lawliet_collection'},
    'android-contacts': {'collect_lawliet_android_contacts', 'query_ancalor_review', 'list_ancalor_files'},
    'android-sms': {'collect_lawliet_android_sms', 'query_ancalor_review', 'list_ancalor_files'},
    'parser-container': {'run_lawliet_exiftool_review', 'query_ancalor_review', 'list_ancalor_files'},
    'sqlite-container': {'run_ancalor_sqlite_query', 'query_ancalor_review', 'list_ancalor_files'},
    'native-container': {'run_ancalor_native_review', 'query_ancalor_review', 'list_ancalor_files'},
    'report-container': {'run_lawliet_report_import', 'query_ancalor_review', 'list_ancalor_files'},
}
PROFILES = ('standard', *PROFILE_TOOLS)
_REQUIRED_MODULES = ('mulder', 'mulder.cli', 'mulder.db', 'mulder.temporal',
                     'mulder.server.app', 'mulder.server.case_scope', 'mulder.server.jobs',
                     'mulder.server.tools.core', 'mulder.server.tools.jobs',
                     'mulder.server.tools.phone', 'mulder.server.tools.mvt',
                     'mulder.server.tools.lawliet_collection')
_EXPORTS = {'PATH', 'PYTHONPATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'SYSTEMROOT',
            'MULDER_ASSET_ROOT', 'XDG_CACHE_HOME', 'MULDER_CWD', 'MULDER_DB_DIR',
            'PYTHONDONTWRITEBYTECODE', 'PYTHONPYCACHEPREFIX', 'LAWLIET_MCP_PROFILE'}
_CLI_CODE = 'from mulder.cli import cli; cli()'
_CONSOLE_SCRIPT = '''import sys
from mulder.cli import cli
if __name__ == '__main__':
    sys.argv[0] = sys.argv[0].removesuffix('.exe')
    sys.exit(cli())
'''


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _read(path, maximum=65536):
    with Path(path).open('rb') as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise RuntimeQualificationError('Qualification input exceeds its size bound: ' + str(path))
    return data


def _run(argv, *, env=None, cwd=None, timeout=30, maximum=2*1024*1024):
    """Bound output and lifetime; retain no subprocess logs or credentials."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            child = subprocess.Popen(list(map(str, argv)), stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, env=env, cwd=cwd, start_new_session=os.name == 'posix')
        except OSError as exc:
            raise RuntimeQualificationError('Qualification executable unavailable: ' + str(argv[0])) from exc
        deadline = time.monotonic() + timeout
        reason = None
        while child.poll() is None:
            if time.monotonic() >= deadline:
                reason = 'Qualification process timed out'
            elif os.fstat(stdout.fileno()).st_size > maximum or os.fstat(stderr.fileno()).st_size > maximum:
                reason = 'Qualification process exceeded its output bound'
            if reason:
                if os.name == 'posix':
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                else: child.kill()
                child.wait()
                raise RuntimeQualificationError(reason)
            time.sleep(0.02)
        stdout.seek(0); data = stdout.read(maximum + 1)
        if len(data) > maximum or os.fstat(stderr.fileno()).st_size > maximum:
            raise RuntimeQualificationError('Qualification process exceeded its output bound')
        if child.returncode:
            # Probe failures can name a missing dependency without emitting arbitrary
            # environment values, source content or exception tracebacks.
            try: error = json.loads(data).get('qualification_error')
            except (ValueError, AttributeError): error = None
            if not isinstance(error, str) or len(error) > 300:
                error = 'Qualification subprocess failed (exit ' + str(child.returncode) + ')'
            raise RuntimeQualificationError(error)
        return data


def resolve_launcher(launcher):
    """Resolve only LAWLIET's literal-export shell wrapper or known console script.

    This deliberately does not interpret general shell, source files, variable
    expansion, arbitrary Python or nested wrappers.
    """
    requested = Path(launcher).expanduser().absolute()
    executable = requested.resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeQualificationError('Configured Mulder launcher is unavailable')
    env = {k: os.environ[k] for k in ('HOME', 'PATH', 'TMPDIR', 'LANG', 'LC_ALL', 'SYSTEMROOT') if k in os.environ}
    pins = {}; targets = {}
    def content(path):
        path = Path(path).absolute()
        resolved = path.resolve(strict=True)
        targets[str(path)] = str(resolved)
        raw = _read(resolved); pins[str(resolved)] = _sha(raw)
        return raw.decode('utf-8')
    script = content(requested)
    if script.startswith('#!/bin/sh\n'):
        lines = [line.strip() for line in script.splitlines()[1:] if line.strip() and not line.lstrip().startswith('#')]
        if not lines or not lines[-1].startswith('exec ') or not lines[-1].endswith(' "$@"'):
            raise RuntimeQualificationError('Unsupported Mulder shell launcher; expected a literal exec wrapper')
        for line in lines[:-1]:
            if line == 'set -eu':
                continue
            if not line.startswith('export ') or any(c in line for c in ('$', '`', '\\')):
                raise RuntimeQualificationError('Unsupported Mulder launcher expansion or command')
            lexer = shlex.shlex(line[7:], posix=True, punctuation_chars=';&|<>()')
            lexer.whitespace_split = True; lexer.commenters = ''
            words = list(lexer)
            if len(words) != 1 or '=' not in words[0]:
                raise RuntimeQualificationError('Unsupported Mulder launcher export')
            name, value = words[0].split('=', 1)
            if name not in _EXPORTS:
                raise RuntimeQualificationError('Unsupported Mulder launcher environment name')
            env[name] = value
        execution = lines[-1][5:-5]
        if any(c in execution for c in ('$', '`', '\n')):
            raise RuntimeQualificationError('Unsupported Mulder launcher execution')
        lexer = shlex.shlex(execution, posix=True, punctuation_chars=';&|<>()')
        lexer.whitespace_split = True; lexer.commenters = ''
        argv = list(lexer)
        if ((len(argv) == 3 and argv[1] == '-c' and _known_cli_code(argv[2])) or
            (len(argv) == 5 and argv[1:4] == ['-B', '-P', '-c'] and _known_cli_code(argv[4]))):
            python = Path(argv[0]).expanduser()
        elif len(argv) == 1 and Path(argv[0]).is_absolute():
            entry = Path(argv[0])
            script = content(entry)
            python = _console_python(script)
        else:
            raise RuntimeQualificationError('Unsupported Mulder launcher command')
    else:
        python = _console_python(script)
    # Do not resolve a venv python symlink to the system interpreter: venv lookup
    # depends on the invoked path. Resolve only the imported module paths later.
    if not python.is_absolute() or not python.is_file() or not os.access(python, os.X_OK):
        raise RuntimeQualificationError('Mulder Python interpreter is unavailable')
    targets[str(python)] = str(python.resolve(strict=True))
    if 'PYTHONPYCACHEPREFIX' in env:
        if env['PYTHONPYCACHEPREFIX'] != '/dev/null/lawliet-source-only' or not stat.S_ISCHR(os.stat('/dev/null').st_mode):
            raise RuntimeQualificationError('Unsupported Mulder bytecode-cache location')
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    result = {'launcher': str(requested), 'python': str(python), 'environment': env,
              'launcher_files': pins, 'launcher_targets': targets}
    verify_launcher_identity(result)
    return result


def verify_launcher_identity(spec):
    """Detect changed launcher bytes or link targets; not an atomic exec guard."""
    try:
        for path, expected in spec['launcher_targets'].items():
            if str(Path(path).resolve(strict=True)) != expected:
                raise RuntimeQualificationError('Mulder launcher or interpreter target changed during qualification')
        for path, expected in spec['launcher_files'].items():
            if _sha(_read(path)) != expected:
                raise RuntimeQualificationError('Mulder launcher changed during qualification')
    except OSError as exc:
        raise RuntimeQualificationError('Mulder launcher became unavailable during qualification') from exc


def _known_cli_code(value):
    try:
        return ast.dump(ast.parse(value)) == ast.dump(ast.parse(_CLI_CODE))
    except (SyntaxError, ValueError):
        return False


def _console_python(script):
    lines = script.splitlines()
    if not lines or not lines[0].startswith('#!/'):
        raise RuntimeQualificationError('Unsupported Mulder console entrypoint')
    python = Path(lines[0][2:])
    try: parsed = ast.dump(ast.parse('\n'.join(lines[1:])))
    except SyntaxError as exc:
        raise RuntimeQualificationError('Unsupported Mulder console entrypoint') from exc
    if parsed != ast.dump(ast.parse(_CONSOLE_SCRIPT)):
        raise RuntimeQualificationError('Unsupported Mulder console entrypoint; cannot establish imported runtime')
    return python


_PROBE = '''import importlib, json, hashlib, pathlib, sys
result = {"python": sys.executable, "modules": {}, "errors": []}
for name in json.loads(sys.argv[1]):
    try:
        module = importlib.import_module(name)
        path = pathlib.Path(module.__file__).resolve()
        with path.open("rb") as handle: raw = handle.read(16*1024*1024+1)
        if len(raw) > 16*1024*1024: raise ValueError("Oversized module source")
        result["modules"][name] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
        if name == "mulder": result["version"] = module.__version__
    except ModuleNotFoundError as exc:
        result["errors"].append({"module": name, "missing_dependency": exc.name})
    except Exception as exc:
        result["errors"].append({"module": name, "error_type": type(exc).__name__})
print(json.dumps(result))
'''


def inspect_runtime(spec, *, timeout=30):
    verify_launcher_identity(spec)
    with tempfile.TemporaryDirectory(prefix='lawliet-runtime-probe-') as folder:
        env = dict(spec['environment'], PYTHONPYCACHEPREFIX=str(Path(folder)/'bytecode'))
        raw = _run([spec['python'], '-B', '-P', '-c', _PROBE, json.dumps(_REQUIRED_MODULES)],
                   env=env, cwd=folder, timeout=timeout)
    verify_launcher_identity(spec)
    try: return json.loads(raw)
    except ValueError as exc:
        raise RuntimeQualificationError('Runtime probe did not return bounded structured identity') from exc


def verify_source_identity(identity, repository, manifest):
    repository = Path(repository).resolve()
    spec = manifest['sources']['mulder']
    if _sha(_read(repository / spec['patch'], 16*1024*1024)) != spec['patch_sha256']:
        raise RuntimeQualificationError('Repository Mulder patch differs from setup manifest')
    package = identity.get('modules', {}).get('mulder', {})
    if not package.get('path'):
        raise RuntimeQualificationError('Mulder cannot be imported by the configured launcher')
    imported = Path(package['path'])
    source = Path(_run(['git', '-C', imported.parent, 'rev-parse', '--show-toplevel']).decode().strip()).resolve()
    if imported != source / 'src/mulder/__init__.py':
        raise RuntimeQualificationError('Imported Mulder is outside the supported pinned source layout')
    if _run(['git', '-C', source, 'rev-parse', 'HEAD']).decode().strip() != spec['commit']:
        raise RuntimeQualificationError('Imported Mulder source revision differs from setup manifest')
    diff = _run(['git', '-C', source, 'diff', 'HEAD', '--binary'], maximum=16*1024*1024)
    if _sha(diff) != spec['patched_diff_sha256']:
        raise RuntimeQualificationError('Imported Mulder source patch differs from setup manifest; version text is insufficient')
    staged = _run(['git', '-C', source, 'diff', '--cached', 'HEAD', '--binary'], maximum=16*1024*1024)
    if _sha(staged) != spec['patched_diff_sha256']:
        raise RuntimeQualificationError('Mulder qualification requires a managed checkout with the exact patch staged')
    flags = _run(['git', '-C', source, 'ls-files', '-v', '-z', 'src/mulder']).decode().split('\0')
    if any(record and (record[0].islower() or record[0] == 'S') for record in flags):
        raise RuntimeQualificationError('Mulder source index has assume-unchanged or skip-worktree flags')
    entries = _run(['git', '-C', source, 'ls-files', '--stage', '-z', 'src/mulder']).decode().split('\0')
    tracked = {}
    for entry in filter(None, entries):
        details, name = entry.split('\t', 1)
        mode, oid, stage = details.split()
        if stage != '0' or mode not in {'100644', '100755'} or len(oid) not in {40, 64}:
            raise RuntimeQualificationError('Unsupported Mulder source index entry')
        tracked[name] = oid
    if len(tracked) > 5000:
        raise RuntimeQualificationError('Mulder source inventory exceeds qualification bound')
    # Ignored injected Python is not visible to git diff. Reject it too, without
    # materializing an unbounded directory tree supplied by a different runtime.
    deadline = time.monotonic() + 30
    for count, path in enumerate((source/'src/mulder').rglob('*'), 1):
        if count > 20000 or time.monotonic() > deadline:
            raise RuntimeQualificationError('Mulder source traversal exceeds qualification bound')
        if path.suffix == '.py' and path.relative_to(source).as_posix() not in tracked:
            raise RuntimeQualificationError('Unexpected Python source in imported Mulder package')
    hashes = {}; total_bytes = 0
    for name in sorted(tracked):
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeQualificationError('Unavailable or linked tracked Mulder source: ' + name)
        raw = _read(path, 16*1024*1024); total_bytes += len(raw)
        if total_bytes > 128*1024*1024 or time.monotonic() > deadline:
            raise RuntimeQualificationError('Mulder source hashing exceeds qualification bound')
        # Compare bytes to the pinned staged blob, independently of Git's stat
        # cache. A cached diff alone cannot prove the working files are exact.
        blob = b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw
        actual_oid = hashlib.new('sha1' if len(tracked[name]) == 40 else 'sha256', blob).hexdigest()
        if actual_oid != tracked[name]:
            raise RuntimeQualificationError('Mulder working source differs from its pinned index blob: ' + name)
        hashes[name] = _sha(raw)
    for name, record in identity.get('modules', {}).items():
        path = Path(record['path'])
        try: relative = path.relative_to(source).as_posix()
        except ValueError as exc:
            raise RuntimeQualificationError('Imported Mulder module escaped the qualified checkout: ' + name) from exc
        if hashes.get(relative) != record['sha256']:
            raise RuntimeQualificationError('Imported Mulder module differs from its qualified source: ' + name)
    if identity.get('errors'):
        details = identity['errors'][0]
        raise RuntimeQualificationError('Runtime import unavailable: ' + details['module'] +
            (' (missing dependency ' + str(details['missing_dependency']) + ')' if 'missing_dependency' in details else ' (' + details['error_type'] + ')'))
    if identity.get('version') != manifest['expected_mulder_version']:
        raise RuntimeQualificationError('Imported Mulder version differs from setup manifest')
    if not set(_REQUIRED_MODULES) <= set(identity['modules']):
        raise RuntimeQualificationError('Required runtime module identity is missing')
    return {'source_root': str(source), 'upstream_commit': spec['commit'],
            'patch_sha256': spec['patch_sha256'], 'patched_diff_sha256': _sha(diff),
            'source_files': hashes, 'source_fingerprint': _sha(json.dumps(hashes, sort_keys=True).encode()),
            'imported_modules': identity['modules'], 'version': identity['version']}


def validate_tool_schemas(profile, tools):
    if profile not in PROFILES:
        raise RuntimeQualificationError('Unknown MCP qualification profile')
    names = set(tools)
    if profile == 'standard':
        required = {'run_aleapp', 'run_ileapp', 'reindex_timestamps', 'get_timeline', 'run_mvt_android'}
        if not required <= names:
            raise RuntimeQualificationError('Standard MCP tools missing: ' + ', '.join(sorted(required - names)))
        if {'collect_lawliet_android_contacts', 'collect_lawliet_android_sms',
            'get_lawliet_collection', 'run_lawliet_collection', 'query_lawliet_collection'} & names:
            raise RuntimeQualificationError('Device collection exposed in standard MCP profile')
        for tool, fields in {'get_timeline': ('limit', 'offset'), 'reindex_timestamps': ('after_id', 'limit')}.items():
            props = tools[tool].get('properties', {})
            if any(props.get(field, {}).get('type') != 'integer' for field in fields):
                raise RuntimeQualificationError('Unsupported MCP input schema: ' + tool)
    elif names != PROFILE_TOOLS[profile]:
        raise RuntimeQualificationError('Restricted MCP profile surface mismatch: ' + profile)
    return {'profile': profile, 'tools_advertised': len(names), 'tool_names': sorted(names),
            'schema_sha256': _sha(json.dumps(tools, sort_keys=True).encode())}


def qualify_runtime(launcher, repository, manifest=None, *, timeout=120):
    """Verify one new isolated process; no existing server, phone or provider calls."""
    repository = Path(repository).resolve()
    manifest = manifest or json.loads((repository/'setup/mobile-macos-arm64.json').read_text())
    launch = resolve_launcher(launcher)
    identity = inspect_runtime(launch, timeout=min(timeout, 30))
    source = verify_source_identity(identity, repository, manifest)
    verify_launcher_identity(launch)
    with tempfile.TemporaryDirectory(prefix='lawliet-mcp-qualification-') as folder:
        env = dict(launch['environment'], PYTHONPYCACHEPREFIX=str(Path(folder)/'bytecode'))
        raw = _run([launch['python'], '-B', '-P', repository/'tools/verify_mcp.py',
                    '--schema-probe', launch['launcher']], env=env, cwd=folder,
                   timeout=timeout, maximum=2*1024*1024)
    try: profiles = json.loads(raw)['profiles']
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeQualificationError('MCP probe did not return qualified profiles') from exc
    if {p.get('profile') for p in profiles} != set(PROFILES):
        raise RuntimeQualificationError('MCP profile qualification is incomplete')
    # Detect changes during qualification; never promote a mutable run as pinned.
    again = verify_source_identity(identity, repository, manifest)
    if again['source_fingerprint'] != source['source_fingerprint']:
        raise RuntimeQualificationError('Mulder source changed during qualification')
    verify_launcher_identity(launch)
    return {'format': 'lawliet-mulder-runtime-qualification-v1', 'status': 'qualified',
            'launcher': launch['launcher'], 'python': launch['python'],
            'launcher_files': launch['launcher_files'], 'launcher_targets': launch['launcher_targets'],
            **source, 'profiles': profiles,
            'scope': 'New isolated MCP processes with fresh bytecode-cache paths and exact imported Mulder source; no tool execution, existing case, phone, model, provider or download checks. Existing connections require restart.',
            'limitations': ['Dependency packages and LAWLIET backend are not fingerprinted by this Mulder source check.',
                           'Qualification requires the managed Git checkout with the exact saved patch staged; arbitrary pip installs and unstaged manual patches are unsupported.',
                           'Read-time source qualification is not an operating-system sandbox or tamper-proof attestation.']}
