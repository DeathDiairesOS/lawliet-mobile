#!/usr/bin/env python3
"""Install and verify LAWLIET on Apple Silicon. No device access or model login."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'setup/mobile-macos-arm64.json'


def run(argv, **kwargs):
    print('+ ' + shlex.join(map(str, argv)), flush=True)
    return subprocess.run(list(map(str, argv)), check=True, stdin=subprocess.DEVNULL, **kwargs)


def checked_manifest():
    value = json.loads(MANIFEST.read_text())
    if value['schema_version'] != 1:
        raise RuntimeError('Unsupported setup manifest.')
    items = [(v['path'], v['sha256']) for v in value['locks'].values()]
    patch = value['sources']['mulder']
    items.append((patch['patch'], patch['patch_sha256']))
    for name, expected in items:
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError('Setup input changed without updating manifest: ' + name)
    return value


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


def wrapper(path, argv, environment=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = '#!/bin/sh\n'
    for key, val in (environment or {}).items():
        text += 'export ' + key + '=' + shlex.quote(str(val)) + '\n'
    text += 'exec ' + shlex.join(map(str, argv)) + ' "$@"\n'
    path.write_text(text)
    path.chmod(0o755)


def checkout(runtime, name, spec):
    destination = runtime / 'sources' / (name + '-' + spec['commit'][:12])
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        run(['git', 'clone', '--no-checkout', spec['url'], destination])
        run(['git', '-C', destination, 'checkout', '--detach', spec['commit']])
    head = subprocess.check_output(['git', '-C', str(destination), 'rev-parse', 'HEAD'], text=True).strip()
    if head != spec['commit']:
        raise RuntimeError('Unexpected source revision: ' + name)
    # Only our declared patch may be present. Never reset a modified checkout.
    dirty = subprocess.check_output(['git', '-C', str(destination), 'diff', 'HEAD', '--name-only'], text=True)
    untracked = subprocess.check_output(['git', '-C', str(destination), 'ls-files', '--others', '--exclude-standard'], text=True)
    if untracked:
        raise RuntimeError('Untracked files in managed source: ' + str(destination))
    if 'patch' in spec:
        patch = ROOT / spec['patch']
        reverse = subprocess.run(['git', '-C', str(destination), 'apply', '--reverse', '--check', str(patch)], capture_output=True)
        if reverse.returncode:
            if dirty:
                raise RuntimeError('Modified source; preserve it and choose a new runtime directory.')
            run(['git', '-C', destination, 'apply', '--check', patch])
            run(['git', '-C', destination, 'apply', '--index', patch])
        # Verify the entire diff, including any unexpected edits, against the patch.
        actual = subprocess.check_output(['git', '-C', str(destination), 'diff', 'HEAD', '--binary'])
        digest = hashlib.sha256(actual).hexdigest()
        if spec['patched_diff_sha256'] != digest:
            raise RuntimeError('Managed patched source has changed: ' + name)
    elif dirty:
        raise RuntimeError('Modified source: ' + str(destination))
    return destination


def environment(runtime, name, python, lock=None):
    target = runtime / 'envs' / name
    executable = target / 'bin/python'
    if not executable.exists():
        run([python, '-m', 'venv', target])
    if lock:
        run([executable, '-m', 'pip', 'install', '--no-deps', '-r', ROOT / lock['path']])
        run([executable, '-m', 'pip', 'check'])
    return executable


def verify(runtime, profile, workspace, manifest):
    results = []
    def check(name, argv, expected=None, env=None):
        try:
            p = run(argv, capture_output=True, text=True, timeout=600, env=env)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(name + ' failed:\n' + (exc.stdout or '')[-2000:] + (exc.stderr or '')[-4000:]) from exc
        if expected and expected not in p.stdout + p.stderr:
            raise RuntimeError('Unexpected verification output: ' + name)
        results.append({'check': name, 'passed': True, 'output': (p.stdout + p.stderr)[-2000:]})
        return p.stdout
    cli = runtime / 'bin/lawliet'
    with tempfile.TemporaryDirectory(prefix='lawliet-setup-check-') as tmp:
        check('synthetic native parsing', [cli, 'demo', '--workspace', tmp, '--json'])
        outcome = json.loads(check('synthetic evidence integrity', [cli, 'verify', '--case', 'demo', '--workspace', tmp, '--json']))
        if not outcome.get('ok') or outcome.get('files_checked', 0) < 1:
            raise RuntimeError('Synthetic integrity check failed.')
    if profile == 'mobile':
        for name in ('aleapp', 'ileapp'):
            check(name + ' plugin imports', [runtime / 'bin' / name, '-h'])
            env = dict(os.environ, **{'LAWLIET_' + name.upper(): str(runtime / 'bin' / name)})
            # Real parsers against synthetic known records, plus importer/provenance assertions.
            env['PYTHONPATH'] = str(ROOT)
            check(name + ' synthetic record integration', [runtime / 'envs/core/bin/python', '-m', 'unittest', 'tests.test_leapp_integration', '-v'], env=env)
        check('patched Mulder version', [runtime / 'bin/mulder', '--version'], manifest['expected_mulder_version'])
        check('Mulder MCP initialization and mobile tool listing', [runtime / 'envs/mulder/bin/python', ROOT / 'tools/verify_mcp.py', runtime / 'bin/mulder'])
        check('MVT CLI', [runtime / 'envs/mvt/bin/mvt-ios', '--help'])
        commands = {'adb': ['version'], 'scrcpy': ['--version'], 'exiftool': ['-ver'], 'yara': ['--version'], 'idevice_id': ['--version'], 'idevicebackup2': ['--version']}
        config = json.loads((workspace / 'tools.json').read_text())
        for name, args in commands.items():
            check(name + ' executable', [config[name], *args])
    receipt = {'profile': profile, 'checks': results, 'device_checks': 'not performed; connect a test phone for acceptance',
               'model_login': 'not performed', 'limitations': manifest['limitations']}
    write_json(runtime / 'verification.json', receipt)
    print('Verification passed. Receipt: ' + str(runtime / 'verification.json'))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['core', 'mobile'], default='mobile')
    parser.add_argument('--runtime', type=Path, default=Path.home() / 'Library/Application Support/LAWLIET/runtime')
    parser.add_argument('--workspace', type=Path, default=Path.home() / 'Documents/LAWLIET/cases')
    parser.add_argument('--app', type=Path, default=Path.home() / 'Applications/LAWLIET.app')
    parser.add_argument('--plan', action='store_true', help='Read-only installation plan')
    parser.add_argument('--verify', action='store_true', help='Verify existing setup without installing')
    parser.add_argument('--no-app', action='store_true', help='CLI-only installation')
    args = parser.parse_args()
    manifest = checked_manifest()
    runtime, workspace = args.runtime.expanduser().resolve(), args.workspace.expanduser().resolve()
    for path in (runtime, workspace, args.app.expanduser().resolve()):
        if path == ROOT or ROOT in path.parents:
            raise RuntimeError('Choose runtime, cases and application locations outside the source checkout.')
    print(json.dumps({'profile': args.profile, 'runtime': str(runtime), 'workspace': str(workspace),
                      'app': None if args.no_app else str(args.app), 'manifest': manifest}, indent=2))
    if args.plan:
        return
    if sys.platform != 'darwin' or platform.machine() != 'arm64':
        raise RuntimeError('This installer currently supports native Apple Silicon macOS only.')
    if int(platform.mac_ver()[0].split('.')[0]) < manifest['minimum_macos']:
        raise RuntimeError('macOS 13 or newer is required.')
    if args.verify:
        verify(runtime, args.profile, workspace, manifest)
        return
    brew = shutil.which('brew') or '/opt/homebrew/bin/brew'
    if not Path(brew).is_file():
        raise RuntimeError('Install Homebrew from https://brew.sh then rerun setup. Homebrew may require your administrator password.')
    run(['xcrun', '--find', 'swiftc'])
    installed = set(subprocess.check_output([brew, 'list', '--formula', '-1'], text=True).splitlines())
    required = manifest['brew_formulae'] if args.profile == 'mobile' else ['python@3.13']
    missing = [name for name in required if name not in installed]
    if missing:
        run([brew, 'install', *missing])
    if args.profile == 'mobile':
        casks = set(subprocess.check_output([brew, 'list', '--cask', '-1'], text=True).splitlines())
        missing = [name for name in manifest['brew_casks'] if name not in casks]
        if missing:
            run([brew, 'install', '--cask', *missing])
    prefix = subprocess.check_output([brew, '--prefix', 'python@3.13'], text=True).strip()
    python = Path(prefix) / 'bin/python3.13'
    runtime.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)
    # Stable managed snapshot: no editable dependency on a movable Git clone.
    core = environment(runtime, 'core', python)
    site = Path(subprocess.check_output([str(core), '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'], text=True).strip())
    destination = site / 'lawliet_mobile'
    if destination.exists():
        shutil.rmtree(destination)  # Only this installer's generated package snapshot.
    shutil.copytree(ROOT / 'lawliet_mobile', destination, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    wrapper(runtime / 'bin/lawliet', [core, '-m', 'lawliet_mobile'])
    config_path = workspace / 'tools.json'
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    if args.profile == 'mobile':
        for name in ('aleapp', 'ileapp'):
            source = checkout(runtime, name, manifest['sources'][name])
            py = environment(runtime, name, python, manifest['locks']['leapp'])
            wrapper(runtime / 'bin' / name, [py, source / (name + '.py')])
            config[name] = str(runtime / 'bin' / name)
        mvt = environment(runtime, 'mvt', python, manifest['locks']['mvt'])
        for name in ('mvt-ios', 'mvt-android'):
            wrapper(runtime / 'bin' / name, [mvt.parent / name])
        source = checkout(runtime, 'mulder', manifest['sources']['mulder'])
        py = environment(runtime, 'mulder', python, manifest['locks']['mulder'])
        # Source is revision-checked and patch-checked; PYTHONPATH avoids unpinned build dependencies.
        env = {'PYTHONPATH': os.pathsep.join([str(source / 'src'), str(site)]),
               'PATH': os.pathsep.join([str(runtime / 'bin'), str(mvt.parent), '/opt/homebrew/bin', '/usr/bin', '/bin']),
               'MULDER_ASSET_ROOT': str(runtime / 'assets'), 'MULDER_CWD': str(runtime / 'scratch'),
               'MULDER_DB_DIR': str(workspace / 'mulder')}
        for folder in ('assets', 'scratch'):
            (runtime / folder).mkdir(exist_ok=True)
        wrapper(runtime / 'bin/mulder', [py, '-c', 'from mulder.cli import cli; cli()'], env)
        for name in ('adb', 'scrcpy', 'exiftool', 'idevice_id', 'idevicebackup2', 'yara'):
            path = Path('/opt/homebrew/bin') / name
            if not path.is_file():
                raise RuntimeError('Missing Homebrew executable: ' + name)
            config[name] = str(path)
        write_json(config_path, config)
        # Generate a snippet, never overwrite unrelated Codex settings or credentials.
        snippet = '[mcp_servers.mulder]\ncommand = ' + json.dumps(str(runtime / 'bin/mulder')) + '\nargs = ["serve"]\n'
        (runtime / 'codex-mcp.toml').write_text(snippet)
    if not args.no_app:
        run([core, ROOT / 'desktop/build.py', '--workspace', workspace, '--output', args.app.expanduser()])
    receipt = {'manifest_sha256': hashlib.sha256(MANIFEST.read_bytes()).hexdigest(), 'profile': args.profile,
               'brew_versions': subprocess.check_output([brew, 'list', '--versions'], text=True),
               'runtime': str(runtime), 'workspace': str(workspace), 'app': None if args.no_app else str(args.app)}
    write_json(runtime / 'installation.json', receipt)
    verify(runtime, args.profile, workspace, manifest)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('Setup incomplete: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
