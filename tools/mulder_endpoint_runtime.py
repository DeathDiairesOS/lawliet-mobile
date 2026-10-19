"""Resolve the source inspected by restricted launchers and execute that source.

This bounded import probe is not full source/schema qualification. Setup performs
that qualification separately. It never calls forensic tools or starts a daemon.
"""
import os
import stat
from pathlib import Path

from lawliet_mobile.mulder_runtime import (
    RuntimeQualificationError, inspect_runtime, resolve_launcher,
)

ROOT = Path(__file__).resolve().parents[1]


def endpoint_runtime(runtime, profile, *, mulder_source=None,
                     lawliet_source=None, environment=None):
    runtime = Path(runtime).expanduser().resolve()
    backend = Path(lawliet_source or ROOT).expanduser().resolve()
    if mulder_source is not None:
        # Preserve the explicit staged-source workflow without requiring a
        # candidate launcher. Never infer this fallback for a default launch.
        source = Path(mulder_source).expanduser().resolve()
        python = runtime / 'mulder-1.5.2/bin/python'
        if not python.is_file() or not os.access(python, os.X_OK):
            raise RuntimeQualificationError('Mulder Python interpreter is unavailable')
        env = {k: os.environ[k] for k in ('HOME', 'LANG', 'LC_ALL', 'SYSTEMROOT') if k in os.environ}
        env.update(PYTHONPATH=os.pathsep.join((str(source), str(backend))),
                   MULDER_ASSET_ROOT=str(runtime/'assets'),
                   XDG_CACHE_HOME=str(runtime/'cache'), TMPDIR=str(runtime/'tmp'),
                   PATH=os.pathsep.join((str(runtime/'bin'), str(runtime/'mulder-1.5.2/bin'),
                                         '/opt/homebrew/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin')))
        spec = {'python': str(python), 'environment': env, 'launcher_files': {},
                'launcher_targets': {str(python): str(python.resolve(strict=True))}}
    else:
        candidate = runtime/'bin/mulder-lawliet-candidate'
        # Development candidates take precedence, including a broken candidate:
        # do not hide a failed qualification by selecting another installation.
        # Fresh setup installations publish the same inspected wrapper as mulder.
        try:
            candidate.lstat()
        except FileNotFoundError:
            launcher = runtime/'bin/mulder'
        else:
            launcher = candidate
        spec = resolve_launcher(launcher)
        env = dict(spec['environment'])
        paths = env.get('PYTHONPATH', '').split(os.pathsep) if env.get('PYTHONPATH') else []
        if any(not p or not Path(p).is_absolute() for p in paths):
            raise RuntimeQualificationError('Mulder launcher requires absolute, nonempty Python source paths')
        if lawliet_source is None and str(backend) not in paths:
            paths.append(str(backend))
        env['PYTHONPATH'] = os.pathsep.join(paths)
    # Neither caller environment nor the launcher may select a different device,
    # daemon, profile or Python startup hook for this restricted endpoint.
    for name in ('PYTHONHOME', 'PYTHONSTARTUP', 'ADB_SERVER_SOCKET',
                 'ANDROID_ADB_SERVER_PORT', 'ANDROID_ADB_SERVER_ADDRESS', 'ANDROID_SERIAL',
                 'DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        env.pop(name, None)
    env.update(environment or {})
    if not stat.S_ISCHR(Path('/dev/null').stat().st_mode):
        raise RuntimeQualificationError('Source-only endpoint execution requires the local null device')
    # -B disables writes, not reads. A prefix beneath a non-directory prevents
    # timestamp-valid stale bytecode from replacing the source inspected by the
    # probe. The probe also uses source-only imports via its fresh cache prefix.
    env.update(LAWLIET_MCP_PROFILE=profile, PYTHONDONTWRITEBYTECODE='1',
               PYTHONPYCACHEPREFIX='/dev/null/lawliet-source-only')
    spec = {**spec, 'environment': env}
    if mulder_source is None and lawliet_source is not None:
        # The backend override must not shadow Mulder itself. Establish the
        # launcher's source first, then keep it ahead of the requested backend,
        # matching the explicit-source workflow's original path ordering.
        base_identity = inspect_runtime(spec)
        package_path = base_identity.get('modules', {}).get('mulder', {}).get('path')
        if base_identity.get('errors') or not package_path or not Path(package_path).is_absolute():
            raise RuntimeQualificationError('Cannot identify Mulder before applying the backend override')
        selected_source = Path(package_path).parent.parent
        env['PYTHONPATH'] = os.pathsep.join((str(selected_source), str(backend)))
    identity = inspect_runtime(spec)
    if identity.get('errors'):
        failed = identity['errors'][0]
        raise RuntimeQualificationError('Selected Mulder runtime cannot import ' + str(failed.get('module', 'required modules')))
    modules = identity.get('modules', {})
    package_path = modules.get('mulder', {}).get('path')
    app_path = modules.get('mulder.server.app', {}).get('path')
    if not package_path or not app_path:
        raise RuntimeQualificationError('Selected Mulder runtime did not identify its package and server')
    package, app = Path(package_path), Path(app_path)
    if not package.is_absolute() or not app.is_absolute() or app != package.parent/'server/app.py':
        raise RuntimeQualificationError('Selected Mulder server is outside its imported package')
    source = package.parent.parent
    if mulder_source is not None and source != Path(mulder_source).expanduser().resolve():
        raise RuntimeQualificationError('Imported Mulder differs from the explicit source override')
    if mulder_source is None and lawliet_source is not None and source != selected_source:
        raise RuntimeQualificationError('Backend override changed the selected Mulder source')
    return {'python': spec['python'], 'environment': env, 'source': source,
            'app': app, 'backend': backend, 'identity': identity}


def endpoint_command(selected):
    """Use the exact probed interpreter/environment, without re-running a wrapper."""
    return [selected['python'], '-B', '-P', '-m', 'mulder.cli']
