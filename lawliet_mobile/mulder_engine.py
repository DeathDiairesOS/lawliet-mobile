"""External Mulder 1.5.2 adapter; no bundled code, provider defaults or auto-install."""
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from .core import UserError, audit, case_dir, connect, digest, now

VERSION = '1.5.2'
REVISION = '5321847887fe1fcb5399cec0a1703db9c513bac8'
TERMINAL = {'completed', 'partial', 'failed', 'cancelled', 'interrupted'}
LIMITATION = 'Mulder 1.5.2 requires findings and ATT&CK mappings at a quality gate; negative/inconclusive mobile investigations may fail that gate. No indicators is not proof of no compromise.'


def job_path(root, jid):
    if not re.fullmatch(r'[a-f0-9]{32}', str(jid)):
        raise UserError('Invalid investigation run ID.')
    path = root / 'engine-runs' / jid
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise UserError('Unsafe investigation directory.')
    return path


def atomic_json(path, value):
    temp = path.with_suffix('.tmp')
    with temp.open('w', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=True)
    os.replace(temp, path)


def read_json(path, maximum=1024*1024):
    if path.is_symlink() or path.stat().st_size > maximum:
        raise UserError('Unsafe or oversized investigation metadata.')
    return json.loads(path.read_text())


def configuration(value):
    allowed = {'executable', 'model', 'provider', 'objective', 'questions', 'known_facts',
               'scope', 'evidence_id', 'authorize_remote', 'authorize_enrichment', 'timeout', 'workers', 'max_output_gib'}
    if type(value) is not dict or set(value) - allowed:
        raise UserError('Unknown engine configuration fields. Credentials belong in the host environment, not configuration.')
    config = dict(value)
    for key in ('objective', 'questions', 'known_facts', 'scope'):
        val = config.setdefault(key, '')
        if not isinstance(val, str) or len(val) > 16000:
            raise UserError('Briefing fields must be text, at most 16000 characters each.')
    if not config['objective'].strip():
        raise UserError('Enter an investigation objective.')
    if config.get('provider') not in ('anthropic', 'ollama'):
        raise UserError('Choose an explicit provider: anthropic (remote) or ollama (local). Other Mulder providers are not yet exposed by this adapter.')
    model = config.get('model', '')
    if not isinstance(model, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}', model):
        raise UserError('Enter a model identifier; no model is selected automatically.')
    if config['provider'] == 'ollama' and not model.startswith('ollama/'):
        raise UserError('Local mode requires an explicit ollama/ model identifier.')
    if config['provider'] == 'anthropic' and not model.startswith('claude-'):
        raise UserError('This remote provider route requires a Claude model identifier.')
    if config['provider'] == 'anthropic' and config.get('authorize_remote') is not True:
        raise UserError('Explicit authorization is required to send evidence to the remote model provider.')
    if config.get('authorize_enrichment') is not True:
        raise UserError('Mulder 1.5.2 may disclose IP indicators to ip-api.com over HTTP and has no reviewed global enrichment-disable flag. Separate explicit enrichment authorization is required; otherwise launch is blocked.')
    for key, default, maximum in (('timeout', 7200, 86400), ('workers', 1, 3), ('max_output_gib', 5, 100)):
        val = config.setdefault(key, default)
        if type(val) is not int or not 1 <= val <= maximum:
            raise UserError('Invalid investigation resource limit: ' + key)
    return config


def environment(config):
    # No inherited proxy/provider overrides, cloud credentials, MCP config or project hooks.
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'SYSTEMROOT') if k in os.environ}
    env.update({'NO_COLOR': '1', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1',
                'DO_NOT_TRACK': '1', 'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
                'PYTHONDONTWRITEBYTECODE': '1'})
    if config.get('provider') == 'anthropic' and os.environ.get('ANTHROPIC_API_KEY'):
        env['ANTHROPIC_API_KEY'] = os.environ['ANTHROPIC_API_KEY']
    if config.get('provider') == 'ollama':
        env['OLLAMA_API_BASE'] = 'http://127.0.0.1:11434'
    return env


def engine_command(executable, *args):
    """Native executable or explicit Python script, always without a shell."""
    executable = Path(executable)
    if os.name == 'nt':
        with executable.open('rb') as stream:
            first = stream.readline(4097)
        if first.startswith(b'#!'):
            try:
                interpreter = Path(first[2:].strip().decode('utf-8'))
            except (UnicodeError, ValueError) as exc:
                raise UserError('Unsupported Windows engine script interpreter.') from exc
            if (len(first) > 4096 or not interpreter.is_absolute() or not interpreter.is_file()
                    or not re.fullmatch(r'python(?:w|\d+(?:\.\d+)*)?\.exe', interpreter.name, re.I)):
                raise UserError('Windows engine scripts require an explicit absolute Python executable shebang.')
            return [str(interpreter), str(executable), *args]
        if not first.startswith(b'MZ'):
            raise UserError('Windows engine must be a native executable or an explicit Python script; shell wrappers are unsupported.')
    return [str(executable), *args]


class MulderEngine:
    def __init__(self, workspace, case):
        self.workspace = Path(workspace).expanduser().resolve()
        self.case = case
        self.root = case_dir(self.workspace, case)

    def get_capabilities(self):
        return {'engine': 'mulder', 'supported_version': VERSION, 'reviewed_revision': REVISION,
                'workflow': 'investigate', 'inputs': ['imported evidence directories'],
                'native_platform': platform.system(), 'native_platform_validated': False,
                'limitations': [LIMITATION, 'Native working copies are not an OS sandbox.',
                                'No local model or live Mulder run has been validated by Lawliet.']}

    def check_availability(self, config):
        requested = config.get('executable') or shutil.which('mulder')
        result = {**self.get_capabilities(), 'available': False, 'ready': False, 'errors': [],
                  'dependencies': {name: bool(shutil.which(name)) for name in ('yara', 'mvt-android', 'aleapp', 'tsk_recover')}}
        if os.name not in ('posix', 'nt'):
            result['errors'].append('The external investigation worker is unsupported on this host.')
        if not requested:
            result['errors'].append('Mulder is not installed/configured. Install it separately following upstream instructions.')
            return result
        executable = Path(requested).expanduser().resolve()
        if not executable.is_file() or not os.access(executable, os.X_OK):
            result['errors'].append('Configured Mulder executable is unavailable.')
            return result
        try:
            # Probe outputs are bounded on disk rather than retaining arbitrary stdout.
            import tempfile
            with tempfile.TemporaryFile() as out:
                probe = subprocess.run(engine_command(executable, '--version'), stdout=out, stderr=subprocess.DEVNULL,
                                       timeout=15, env=environment({}), stdin=subprocess.DEVNULL)
                out.seek(0); version = out.read(4096).decode('utf-8', errors='replace').strip()
            result['version'] = version
            result['available'] = probe.returncode == 0
            if probe.returncode or not re.fullmatch(r'mulder, version 1\.5\.2', version, re.I):
                result['errors'].append('Only the reviewed Mulder CLI version 1.5.2 is supported.')
            else:
                with tempfile.TemporaryFile() as out:
                    help_probe = subprocess.run(engine_command(executable, 'investigate', '--help'), stdout=out,
                                                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                                timeout=15, env=environment({}))
                    out.seek(0); help_text = out.read(65536).decode('utf-8', errors='replace')
                if help_probe.returncode or not all(flag in help_text for flag in ('--cwd', '--db-dir', '--workers', '--model', '--max-compactions')):
                    result['errors'].append('Installed investigation CLI does not expose the reviewed interface.')
                verify_probe = subprocess.run(engine_command(executable, 'setup', '--verify', '--json'),
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                              stdin=subprocess.DEVNULL, timeout=30, env=environment({}))
                result['asset_verification_exit_code'] = verify_probe.returncode
                if verify_probe.returncode:
                    result['errors'].append('Mulder asset verification failed. Run mulder setup --verify separately to inspect missing assets. Lawliet did not install anything.')
            result['executable'] = str(executable)
            result['executable_sha256'] = digest(executable)
        except (OSError, subprocess.TimeoutExpired, UserError):
            result['errors'].append('Mulder version probe failed or timed out.')
        try:
            normalized = configuration(config)
            if normalized['provider'] == 'anthropic' and not os.environ.get('ANTHROPIC_API_KEY'):
                result['errors'].append('ANTHROPIC_API_KEY is missing from the Lawliet process environment; credential validity has not been tested.')
            if normalized['provider'] == 'ollama':
                result['errors'].append('Local Ollama route is not yet validated for no-egress execution; launching is disabled pending validation.')
        except UserError as exc:
            result['errors'].append(str(exc))
        result['ready'] = result['available'] and not result['errors']
        return result

    def start_investigation(self, value):
        config = configuration(value)
        available = self.check_availability(config)
        if not available['ready']:
            raise UserError('; '.join(available['errors']))
        config['executable'] = available['executable']
        config['executable_sha256'] = available['executable_sha256']
        jid = uuid.uuid4().hex
        path = job_path(self.root, jid)
        with connect(self.workspace, self.case) as (_, db):
            if not db.execute('SELECT 1 FROM evidence WHERE id=? AND encrypted=0', (config.get('evidence_id'),)).fetchone():
                raise UserError('Select existing unencrypted case evidence.')
            path.mkdir(parents=True, mode=0o700)
            atomic_json(path / 'config.json', config)
            atomic_json(path / 'status.json', {'id': jid, 'engine': 'mulder', 'status': 'queued', 'created_at': now(),
                                              'evidence_id': config['evidence_id'], 'objective': config['objective']})
            audit(db, 'engine.requested', {'run_id': jid, 'engine': 'mulder', 'version': VERSION,
                                          'config_sha256': digest(path / 'config.json'),
                                          'remote_authorized': config.get('authorize_remote') is True,
                                          'enrichment_authorized': config.get('authorize_enrichment') is True})
        env = environment(config)
        env['PYTHONPATH'] = str(Path(__file__).resolve().parent.parent)
        try:
            with (path / 'worker.log').open('wb') as log:
                child = subprocess.Popen([sys.executable, '-m', 'lawliet_mobile.engine_worker', str(self.workspace), self.case, jid],
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env,
                                 start_new_session=os.name == 'posix', close_fds=True,
                                 creationflags=(subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP) if os.name == 'nt' else 0)
                atomic_json(path / 'worker.json', {'pid': child.pid, 'started_at': now()})
                threading.Thread(target=child.wait, daemon=True).start()
        except OSError as exc:
            atomic_json(path / 'status.json', {'id': jid, 'engine': 'mulder', 'status': 'failed', 'error': 'Worker launch failed.'})
            raise UserError('Could not launch the investigation worker.') from exc
        return self.get_status(jid)

    def get_status(self, job_id):
        path = job_path(self.root, job_id)
        state = read_json(path / 'status.json')
        pid = state.get('worker_pid')
        if not pid and (path / 'worker.json').is_file(): pid = read_json(path / 'worker.json').get('pid')
        if state['status'] not in TERMINAL and pid:
            try:
                if os.name == 'nt':
                    from .runner_windows import process_running
                    if not process_running(pid):
                        raise ProcessLookupError()
                else:
                    os.kill(pid, 0)
            except ProcessLookupError:
                state.update(status='interrupted', error='Worker no longer exists. Outputs retained; no automatic retry.')
        state['limitations'] = [LIMITATION]
        return state

    def list_runs(self):
        parent = self.root / 'engine-runs'
        if not parent.exists():
            return []
        return sorted([self.get_status(p.name) for p in parent.iterdir()
                       if re.fullmatch('[a-f0-9]{32}', p.name) and (p / 'status.json').is_file()],
                      key=lambda state:state.get('created_at',''))[-100:]

    def cancel_investigation(self, job_id):
        state = self.get_status(job_id)
        if state['status'] not in TERMINAL:
            path = job_path(self.root, job_id)
            if (path / 'cancel').is_symlink(): raise UserError('Unsafe cancellation marker.')
            (path / 'cancel').touch(mode=0o600)
            with connect(self.workspace, self.case) as (_, db):
                audit(db, 'engine.cancel_requested', {'run_id': job_id})
        return {**state, 'cancel_requested': state['status'] not in TERMINAL}

    def get_results(self, job_id):
        return self.get_status(job_id)

    def get_logs(self, job_id):
        path = job_path(self.root, job_id) / 'process.log'
        if not path.exists():
            return {'text': 'No process output yet.', 'truncated': False}
        if path.is_symlink():
            raise UserError('Unsafe log path.')
        with path.open('rb') as stream:
            size = path.stat().st_size
            stream.seek(max(0, size - 16384))
            data = stream.read(16384).decode('utf-8', errors='replace')
        return {'text': data, 'truncated': size > 16384}
