"""Bounded, local desktop bridge reusing the existing JSON backend protocol.

Only the trusted packaged interface receives this bridge. Evidence is data and
never loaded as a web page. No HTTP listener, shell commands or network API.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

from .core import UserError

MAX_REQUEST = 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
MAX_MEDIA = 16 * 1024 * 1024
CASE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')
ALLOWED = frozenset('''catalog create overview records source-stats date-range
case-management case-update case-task-add case-task-update import-evidence import
import-chat import-discord signal-preflight decrypt-signal analyze analysis-plan
file-inventory file-preview evidence-inspect related-attachments conversations
findings finding-add findings-export export verify devices assess-android preflight
collect app-coverage validate scenario-assessment coverage-ledger coverage-record
agent-collection-create agent-collection-list agent-collection-status
engine-check engine-list engine-status engine-logs engine-findings engine-review
engine-report engine-start engine-cancel engine-import-output engine-export-report
mvt-preview mvt-import mvt-list mvt-review mvt-record
sqlite-files sqlite-schema sqlite-query sqlite-query-result recover
investigation-from-findings investigation-from-examination
customer-report-draft customer-report-review customer-report-approve
customer-report-release customer-report-masking-preview customer-report-redacted-draft
customer-report-redacted-check customer-report-redacted-approve customer-report-redacted-release
report-history desktop-report desktop-media custody-list custody-record
device-state-list device-state-record identity-history identity-groups identity-record
competency-history competency-record remediation-history remediation-record'''.split())
READ_ONLY = frozenset('''catalog overview records source-stats date-range case-management
file-inventory evidence-inspect related-attachments conversations findings
app-coverage scenario-assessment coverage-ledger agent-collection-list agent-collection-status
engine-check engine-list engine-status engine-logs engine-findings engine-report
mvt-preview mvt-list mvt-review sqlite-files sqlite-query-result report-history
desktop-report custody-list device-state-list identity-history identity-groups
competency-history remediation-history preflight analysis-plan signal-preflight'''.split())
PATH_ACTIONS = frozenset('''import-evidence import import-chat import-discord signal-preflight
decrypt-signal findings-export export engine-import-output engine-export-report
mvt-preview mvt-import customer-report-release customer-report-redacted-release'''.split())


def worker(request):
    """One subprocess request; imports heavy backend code only in this process."""
    from .app_backend import handle
    from .case_catalog import catalog, history
    from .core import connect
    workspace = Path(request.pop('workspace')).resolve()
    action = request.get('action')
    if action not in ALLOWED:
        raise UserError('Unsupported desktop action.')
    if action == 'catalog':
        result = catalog([str(workspace)], max_depth=1)
        result['cases'] = [row for row in result['cases'] if Path(row['workspace']) == workspace]
        return result
    if action == 'report-history':
        if not CASE_ID.fullmatch(request.get('case', '')):
            raise UserError('Select a case.')
        return history(str(workspace/request['case']), request.get('offset', 0))
    if action == 'desktop-media':
        result = handle(workspace, {**request, 'action': 'preview'})
        if result['bytes'] > MAX_MEDIA:
            raise UserError('Inline media is limited to 16 MiB. The original remains preserved.')
        path = Path(result['path'])
        if path.is_symlink() or not path.resolve().is_relative_to(workspace/request['case']/'previews'):
            raise UserError('Preview path is outside this case.')
        with path.open('rb') as source:
            data = source.read(MAX_MEDIA + 1)
        if len(data) > MAX_MEDIA or hashlib.sha256(data).hexdigest() != result['sha256']:
            raise UserError('Preview bytes changed after verification.')
        if result['mime'] not in {'image/png','image/jpeg','image/gif','image/webp','image/heic',
                                  'audio/wav','audio/x-caf','audio/mp4','video/quicktime','video/mp4'}:
            raise UserError('This media type is not supported inline.')
        return {**result, 'data_url': 'data:'+result['mime']+';base64,'+base64.b64encode(data).decode('ascii')}
    if action == 'desktop-report':
        from .investigation_report import _checked_draft, _checked_redacted_customer_draft
        from .report_review import review_bundle
        kind = request.get('kind')
        if kind not in {'original', 'redacted'}:
            raise UserError('Select an original or redacted report.')
        with connect(workspace, request['case']) as (root, db):
            check = _checked_draft if kind == 'original' else _checked_redacted_customer_draft
            folder, manifest, checksum = check(root, db, request['bundle_id'])
            path = folder/'report.txt'
            if path.is_symlink() or not path.is_file():
                raise UserError('No regular verified text report is available.')
            with path.open('rb') as stream:
                raw = stream.read(2*1024*1024+1)
            expected = next((x for x in manifest['files'] if x['path']=='report.txt'), None)
            if expected is None:
                raise UserError('Report text is not in the verified manifest.')
            truncated = len(raw) > 2*1024*1024
            if not truncated and hashlib.sha256(raw).hexdigest() != expected['sha256']:
                raise UserError('Report changed during review.')
            if truncated:
                raise UserError('Report exceeds the 2 MiB review limit. Use the existing native review workflow.')
            result = review_bundle(root, db, request['bundle_id'], kind, checksum)
            return {**result, 'text': raw.decode('utf-8'), 'manifest': manifest, 'truncated': False}
    return handle(workspace, request)


def worker_main():
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise UserError('Desktop request exceeds its limit.')
        result = worker(json.loads(raw))
        response = json.dumps({'ok': True, 'result': result}, ensure_ascii=False).encode('utf-8')
        if len(response) > MAX_RESPONSE:
            raise UserError('Response exceeds the desktop limit. Narrow the source or query.')
        sys.stdout.buffer.write(response)
        return 0
    except Exception as error:
        sys.stdout.buffer.write(json.dumps({'ok': False, 'error': str(error)}, ensure_ascii=False).encode('utf-8'))
        return 1


class DesktopBridge:
    def __init__(self, workspace, *, timeout=7200, smoke_fixture=None, smoke_result=None):
        self._workspace = Path(workspace).expanduser().resolve()
        self._timeout = timeout
        self._window = None
        self._slots = threading.BoundedSemaphore(2)
        self._lock = threading.RLock()
        self._mutations = set()
        self._processes = set()
        self._grants = set()
        self._closed = False
        self._smoke_fixture = smoke_fixture
        self._smoke_result = smoke_result
        if smoke_fixture:
            self._grants.add(str(Path(smoke_fixture['path']).resolve()))

    def _attach(self, window):
        self._window = window

    def _stop(self, process):
        if process.poll() is not None:
            return
        try:
            if os.name == 'posix':
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == 'posix':
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            else:
                process.kill()
            process.wait(timeout=5)
        except ProcessLookupError:
            pass

    def _close(self):
        with self._lock:
            self._closed = True
            processes = tuple(self._processes)
        for process in processes:
            self._stop(process)

    def _invoke(self, request):
        raw = json.dumps(request, ensure_ascii=False).encode('utf-8')
        if len(raw) > MAX_REQUEST:
            raise UserError('Desktop request exceeds its limit.')
        env = dict(os.environ)
        env.update(PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1')
        # The installed package and development clone follow the same route.
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
        # GUI entry points can use pythonw.exe, whose standard streams are
        # unavailable. Run the worker with the same venv's console interpreter,
        # and CREATE_NO_WINDOW so no terminal flashes during GUI operations.
        interpreter = Path(sys.executable)
        if os.name == 'nt' and interpreter.name.lower() == 'pythonw.exe':
            interpreter = interpreter.with_name('python.exe')
            if not interpreter.is_file():
                raise UserError('This desktop environment is missing its Python worker interpreter.')
        process = subprocess.Popen([str(interpreter), '-B', '-m', 'lawliet_mobile.desktop', '--worker'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, start_new_session=(os.name=='posix'),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        with self._lock:
            self._processes.add(process)
            closed = self._closed
        captured = bytearray()
        overflow = threading.Event()
        def drain(stream, retain):
            while True:
                chunk = stream.read(65536)
                if not chunk: break
                if retain:
                    if len(captured)+len(chunk)>MAX_RESPONSE:
                        overflow.set()
                    else:
                        captured.extend(chunk)
            stream.close()
        readers = [threading.Thread(target=drain, args=(process.stdout, True), daemon=True),
                   threading.Thread(target=drain, args=(process.stderr, False), daemon=True)]
        for thread in readers: thread.start()
        try:
            if closed:
                raise UserError('The desktop is closing.')
            process.stdin.write(raw); process.stdin.close()
            deadline = time.monotonic()+self._timeout
            while process.poll() is None:
                if overflow.is_set() or time.monotonic() > deadline or self._closed:
                    self._stop(process)
                    raise UserError('Operation stopped or exceeded its limit. Inspect retained case history before retrying.')
                time.sleep(.05)
            for thread in readers: thread.join(timeout=5)
            if overflow.is_set() or any(thread.is_alive() for thread in readers):
                raise UserError('Backend response exceeded its limit or did not finish.')
            response = json.loads(captured)
            if not isinstance(response, dict) or type(response.get('ok')) is not bool:
                raise ValueError('Invalid envelope')
            if process.returncode and response['ok']:
                raise UserError('Backend exited unsuccessfully; its result was not accepted.')
            return response
        except (ValueError, BrokenPipeError) as error:
            raise UserError('Backend returned an incomplete response. Inspect case history.') from error
        finally:
            self._stop(process)
            if process.stdin and not process.stdin.closed: process.stdin.close()
            with self._lock: self._processes.discard(process)

    def request(self, request):
        acquired = False
        mutation = None
        try:
            if not isinstance(request, dict) or 'workspace' in request or len(json.dumps(request)) > MAX_REQUEST:
                raise UserError('Invalid desktop request; workspace is selected through the native dialog.')
            action = request.get('action')
            if action == 'desktop-info':
                return {'ok': True, 'result': {'workspace': str(self._workspace), 'platform': sys.platform,
                    'version': '0.1.0', 'capabilities': {'agent_endpoint': sys.platform=='darwin', 'device_mirroring': False},
                    'limitations': ['Tool availability is separate from device acquisition coverage.',
                                    'The restricted Mulder collection endpoint currently requires macOS.',
                                    'This desktop does not implement device screen mirroring.']}}
            if action == 'desktop-smoke-fixture' and self._smoke_fixture:
                return {'ok': True, 'result': dict(self._smoke_fixture)}
            if action == 'desktop-smoke-result' and self._smoke_fixture and self._smoke_result:
                self._smoke_result(request.get('result'))
                return {'ok': True, 'result': {'recorded': True}}
            if action not in ALLOWED:
                raise UserError('Unsupported desktop action.')
            if action not in {'catalog', 'create', 'devices'} and not CASE_ID.fullmatch(request.get('case','')):
                raise UserError('Select a valid case in this workspace.')
            if request.get('case'):
                folder = self._workspace/request['case']
                if folder.is_symlink() or not folder.resolve().is_relative_to(self._workspace):
                    raise UserError('Case path must remain inside the selected workspace.')
            if action == 'collect' and request.get('authorized') is not True:
                raise UserError('Explicit authorization is required for device collection.')
            if action in PATH_ACTIONS:
                path = str(Path(request.get('path','')).expanduser().resolve())
                if path not in self._grants:
                    raise UserError('Select the source or destination with the native file dialog.')
            with self._lock:
                if self._closed: raise UserError('The desktop is closing.')
                workspace = str(self._workspace)
                if action not in READ_ONLY:
                    mutation = (workspace, request.get('case', request.get('id', '')))
                    if mutation in self._mutations:
                        mutation = None
                        raise UserError('An operation is already writing this case. Wait for its result.')
                    self._mutations.add(mutation)
            acquired = self._slots.acquire(blocking=False)
            if not acquired:
                raise UserError('Two background operations are already running. Retry when one finishes.')
            return self._invoke({**request, 'workspace': workspace})
        except Exception as error:
            return {'ok': False, 'error': str(error)}
        finally:
            if acquired: self._slots.release()
            if mutation:
                with self._lock: self._mutations.discard(mutation)

    def media(self, request):
        if not isinstance(request, dict): return {'ok': False, 'error': 'Invalid media request.'}
        return self.request({**request, 'action': 'desktop-media'})

    def choose_path(self, kind):
        import webview
        if self._window is None or kind not in {'file', 'folder', 'save', 'workspace'}:
            return None
        if kind == 'workspace':
            with self._lock:
                if self._processes or self._mutations: return None
        dialog = webview.FileDialog.SAVE if kind=='save' else webview.FileDialog.FOLDER if kind in {'folder','workspace'} else webview.FileDialog.OPEN
        selected = self._window.create_file_dialog(dialog, allow_multiple=False)
        if not selected: return None
        path = str(Path(selected[0] if isinstance(selected, (tuple,list)) else selected).expanduser().resolve())
        with self._lock:
            if kind == 'workspace':
                if self._processes or self._mutations: return None
                self._workspace = Path(path)
                self._grants.clear()
            else:
                self._grants.add(path)
        return path
