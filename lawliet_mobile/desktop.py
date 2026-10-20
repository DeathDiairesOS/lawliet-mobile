"""LAWLIET desktop window for Windows, macOS and Linux. No browser/server needed."""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
import hashlib
from importlib.resources import files
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading


def shell_html():
    assets = files('lawliet_mobile').joinpath('desktop_assets')
    css = assets.joinpath('app.css').read_text(encoding='utf-8')
    script = assets.joinpath('app.js').read_text(encoding='utf-8')
    def sha(value):
        return base64.b64encode(hashlib.sha256(value.encode('utf-8')).digest()).decode('ascii')
    # pywebview 6 constructs its trusted API stubs with Function(). Evidence is
    # rendered only as text; scripts still require the packaged source hash.
    csp = ("default-src 'none'; script-src 'unsafe-eval' 'sha256-"+sha(script)+"'; style-src 'sha256-"+sha(css)+"'; "
           "img-src data:; media-src data:; connect-src 'none'; object-src 'none'; "
           "frame-src 'none'; base-uri 'none'; form-action 'none'")
    return (assets.joinpath('index.html').read_text(encoding='utf-8')
            .replace('<!-- LAWLIET_CSP -->', '<meta http-equiv="Content-Security-Policy" content="'+csp+'">')
            .replace('/* LAWLIET_CSS */', css).replace('/* LAWLIET_JS */', script)
            .replace('<!-- LAWLIET_LOGO -->', 'data:image/png;base64,'+base64.b64encode(assets.joinpath('monolith.png').read_bytes()).decode('ascii')))


def synthetic_fixture(directory):
    source = Path(directory)/'synthetic-evidence'
    source.mkdir()
    with closing(sqlite3.connect(source/'sms.db')) as db:
        db.execute('CREATE TABLE sms(_id INTEGER,thread_id INTEGER,address TEXT,date INTEGER,type INTEGER,body TEXT)')
        db.executemany('INSERT INTO sms VALUES(?,?,?,?,?,?)', [
            (1,1,'+12025550100',1700000000000,1,'LAWLIET desktop synthetic message'),
            (2,1,'+12025550100',1700000010000,2,'<img src=x onerror="window.evidenceExecuted=true">')])
        db.commit()
    source.joinpath('pixel.png').write_bytes(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a9xkAAAAASUVORK5CYII='))
    return {'case_id': 'DESKTOP-SMOKE', 'path': str(source)}


def _source_hashes(fixture):
    """Hash the independently supplied inputs, including intentionally partial input."""
    result = {}
    for key in ('path', 'missing_path'):
        if fixture.get(key):
            root = Path(fixture[key])
            if not root.is_dir() or root.is_symlink():
                raise ValueError('Original synthetic source directory is missing or unsafe')
            result[key] = {str(p.relative_to(root)).replace(os.sep, '/'): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sorted(root.rglob('*')) if p.is_file()}
            oracle = fixture.get('oracle' if key == 'path' else 'missing_oracle')
            if oracle is not None and result[key] != oracle['files']:
                raise ValueError('Original synthetic inventory differs from the frozen oracle')
    return result


def _selected_oracle(fixture):
    rows = [r for r in fixture['oracle']['records']
            if r['body'] == '<img src=x onerror="window.evidenceExecuted=true">']
    if len(rows) != 1:
        raise ValueError('Synthetic selected-record oracle is ambiguous')
    return rows[0]


def _check_selected_snapshot(fixture, snapshot):
    """A same-file hash cannot identify the selected SQLite record."""
    expected = _selected_oracle(fixture)
    for key in ('logical_path', 'source_ref', 'source_sha256', 'body', 'title',
                'timestamp', 'timestamp_raw', 'parser', 'category'):
        if snapshot.get(key) != expected[key]:
            raise ValueError('Selected finding/report citation differs from the independent oracle: '+key)
    return {key: expected[key] for key in ('logical_path', 'source_ref', 'source_sha256', 'body')}


def _check_source_inspection(fixture, result):
    expected = _selected_oracle(fixture)
    source = Path(fixture['path']) / expected['logical_path']
    raw = source.read_bytes()
    window = raw[:4096]
    if (result.get('logical_path') != expected['logical_path']
            or result.get('source_sha256') != expected['source_sha256']
            or result.get('source_size') != len(raw)
            or result.get('offset') != 0 or result.get('end_offset_exclusive') != len(window)
            or result.get('bytes_returned') != len(window)
            or result.get('hex') != window.hex()
            or result.get('window_sha256') != hashlib.sha256(window).hexdigest()):
        raise ValueError('Displayed source bytes differ from the frozen evidence window')
    return {'ok': True, 'bytes_checked': len(window), 'window_sha256': hashlib.sha256(window).hexdigest()}


def _check_export(fixture, outcome):
    """Check the complete package and selected source against independent answers."""
    from .package_verification import verify_package
    target = Path(fixture['export_path'])
    report = outcome.get('report', {})
    verified = verify_package(target, report.get('manifest_sha256'))
    if (verified['format'] != 'ancalor-customer-bundle-v1'
            or not verified['release_receipt_present']
            or verified['counts'] != {'entries': 1, 'unique_cited_artifacts': 1}):
        raise ValueError('Synthetic export is not the complete single-finding released package')
    receipt = json.loads((target/'release-receipt.json').read_text(encoding='utf-8'))
    if receipt.get('manifest_sha256') != report['manifest_sha256'] or receipt.get('draft_id') != report['id']:
        raise ValueError('Synthetic export receipt is not bound to its report')
    annex = json.loads((target/'technical-annex.json').read_text(encoding='utf-8'))
    if len(annex['citations']) != 1:
        raise ValueError('Synthetic report must cite exactly the selected record')
    citation = annex['citations'][0]
    selected = outcome['selected_finding_snapshot']
    _check_selected_snapshot(fixture, selected)
    selected_source = _check_selected_snapshot(fixture, citation['snapshot'])
    if citation['artifact_id'] != selected.get('id'):
        raise ValueError('Report citation does not refer to the selected finding artifact')
    report_text = (target/'report.txt').read_text(encoding='utf-8')
    if any(value not in report_text for value in selected_source.values()):
        raise ValueError('Readable report is missing the selected original source citation')
    return {'ok': True, 'files_checked': verified['files_checked'],
            'manifest_sha256': report['manifest_sha256'], 'selected_source': selected_source,
            'package_counts': verified['counts']}


def _combine_restart(initial, reopened):
    if not reopened.get('ok') or reopened.get('process_id') == initial.get('process_id'):
        raise ValueError('A fresh native process did not successfully reopen the synthetic case')
    for key in ('case_id', 'corpus_sha256', 'field_fingerprint_sha256', 'report'):
        if initial.get(key) != reopened.get(key):
            raise ValueError('Persisted synthetic state changed after restart: '+key)
    return {'ok': True, 'initial_pid': initial['process_id'], 'reopened_pid': reopened['process_id'],
            'new_process': True, 'case_id': reopened['case_id'], 'report_id': reopened['report']['id'],
            'approval_persisted': reopened.get('approval_persisted') is True,
            'export_verified': reopened.get('export_verification', {}).get('ok') is True,
            'steps': reopened.get('steps', [])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path.home()/'Documents/LAWLIET/cases')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--smoke-test', type=Path, help='Run synthetic native-window checks and write their JSON result; requires an empty workspace')
    parser.add_argument('--smoke-reopen', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--renderer', choices=('gtk','qt','cocoa','edgechromium'), help='Select an installed native web renderer')
    parser.add_argument('--hidden', action='store_true', help='Start hidden (used for CI desktop smoke tests)')
    args = parser.parse_args(argv)
    if args.worker:
        from .desktop_bridge import worker_main
        return worker_main()
    if args.smoke_reopen and not args.smoke_test:
        parser.error('--smoke-reopen is only available with an explicit synthetic smoke test')
    try:
        import webview
    except ImportError:
        parser.error('Desktop dependencies are missing. Install lawliet-mobile[desktop]; Linux also requires GTK/WebKit or the desktop-qt extra.')
    from .desktop_bridge import DesktopBridge
    workspace = args.workspace.expanduser().resolve()
    if args.smoke_test and not args.smoke_reopen and workspace.exists() and any(workspace.iterdir()):
        parser.error('Desktop smoke tests require an empty, dedicated workspace.')
    if args.smoke_test and args.smoke_test.exists():
        parser.error('Choose a new smoke receipt path; existing test results are never overwritten.')
    workspace.mkdir(parents=True, exist_ok=True)
    fixture = None
    if args.smoke_reopen:
        if args.smoke_reopen.stat().st_size > 1024*1024:
            parser.error('Synthetic restart checkpoint exceeds its limit.')
        checkpoint = json.loads(args.smoke_reopen.read_text(encoding='utf-8'))
        if checkpoint.get('schema_version') != 2 or checkpoint.get('workspace') != str(workspace) or checkpoint.get('fixture', {}).get('synthetic') is not True:
            parser.error('Invalid synthetic restart checkpoint.')
        fixture = {**checkpoint['fixture'], 'phase': 'reopen', 'previous': checkpoint['outcome']}
        originals = checkpoint['originals']
    elif args.smoke_test:
        from .desktop_smoke import build_fixture
        fixture_root = args.smoke_test.resolve().parent/(args.smoke_test.stem+'-fixture')
        fixture_root.mkdir(parents=True, exist_ok=False)
        fixture = build_fixture(fixture_root)
        fixture.update(phase='initial', export_path=str(fixture_root/'synthetic-report-export'),
                       nonexistent_path=str(fixture_root/'deliberately-missing-input.sqlite'))
        originals = _source_hashes(fixture)
    outcome, completed = {}, threading.Event()
    def record(result):
        if isinstance(result, dict): outcome.update(result)
        else: outcome.update(ok=False, error='Invalid native-window smoke result')
        completed.set()
    bridge = DesktopBridge(workspace, smoke_fixture=fixture,
                           smoke_result=record if fixture else None)
    if fixture:
        # Exact paths supplied by this synthetic run replace only the native
        # picker, never the approval/export handlers or backend path checks.
        for key in ('export_path', 'nonexistent_path', 'missing_path'):
            if fixture.get(key): bridge._grants.add(str(Path(fixture[key]).resolve()))
    # Deliberately in-memory HTML: no local static-file server exposes case data.
    webview.settings['ALLOW_DOWNLOADS'] = False
    webview.settings['ALLOW_FILE_URLS'] = False
    window = webview.create_window('LAWLIET', html=shell_html(), js_api=bridge, width=1360, height=900,
                                  min_size=(960,640), hidden=args.hidden, text_select=True,
                                  background_color='#191B20')
    bridge._attach(window)
    window.events.closed += bridge._close
    def smoke():
        if not window.events.loaded.wait(timeout=45):
            record({'ok': False, 'error': 'Native web renderer did not load the application'})
        else:
            # run_js avoids eval; the packaged script and bridge remain CSP-bound.
            window.run_js("(function start(){if(window.pywebview && window.lawlietSmoke){window.lawlietSmoke();}else{setTimeout(start,100);}})();")
            if not completed.wait(180):
                record({'ok': False, 'error': 'Native-window smoke test timed out'})
        outcome.update(schema_version=2, process_id=os.getpid(), corpus_sha256=fixture['corpus_sha256'],
                       oracle_sha256=fixture['oracle_sha256'], fixture_path=fixture['path'],
                       oracle=fixture['oracle'], raw_validation=fixture['raw_validation'])
        try:
            outcome['originals_unchanged'] = _source_hashes(fixture) == originals
            if not outcome['originals_unchanged']:
                raise ValueError('Original synthetic evidence changed during examination')
            if outcome.get('ok'):
                from .desktop_smoke import compare_records
                compared = compare_records(outcome['actual_records'], fixture['oracle'])
                outcome.update(compared)
                if not compared['passed']:
                    raise ValueError('Native-window records differ from the independent frozen oracle')
                if outcome.get('phase') == 'initial':
                    missing = compare_records(outcome['missing_actual_records'], fixture['missing_oracle'])
                    outcome['missing_comparison'] = missing
                    if not missing['passed']:
                        raise ValueError('Missing-WAL results differ from the independently specified partial corpus')
                _check_selected_snapshot(fixture, outcome['selected_finding_snapshot'])
                outcome['source_inspection_verification'] = _check_source_inspection(fixture, outcome['source_inspection'])
                outcome['export_verification'] = _check_export(fixture, outcome)
        except Exception as error:
            outcome.update(ok=False, error=str(error))
        args.smoke_test.parent.mkdir(parents=True, exist_ok=True)
        args.smoke_test.write_text(json.dumps(outcome, indent=2)+'\n', encoding='utf-8')
        window.destroy()
    renderer = args.renderer or ('edgechromium' if sys.platform=='win32' else 'cocoa' if sys.platform=='darwin' else None)
    try:
        webview.start(smoke if args.smoke_test else None, gui=renderer, debug=False,
                      http_server=False, private_mode=True)
    finally:
        bridge._close()
    if args.smoke_test and not args.smoke_reopen and outcome.get('ok'):
        checkpoint_path = fixture_root/'restart-checkpoint.json'
        checkpoint_path.write_text(json.dumps({'schema_version': 2, 'workspace': str(workspace),
            'fixture': fixture, 'originals': originals, 'outcome': outcome}, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        reopened_path = args.smoke_test.with_name(args.smoke_test.stem+'-reopened.json').resolve()
        command = [sys.executable, '-m', 'lawliet_mobile.desktop', '--workspace', str(workspace),
                   '--smoke-test', str(reopened_path), '--smoke-reopen', str(checkpoint_path)]
        if renderer: command.extend(['--renderer', renderer])
        if args.hidden: command.append('--hidden')
        try:
            with args.smoke_test.with_suffix('.restart.log').open('w', encoding='utf-8') as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=210,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            if result.returncode:
                raise ValueError('Restarted synthetic native window failed; inspect its retained receipt/log')
            reopened = json.loads(reopened_path.read_text(encoding='utf-8'))
            outcome['restart'] = _combine_restart(outcome, reopened)
            if not outcome['restart']['approval_persisted'] or not outcome['restart']['export_verified']:
                raise ValueError('Persisted synthetic approval/export did not survive process restart')
        except Exception as error:
            outcome.update(ok=False, error=str(error), restart={'ok': False})
        args.smoke_test.write_text(json.dumps(outcome, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return 0 if not args.smoke_test or outcome.get('ok') is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
