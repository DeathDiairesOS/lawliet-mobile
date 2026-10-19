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
import sys
import tempfile
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path.home()/'Documents/LAWLIET/cases')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--smoke-test', type=Path, help='Run synthetic native-window checks and write their JSON result; requires an empty workspace')
    parser.add_argument('--renderer', choices=('gtk','qt','cocoa','edgechromium'), help='Select an installed native web renderer')
    parser.add_argument('--hidden', action='store_true', help='Start hidden (used for CI desktop smoke tests)')
    args = parser.parse_args(argv)
    if args.worker:
        from .desktop_bridge import worker_main
        return worker_main()
    try:
        import webview
    except ImportError:
        parser.error('Desktop dependencies are missing. Install lawliet-mobile[desktop]; Linux also requires GTK/WebKit or the desktop-qt extra.')
    from .desktop_bridge import DesktopBridge
    workspace = args.workspace.expanduser().resolve()
    if args.smoke_test and workspace.exists() and any(workspace.iterdir()):
        parser.error('Desktop smoke tests require an empty, dedicated workspace.')
    workspace.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix='lawliet-desktop-smoke-') if args.smoke_test else None
    outcome, completed = {}, threading.Event()
    def record(result):
        if isinstance(result, dict): outcome.update(result)
        else: outcome.update(ok=False, error='Invalid native-window smoke result')
        completed.set()
    bridge = DesktopBridge(workspace, smoke_fixture=synthetic_fixture(temporary.name) if temporary else None,
                           smoke_result=record if temporary else None)
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
            if not completed.wait(120):
                record({'ok': False, 'error': 'Native-window smoke test timed out'})
        args.smoke_test.parent.mkdir(parents=True, exist_ok=True)
        args.smoke_test.write_text(json.dumps(outcome, indent=2)+'\n', encoding='utf-8')
        window.destroy()
    renderer = args.renderer or ('edgechromium' if sys.platform=='win32' else 'cocoa' if sys.platform=='darwin' else None)
    try:
        webview.start(smoke if args.smoke_test else None, gui=renderer, debug=False,
                      http_server=False, private_mode=True)
    finally:
        bridge._close()
        if temporary: temporary.cleanup()
    return 0 if not args.smoke_test or outcome.get('ok') is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
