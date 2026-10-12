#!/usr/bin/env python3
"""Read local recovery receipts; progress is scoped, never release approval."""
import argparse
import json
import re
from pathlib import Path


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def latest_native_replay(validation, platform):
    """Select explicit versioned receipts by tested version, never file mtime."""
    candidates = []
    acquisition = validation / 'acquisition'
    for folder in acquisition.glob('native[0-9]*-replay-results'):
        if not re.fullmatch(r'native[0-9]+-replay-results', folder.name):
            continue
        for filename in (platform + '.json', platform + '-clean-replay.json'):
            path = folder / filename
            value = read_json(path)
            versions = value.get('current_parser_versions', []) if isinstance(value, dict) else []
            parsed = [tuple(map(int, match.groups())) for version in versions
                      if isinstance(version, str) and (match := re.fullmatch(r'native/(\d+)\.(\d+)\.(\d+)', version))]
            if parsed:
                candidates.append((max(parsed), filename.endswith('-clean-replay.json'), str(path), value))
    if candidates:
        _, _, path, value = max(candidates, key=lambda item: item[:3])
        return Path(path), value
    path = acquisition / 'native-replay-results' / (platform + '.json')
    return path, read_json(path)


def bar(label, done, total):
    fraction = min(1, max(0, done / total)) if total else 0
    cells = int(fraction * 20)
    print(f'{label:29} [{"#" * cells}{"-" * (20-cells)}] {fraction:.1%} ({done:,}/{total:,})')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--projects', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    validation = args.projects / 'lawliet-validation'
    workspace = args.projects / 'lawliet-mobile'
    cases = args.projects / 'lawliet-cases'
    project = read_json(validation / 'linear-handoff-20261011/project-issues-current.json')
    if project:
        bar('Linear descriptions captured', len({r['id'] for r in project['issues']}), project['project_count'])
    mapping = read_json(validation / 'dfir58/mob-reconciliation.json')
    if mapping:
        bar('Requirements mapped (not done)', len(mapping['rows']), mapping['total'])
        print('  Dispositions:', json.dumps(mapping['counts'], sort_keys=True))
    log = validation / 'acquisition/android13-stream.log'
    downloaded = 0
    receipt = read_json(validation / 'acquisition/hickman-android13-selected/receipt.json')
    try:
        with log.open('rb') as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - 65536))
            for line in handle.read().splitlines():
                try:
                    downloaded = max(downloaded, json.loads(line).get('source_bytes_read', 0))
                except (ValueError, AttributeError, TypeError):
                    continue
        if receipt.get('publisher_hash_match') is True and receipt.get('status') == 'verified_selected_subset':
            downloaded = receipt.get('expected_bytes', downloaded)
        bar('Android13 download bytes', downloaded, 19829896719)
    except OSError:
        print('Android13 download: log unavailable')
    for label, filename in [('Android13 validation', 'android13-pipeline-status.json'),
                            ('MVS2026 Android queue', 'mvs2026-android-queue-status.json'),
                            ('MVS Android validation queue', 'mvs-android-validation-queue-status.json'),
                            ('MVS2026 iOS queue', 'mvs2026-ios-queue-status.json'),
                            ('Android14 queue', 'android14-queue-status.json'),
                            ('iOS17 backup queue', 'ios17-backup-queue-status.json')]:
        status = read_json(validation / 'acquisition' / filename)
        print(f'{label}: {status.get("status", "unknown")}')
    try:
        with (validation / 'acquisition/mvs2026-android-stream.log').open('rb') as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - 65536))
            progress = {}
            for line in handle.read().splitlines():
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict) and entry.get('inner_zip_expected_bytes'):
                        progress = entry
                except (ValueError, TypeError):
                    continue
            if progress:
                bar('MVS inner archive streamed', progress.get('inner_zip_bytes_read', 0), progress['inner_zip_expected_bytes'])
                print('  Expanded inner-archive bytes; selected files stay quarantined until full verification.')
    except OSError:
        pass
    ios = read_json(cases / 'DFIR47-HICKMAN-IOS13-LOCAL/05-review/ileapp-summary.json')
    if ios:
        total = ios.get('retained_report_rows', 0)
        bar('iOS13 report rows reconciled', total if ios.get('passed') else 0, total)
        print('  Report field fidelity only; full iOS track and independent review remain pending.')
    handoff = read_json(workspace / 'docs/session-handoff.json')
    backend = handoff.get('sessions', {}).get('other_active_session', {})
    checks = backend.get('verification', {})
    try:
        match = re.search(r'^VERSION\s*=\s*[\'"]([^\'"]+)', (workspace / 'lawliet_mobile/parsers.py').read_text(), re.M)
        current_parser = match.group(1) if match else 'unknown'
    except OSError:
        current_parser = 'unknown'
    print('Current native parser:', current_parser)
    progress = read_json(workspace / 'docs/task-progress.json')
    suite = progress.get('backend_suite') or checks.get('latest_backend_suite', {})
    if suite:
        print(f'Last combined backend suite: {suite.get("passed", "unknown")} passed; '
              f'{suite.get("skipped", "unknown")} skipped (checkpoint, not a live test run).')
    exports = progress.get('post_export_checkpoint')
    if exports:
        print('Post-export checks:', exports.get('actual_mcp_checks'), 'MCP;',
              exports.get('actual_stdio_checks'), 'stdio (scoped receipts, not formal acceptance).')
    failure_matrix = progress.get('failure_matrix_checkpoint')
    if failure_matrix:
        print('Failure matrix:', failure_matrix.get('status'))
    for platform in ('android', 'ios'):
        replay_path, replay = latest_native_replay(validation, platform)
        if replay:
            matched = replay.get('semantic_replay_equal') is True
            unchanged = replay.get('source_unchanged') is True and replay.get('frozen_key_unchanged') is True
            print(f'{platform.title()} native replay: '
                  f'{"matched; sources and reference key unchanged" if matched and unchanged else "review required"}; '
                  f'tested versions {replay.get("current_parser_versions", [])}')
            print('  Receipt:', replay_path)
            if current_parser not in replay.get('current_parser_versions', []):
                print('  Version mismatch: changed parser requires fresh validation; this replay is historical evidence.')
            else:
                print('  Version label matches; this alone does not establish matching source pins or independent acceptance.')
    pending = progress.get('current_parser_validation') or progress.get('pending_current_parser_validation')
    if pending:
        print('Current parser validation:', pending.get('status', 'pending'))
    health = read_json(validation / 'acquisition/acquisition-health.json')
    if health:
        print('Acquisition health:', health.get('updated_at', 'unknown'),
              'needs_attention=', health.get('needs_attention', 'unknown'))
        for name, entry in health.get('queues', {}).items():
            print('  ', name + ':', entry.get('status', 'unknown'))
        print('  Heartbeat status is not accepted evidence or indefinite process liveness.')
    else:
        queue = progress.get('acquisition_queue_checkpoint')
        if queue:
            print('Acquisition checkpoint:', queue.get('status', 'unknown'))
            print('  MVS:', queue.get('mvs_android', 'unknown'))
    print('Backend work:', backend.get('current_task', 'unknown'))
    ui = handoff.get('sessions', {}).get('ui', {})
    print('UI session:', ui.get('current_task', ui.get('status', 'unknown')))
    print('UI checkpoint:', ui.get('updated_at', 'unknown'))
    print('Recovery NOT complete: local reconstruction is not recovery of the damaged drive.')
    print('No overall percentage or release approval inferred from downloads or test counts.')


if __name__ == '__main__':
    main()
