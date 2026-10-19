"""Bounded, read-only native catalog queries; no forensic processing or migrations."""
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from contextlib import closing

SKIP = {'evidence', 'derived', 'working', 'work', 'customer-drafts', 'customer-redacted-drafts', 'reports',
        'node_modules', '__pycache__', '.git', '.venv', 'venv', 'originals', 'staging',
        'retained-tools', 'data', 'inputs', 'extractions'}
CASE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')


def roots_for(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise ValueError('Select between one and 32 case folders.')
    roots = []
    for value in values:
        if not isinstance(value, str) or not value or '\0' in value:
            raise ValueError('Invalid case folder.')
        # Do not probe a known failed drive, even through a stale preference.
        if value == '/Volumes/easystore' or value.startswith('/Volumes/easystore/'):
            raise ValueError('The former easystore location is unavailable. Select a local folder.')
        requested = Path(value).expanduser()
        if not requested.is_absolute():
            raise ValueError('Case folders must be absolute paths.')
        path = requested.resolve()
        if str(path) == '/Volumes/easystore' or str(path).startswith('/Volumes/easystore/'):
            raise ValueError('The former easystore location is unavailable. Select a local folder.')
        if any(path == r or r in path.parents for r in roots):
            continue
        roots = [r for r in roots if path not in r.parents]
        roots.append(path)
    return roots


def case_metadata(folder, root):
    path = folder / 'case.sqlite'
    result = {'id': folder.name, 'path': str(folder), 'workspace': str(folder.parent),
              'location': str(folder.relative_to(root)) if folder != root else folder.name,
              'root': str(root), 'name': folder.name, 'available': False, 'error': ''}
    try:
        if not CASE_ID.fullmatch(folder.name) or path.is_symlink():
            raise ValueError('Unsupported case identifier or symlinked database.')
        wal = path.with_name('case.sqlite-wal')
        if wal.exists() and wal.stat().st_size:
            raise ValueError('Pending SQLite WAL: metadata not read. Refresh after the writer checkpoints this case.')
        before = path.stat()
        # Immutable mode prevents SQLite creating journal/SHM files in a case.
        # Nonempty WALs are explicitly refused rather than silently ignored.
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True, timeout=0.2)) as db:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA query_only=ON')
            deadline = time.monotonic() + 0.5
            db.set_progress_handler(lambda: time.monotonic() > deadline, 1000)
            meta = dict(db.execute("SELECT key,substr(value,1,65537) FROM meta WHERE key IN ('case_id','name','created_at','examiner','schema_version','case_management') LIMIT 7"))
            if meta.get('case_id') != folder.name or not meta.get('created_at') or meta.get('schema_version') != '1':
                raise ValueError('Not a supported Lawliet case metadata schema.')
            if any(not isinstance(v, str) or len(v) > 65536 for v in meta.values()):
                raise ValueError('Unsupported case metadata size or type.')
            profile = json.loads(meta.get('case_management', '{}'))
            if not isinstance(profile, dict):
                raise ValueError('Invalid case profile.')
            tables = set(r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='case_tasks'"))
            tasks = db.execute('SELECT COUNT(*) FROM case_tasks WHERE completed=0').fetchone()[0] if tables else 0
            result.update({k: profile.get(k, default) for k, default in
                           [('status', 'Untriaged'), ('priority', 'Normal'), ('client', ''),
                            ('owner', meta.get('examiner', '')), ('due_date', '')]})
            if any(not isinstance(result[k], str) for k in ['status', 'priority', 'client', 'owner', 'due_date']):
                raise ValueError('Invalid case summary fields.')
            result.update(name=meta.get('name', folder.name), created=meta['created_at'], open_tasks=tasks)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or (wal.exists() and wal.stat().st_size):
            raise ValueError('Case changed during metadata read. Refresh for a new snapshot.')
        result['available'] = True
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        result['error'] = str(exc)
    return result


def catalog(values, max_dirs=5000, max_cases=2000, max_depth=12, seconds=20):
    roots = roots_for(values)
    found, warnings, visited = {}, [], set()
    deadline = time.monotonic() + seconds
    partial = False
    for root in roots:
        stack = [(root, 0)]
        while stack:
            folder, depth = stack.pop()
            if folder in visited:
                continue
            if len(visited) >= max_dirs or len(found) >= max_cases or time.monotonic() >= deadline:
                partial = True
                warnings.append('Discovery limit reached. Add a narrower case folder to inspect omitted locations.')
                stack.clear()
                break
            visited.add(folder)
            try:
                if folder.is_symlink():
                    continue
                entries = []
                with os.scandir(folder) as stream:
                    for entry in stream:
                        if len(entries) >= 10000:
                            partial = True
                            warnings.append(f'Directory entry limit at {folder}; omitted entries may contain cases.')
                            break
                        entries.append(entry)
                entries.sort(key=lambda e: e.name)
                names = {e.name for e in entries}
                if 'case.sqlite' in names:
                    item = case_metadata(folder, root)
                    found[item['path']] = item
                    continue  # Never descend into a case's evidence or outputs.
                children = [e for e in entries if not e.name.startswith('.') and e.name not in SKIP
                            and e.is_dir(follow_symlinks=False)]
                if depth >= max_depth:
                    if children:
                        partial = True
                        warnings.append(f'Depth limit at {folder}. Add that case folder explicitly.')
                    continue
                stack.extend((Path(e.path), depth + 1) for e in reversed(children))
            except OSError as exc:
                partial = True
                warnings.append(f'{folder}: {exc}')
        if partial and (len(visited) >= max_dirs or len(found) >= max_cases):
            break
    return {'schema_version': 1, 'cases': sorted(found.values(), key=lambda r: (r.get('created', ''), r['path']), reverse=True),
            'roots': [str(r) for r in roots], 'warnings': warnings[:100], 'partial': partial,
            'directories_checked': len(visited), 'metadata_only': True}


def history(case_path, offset=0):
    if type(offset) is not int or offset < 0:
        raise ValueError('Invalid report page.')
    case = roots_for([case_path])[0]
    if not (case / 'case.sqlite').is_file() or (case / 'case.sqlite').is_symlink():
        raise ValueError('Select an existing Lawliet case.')
    rows = []
    scanned = 0
    for dirname, kind, format_name, id_key in [
        ('customer-drafts', 'original', 'ancalor-customer-bundle-v1', 'draft_id'),
        ('customer-redacted-drafts', 'redacted', 'ancalor-customer-redacted-bundle-v1', 'derivative_id')]:
        folder = case / dirname
        if folder.is_symlink():
            raise ValueError('Symlinked report directories are not supported.')
        if not folder.exists():
            continue
        with os.scandir(folder) as entries:
            for entry in entries:
                scanned += 1
                if scanned > 2000:
                    raise ValueError('More than 2,000 report folders. Narrow the case report archive before listing.')
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    continue
                manifest = Path(entry.path) / 'manifest.json'
                item = {'id': entry.name, 'path': entry.path, 'kind': kind, 'available': False, 'error': '', 'entries': 0, 'sources': 0}
                try:
                    if manifest.is_symlink() or manifest.stat().st_size > 512 * 1024:
                        raise ValueError('Unsafe or oversized manifest.')
                    with manifest.open('rb') as stream:
                        value = json.loads(stream.read(512 * 1024 + 1))
                    if not isinstance(value, dict) or value.get('format') != format_name or value.get(id_key) != entry.name:
                        raise ValueError('Unsupported draft manifest.')
                    counts = value.get('counts', {})
                    for key in ['entries', 'unique_cited_artifacts']:
                        if type(counts.get(key)) is not int or not 0 <= counts[key] <= 10000:
                            raise ValueError('Invalid draft counts.')
                    item.update(available=True, entries=counts['entries'], sources=counts['unique_cited_artifacts'],
                                investigation_id=str(value.get('investigation_id', ''))[:160],
                                review_status='Open to verify approval', modified=manifest.stat().st_mtime)
                except (OSError, ValueError, TypeError, AttributeError) as exc:
                    item['error'] = str(exc)
                rows.append(item)
    rows.sort(key=lambda r: (r.get('modified', 0), r['id']), reverse=True)
    return {'schema_version': 1, 'case_path': str(case), 'items': rows[offset:offset + 50],
            'total': len(rows), 'offset': offset, 'has_more': offset + 50 < len(rows)}


def handle(request):
    if request.get('action') == 'catalog':
        return catalog(request.get('roots'))
    if request.get('action') == 'report-history':
        if not isinstance(request.get('case'), str) or not CASE_ID.fullmatch(request['case']):
            raise ValueError('Invalid case identifier.')
        return history(str(Path(request['workspace']) / request['case']), request.get('offset', 0))
    raise ValueError('Unsupported catalog action.')


def main():
    try:
        payload = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise ValueError('Catalog request too large.')
        print(json.dumps({'ok': True, 'result': handle(json.loads(payload))}))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        sys.exit(1)


if __name__ == '__main__':
    main()
