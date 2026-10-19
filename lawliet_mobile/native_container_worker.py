"""Private native scratch worker. Controller owns isolation, time and publication.

Standalone entry point uses only fixed container paths. This module is a
validation candidate; its local CaseDB and ownership never confer host authority.
"""
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import time

PROTOCOL = 'lawliet-native-artifacts/1'
MAX_FILES = 1000
MAX_MANIFEST = 2 * 1024**2
MAX_INPUT = 32 * 1024**2
MAX_ARTIFACTS = 16 * 1024**2
MAX_LINE = 8 * 1024**2
MAX_DETAIL = 1024**2
MAX_TRANSPORT = 18 * 1024**2
MAX_ROWS = 100000
MAX_DEPTH = 64
MAX_WALL = 90
HASH = re.compile(r'[0-9a-f]{64}\Z')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(',', ':')).encode('utf-8')


def read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError('file bound/type')
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        named = os.stat(path, follow_symlinks=False)
        if len(raw) != before.st_size or identity(before) != identity(after) or identity(after) != identity(named):
            raise ValueError('file changed')
        return bytes(raw)
    finally:
        os.close(fd)


def strict(raw):
    # Bound structural depth before the recursive decoder, ignoring string text.
    text = raw.decode('utf-8')
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError('JSON depth')
        elif char in ']}':
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def number(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError('nonfinite JSON')
        return parsed
    def constant(value):
        raise ValueError('nonfinite JSON')
    return json.loads(text, object_pairs_hook=pairs, parse_float=number, parse_constant=constant)


def safe_path(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 4096 or '\\' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('unsafe physical path')
    path = PurePosixPath(value)
    if not path.parts or path.is_absolute() or '..' in path.parts or ':' in path.parts[0] or path.as_posix() != value or value == '.':
        raise ValueError('unsafe physical path')
    return value


def validate_request(request):
    if not isinstance(request, dict) or set(request) != {'protocol', 'bootstrap_sha256', 'package_sha256', 'evidence', 'inputs'} or request['protocol'] != PROTOCOL:
        raise ValueError('request schema')
    if not isinstance(request['bootstrap_sha256'], str) or not HASH.fullmatch(request['bootstrap_sha256']):
        raise ValueError('bootstrap hash')
    package = request['package_sha256']
    if not isinstance(package, dict) or not package or any(not isinstance(n, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.py', n) or not isinstance(h, str) or not HASH.fullmatch(h) for n, h in package.items()):
        raise ValueError('package schema')
    evidence = request['evidence']
    if not isinstance(evidence, dict) or set(evidence) != {'id', 'platform', 'label', 'input_name', 'encrypted'}:
        raise ValueError('evidence schema')
    if not isinstance(evidence['id'], str) or not re.fullmatch(r'[0-9a-f]{12}', evidence['id']) or evidence['platform'] not in ('ios', 'android', 'unknown') or evidence['encrypted'] is not False:
        raise ValueError('evidence identity')
    for key in ('label', 'input_name'):
        if not isinstance(evidence[key], str) or len(evidence[key].encode('utf-8')) > 4096 or '\x00' in evidence[key]:
            raise ValueError('evidence text')
    inputs = request['inputs']
    if not isinstance(inputs, list) or len(inputs) > MAX_FILES:
        raise ValueError('inventory count')
    ids, paths, total = set(), set(), 0
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {'id', 'path', 'logical_path', 'sha256', 'bytes'}:
            raise ValueError('input schema')
        if type(item['id']) is not int or not 0 < item['id'] <= 2**63 - 1 or item['id'] in ids or type(item['bytes']) is not int or item['bytes'] < 0 or not isinstance(item['sha256'], str) or not HASH.fullmatch(item['sha256']):
            raise ValueError('input identity')
        safe_path(item['path'])
        if item['path'] in paths or not isinstance(item['logical_path'], str) or not item['logical_path'] or len(item['logical_path'].encode('utf-8')) > 4096 or '\x00' in item['logical_path']:
            raise ValueError('input path')
        ids.add(item['id']); paths.add(item['path']); total += item['bytes']
    if total > MAX_INPUT or any(parent.as_posix() in paths for name in paths for parent in PurePosixPath(name).parents if parent.as_posix() != '.'):
        raise ValueError('input byte/path bound')
    return ids, paths, total


def package_hashes(package):
    result = {}
    for path in package.iterdir():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.py', path.name):
            raise ValueError('unexpected package entry')
        result[path.name] = sha(read(path, 2 * 1024**2))
    return result


def validate_mount(scratch, source):
    """Static checks only; actual RO mount inspection belongs to controller."""
    if os.getuid() != 65534 or os.geteuid() != 65534:
        raise ValueError('worker uid')
    for path, owner, mode in ((scratch, 0, 0o1777), (scratch / 'evidence', 0, 0o755)):
        value = path.lstat()
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != owner or stat.S_IMODE(value.st_mode) != mode:
            raise ValueError('mount ownership/type/mode')
    value = source.lstat()
    if not stat.S_ISDIR(value.st_mode):
        raise ValueError('evidence mount type')


def verify_inputs(source, inputs, paths):
    found = set()
    for current, dirs, files in os.walk(source, followlinks=False):
        for name in dirs + files:
            path = Path(current) / name
            value = path.lstat()
            if stat.S_ISDIR(value.st_mode):
                continue
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
                raise ValueError('unsafe inventory entry')
            found.add(path.relative_to(source).as_posix())
    if found != paths:
        raise ValueError('inventory mismatch')
    for item in inputs:
        raw = read(source / item['path'], MAX_INPUT)
        if len(raw) != item['bytes'] or sha(raw) != item['sha256']:
            raise ValueError('input hash')


def frame(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('utf-8') + b'\n'


def execute(output, *, request_path=Path('/control/request.json'), code_root=Path('/code'), scratch=Path('/scratch')):
    started = time.monotonic()
    def deadline():
        if time.monotonic() - started > MAX_WALL:
            raise ValueError('worker elapsed limit')
    request_raw = read(request_path, MAX_MANIFEST)
    request = strict(request_raw)
    ids, paths, total = validate_request(request)
    if sha(read(__file__, 1024**2)) != request['bootstrap_sha256']:
        raise ValueError('bootstrap hash mismatch')
    package = code_root / 'lawliet_mobile'
    actual = package_hashes(package)
    if actual != request['package_sha256']:
        raise ValueError('package hash mismatch')
    evidence = request['evidence']; eid = evidence['id']
    source = scratch / 'evidence' / eid
    validate_mount(scratch, source)
    verify_inputs(source, request['inputs'], paths)
    deadline()
    os.environ['TMPDIR'] = str(scratch)
    os.environ['SQLITE_TMPDIR'] = str(scratch)
    tempfile.tempdir = str(scratch)
    sys.path.insert(0, str(code_root))
    from lawliet_mobile.core import create_case, connect, audit, now, verify, json_text
    from lawliet_mobile.parsers import native_analyze, VERSION
    seed = create_case(scratch / 'bootstrap', 'scratch')
    # Fresh container scratch must never overwrite an existing database.
    target = scratch / 'case.sqlite'
    if target.exists() or target.is_symlink():
        raise ValueError('scratch database already exists')
    os.rename(seed / 'case.sqlite', target)
    with connect(scratch.parent, scratch.name) as (root, db):
        db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)', (eid, evidence['label'], evidence['platform'], evidence['input_name'], now(), None, int(evidence['encrypted'])))
        for item in request['inputs']:
            db.execute('INSERT INTO files(id,evidence_id,path,logical_path,sha256,size) VALUES(?,?,?,?,?,?)', (item['id'], eid, item['path'], item['logical_path'], item['sha256'], item['bytes']))
        audit(db, 'evidence.imported', {'evidence_id': eid, 'files': len(ids), 'bytes': total, 'scope': 'Private scratch-only copy of supplied verified inventory.'})
        db.commit()
        result = native_analyze(root, db, eid)
        if result['status'] not in ('complete', 'partial') or not verify(root, db)['ok']:
            raise ValueError('native terminal state')
        detail = json_text(result)
        if len(detail.encode('utf-8')) > MAX_DETAIL:
            raise ValueError('native detail bound')
        deadline()
        # Spool bounded artifact frames before emitting a complete transport.
        with tempfile.TemporaryFile(dir=scratch) as spool:
            digest = hashlib.sha256(); count = size = 0
            for row in db.execute('SELECT a.* FROM artifacts a JOIN artifact_runs ar ON ar.artifact_id=a.id WHERE ar.run_id=? ORDER BY a.rowid', (result['run_id'],)):
                if row['evidence_id'] != eid or type(row['file_id']) is not int or row['file_id'] not in ids or row['parser'] != VERSION:
                    raise ValueError('artifact source')
                count += 1
                value = {key: row[key] for key in ('evidence_id', 'file_id', 'category', 'timestamp', 'timestamp_raw', 'title', 'body', 'source_ref', 'parser')}
                line = frame({'kind': 'artifact', 'seq': count, **value, 'data_json': row['data']})
                if len(line) > MAX_LINE or count > MAX_ROWS or size + len(line) > MAX_ARTIFACTS:
                    raise ValueError('artifact output bound')
                size += len(line); digest.update(line); spool.write(line)
                deadline()
            if type(result['new_records']) is not int or result['new_records'] != count:
                raise ValueError('native counter')
            verify_inputs(source, request['inputs'], paths)
            if actual != package_hashes(package):
                raise ValueError('package changed')
            deadline()
            bindings = {'protocol': PROTOCOL, 'request_sha256': sha(request_raw), 'source_manifest_sha256': sha(canonical(request['inputs']))}
            header = frame({'kind': 'header', **bindings, 'evidence_id': eid, 'native_parser_version': VERSION, 'package_manifest_sha256': sha(canonical(actual)), 'bootstrap_sha256': request['bootstrap_sha256']})
            footer = frame({'kind': 'final', **bindings, 'artifact_count': count, 'artifact_bytes': size, 'artifacts_sha256': digest.hexdigest(), 'native_status': result['status'], 'native_detail_json': detail, 'runtime': {'python_version': sys.version.split()[0], 'sqlite_version': sqlite3.sqlite_version}})
            if len(header) > 8192 or len(header) + size + len(footer) > MAX_TRANSPORT:
                raise ValueError('transport bound')
            output.write(header)
            spool.seek(0)
            shutil.copyfileobj(spool, output, 65536)
            output.write(footer)


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError('worker arguments refused')
        execute(sys.stdout.buffer)
        return 0
    except Exception as exc:
        # No untrusted source text/path is echoed into diagnostics.
        sys.stderr.write('native worker refused: ' + type(exc).__name__ + '\n')
        return 125


if __name__ == '__main__':
    raise SystemExit(main())
