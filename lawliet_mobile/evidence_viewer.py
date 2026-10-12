"""Exact source byte windows with explicitly derived, bounded structured views."""
import base64
from collections import Counter
import hashlib
import json
import math
import plistlib
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from xml.parsers import expat

VERSION = 'evidence-viewer/1'
MAX_SOURCE = 512 * 1024**2
MAX_WINDOW = 65536
MAX_STRUCTURED = 1024**2
MAX_OUTPUT = 4 * 1024**2
MAX_NODES = 10000
MAX_DEPTH = 64


class LimitError(ValueError):
    pass


class Pairs(list):
    pass


class Number(str):
    pass


class UniqueDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise ValueError('Duplicate plist dictionary key; raw bytes retained, structured interpretation refused.')
        super().__setitem__(key, value)


def _xml(raw, plist_doctype=False):
    version = tuple(int(x) for x in re.findall(r'\d+', expat.EXPAT_VERSION)[:3])
    if version < (2, 7, 2):
        raise ValueError('XML structured parsing requires Expat >= 2.7.2.')
    parser = expat.ParserCreate()
    parser.ordered_attributes = True
    stack = []
    root = None
    count = 0
    text_bytes = 0
    def forbidden(*args):
        raise ValueError('XML DTD/entities/external resolution are unsupported and refused.')
    def start(name, attrs):
        nonlocal root, count
        count += 1 + len(attrs) // 2
        if count > MAX_NODES or len(stack) >= MAX_DEPTH:
            raise LimitError('XML node/depth bound exceeded.')
        node = {'kind': 'element', 'name': name, 'attributes': [[attrs[i], attrs[i+1]] for i in range(0, len(attrs), 2)], 'children': []}
        if stack:
            stack[-1]['children'].append(node)
        else:
            root = node
        stack.append(node)
    def end(name):
        stack.pop()
    def text(value):
        nonlocal count, text_bytes
        if not value:
            return
        count += 1; text_bytes += len(value.encode('utf-8'))
        if count > MAX_NODES or text_bytes > MAX_OUTPUT:
            raise LimitError('XML text/node bound exceeded.')
        if stack:
            stack[-1]['children'].append({'kind': 'text', 'value': value})
    def comment(value):
        nonlocal count
        count += 1
        if count > MAX_NODES:
            raise LimitError('XML node bound exceeded.')
        if stack:
            stack[-1]['children'].append({'kind': 'comment', 'value': value})
    parser.StartElementHandler = start; parser.EndElementHandler = end
    parser.CharacterDataHandler = text; parser.CommentHandler = comment
    def doctype(name, system, public, has_internal_subset):
        if not (plist_doctype and name == 'plist' and not has_internal_subset and
                public == '-//Apple//DTD PLIST 1.0//EN' and system == 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'):
            forbidden()
        # Canonical plist declaration is inert metadata: no DTD is fetched.
    parser.StartDoctypeDeclHandler = doctype; parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden; parser.UnparsedEntityDeclHandler = forbidden
    parser.ProcessingInstructionHandler = forbidden
    parser.Parse(raw, True)
    return root


def _typed(value, count, depth=0):
    count[0] += 1
    if count[0] > MAX_NODES or depth > MAX_DEPTH:
        raise LimitError('Structured node/depth bound exceeded.')
    child = lambda item: _typed(item, count, depth + 1)
    if isinstance(value, Pairs):
        keys = [k for k, _ in value]
        return {'kind': 'object', 'pairs': [[k, child(v)] for k, v in value], 'duplicate_keys': sorted(k for k, n in Counter(keys).items() if n > 1)}
    if isinstance(value, Number):
        return {'kind': 'number', 'lexeme': str(value)}
    if isinstance(value, dict):
        return {'kind': 'dictionary', 'pairs': [[str(k), child(v)] for k, v in value.items()]}
    if isinstance(value, (list, tuple)):
        return {'kind': 'array', 'items': [child(v) for v in value]}
    if isinstance(value, bytes):
        return {'kind': 'data', 'base64': base64.b64encode(value).decode('ascii'), 'byte_count': len(value)}
    if isinstance(value, plistlib.UID):
        return {'kind': 'uid', 'value': value.data}
    if isinstance(value, datetime):
        return {'kind': 'plist-date', 'value': value.isoformat(), 'timezone_semantics': 'plist UTC date; not an inferred event timezone'}
    if type(value) is float and not math.isfinite(value):
        return {'kind': 'nonfinite-real', 'value': str(value)}
    return {'kind': 'null' if value is None else 'boolean' if type(value) is bool else 'integer' if type(value) is int else 'real' if type(value) is float else 'string', 'value': value}


def _structured(raw, mode):
    if len(raw) > MAX_STRUCTURED:
        raise LimitError('Whole-file structured input exceeds 1 MiB.')
    if mode == 'json':
        def invalid_constant(value):
            raise ValueError('Nonstandard JSON numeric constant: ' + value)
        value = json.loads(raw, object_pairs_hook=Pairs, parse_int=Number, parse_float=Number, parse_constant=invalid_constant)
        return _typed(value, [0])
    if mode == 'xml':
        return _xml(raw)
    if mode == 'plist':
        # plistlib rejects XML entity declarations; require current Expat for XML plist too.
        if not raw.startswith(b'bplist00'):
            if tuple(int(x) for x in re.findall(r'\d+', expat.EXPAT_VERSION)[:3]) < (2, 7, 2):
                raise ValueError('XML plist parsing requires Expat >= 2.7.2.')
            _xml(raw, plist_doctype=True)
        value = plistlib.loads(raw, dict_type=UniqueDict)
        return _typed(value, [0])
    raise ValueError('Unsupported structured format.')


def _worker(input_path, output_path, mode):
    sys.setrecursionlimit(500)
    result = {'state': 'unsupported-or-invalid', 'format': mode, 'parser': VERSION,
              'python_version': sys.version.split()[0], 'expat_version': expat.EXPAT_VERSION,
              'source_offsets': False, 'interpretation': 'Derived structure; only raw byte windows establish byte offsets.'}
    try:
        raw = Path(input_path).read_bytes()
        result['tree'] = _structured(raw, mode)
        result['state'] = 'parsed'
        encoded = json.dumps(result, ensure_ascii=True, allow_nan=False)
        if len(encoded.encode('utf-8')) > MAX_OUTPUT:
            raise LimitError('Structured output exceeds 4 MiB.')
    except (ValueError, TypeError, OverflowError, RecursionError, MemoryError, expat.ExpatError, plistlib.InvalidFileException) as exc:
        result.pop('tree', None)
        result.update(state='resource-limited' if isinstance(exc, (LimitError, RecursionError, MemoryError)) else 'unsupported-or-invalid', error=str(exc)[:2000])
    Path(output_path).write_text(json.dumps(result, ensure_ascii=True, allow_nan=False))


def _decode(raw, encoding, offset):
    errors = []; cursor = 0; total = 0
    while cursor < len(raw):
        try:
            raw[cursor:].decode(encoding, 'strict')
            break
        except UnicodeDecodeError as exc:
            start = cursor + exc.start; end = cursor + exc.end
            total += 1
            if len(errors) < 128:
                errors.append({'start_offset': offset + start, 'end_offset_exclusive': offset + end,
                               'hex': raw[start:end].hex(), 'reason': exc.reason})
            cursor = end
    return {'encoding': encoding, 'text': raw.decode(encoding, 'backslashreplace'), 'errors': errors,
            'error_count': total, 'errors_truncated': total > len(errors),
            'text_is_derived': True, 'byte_order_mark_removed': False,
            'boundary_note': 'A byte window may begin/end inside a codepoint. Escapes describe decoding failure, not source characters; hex is authoritative.'}


def inspect_file(root, db, file_id, offset=0, length=4096, encoding='utf-8', format_name=None):
    """Read case-local retained bytes; never opens an arbitrary caller path."""
    from .core import UserError, digest
    if type(file_id) is not int or file_id < 1 or type(offset) is not int or offset < 0 or type(length) is not int or not 1 <= length <= MAX_WINDOW:
        raise UserError('Positive file ID, nonnegative offset and length 1–65536 required.')
    if not isinstance(encoding, str) or encoding not in {'utf-8', 'utf-16-le', 'utf-16-be', 'latin-1'}:
        raise UserError('Select explicit utf-8, utf-16-le, utf-16-be or latin-1 encoding.')
    if format_name is not None and (not isinstance(format_name, str) or format_name not in {'json', 'xml', 'plist'}):
        raise UserError('Structured format must be json, xml or plist; unknown binary formats are unsupported.')
    row = db.execute('SELECT * FROM files WHERE id=?', (file_id,)).fetchone()
    if row is None:
        raise UserError('Unknown retained file in this case.')
    base = Path(root).absolute() / 'evidence' / row['evidence_id']; path = base / row['path']
    if (any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file() or
            not path.resolve().is_relative_to(base.resolve())):
        raise UserError('Unsafe retained source path.')
    if path.stat().st_size > MAX_SOURCE:
        raise UserError('Source exceeds the 512 MiB verified-view bound.')
    if path.stat().st_size != row['size'] or digest(path) != row['sha256']:
        raise UserError('Retained source integrity mismatch.')
    with path.open('rb') as stream:
        stream.seek(offset); raw = stream.read(length)
    result = {'viewer_version': VERSION, 'file_id': file_id, 'evidence_id': row['evidence_id'],
              'logical_path': row['logical_path'], 'source_sha256': row['sha256'], 'source_size': row['size'],
              'offset': offset, 'end_offset_exclusive': offset + len(raw), 'bytes_returned': len(raw),
              'hex': raw.hex(), 'window_sha256': hashlib.sha256(raw).hexdigest(),
              'has_more': offset + len(raw) < row['size'], 'text': _decode(raw, encoding, offset),
              'structured': None, 'limitations': ['Read-only supplied file inspection; no semantic artifact/finding/deletion determination.',
               'Structured trees do not map their nodes to exact source byte offsets.',
               'Input/window/structure caps and worker timeout are enforced; no general filesystem or memory sandbox is claimed.']}
    if format_name:
        if row['size'] > MAX_STRUCTURED:
            result['structured'] = {'state': 'resource-limited', 'error': 'Whole-file structured input exceeds 1 MiB; raw window remains available.'}
        else:
            with tempfile.TemporaryDirectory(prefix='lawliet-viewer-') as folder:
                source = Path(folder) / 'input'; output = Path(folder) / 'output.json'
                payload = path.read_bytes()
                if hashlib.sha256(payload).hexdigest() != row['sha256']:
                    raise UserError('Source changed before structured parsing.')
                source.write_bytes(payload)
                try:
                    process = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), '--worker', str(source), str(output), format_name],
                                             cwd=folder, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                    if process.returncode or not output.is_file() or output.stat().st_size > MAX_OUTPUT:
                        result['structured'] = {'state': 'worker-failed', 'error': 'Isolated parser failed or exceeded its output bound.'}
                    else:
                        result['structured'] = json.loads(output.read_text())
                except subprocess.TimeoutExpired:
                    result['structured'] = {'state': 'resource-limited', 'error': 'Isolated parser exceeded 5-second wall-clock bound.'}
    if path.stat().st_size != row['size'] or digest(path) != row['sha256']:
        raise UserError('Retained source changed during viewing.')
    result['original_unchanged'] = True
    return result


if __name__ == '__main__':
    if len(sys.argv) != 5 or sys.argv[1] != '--worker':
        raise SystemExit('Private viewer worker requires input, output and format.')
    _worker(sys.argv[2], sys.argv[3], sys.argv[4])
