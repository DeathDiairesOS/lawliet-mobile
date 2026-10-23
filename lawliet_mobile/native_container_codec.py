"""Bounded native JSONL validation. This module never opens evidence or child databases."""
from dataclasses import dataclass
import hashlib
import json
import math

from .core import json_text

PROTOCOL = 'lawliet-native-artifacts/1'
# These parser releases share the reviewed envelope and reference schema.
# Keep this explicit: importing the current parser version here would silently
# admit future formats before the host validator has been qualified for them.
SUPPORTED_NATIVE_VERSIONS = frozenset({'native/0.1.12', 'native/0.1.13', 'native/0.1.14'})
MAX_STDOUT = 18 * 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_LINE = 8 * 1024 * 1024
MAX_DETAIL = 1024 * 1024
MAX_COUNT = 100000
MAX_DEPTH = 64
BINDINGS = {'protocol', 'request_sha256', 'source_manifest_sha256', 'evidence_id',
            'native_parser_version', 'package_manifest_sha256', 'bootstrap_sha256'}
HEADER = BINDINGS | {'kind'}
ARTIFACT = {'kind', 'seq', 'evidence_id', 'file_id', 'category', 'timestamp',
            'timestamp_raw', 'title', 'body', 'source_ref', 'parser', 'data_json'}
FOOTER = {'kind', 'protocol', 'request_sha256', 'source_manifest_sha256',
          'artifact_count', 'artifact_bytes', 'artifacts_sha256', 'native_status',
          'native_detail_json', 'runtime'}
CATEGORIES = {'apps', 'attachments', 'browser', 'calls', 'contacts', 'device',
              'logs', 'media', 'messages', 'mms_candidates'}


class ValidationError(ValueError):
    """Untrusted output cannot be published, including a seemingly valid prefix."""


def _require(condition, message):
    if not condition:
        raise ValidationError(message)


def _integer(value):
    return type(value) is int and value >= 0


def _depth(text):
    # Count containers before json.loads, which otherwise recurses first.
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
            _require(depth <= MAX_DEPTH, 'JSON nesting limit exceeded')
        elif char in ']}':
            depth -= 1
            _require(depth >= 0, 'Invalid JSON nesting')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValidationError('Nonfinite outer JSON constant')


def _finite_float(text):
    value = float(text)
    _require(math.isfinite(value), 'Nonfinite outer JSON number')
    return value


def _decode(text, *, legacy=False):
    _require(type(text) is str, 'Expected JSON text')
    _depth(text)
    try:
        options = {'object_pairs_hook': _pairs}
        if not legacy:
            options.update(parse_constant=_reject_constant, parse_float=_finite_float)
        value = json.loads(text, **options)
        _require(type(value) is dict, 'Expected JSON object')
        # Reject unpaired surrogate strings at every nested location without recursion.
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                stack.extend(item.keys()); stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, str):
                item.encode('utf-8')
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError('Invalid JSON encoding') from exc


def _stored(text, limit):
    _require(type(text) is str, 'Stored JSON must be a string')
    _require(len(text.encode('utf-8')) <= limit, 'Stored JSON exceeds limit')
    value = _decode(text, legacy=True)
    _require(json_text(value) == text, 'Stored JSON is not exact canonical native text')
    return value


def _manifest(rows, eid):
    _require(isinstance(rows, (list, tuple)) and len(rows) <= 1000, 'Invalid manifest count')
    files = {}
    paths = set()
    total = 0
    for row in rows:
        _require(type(row) is dict, 'Invalid manifest row')
        fid = row.get('id')
        size = row.get('size', row.get('bytes'))
        _require(_integer(fid) and fid > 0 and fid not in files, 'Invalid manifest file ID')
        _require(_integer(size), 'Invalid manifest size')
        _require(row.get('evidence_id', eid) == eid, 'Foreign manifest evidence')
        for field in ('path', 'logical_path', 'sha256'):
            _require(type(row.get(field)) is str, 'Missing manifest metadata')
        _require(row['path'] not in paths, 'Duplicate manifest physical path')
        _require(len(row['sha256']) == 64 and all(c in '0123456789abcdef' for c in row['sha256']), 'Invalid manifest hash')
        total += size
        paths.add(row['path'])
        files[fid] = {**row, 'size': size}
    _require(total <= 32 * 1024 * 1024, 'Evidence inventory exceeds limit')
    return files


def _source(source, files):
    _require(type(source) is str, 'Invalid coverage source')
    matches = [f for f in files.values() if source == f['logical_path'] or source.startswith(f['logical_path'] + '#')]
    _require(len(matches) == 1, 'Unknown or ambiguous coverage source')
    return matches[0]


def _sidecars(items, files, parent=None):
    _require(type(items) is list, 'Invalid sidecar references')
    for item in items:
        _require(type(item) is dict, 'Invalid sidecar reference')
        source = _source(item.get('logical_path'), files)
        _require(item.get('sha256') == source['sha256'], 'Sidecar hash mismatch')
        if parent is not None:
            _require(source['logical_path'] in {parent['logical_path'] + '-wal', parent['logical_path'] + '-shm'} or source['path'] in {parent['path'] + '-wal', parent['path'] + '-shm'}, 'Unrelated sidecar source')


def _wal(wal, source, files):
    _require(type(wal) is dict, 'Invalid WAL coverage')
    _require(wal.get('source_sha256') == source['sha256'], 'WAL source hash mismatch')
    _sidecars(wal.get('sidecars'), files, source)


def _reference(ref, files, kind):
    _require(type(ref) is dict, 'Invalid semantic file reference')
    fid = ref.get('file_id')
    status = ref.get('status')
    allowed = {'media': {'available'},
               'attachment': {'available', 'size_mismatch', 'not_acquired', 'unsupported_reference', 'external_reference', 'ambiguous_path'},
               'payload': {'no-file-reference', 'unsupported-path', 'not-acquired', 'ambiguous-path', 'exact-retained-path-reference'}}[kind]
    _require(type(status) is str and status in allowed, 'Unknown semantic reference status')
    retained = status in {'available', 'size_mismatch', 'exact-retained-path-reference'}
    if not retained:
        _require(fid is None, 'Unresolved reference has live file ID')
        return
    _require(_integer(fid) and fid > 0 and fid in files, 'Foreign semantic file ID')
    source = files[fid]
    for key, expected in (('logical_path', source['logical_path']), ('sha256', source['sha256']), ('bytes', source['size'])):
        # Native media stores only file ID, byte count, MIME and status.
        if kind == 'media' and key != 'bytes' and key not in ref:
            continue
        _require(type(ref.get(key)) is type(expected) and ref.get(key) == expected, 'Semantic file metadata mismatch')


def _data_references(data, source, files):
    for key in ('media', 'attachment'):
        if key in data:
            _reference(data[key], files, key)
            if key == 'media':
                _require(data[key]['file_id'] == source['id'], 'Media reference differs from artifact source')
    if 'mms_schema' in data:
        if 'payload' in data:
            _reference(data['payload'], files, 'payload')
        _require(type(data.get('parts', [])) is list, 'Invalid MMS parts')
        for part in data.get('parts', []):
            _require(type(part) is dict and 'payload' in part, 'Invalid MMS part')
            _reference(part['payload'], files, 'payload')
    if 'source_database' in data:
        _require(data['source_database'] == source['logical_path'], 'Foreign source database')
    if 'source_sidecars' in data:
        _sidecars(data['source_sidecars'], files, source)
    if 'sqlite_wal_coverage' in data:
        _wal(data['sqlite_wal_coverage'], source, files)


def _artifact(frame, seq, bindings, files):
    _require(set(frame) == ARTIFACT and frame.get('kind') == 'artifact', 'Invalid artifact fields')
    _require(type(frame['seq']) is int and frame['seq'] == seq, 'Invalid artifact sequence')
    _require(frame['evidence_id'] == bindings['evidence_id'], 'Foreign artifact evidence')
    fid = frame['file_id']
    _require(type(fid) is int and fid > 0 and fid in files, 'Foreign artifact file ID')
    _require(frame['parser'] == bindings['native_parser_version'], 'Wrong parser version')
    _require(type(frame['category']) is str and frame['category'] in CATEGORIES, 'Unknown artifact category')
    for name in ('timestamp', 'timestamp_raw'):
        _require(frame[name] is None or type(frame[name]) is str, 'Invalid stored timestamp')
    for name in ('title', 'body', 'source_ref'):
        _require(type(frame[name]) is str, 'Invalid stored text')
    data = _stored(frame['data_json'], MAX_LINE)
    _data_references(data, files[fid], files)
    return {**frame, 'data': data}


def _detail(detail, status, count, files):
    if 'status' in detail:
        _require(detail['status'] == status, 'Conflicting native status')
    if 'new_records' in detail:
        _require(type(detail['new_records']) is int and detail['new_records'] == count, 'Conflicting native record count')
    for key in ('sqlite_files_examined', 'databases_with_records'):
        _require(_integer(detail.get(key)) and detail[key] <= len(files), 'Invalid coverage count')
    _require(detail['databases_with_records'] <= detail['sqlite_files_examined'], 'Invalid database coverage counts')
    _require(type(detail.get('coverage')) is str, 'Missing coverage limitation')
    for key in ('errors', 'unparsed_candidates'):
        _require(type(detail.get(key)) is list, 'Missing coverage diagnostics')
        for item in detail[key]:
            _require(type(item) is dict, 'Invalid coverage diagnostic')
            source = _source(item.get('source'), files)
            if 'sqlite_wal_coverage' in item:
                _wal(item['sqlite_wal_coverage'], source, files)
    _require((status == 'partial') == bool(detail['errors']), 'Native status hides source failures')


@dataclass(frozen=True)
class ValidatedResult:
    raw: bytes
    header: dict
    footer: dict
    detail: dict
    runtime: dict
    artifact_count: int
    artifact_bytes: int
    _bindings: dict
    _files: dict

    def iter_artifacts(self):
        """Second bounded pass; no list of all decoded artifacts is retained."""
        offset = self.raw.index(b'\n') + 1
        for seq in range(1, self.artifact_count + 1):
            end = self.raw.index(b'\n', offset) + 1
            frame = _decode(self.raw[offset:end].decode('utf-8'))
            yield _artifact(frame, seq, self._bindings, self._files)
            offset = end


def _validate(raw, trusted_bindings, manifest):
    """Validate the WHOLE stream before exposing an iterator. Never salvage prefixes."""
    _require(type(raw) is bytes and len(raw) <= MAX_STDOUT and raw.endswith(b'\n'), 'Invalid transport size or termination')
    _require(type(trusted_bindings) is dict and set(trusted_bindings) == BINDINGS, 'Invalid trusted bindings')
    _require(trusted_bindings['protocol'] == PROTOCOL, 'Unsupported native protocol')
    _require(all(type(v) is str for v in trusted_bindings.values()), 'Invalid trusted binding types')
    _require(trusted_bindings['native_parser_version'] in SUPPORTED_NATIVE_VERSIONS, 'Unsupported native schema version')
    files = _manifest(manifest, trusted_bindings['evidence_id'])
    offset = count = artifact_bytes = 0
    digest = hashlib.sha256()
    header = footer = None
    while offset < len(raw):
        end = raw.find(b'\n', offset)
        _require(end >= 0, 'Missing final newline')
        length = end + 1 - offset
        _require(length <= MAX_LINE, 'Frame exceeds byte limit')
        try:
            frame = _decode(raw[offset:end].decode('utf-8'))
        except UnicodeError as exc:
            raise ValidationError('Invalid UTF8 transport') from exc
        if header is None:
            _require(length <= 8192 and set(frame) == HEADER and frame.get('kind') == 'header', 'Invalid header')
            _require(all(frame[k] == v and type(frame[k]) is type(v) for k, v in trusted_bindings.items()), 'Header binding mismatch')
            header = frame
        elif frame.get('kind') == 'artifact':
            count += 1
            artifact_bytes += length
            _require(count <= MAX_COUNT and artifact_bytes <= MAX_ARTIFACT_BYTES, 'Artifact output exceeds limit')
            _artifact(frame, count, trusted_bindings, files)
            digest.update(raw[offset:end + 1])
        else:
            _require(set(frame) == FOOTER and frame.get('kind') == 'final' and end + 1 == len(raw), 'Invalid or nonterminal footer')
            footer = frame
        offset = end + 1
    _require(footer is not None, 'Missing final footer')
    for key in ('protocol', 'request_sha256', 'source_manifest_sha256'):
        _require(footer[key] == trusted_bindings[key], 'Footer binding mismatch')
    _require(type(footer['artifact_count']) is int and footer['artifact_count'] == count, 'Artifact count mismatch')
    _require(type(footer['artifact_bytes']) is int and footer['artifact_bytes'] == artifact_bytes, 'Artifact byte count mismatch')
    _require(footer['artifacts_sha256'] == digest.hexdigest(), 'Artifact digest mismatch')
    _require(footer['native_status'] in ('complete', 'partial'), 'Unpublishable native status')
    runtime = footer['runtime']
    _require(type(runtime) is dict and set(runtime) == {'python_version', 'sqlite_version'} and all(type(v) is str and 0 < len(v) < 128 for v in runtime.values()), 'Invalid runtime metadata')
    detail = _stored(footer['native_detail_json'], MAX_DETAIL)
    _detail(detail, footer['native_status'], count, files)
    return ValidatedResult(raw, header, footer, detail, runtime, count, artifact_bytes, dict(trusted_bindings), files)


def validate(raw, trusted_bindings, manifest):
    """Validate a complete bounded stream, normalizing malformed-input failures."""
    try:
        return _validate(raw, trusted_bindings, manifest)
    except ValidationError:
        raise
    except (TypeError, KeyError, UnicodeError, RecursionError, OverflowError, ValueError) as exc:
        raise ValidationError('Invalid native output structure') from exc
