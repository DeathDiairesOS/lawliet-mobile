"""Bounded, text-only inspection of iMessage attributedBody archives.

No Objective-C objects are instantiated and no general unarchiver is used.
The typedstream reader recognizes qualified Foundation prefixes and the first
NSString field only; attribute objects after that field are not interpreted.
The keyed reader follows only an attributed string's documented NSString key.
See tests/fixtures/ios_attributed_body for independently Apple-encoded fixtures.
"""
import hashlib
import plistlib

DECODER_VERSION = 'ios-attributed-text/1'
MAX_BYTES = 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024
MAX_OBJECTS = 4096
MAX_REFERENCES = 16384
MAX_DEPTH = 32
LIMITATION = ('Text field only. Formatting, attribute objects, attachments, reactions, '
              'edits and retractions are not decoded. Original bytes remain in the source database.')


class _DecodeError(Exception):
    def __init__(self, state, reason):
        self.state, self.reason = state, reason


def _fail(state, reason):
    raise _DecodeError(state, reason)


def _typed_prefixes():
    # Qualified using Apple's NSArchiver, not adapted from a third-party decoder.
    header = bytes.fromhex('040b73747265616d747970656481e80384014084')
    def classes(names):
        return b''.join(b'\x84\x84' + bytes((len(name),)) + name + bytes((version,))
                        for name, version in names)
    for mutable_root in (False, True):
        roots = ([(b'NSMutableAttributedString', 0)] if mutable_root else [])
        roots += [(b'NSAttributedString', 0), (b'NSObject', 0)]
        for mutable_string in (False, True):
            strings = ([(b'NSMutableString', 1)] if mutable_string else []) + [(b'NSString', 1)]
            yield (header + classes(roots) + b'\x85\x92\x84' + classes(strings)
                   + bytes((0x92 + len(roots),)) + b'\x84\x01+')


_TYPED_PREFIXES = tuple(_typed_prefixes())


def _typed_text(data):
    prefix = next((p for p in _TYPED_PREFIXES if data.startswith(p)), None)
    if prefix is None:
        if any(p.startswith(data) for p in _TYPED_PREFIXES):
            _fail('malformed', 'Truncated typedstream text header.')
        _fail('unsupported', 'Unsupported typedstream header, class layout or class version.')
    offset = len(prefix)
    if offset >= len(data):
        _fail('malformed', 'Missing typedstream string length.')
    marker = data[offset]
    offset += 1
    if marker <= 0x7f:
        length = marker
    elif marker in (0x81, 0x82):
        width = 2 if marker == 0x81 else 4
        if offset + width > len(data):
            _fail('malformed', 'Truncated typedstream string length.')
        length = int.from_bytes(data[offset:offset + width], 'little')
        offset += width
    else:
        _fail('unsupported', 'Unsupported typedstream string length encoding.')
    if length > MAX_TEXT_BYTES:
        _fail('limit_exceeded', 'Attributed text exceeds its byte limit.')
    end = offset + length
    if end >= len(data) or data[end] != 0x86:
        _fail('malformed', 'Truncated typedstream text or missing string terminator.')
    try:
        text = data[offset:end].decode('utf-8', errors='strict')
    except UnicodeError:
        _fail('malformed', 'Invalid UTF-8 in typedstream NSString.')
    tail = data[end + 1:]
    if not tail or tail[-1] != 0x86:
        _fail('malformed', 'Truncated attributed-string envelope.')
    if tail != b'\x86' and not tail.startswith(b'\x84\x02iI'):
        _fail('unsupported', 'Unsupported attributed-string field layout after text.')
    return text, {'source_byte_range': [offset, end],
                  'source_byte_range_scope': 'attributedBody BLOB; zero-based bytes, end exclusive; not SQLite file offsets',
                  'archive_validation': 'text_field_only',
                  'unparsed_attribute_bytes': len(tail) - 1}


def _plist_preflight(data):
    """Bound the binary plist graph before plistlib allocates or recurses."""
    if len(data) < 40:
        _fail('malformed', 'Truncated binary property list.')
    trailer = data[-32:]
    width, refs = trailer[6], trailer[7]
    count = int.from_bytes(trailer[8:16], 'big')
    top = int.from_bytes(trailer[16:24], 'big')
    table = int.from_bytes(trailer[24:32], 'big')
    if count > MAX_OBJECTS:
        _fail('limit_exceeded', 'Binary property list exceeds its object limit.')
    if (not count or width not in (1, 2, 4, 8) or refs not in (1, 2, 4, 8)
            or top >= count or table < 8 or table + count * width != len(data) - 32):
        _fail('malformed', 'Invalid binary property-list trailer.')
    offsets = [int.from_bytes(data[table + i * width:table + (i + 1) * width], 'big') for i in range(count)]
    if len(set(offsets)) != count or any(not 8 <= offset < table for offset in offsets):
        _fail('malformed', 'Invalid binary property-list offsets.')
    ordered = sorted(offsets) + [table]
    boundaries = dict(zip(ordered, ordered[1:]))
    graph, strings, total_refs = [], {}, 0
    for offset in offsets:
        token, end = data[offset], boundaries[offset]
        kind, size, start = token >> 4, token & 15, offset + 1
        if kind in (4, 5, 6, 10, 13) and size == 15:
            if start >= end or data[start] >> 4 != 1 or data[start] & 15 > 3:
                _fail('malformed', 'Invalid binary property-list length.')
            length_width = 1 << (data[start] & 15)
            start += 1
            if start + length_width > end:
                _fail('malformed', 'Truncated binary property-list length.')
            size = int.from_bytes(data[start:start + length_width], 'big')
            start += length_width
        edges = []
        if kind in (10, 13):
            length = size * (2 if kind == 13 else 1)
            total_refs += length
            if total_refs > MAX_REFERENCES:
                _fail('limit_exceeded', 'Binary property list exceeds its reference limit.')
            if start + length * refs > end:
                _fail('malformed', 'Truncated binary property-list references.')
            edges = [int.from_bytes(data[start + i * refs:start + (i + 1) * refs], 'big') for i in range(length)]
            if any(ref >= count for ref in edges):
                _fail('malformed', 'Binary property-list reference is out of range.')
        elif kind in (4, 5, 6):
            length = size * (2 if kind == 6 else 1)
            if start + length > end:
                _fail('malformed', 'Truncated binary property-list value.')
            if kind in (5, 6):
                try:
                    strings[len(graph)] = data[start:start + length].decode('ascii' if kind == 5 else 'utf-16-be')
                except UnicodeError:
                    _fail('malformed', 'Invalid property-list string encoding.')
        elif kind in (1, 2, 3, 8):
            length = size + 1 if kind == 8 else 1 << size
            if length > 8:
                _fail('unsupported', 'Unsupported binary property-list scalar width.')
            if start + length > end:
                _fail('malformed', 'Truncated binary property-list scalar.')
        elif token not in (0, 8, 9):
            _fail('unsupported', 'Unsupported binary property-list object type.')
        graph.append(edges)
    for index, offset in enumerate(offsets):
        if data[offset] >> 4 == 13:
            keys = graph[index][:len(graph[index]) // 2]
            if any(key not in strings for key in keys) or len({strings[key] for key in keys}) != len(keys):
                _fail('malformed', 'Invalid or duplicate property-list dictionary keys.')
    # Acyclic plist containers only. UID references are data, never instantiated.
    colors, heights = {}, {}
    def visit(index, depth):
        if depth > MAX_DEPTH:
            _fail('limit_exceeded', 'Binary property list exceeds its depth limit.')
        if colors.get(index) == 1:
            _fail('malformed', 'Cyclic binary property-list containers.')
        if colors.get(index) == 2:
            if depth + heights[index] > MAX_DEPTH:
                _fail('limit_exceeded', 'Binary property list exceeds its depth limit.')
            return
        colors[index] = 1
        for child in graph[index]:
            visit(child, depth + 1)
        heights[index] = max((heights[child] + 1 for child in graph[index]), default=0)
        colors[index] = 2
    visit(top, 0)


def _keyed_text(data):
    _plist_preflight(data)
    try:
        archive = plistlib.loads(data, fmt=plistlib.FMT_BINARY)
    except (ValueError, TypeError, OverflowError, RecursionError, plistlib.InvalidFileException):
        _fail('malformed', 'Invalid binary property list.')
    if (not isinstance(archive, dict) or archive.get('$archiver') != 'NSKeyedArchiver'
            or type(archive.get('$version')) is not int or archive.get('$version') != 100000):
        _fail('unsupported', 'Property list is not a supported NSKeyedArchiver archive.')
    objects, top = archive.get('$objects'), archive.get('$top')
    if not isinstance(objects, list) or not isinstance(top, dict) or set(top) != {'root'}:
        _fail('malformed', 'Invalid keyed archive object table or root.')
    def resolve(value):
        if not isinstance(value, plistlib.UID) or value.data >= len(objects):
            _fail('malformed', 'Invalid keyed archive object reference.')
        return objects[value.data]
    def typed(value, allowed):
        if not isinstance(value, dict):
            _fail('unsupported', 'Unsupported keyed archive object shape.')
        descriptor = resolve(value.get('$class'))
        if (not isinstance(descriptor, dict) or not isinstance(descriptor.get('$classname'), str)
                or descriptor.get('$classname') not in allowed
                or descriptor.get('$classes') != allowed[descriptor['$classname']]):
            _fail('unsupported', 'Unsupported keyed archive class.')
    root = resolve(top['root'])
    typed(root, {'NSAttributedString': ['NSAttributedString', 'NSObject'],
                 'NSMutableAttributedString': ['NSMutableAttributedString', 'NSAttributedString', 'NSObject']})
    text = resolve(root.get('NSString'))
    if isinstance(text, dict):
        typed(text, {'NSString': ['NSString', 'NSObject'],
                     'NSMutableString': ['NSMutableString', 'NSString', 'NSObject']})
        text = text.get('NS.string')
    if not isinstance(text, str):
        _fail('unsupported', 'Attributed string does not contain a supported NSString text value.')
    if len(text.encode('utf-8')) > MAX_TEXT_BYTES:
        _fail('limit_exceeded', 'Attributed text exceeds its byte limit.')
    return text, {'archive_validation': 'bounded_plist_and_text_references',
                  'source_key_path': '$top.root -> NSString -> NS.string (when mutable)'}


def decode_attributed_body(value):
    """Return text only when its specific archive field was safely decoded.

    Formats outside the qualified little-endian typedstream-v4 prefixes and
    binary NSKeyedArchiver attributed-string layouts are explicitly unsupported.
    XML archives, serialized classes, arbitrary plists, and plain-text BLOBs are
    not guessed. Oversized values are not copied or hashed.
    """
    result = {'decoder_version': DECODER_VERSION, 'state': 'absent', 'format': None,
              'blob_bytes': 0, 'blob_sha256': None, 'limitation': LIMITATION}
    if value is None or isinstance(value, (bytes, bytearray)) and not value:
        return result
    if not isinstance(value, (bytes, bytearray)):
        return {**result, 'state': 'unsupported', 'reason': 'attributedBody is not a binary value.'}
    result['blob_bytes'] = len(value)
    if len(value) > MAX_BYTES:
        return {**result, 'state': 'limit_exceeded', 'reason': 'Attributed body exceeds its byte limit.'}
    data = bytes(value)
    result['blob_sha256'] = hashlib.sha256(data).hexdigest()
    try:
        if data.startswith(b'bplist00'):
            result['format'] = 'NSKeyedArchiver-bplist00'
            text, detail = _keyed_text(data)
        elif data.startswith(b'\x04\x0bstreamtyped'):
            result['format'] = 'typedstream-v4-little-endian'
            text, detail = _typed_text(data)
        else:
            _fail('unsupported', 'Unrecognized attributed-body encoding.')
    except _DecodeError as error:
        return {**result, 'state': error.state, 'reason': error.reason}
    return {**result, 'state': 'decoded', 'text': text, **detail}
