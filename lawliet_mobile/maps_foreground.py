"""Narrow, provisional Google Maps 9.77.5 preferences decoding."""
import base64
import struct
import xml.etree.ElementTree as ET
from .core import UserError
from .parsers import timestamp


def wire_fields(blob):
    if len(blob) > 256:
        raise UserError('Location protobuf exceeds 256 bytes.')
    cursor, fields = 0, {}
    def varint():
        nonlocal cursor
        value = 0
        for shift in range(0,70,7):
            if cursor >= len(blob): raise UserError('Truncated protobuf varint.')
            byte = blob[cursor];cursor += 1;value |= (byte & 127) << shift
            if byte < 128: return value
        raise UserError('Oversized protobuf varint.')
    while cursor < len(blob):
        if len(fields) >= 32: raise UserError('Too many protobuf fields.')
        tag = varint();number,kind = tag >> 3,tag & 7
        if number == 0 or number in fields: raise UserError('Invalid or duplicate protobuf field.')
        if kind == 0: value = varint()
        elif kind in (1,2,5):
            size = varint() if kind == 2 else 8 if kind == 1 else 4
            if cursor+size > len(blob): raise UserError('Truncated protobuf value.')
            data = blob[cursor:cursor+size];cursor += size
            value = data if kind == 2 else int.from_bytes(data,'little')
        else: raise UserError('Unsupported protobuf wire type.')
        fields[number] = (kind,value)
    return fields


def decode_preferences(text):
    if len(text.encode('utf-8')) > 64*1024 or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise UserError('Unsupported or oversized Maps preference XML.')
    tree = ET.fromstring(text)
    if tree.tag != 'map': raise UserError('Expected Android preference map.')
    values = {}
    for node in tree:
        name = node.attrib.get('name')
        if name in values: raise UserError('Duplicate preference key.')
        values[name] = node.attrib.get('value',node.text or '')
    if values.get('app_version') != '9.77.5':
        raise UserError('Only the tested Maps 9.77.5 preference layout is supported.')
    encoded = values.get('last_foreground_location','').strip()
    if len(encoded) > 512: raise UserError('Location encoding exceeds bound.')
    try: blob = base64.b64decode(encoded,validate=True)
    except (ValueError,TypeError) as exc: raise UserError('Invalid location base64.') from exc
    fields = wire_fields(blob)
    if fields.get(5,(None,None))[0] != 2: raise UserError('Expected nested coordinate field 5.')
    point = wire_fields(fields[5][1])
    if set(point) != {1,2} or any(point[k][0] != 5 for k in (1,2)):
        raise UserError('Unsupported coordinate layout.')
    signed = lambda v: v if v < 2**31 else v-2**32
    lat, lon = signed(point[1][1])/10**7,signed(point[2][1])/10**7
    if not (-90 <= lat <= 90 and -180 <= lon <= 180): raise UserError('Coordinates out of range.')
    return {'state':'limited','method':'maps-preferences-9.77.5-provisional/1',
        'source_key':'last_foreground_location','source_base64':encoded,'protobuf_hex':blob.hex(),
        'latitude':lat,'longitude':lon,'coordinate_interpretation':'Nested field 5 fixed32 fields 1/2 interpreted as signed E7 integers.',
        'app_last_used_raw':values.get('gmm_last_used'),
        'app_last_used_utc':timestamp(values.get('gmm_last_used'),unit='milliseconds'),
        'uninterpreted_fields':{str(k):{'wire_type':kind,'value':value.hex() if isinstance(value,bytes) else value} for k,(kind,value) in fields.items() if k != 5},
        'limitations':['Provisional layout validated on controlled fixtures and this supplied lab only; independent device validation pending.',
                       'Cached app coordinate is not proof that the person visited a named venue.',
                       'App last-used time is not established as the coordinate observation time.',
                       'No automatic reverse geocoding or invented venue/accuracy is provided.']}
