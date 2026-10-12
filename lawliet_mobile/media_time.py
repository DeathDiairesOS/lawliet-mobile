"""EXIF capture times with explicit offsets; original metadata stays intact."""
import re
from datetime import datetime, timezone


def capture_time(fields):
    """Return (UTC time, interpretation). Never use host file times or GPS time.

    EXIF fractions beyond six digits are truncated in normalized UTC only.
    Conflicting timezone/fraction declarations stay undated.
    """
    key = next((k for k in ('DateTimeOriginal', 'CreateDate') if fields.get(k)), None)
    detail = {'field': key, 'status': 'unavailable', 'meaning': 'Metadata-declared capture time; not authenticated capture truth.'}
    if key is None:
        return None, detail
    raw = str(fields[key])
    match = re.fullmatch(r'(\d{4})[:-](\d{2})[:-](\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?', raw)
    if not match:
        return None, {**detail, 'status': 'invalid_date'}
    year, month, day, hour, minute, second, fraction, inline_offset = match.groups()
    offset_key = 'OffsetTimeOriginal' if key == 'DateTimeOriginal' else 'OffsetTimeDigitized'
    fraction_key = 'SubSecTimeOriginal' if key == 'DateTimeOriginal' else 'SubSecTimeDigitized'
    separate_offset = fields.get(offset_key)
    normalize = lambda value: '+00:00' if value == 'Z' else value
    if separate_offset is not None and (not isinstance(separate_offset, str) or not re.fullmatch(r'[+-]\d{2}:\d{2}', separate_offset)):
        return None, {**detail, 'status': 'invalid_offset'}
    if inline_offset and separate_offset and normalize(inline_offset) != normalize(separate_offset):
        return None, {**detail, 'status': 'conflicting_offset'}
    offset = inline_offset or separate_offset
    if not offset:
        return None, {**detail, 'status': 'unknown_timezone'}
    offset = normalize(offset)
    # Reject offsets outside the ISO timezone range, rather than silently wrapping.
    oh, om = int(offset[1:3]), int(offset[4:6])
    if oh > 14 or om > 59 or (oh == 14 and om):
        return None, {**detail, 'status': 'invalid_offset'}
    separate_fraction = fields.get(fraction_key)
    if separate_fraction is not None:
        separate_fraction = str(separate_fraction)
        if not re.fullmatch(r'\d{1,32}', separate_fraction):
            return None, {**detail, 'status': 'invalid_subseconds'}
        if fraction and fraction.rstrip('0') != separate_fraction.rstrip('0'):
            return None, {**detail, 'status': 'conflicting_subseconds'}
    fraction = fraction or separate_fraction
    try:
        parsed = datetime.fromisoformat(f'{year}-{month}-{day}T{hour}:{minute}:{second}' + ('.' + fraction[:6] if fraction else '') + offset)
        if not 1990 <= parsed.year <= 2200:
            raise ValueError('Outside supported date range')
        when = parsed.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    except (ValueError, OverflowError):
        return None, {**detail, 'status': 'invalid_date'}
    return when, {**detail, 'status': 'normalized', 'offset_field': offset_key if separate_offset else None,
                  'subsecond_field': fraction_key if separate_fraction else None,
                  'precision': 'microseconds', 'fraction_truncated': bool(fraction and len(fraction) > 6)}
