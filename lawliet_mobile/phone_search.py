"""Formatting-only phone pivots; no country-code or identity inference."""
import json
import re

PHONE_FIELDS = frozenset({'phone number', 'address', 'partner', 'from_id', 'to_id',
    'phone account address', 'number', 'sender phone number', 'recipient phone number',
    'to address'})
FORMATTED = re.compile(r'\+?\(?[0-9][0-9\s().-]*\Z')


def phone_digits(value):
    if not isinstance(value, str) or not FORMATTED.fullmatch(value.strip()):
        return None
    digits = ''.join(c for c in value if c in '0123456789')
    return digits if 7 <= len(digits) <= 15 else None


def has_phone(raw, target):
    data = json.loads(raw)
    fields = data.get('_leapp_fields', data)
    candidates = []
    if isinstance(fields, dict) and data.get('_leapp_report_name'):
        candidates.extend(v for k,v in fields.items() if k.strip().casefold() in PHONE_FIELDS)
    message = data.get('message')
    if isinstance(message, dict):
        candidates.extend(message.get(key) for key in ('sender', 'recipient'))
    # Native vCard exports keep repeated TEL values in their own properties
    # list. Do not search NOTE, UID or arbitrary nested text for phone identity.
    properties = data.get('properties')
    if data.get('vcard_version') in ('3.0', '4.0') and isinstance(properties, dict):
        phones = properties.get('TEL')
        if isinstance(phones, list):
            candidates.extend(value[4:] if value[:4].lower() == 'tel:' else value
                              for value in phones if isinstance(value, str))
    return any(phone_digits(value) == target for value in candidates)
