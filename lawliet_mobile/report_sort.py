"""Explicit, conservative interpretation of original report values for ordering."""
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

NUMBER = re.compile(r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z')
ISO = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z')


def sort_value(value, mode):
    if not isinstance(value, str):
        return None
    if mode == 'text':
        return value.casefold()
    value = value.strip()
    if mode == 'number':
        if not NUMBER.fullmatch(value):
            return None
        try:
            return value if Decimal(value).is_finite() else None
        except InvalidOperation:
            return None
    if mode == 'timestamp':
        # No timezone assumptions, epoch guessing or silent fractional truncation.
        if not ISO.fullmatch(value):
            return None
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)
            return parsed.isoformat(timespec='microseconds')
        except (ValueError, OverflowError):
            return None
    return None


def compare_numbers(left, right):
    a, b = Decimal(left), Decimal(right)
    return (a > b) - (a < b)
