"""Shared bounded reader for upstream report fields."""
import csv

MAX_FIELD_CHARACTERS = 8 * 1024**2


def report_reader(stream):
    # csv's 128 KiB default rejects legitimate browser local-storage values.
    # Keep a deliberate bound rather than disabling the parser's allocation guard.
    csv.field_size_limit(MAX_FIELD_CHARACTERS)
    return csv.DictReader(stream, delimiter='\t')
