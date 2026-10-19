"""Conservative diagnostics after a native SQLite decoder emits no rows.

Recognition qualifies only the supplied view and table, never device absence.
Other recognized decoder families remain unresolved until independently qualified.
"""

def no_record_diagnostic(db, logical_path, platform):
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    common = {'source': logical_path, 'rows_observed': None,
              'count_state': 'unknown', 'scope_level': 'source'}
    if platform == 'android' and 'sms' in names:
        cols = {r[1] for r in db.execute('PRAGMA table_info("sms")')}
        if {'_id', 'thread_id', 'address', 'date', 'type', 'body'} <= cols:
            # Read at most one record; avoid unbounded aggregate work on evidence.
            if db.execute('SELECT 1 FROM "sms" LIMIT 1').fetchone() is None:
                return {**common, 'state': 'parsed-empty', 'table': 'sms',
                        'category': 'messages', 'records': 0, 'rows_observed': 0,
                        'schema': 'android-sms-six-column-v1',
                        'count_state': 'empty_in_supplied_sqlite_view',
                        'reason': 'Recognized Android SMS table examined; zero rows observed in the supplied SQLite view. '
                                  'This table-scoped result does not establish absent device activity, deleted-record recovery, '
                                  'MMS/RCS coverage or completeness of missing/unverified WAL data.'}
            return {**common, 'state': 'unresolved', 'table': 'sms',
                    'reason': 'Recognized Android SMS table contains rows but native decoding emitted none. '
                              'Inspect parser diagnostics; no empty-table or absence conclusion.'}
    # Tables that any native decoder may recognize must not be labelled unsupported
    # solely because they yielded zero rows. Their empty-source qualification is pending.
    candidates = {'message', 'recipient', 'thread', 'handle', 'sms', 'pdu', 'part', 'addr',
                  'history_visits', 'history_items', 'urls', 'visits', 'ABPerson', 'data',
                  'attachment', 'calls', 'ZCALLRECORD'}
    if not names.intersection(candidates):
        return {**common, 'state': 'unsupported',
                'reason': 'No table recognized by the current native SQLite decoders was observed. '
                          'This supplied database schema is unsupported by the native baseline; '
                          'other parsers may support it. No absence-of-evidence conclusion.'}
    return {**common, 'state': 'unresolved',
            'reason': 'No baseline records emitted; recognized table names require further schema/empty-view qualification. '
                      'No empty or complete parsing conclusion. Consider the platform LEAPP engine.'}
