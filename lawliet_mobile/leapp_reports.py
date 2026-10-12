"""Conservative LEAPP report categorization; unknown schemas retain every field."""
import re
from .messages import leapp_message
from .parsers import timestamp
from .report_sort import sort_value

# Increment when normalization changes. Original report fields are never versioned
# away; this marker describes Lawliet's interpretation, not the upstream parser.
MAPPING_VERSION = '5'

# Report names AND required headers are checked to avoid guessing from filenames.
SCHEMAS = {
    'Contacts': ('contacts', {'Mimetype', 'Data 1', 'Display Name'}, None),
    'Address Book': ('contacts', {'Display Name'}, 'Modification Date'),
    'Call Logs': ('calls', {'start_date', 'number', 'duration', 'call_type'}, 'start_date'),
    'Call logs ':  ('calls', {'Call Date', 'Partner', 'Duration in Secs'}, 'Call Date'),
    'Call History': ('calls', {'Starting Timestamp', 'Call Type', 'Phone Number', 'Call Duration'}, 'Starting Timestamp'),
    'Web History': ('browser', {'Last Visit Time', 'URL', 'Title'}, 'Last Visit Time'),
    'Web Visits': ('browser', {'Visit Timestamp', 'URL', 'Title'}, 'Visit Timestamp'),
    'Safari Browser - History': ('browser', {'Visit Timestamp', 'URL', 'Title'}, 'Visit Timestamp'),
}

# One declared timeline anchor per row; other timestamps stay in original fields.
ACTIVITY_TIMES = {
    'Recent Activity': ({'CE Profile', 'Task ID', 'Affinity', 'Last Time Moved'},
                        'Last Time Moved',
                        'Timeline uses Last Time Moved: task metadata, not image capture time or proof of physical presence.'),
    'Usage Stats': ({'User (UID)', 'Package', 'Usage Type', 'Timestamp / Last Time Active'},
                    'Timestamp / Last Time Active',
                    'Timeline uses Timestamp / Last Time Active. Interpret it with Usage Type and Event Type; usage summaries are not individual user actions.'),
}


def report_review_note(data):
    note = _report_review_note(data)
    precision = data.get('_timestamp_precision', {})
    if isinstance(precision, dict) and precision.get('source_fractional_digits') == 0:
        note += (' ' if note else '') + 'This report supplies time only to whole seconds; displayed zeros do not establish subsecond precision in the underlying evidence.'
    return note


def _report_review_note(data):
    fields=data.get('_leapp_fields',data)
    activity=ACTIVITY_TIMES.get(data.get('_leapp_report_name'))
    if activity and isinstance(fields,dict) and activity[0] <= fields.keys():
        return activity[2]
    if (data.get('_leapp_report_name')=='SMS - Missing ROWIDs'
            and isinstance(fields,dict)
            and {'Beginning Timestamp','Ending Timestamp','Previous ROWID','ROWID','Number of Missing ROWIDs'} <= fields.keys()):
        return ('This row describes a gap in the message table ROWID sequence, not recovered message content. '
                'A gap alone does not establish deletion or the number of deleted messages. '
                'The timestamps describe the surrounding records; they are not deletion times. '
                '“Time of Extraction” is an upstream label, not a recorded deletion timestamp.')
    message=data.get('message',{})
    if data.get('_leapp_report_name') in {'SMS Backup and Restore Messages','SMS Messages','SMS and MMS Messages','discordChats','Discord - Cached Messages (API cache)'} and isinstance(message,dict):
        return message.get('row_count_note','')
    return ''


def leapp_artifact(name, row, evidence_id):
    mapped = leapp_message(name, row, evidence_id)
    if mapped:
        category, when, raw, title, body, data = mapped
    else:
        category, time_col = 'external', None
        spec = next((v for k,v in SCHEMAS.items() if k.strip().casefold()==name.strip().casefold() and v[1] <= set(row)), None)
        if spec:
            category, _, time_col = spec
        elif name == 'Address Book' and {'First Name', 'Last Name', 'Phone Numbers', 'Email addresses', 'Modification Date'} <= row.keys():
            category, time_col = 'contacts', 'Modification Date'
        if time_col:
            raw = row.get(time_col)
        else:
            raw = next((v for k,v in row.items() if k.lower().strip() in
                        {'timestamp','date','datetime','date/time','time','date time'} and v), None)
        when = timestamp(raw)
        activity = ACTIVITY_TIMES.get(name)
        if activity and activity[0] <= row.keys():
            raw = row.get(activity[1])
            normalized = sort_value(raw, 'timestamp')
            when = normalized.replace('+00:00', 'Z') if normalized else None
        title = name
        body = ' · '.join(f'{k}: {v}' for k,v in row.items() if v)
        data = dict(row)
    # Keep upstream columns separate from our metadata, including columns whose
    # names happen to collide with message/provenance keys. No normalization here.
    data['_leapp_fields'] = dict(row)
    # JSON objects are serialized with sorted keys; retain TSV header order
    # explicitly so desktop review does not reconstruct it alphabetically.
    data['_leapp_columns'] = list(row)
    if not mapped:
        # This key is reserved for structured conversation metadata. The
        # upstream column remains available in _leapp_fields.
        data.pop('message', None)
    data['_leapp_report_name'] = name
    if when and isinstance(raw, str):
        match = re.fullmatch(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.(\d+))?(?:Z|[+-]\d{2}:?\d{2})', raw)
        if match:
            data['_timestamp_precision'] = {'source_fractional_digits': len(match[1] or ''),
                                            'normalized_fractional_digits': 6,
                                            'scope': 'Precision of supplied report text, not original database'}
    data['_ancalor_mapping_version'] = MAPPING_VERSION
    return category, when, raw, title, body, data
