"""Message normalization and explicit, source-scoped conversation identities."""
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .core import UserError, add_artifact, audit, begin_run_index, import_evidence, json_text, now


def metadata(app, conversation, sender='', recipient='', direction='unknown', **extra):
    return {'app': app, 'conversation': str(conversation or ''), 'sender': str(sender or ''),
            'recipient': str(recipient or ''), 'direction': direction, **extra}


def scope_message(data, evidence_id, scope):
    message = data.get('message')
    if isinstance(message, dict):
        # Do not merge same-named chats or different app accounts by display label.
        identity = [evidence_id, scope, message['app'], message['conversation']]
        message['conversation_id'] = hashlib.sha256(json_text(identity).encode()).hexdigest()[:20]
    return data


def ios_event_markers(row):
    """Expose unhandled message structures without guessing their event meaning.

    Values are observations from the supplied database schema. A nonzero marker
    does not by itself identify a reaction, edit, deletion time or actor.
    The original database remains the source for opaque binary content.
    """
    fields = ('associated_message_type', 'associated_message_guid',
              'group_action_type', 'item_type', 'date_edited', 'edit_version',
              'date_retracted', 'balloon_bundle_id')
    # Presence only: these supplied values do not establish a decoded reply,
    # linked target, emoji meaning or actor. Text '0' is still a supplied value.
    linked_fields = ('reply_to_guid', 'thread_originator_guid',
                     'thread_originator_part', 'associated_message_emoji')
    markers = {name: row[name] for name in fields
               if name in row and row[name] not in (None, '', 0, '0')}
    markers.update({name: row[name] for name in linked_fields
                    if name in row and row[name] is not None and row[name] != ''
                    and not (name == 'thread_originator_part' and type(row[name]) in (int, float) and row[name] == 0)})
    opaque = {}
    if not row.get('text'):
        for name in ('attributedBody', 'payload_data'):
            value = row.get(name)
            if isinstance(value, dict) and value.get('blob_bytes', 0) > 0:
                opaque[name] = value
    state = 'not_decoded' if markers or opaque else (
        'no_nonzero_marker_observed' if any(name in row for name in fields + linked_fields) else 'not_assessed')
    return {'schema': 'ios-rich-event-markers/2', 'state': state,
            'markers': markers, 'opaque_body_fields': opaque,
            'limitation': 'Raw markers are not decoded event semantics. No reaction, reply relationship, linked target, emoji meaning, edit history, deletion time or actor is inferred; opaque bytes remain in the retained source database.'}


def telephony_records(path):
    from .android_backup import backup_rows
    from .parsers import timestamp
    mms = path.name.endswith('mms_backup')
    app = 'mms' if mms else 'sms'
    for number, row in enumerate(backup_rows(path)):
        raw = row.get('date')
        address = row.get('address') or ', '.join(str(x) for x in row.get('recipients', []))
        direction = {'1': 'incoming', '2': 'outgoing', '3': 'draft', '4': 'outbox', '5': 'failed', '6': 'queued'}.get(str(row.get('msg_box' if mms else 'type')), 'unknown')
        data = {'original': row, 'message': metadata(app, address, address if direction == 'incoming' else '',
                address if direction == 'outgoing' else '', direction,
                attachment_status='not_assessed', timestamp_field='date')}
        yield 'messages', timestamp(raw, unit='seconds' if mms else 'milliseconds'), raw, f'{app.upper()} · {direction} · {address}', row.get('mms_body' if mms else 'body', ''), f'json:index={number}', data


# Explicit mappings for known upstream reports; unknown schemas stay external.
LEAPP_MESSAGES = {
    'SMS and MMS Backup - SMS': ('sms', 'Date', 'Body', 'Address', 'Direction'),
    'SMS and MMS Backup - MMS': ('mms', 'Date', 'Body', 'Recipients', 'Message Box'),
    'WhatsApp - Messages': ('whatsapp', 'Message Timestamp', 'Message', 'Key Remote JID', 'Direction'),
    'WhatsApp - One To One Messages': ('whatsapp', 'Message Timestamp', 'Message', 'Other Participant JID', 'Message Direction'),
    'WhatsApp - Group Messages': ('whatsapp', 'Message Timestamp', 'Message', 'Group JID', 'Message Direction'),
    'Signal - Messages': ('signal', 'Date Sent', 'Message', 'Thread ID', 'Direction'),
}


def leapp_message(name, row, evidence_id):
    from .parsers import timestamp
    if name == 'SMS Backup and Restore Messages':
        required = {'Timestamp', 'Direction', 'Number', 'Message', 'Backup File', 'Source File'}
        if not required <= row.keys() or not row['Number'] or not row['Source File']:
            return None
        address = row['Number']
        direction = {'received': 'incoming', 'sent': 'outgoing'}.get(row['Direction'].lower(), 'unknown')
        data = dict(row)
        data['message'] = metadata('sms', address,
            address if direction == 'incoming' else '',
            address if direction == 'outgoing' else '', direction,
            label=address, timestamp_field='Timestamp', attachment_status='not_assessed',
            row_count_note='Backup rows are occurrences, not distinct messages across backups. They do not establish current device contents or deletion.',
            scope_note='Conversation scoped to evidence, report and source backup file; number is a supplied identifier, not verified identity.')
        scope_message(data, evidence_id, json_text([name, row['Source File']]))
        from .report_sort import sort_value
        normalized = sort_value(row['Timestamp'], 'timestamp')
        when = normalized.replace('+00:00', 'Z') if normalized else None
        return 'messages', when, row['Timestamp'], f'sms · {direction} · {address}', row['Message'], data
    if name in {'discordChats', 'Discord - Cached Messages (API cache)'}:
        id_col, account_col = ('ID', 'Account ID') if name == 'discordChats' else ('Message ID', 'Account IDs')
        if not {'Timestamp','Direction','Username','Content','Channel ID','Sender ID',id_col,account_col} <= row.keys() or not row[id_col]:
            return None
        direction = {'incoming':'incoming','outgoing':'outgoing'}.get(row['Direction'].lower(), 'unknown')
        account, channel = row[account_col], row['Channel ID']
        # Account IDs may be an upstream set; preserve it without inventing a
        # single account or treating a channel as a recipient/person.
        conversation = json_text([account,channel]) if account and channel else 'unlinked-message:'+row[id_col]
        data = dict(row)
        data['message'] = metadata('discord',conversation,row['Sender ID'],'',direction,
            label='Channel '+channel if channel else 'Unlinked message '+row[id_col],
            account_ids=account,channel_id=channel,sender_label=row['Username'],
            source_row_id=row[id_col],timestamp_field='Timestamp',
            attachment_status='upstream_report_references_only',
            row_count_note='Discord storage and API-cache reports can repeat the same message ID. Report rows are not distinct-message counts; cache contents do not establish complete conversation history.',
            scope_note='Conversation scoped to evidence, report and supplied account/channel identifiers. Missing account or channel leaves messages unlinked. Direction is retained from the upstream report, not independently inferred.')
        scope_message(data,evidence_id,name)
        from .report_sort import sort_value
        normalized=sort_value(row['Timestamp'],'timestamp')
        when=normalized.replace('+00:00','Z') if normalized else None
        return 'messages',when,row['Timestamp'],f'discord · {direction} · {data["message"]["label"]}',row['Content'],data
    if name == 'SMS' and {'Message Timestamp', 'Message', 'Service', 'Message Direction',
                          'Message Row ID', 'Chat ID', 'Sender'} <= set(row):
        app = row['Service'].lower() or 'unknown'
        direction = row['Message Direction'].lower()
        if direction not in {'incoming', 'outgoing'}:
            direction = 'unknown'
        # Unlinked messages must not be combined into a fabricated conversation.
        conversation = ('chat:' + row['Chat ID']) if row['Chat ID'] else ('unlinked-message:' + row['Message Row ID'])
        if not row['Message Row ID']:
            return None
        data = dict(row)
        data['message'] = metadata(app, conversation, row['Sender'], '', direction,
            label=row.get('Chat Name') or row.get('Chat Contact ID') or conversation,
            source_row_id=row['Message Row ID'], source_guid=row.get('Message GUID'),
            participants=row.get('Chat Participants', ''),
            attachment_status='upstream_report_references_only',
            body_status='upstream_plaintext_or_decoded_attributed_body',
            row_count_note='One message may produce multiple attachment or chat rows; count distinct Message Row ID within its source database.')
        scope_message(data, evidence_id, name)
        raw = row['Message Timestamp']
        return 'messages', timestamp(raw), raw, f'{app} · {direction} · {data["message"]["label"]}', row['Message'], data
    if name in {'SMS Messages', 'SMS and MMS Messages'}:
        direction_col = 'Type' if name == 'SMS Messages' else 'Direction'
        required = {'Date', 'Body', 'Address', 'MSG ID', 'Thread ID', direction_col}
        if name == 'SMS and MMS Messages':
            required |= {'Message Type', 'Source Table'}
        if not required <= set(row) or not row['MSG ID']:
            return None
        app = 'sms' if name == 'SMS Messages' else row['Message Type'].lower()
        if app not in {'sms', 'mms'}:
            return None
        direction = {'received':'incoming', 'sent':'outgoing', 'draft':'draft',
                     'outbox':'outbox', 'failed':'failed', 'queued':'queued'}.get(row[direction_col].lower(), 'unknown')
        conversation = 'thread:' + row['Thread ID'] if row['Thread ID'] else 'unlinked:' + app + ':' + row['MSG ID']
        address = row['Address']
        data = dict(row)
        data['message'] = metadata(app, conversation,
            address if direction == 'incoming' or app == 'mms' else '',
            (row.get('To Address','') if app == 'mms' else address) if direction == 'outgoing' else '',
            direction, label=address or conversation, source_row_id=row['MSG ID'],
            source_table=row.get('Source Table','unspecified SMS table'), timestamp_field='Date',
            attachment_status='upstream_report_references_only',
            row_count_note='Separate and combined ALEAPP reports can repeat the same source message. MMS parts can repeat IDs. Report rows are not distinct-message counts.',
            scope_note='Conversation scoped to evidence and report; separate source databases require separate evidence inputs.')
        scope_message(data,evidence_id,name)
        return 'messages',timestamp(row['Date']),row['Date'],f'{app} · {direction} · {address or conversation}',row['Body'],data
    spec = LEAPP_MESSAGES.get(name)
    if not spec or not set(spec[1:]) <= set(row):
        return None
    app, time_col, body_col, conversation_col, direction_col = spec
    direction = {'incoming': 'incoming', 'received': 'incoming', 'inbox': 'incoming',
                 'outgoing': 'outgoing', 'sent': 'outgoing', 'draft': 'draft', 'drafts': 'draft'}.get(str(row[direction_col]).lower(), 'unknown')
    # A missing stable identity must not collapse unrelated chats into one thread.
    if not row[conversation_col]:
        return None
    sender = row.get('Sender Phone Number') or row.get('Sender') or row.get('Sending Party JID') or row.get('Group Sender') or ''
    if not sender and direction == 'incoming' and 'Group' not in name:
        sender = row[conversation_col]
    recipient = row.get('Recipient Phone Number') or row.get('Recipient') or ''
    data = dict(row)
    data['message'] = metadata(app, row[conversation_col], sender, recipient, direction,
                               label=row.get('Conversation Name') or row.get('Other Participant WA User Name') or row[conversation_col],
                               timestamp_field=time_col, attachment_status='upstream_report_references_only')
    # Generic reports cannot establish which account/database generated each row.
    # Keep report families separate, and expose this limitation in the metadata.
    data['message']['scope_note'] = 'Conversation identity is scoped to evidence and report; multiple accounts require separate evidence inputs.'
    scope_message(data, evidence_id, name)
    raw = row[time_col]
    return 'messages', timestamp(raw), raw, f'{app} · {direction} · {data["message"]["label"]}', row[body_col], data


def conversations(db, app=None, evidence=None, parser=None, run=None):
    # SQL aggregation avoids loading bodies for large cases.
    clauses = ["category='messages'", "json_extract(data,'$.message.conversation_id') IS NOT NULL"]
    args = []
    if run:
        from .core import run_scope
        clause, params = run_scope(db, run)
        clauses.append(clause)
        args.extend(params)
    for expression, value in [("json_extract(data,'$.message.app')", app), ('evidence_id', evidence), ('parser', parser)]:
        if value:
            clauses.append(expression + '=?')
            args.append(value)
    query = """SELECT json_extract(data,'$.message.conversation_id') AS conversation_id,
      json_extract(data,'$.message.app') AS app, evidence_id,
      json_extract(data,'$.message.conversation') AS conversation,
      MAX(json_extract(data,'$.message.label')) AS label,
      json_group_array(DISTINCT json_extract(data,'$._leapp_report_name')) AS reports_json,
      COUNT(*) AS records, MIN(timestamp) AS first_utc, MAX(timestamp) AS last_utc,
      SUM(timestamp IS NULL) AS undated FROM artifacts WHERE """ + ' AND '.join(clauses) + ' GROUP BY conversation_id ORDER BY first_utc IS NULL,first_utc,conversation_id'
    result=[]
    for row in db.execute(query,args):
        item=dict(row)
        item['reports']=sorted(x for x in json.loads(item.pop('reports_json')) if isinstance(x,str) and x)
        result.append(item)
    return result


def local_time(raw, date_order, zone, year_century=None):
    cleaned = raw.replace('\u202f', ' ').replace('\u00a0', ' ')
    date_part, _, time_part = cleaned.partition(', ')
    pieces = re.split(r'[/.-]', date_part)
    if len(pieces) != 3 or (len(pieces[date_order.index('y')]) != 4 and not (len(pieces[date_order.index('y')]) == 2 and year_century is not None)):
        return None, 'Unsupported date or two-digit year; original retained'
    values = dict(zip(date_order, map(int, pieces)))
    if len(pieces[date_order.index('y')]) == 2:
        values['y'] += year_century
    clock = None
    for fmt in ('%H:%M:%S', '%H:%M', '%I:%M:%S %p', '%I:%M %p'):
        try:
            clock = datetime.strptime(time_part.strip(), fmt)
            break
        except ValueError:
            pass
    if clock is None:
        return None, 'Unrecognized time'
    try:
        naive = datetime(values['y'], values['m'], values['d'], clock.hour, clock.minute, clock.second)
    except ValueError:
        return None, 'Invalid calendar date'
    if zone is None:
        return None, 'Timezone not supplied'
    # Reject DST gaps and ambiguous times; never silently choose one occurrence.
    candidates = {naive.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc)
                  for fold in (0, 1)
                  if naive.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None) == naive}
    if len(candidates) != 1:
        return None, 'Ambiguous or nonexistent local time'
    return candidates.pop().isoformat(timespec='microseconds').replace('+00:00', 'Z'), 'Operator-supplied date order and timezone'


def import_chat(root, db, source, date_order, timezone_name=None, label=None, year_century=None):
    if year_century is not None and (type(year_century) is not int or not 1000 <= year_century <= 9900 or year_century % 100):
        raise UserError('Year century must be an explicitly supplied multiple of 100 from 1000 to 9900.')
    if date_order not in {'dmy', 'mdy', 'ymd'}:
        raise UserError('Specify date order dmy, mdy, or ymd.')
    try:
        zone = ZoneInfo(timezone_name) if timezone_name else None
    except ZoneInfoNotFoundError as exc:
        raise UserError('Unknown timezone; use an IANA name such as America/New_York.') from exc
    path = Path(source).expanduser()
    if not path.is_file() or path.suffix.lower() != '.txt':
        raise UserError('Supply the WhatsApp exported .txt file; import media separately.')
    eid, _, _ = import_evidence(root, db, path, 'android', label or 'WhatsApp chat export', 64 * 1024**2, expand_archives=False)
    file = db.execute('SELECT * FROM files WHERE evidence_id=?', (eid,)).fetchone()
    text = (root / 'evidence' / eid / file['path']).read_text(encoding='utf-8-sig')
    pattern = re.compile(r'^\[?(\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4},\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[APap][Mm])?)(?:\]\s*|\s+-\s+)(.*)$')
    entries, current, unparsed = [], None, []
    for number, line in enumerate(text.splitlines(), 1):
        clean = line.lstrip('\u200e\u200f').replace('\u202f', ' ').replace('\u00a0', ' ')
        match = pattern.match(clean)
        if match:
            current = {'line': number, 'end': number, 'date': match[1], 'content': match[2], 'raw': line}
            entries.append(current)
        elif current:
            current['content'] += '\n' + line
            current['raw'] += '\n' + line
            current['end'] = number
        else:
            unparsed.append(number)
    run_id = uuid.uuid4().hex[:12]
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,records) VALUES(?,?,?,?,?,?)',
               (run_id, eid, 'whatsapp-export/2', now(), 'running', 0))
    begin_run_index(db, run_id)
    count = 0
    for entry in entries:
        sender, separator, body = entry['content'].partition(': ')
        # Text exports do not supply stable message IDs or authenticated identity.
        when, semantics = local_time(entry['date'], date_order, zone, year_century)
        data = {'original': entry, 'message': metadata('whatsapp', file['path'], sender if separator else '',
                    direction='unknown', label=label or path.stem, attachment_status='not_assessed'),
                'date_order': date_order, 'year_century': year_century, 'timezone': timezone_name, 'timestamp_semantics': semantics,
                'source_time_precision': 'second' if entry['date'].partition(', ')[2].count(':') >= 2 else 'minute',
                'source_kind': 'user_export', 'limitation': 'Text export is editable; completeness and sender identity are not independently established.'}
        scope_message(data, eid, file['path'])
        count += add_artifact(db, eid, file['id'], 'messages' if separator else 'message_events', when, entry['date'],
                              'WhatsApp · ' + (sender if separator else 'system event'), body if separator else entry['content'],
                              f'lines={entry["line"]}-{entry["end"]}', 'whatsapp-export/2', data, run_id=run_id)
    status = 'partial' if unparsed or not entries else 'complete'
    detail = {'date_order': date_order, 'year_century': year_century, 'timezone': timezone_name, 'unparsed_preamble_lines': unparsed,
              'coverage': 'Single exported chat; attachments and completeness not established. Unsupported or ambiguous timestamps remain undated.'}
    db.execute('UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?',
               (now(), status, count, json_text(detail), run_id))
    audit(db, 'chat.imported', {'evidence_id': eid, 'run_id': run_id, 'records': count, **detail})
    db.commit()
    return {'evidence_id': eid, 'run_id': run_id, 'records': count, 'status': status, **detail}
