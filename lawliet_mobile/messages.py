"""Message normalization and explicit, source-scoped conversation identities."""
import hashlib
import json
import os
import re
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .core import UserError, add_artifact, audit, begin_run_index, digest, extract_archive, import_evidence, json_text, now


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
    parts = re.split(r',\s*', cleaned, maxsplit=1)
    date_part, time_part = (parts + [''])[:2]
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


_CHAT_HEADER = re.compile(r'^\[?(\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4},\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[APap][Mm])?)(?:\]\s*|\s+-\s+)(.*)$')
_CHAT_MAX_BYTES = 64 * 1024**2


def _chat_line(line):
    return line.lstrip('\u200e\u200f').replace('\u202f', ' ').replace('\u00a0', ' ')


def _chat_entries(path, unparsed):
    current = None
    with path.open(encoding='utf-8-sig') as handle:
        for number, raw in enumerate(handle, 1):
            line = raw.rstrip('\r\n')
            match = _CHAT_HEADER.match(_chat_line(line))
            if match:
                if current:
                    yield current
                current = {'line': number, 'end': number, 'date': match[1], 'content': match[2], 'raw': line}
            elif current:
                current['content'] += '\n' + line
                current['raw'] += '\n' + line
                current['end'] = number
            else:
                unparsed.append(number)
    if current:
        yield current


def _chat_attachment(body, files_by_name):
    """Resolve explicit export markers only, within this one retained bundle."""
    first = _chat_line(body.split('\n', 1)[0]).strip()
    if re.fullmatch(r'<?(?:media|image|video|audio|sticker|document|contact|GIF) omitted>?', first, re.I):
        return {'status': 'omitted_from_export', 'original_reference': first}
    match = re.fullmatch(r'<attached:\s*(.*?)>', first, re.I) or re.fullmatch(r'(.*?)\s*\(file attached\)', first, re.I)
    if not match:
        return {'status': 'not_indicated'}
    reference = match[1].strip()
    item = {'status': 'not_acquired', 'original_reference': first, 'filename': reference}
    if (not reference or reference in {'.', '..'} or any(ord(c) < 32 or ord(c) == 127 for c in reference)
            or any(c in reference for c in '/\\:')):
        return {**item, 'status': 'unsupported_reference'}
    matches = files_by_name.get(reference, [])
    if len(matches) > 1:
        return {**item, 'status': 'ambiguous_path', 'candidate_paths': [file['path'] for file in matches]}
    if matches:
        file = matches[0]
        return {**item, 'status': 'available', 'file_id': file['id'], 'source_file': file['path'],
                'logical_path': file['logical_path'], 'sha256': file['sha256'], 'bytes': file['size'],
                'relationship': 'Unique exact filename in supplied chat bundle; export association is not independently authenticated.'}
    return item


def _reusable_chat(root, db, path, configuration, max_bytes, max_files):
    """Opt-in replay. Never merge different imports or interpretation settings."""
    for run in db.execute("SELECT r.*,e.input_path,e.container_sha256 FROM runs r JOIN evidence e ON e.id=r.evidence_id WHERE e.input_path=? AND r.engine IN ('whatsapp-export/2','whatsapp-export/3') AND r.status IN ('complete','partial') ORDER BY r.rowid DESC", (str(path.resolve()),)):
        detail = json.loads(run['detail'] or '{}')
        if detail.get('intake_configuration') != configuration:
            continue
        files = list(db.execute('SELECT * FROM files WHERE evidence_id=?', (run['evidence_id'],)))
        if len(files) > max_files or sum(file['size'] for file in files) > max_bytes:
            raise UserError('Retained export exceeds the requested intake limits.')
        if path.is_file():
            unchanged = digest(path) == run['container_sha256']
        else:
            expected = {file['path']: file['sha256'] for file in files}
            observed = set()
            unchanged = True
            for current, dirs, names in os.walk(path, followlinks=False):
                for name in dirs + names:
                    if (Path(current) / name).is_symlink():
                        raise UserError('Evidence contains symlinks; supply a regular-file extraction.')
                for name in names:
                    item = Path(current) / name
                    relative = item.relative_to(path).as_posix()
                    observed.add(relative)
                    if not item.is_file() or relative not in expected or digest(item) != expected[relative]:
                        unchanged = False
                        break
                if not unchanged:
                    break
            unchanged = unchanged and observed == set(expected)
        if not unchanged:
            continue
        for file in files:
            retained = root / 'evidence' / run['evidence_id'] / file['path']
            if (retained.is_symlink() or not retained.is_file()
                    or not retained.resolve().is_relative_to((root / 'evidence' / run['evidence_id']).resolve())
                    or digest(retained) != file['sha256']):
                raise UserError('Retained WhatsApp evidence integrity check failed; replay refused.')
        return {'evidence_id': run['evidence_id'], 'run_id': run['id'], 'records': run['records'],
                'status': run['status'], **detail, 'reused': True}
    return None


def _import_chat_archive(root, db, path, label, max_bytes, max_files):
    """Retain container bytes and members through one ordinary intake boundary.

    Member paths stay unchanged for transcript selection and attachment links.
    The reserved container is explicitly excluded from export attachments.
    """
    archive_hash = digest(path)
    relative = Path('_lawliet_original_archive') / path.name
    with tempfile.TemporaryDirectory(prefix='lawliet-whatsapp-') as temporary:
        stage = Path(temporary)
        retained = stage / relative
        retained.parent.mkdir()
        size = 0
        with path.open('rb') as source, retained.open('xb') as target:
            while chunk := source.read(1024**2):
                size += len(chunk)
                if size > max_bytes:
                    raise UserError('WhatsApp ZIP exceeds the intake byte limit while copying.')
                target.write(chunk)
        if digest(retained) != archive_hash or digest(path) != archive_hash:
            raise UserError('WhatsApp ZIP changed during preservation; retry with a stable input.')
        if max_files < 2 or max_bytes <= size:
            raise UserError('Intake limits must cover the original WhatsApp ZIP and its extracted members.')
        # Do not allow supplied archive content to impersonate the container.
        with zipfile.ZipFile(retained) as archive:
            if any(PurePosixPath(info.filename).parts[:1] == ('_lawliet_original_archive',) for info in archive.infolist()):
                raise UserError('WhatsApp ZIP uses the reserved original-container path; intake refused.')
        extract_archive(retained, stage, max_bytes - size, max_files - 1)
        eid, _, _ = import_evidence(root, db, stage, 'android', label or 'WhatsApp chat export',
                                    max_bytes, max_files, expand_archives=False)
    db.execute('UPDATE evidence SET input_path=?,container_sha256=? WHERE id=?',
               (str(path.resolve()), archive_hash, eid))
    audit(db, 'chat.archive_preserved', {'evidence_id': eid, 'input_path': str(path.resolve()),
                                        'container_sha256': archive_hash,
                                        'container_path': relative.as_posix()})
    db.commit()
    return eid, relative.as_posix()


def import_chat(root, db, source, date_order, timezone_name=None, label=None, year_century=None,
                *, chat_path=None, max_bytes=1024**3, max_files=10000, reuse=False):
    if year_century is not None and (type(year_century) is not int or not 1000 <= year_century <= 9900 or year_century % 100):
        raise UserError('Year century must be an explicitly supplied multiple of 100 from 1000 to 9900.')
    if date_order not in {'dmy', 'mdy', 'ymd'}:
        raise UserError('Specify date order dmy, mdy, or ymd.')
    try:
        zone = ZoneInfo(timezone_name) if timezone_name else None
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise UserError('Unknown timezone; use an IANA name such as America/New_York.') from exc
    if type(max_bytes) is not int or max_bytes < 1 or type(max_files) is not int or not 1 <= max_files <= 100000:
        raise UserError('Specify positive intake bytes and 1–100000 files.')
    path = Path(source).expanduser()
    if path.is_symlink():
        raise UserError('Evidence input must not be a symlink.')
    plain = path.is_file() and path.suffix.lower() == '.txt'
    if not (plain or path.is_dir() or path.is_file() and zipfile.is_zipfile(path)):
        raise UserError('Supply an exported WhatsApp .txt, ZIP, or regular-file export directory.')
    if path.is_file() and path.stat().st_size > (min(max_bytes, _CHAT_MAX_BYTES) if plain else max_bytes):
        raise UserError('Evidence exceeds intake size limit.')
    if chat_path is not None:
        if not isinstance(chat_path, str) or not chat_path or '\\' in chat_path or ':' in chat_path:
            raise UserError('Transcript path must be a relative path inside the export.')
        relative = PurePosixPath(chat_path)
        if relative.is_absolute() or '..' in relative.parts or any(ord(c) < 32 for c in chat_path):
            raise UserError('Transcript path must be a relative path inside the export.')
        chat_path = relative.as_posix()
    configuration = {'schema': 3, 'date_order': date_order, 'year_century': year_century,
                     'timezone': timezone_name, 'label': label, 'chat_path': chat_path}
    is_archive = path.is_file() and not plain
    if is_archive:
        configuration['archive_preservation'] = 'container_and_members'
    if reuse:
        existing = _reusable_chat(root, db, path, configuration, max_bytes, max_files)
        if existing:
            return existing
    archive_path = None
    if is_archive:
        eid, archive_path = _import_chat_archive(root, db, path, label, max_bytes, max_files)
    else:
        eid, _, _ = import_evidence(root, db, path, 'android', label or 'WhatsApp chat export',
                                    min(max_bytes, _CHAT_MAX_BYTES) if plain else max_bytes, max_files,
                                    expand_archives=False)
    files = list(db.execute('SELECT * FROM files WHERE evidence_id=? ORDER BY path', (eid,)))
    engine = 'whatsapp-export/2' if plain else 'whatsapp-export/3'
    run_id = uuid.uuid4().hex[:12]
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,records) VALUES(?,?,?,?,?,?)',
               (run_id, eid, engine, now(), 'running', 0))
    begin_run_index(db, run_id)
    count, chat_records, media_records, undated = 0, 0, 0, 0
    unparsed, attachment_counts = [], {}
    detail = {'date_order': date_order, 'year_century': year_century, 'timezone': timezone_name,
              'intake_configuration': configuration,
              'coverage': 'One supplied chat export, not a complete application acquisition. Only explicit English attachment markers are linked; supplied media may be incomplete. Editable export contents and sender labels are not authenticated. Unsupported or ambiguous timestamps remain undated.'}
    if archive_path:
        archive_file = next(file for file in files if file['path'] == archive_path)
        detail['original_archive'] = {'file_id': archive_file['id'], 'path': archive_file['path'],
                                      'sha256': archive_file['sha256'], 'bytes': archive_file['size']}
    try:
        if chat_path:
            candidates = [file for file in files if file['path'] == chat_path and file['path'].lower().endswith('.txt')]
        elif plain:
            candidates = files
        else:
            candidates = []
            for candidate in files:
                if not candidate['path'].lower().endswith('.txt') or candidate['size'] > _CHAT_MAX_BYTES:
                    continue
                with (root / 'evidence' / eid / candidate['path']).open('rb') as handle:
                    sample = handle.read(65536).decode('utf-8-sig', errors='replace')
                if any(_CHAT_HEADER.match(_chat_line(line)) for line in sample.splitlines()):
                    candidates.append(candidate)
        if len(candidates) != 1:
            raise UserError('Export must contain one recognizable chat transcript; supply chat_path to select a relative .txt path when needed.')
        file = candidates[0]
        if file['size'] > _CHAT_MAX_BYTES:
            raise UserError('Chat transcript exceeds the 64 MiB parsing limit.')
        detail['transcript'] = {'file_id': file['id'], 'path': file['path'], 'sha256': file['sha256']}
        attachments = [candidate for candidate in files if candidate['id'] != file['id'] and candidate['path'] != archive_path]
        files_by_name = {}
        for candidate in attachments:
            files_by_name.setdefault(PurePosixPath(candidate['path']).name, []).append(candidate)
        for entry in _chat_entries(root / 'evidence' / eid / file['path'], unparsed):
            sender, separator, body = entry['content'].partition(': ')
            when, semantics = local_time(entry['date'], date_order, zone, year_century)
            attachment = _chat_attachment(body, files_by_name) if separator else {'status': 'not_indicated'}
            if separator:
                attachment_counts[attachment['status']] = attachment_counts.get(attachment['status'], 0) + 1
            if when is None:
                undated += 1
            data = {'original': entry, 'message': metadata('whatsapp', file['path'], sender if separator else '',
                        direction='unknown', label=label or path.stem, attachment_status=attachment['status']),
                    'date_order': date_order, 'year_century': year_century, 'timezone': timezone_name,
                    'timestamp_semantics': semantics,
                    'source_time_precision': 'second' if re.split(r',\s*', entry['date'], maxsplit=1)[-1].count(':') >= 2 else 'minute',
                    'source_kind': 'user_export',
                    'limitation': 'Text export is editable; completeness and sender identity are not independently established. Attachment markers may be manually edited.'}
            if attachment['status'] != 'not_indicated':
                data['attachment'] = attachment
            scope_message(data, eid, file['path'])
            count += add_artifact(db, eid, file['id'], 'messages' if separator else 'message_events', when, entry['date'],
                                  'WhatsApp · ' + (sender if separator else 'system event'), body if separator else entry['content'],
                                  f'lines={entry["line"]}-{entry["end"]}', engine, data, run_id=run_id)
            chat_records += 1
        if not plain:
            from .media import index_media
            media_records = index_media(root, db, eid, attachments, 'native/whatsapp-export/3', run_id=run_id)
            count += media_records
        status = 'partial' if unparsed or not chat_records else 'complete'
        detail.update(unparsed_preamble_lines=unparsed, chat_records=chat_records, media_records=media_records,
                      undated_records=undated, attachments=attachment_counts, retained_files=len(files))
    except (UserError, UnicodeError, OSError, ValueError) as exc:
        detail.update(error=str(exc), unparsed_preamble_lines=unparsed, chat_records=chat_records,
                      media_records=media_records, undated_records=undated, attachments=attachment_counts)
        db.execute('UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?',
                   (now(), 'failed', count, json_text(detail), run_id))
        audit(db, 'chat.import_failed', {'evidence_id': eid, 'run_id': run_id, **detail})
        db.commit()
        if isinstance(exc, UserError):
            raise
        raise UserError('WhatsApp export could not be fully parsed; retained evidence and failure details are available.') from exc
    db.execute('UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?',
               (now(), status, count, json_text(detail), run_id))
    audit(db, 'chat.imported', {'evidence_id': eid, 'run_id': run_id, 'records': count, **detail})
    db.commit()
    return {'evidence_id': eid, 'run_id': run_id, 'records': count, 'status': status, **detail, 'reused': False}
