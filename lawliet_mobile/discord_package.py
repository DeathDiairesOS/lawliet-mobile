"""Offline Discord account-package intake; never an account or CDN collector.

Schema reference: Discord's "Your Discord Data Package", Messages section
https://support.discord.com/hc/en-us/articles/360004957991
The current format is messages.json; the older official localized documentation
describes messages.csv with ID, Timestamp, Contents and Attachments columns.
Unsupported layouts remain preserved and are reported, never guessed.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .core import (UserError, add_artifact, audit, begin_run_index, digest,
                   extract_archive, import_evidence, json_text, now)
from .messages import metadata, scope_message
from .parsed_import import _artifact_json
from .runner_lease import lease, ownership

PARSER = 'discord-package/1'
MAX_JSON = 64 * 1024**2
MAX_RECORD = 1024**2
MAX_RECORDS = 1_000_000
MAX_ISSUES = 200
FIELDS = {'ID', 'Timestamp', 'Contents', 'Attachments'}
LIMITATIONS = [
    'A Discord account data package contains the requesting account\'s sent messages; it is not both sides of a conversation.',
    'Manually deleted messages are excluded by Discord. No deleted-message recovery or complete account history is established.',
    'Attachment URLs are retained references only; attachment bytes were not downloaded or acquired by this importer.',
    'Package contents are editable. Account, sender, channel and message identifiers are supplied claims, not independently authenticated.',
    'Only supported message transcripts and their account/channel metadata are parsed. Other package sections remain preserved but unparsed.',
    'Timestamps without an explicit offset remain undated unless the examiner supplies an IANA timezone. No timezone is inferred from message IDs.',
    'Indexed counts are source observations. Duplicate IDs in separate transcripts are preserved; counts do not establish distinct-message totals.',
]


def _identity(entries):
    return hashlib.sha256(json_text(sorted(entries)).encode()).hexdigest()


def _source_identity(source, max_bytes, max_files):
    if source.is_symlink() or not (source.is_file() or source.is_dir()):
        raise UserError('Select a regular Discord data-package ZIP or extracted directory; symlinks are not accepted.')
    if source.is_file():
        if source.stat().st_size > max_bytes:
            raise UserError('Discord package exceeds the intake byte limit.')
        if not zipfile.is_zipfile(source):
            raise UserError('Discord package file must be a ZIP; select its extracted directory otherwise.')
        return digest(source), 'zip'
    entries, total = [], 0
    for folder, dirs, names in os.walk(source, followlinks=False):
        for name in dirs + names:
            if (Path(folder) / name).is_symlink():
                raise UserError('Discord package contains a symlink; use a regular-file extraction.')
        for name in names:
            path = Path(folder) / name
            if not path.is_file():
                raise UserError('Discord package contains a special file.')
            size = path.stat().st_size
            total += size
            if total > max_bytes or len(entries) >= max_files:
                raise UserError('Discord package exceeds the intake byte/file limits.')
            entries.append([path.relative_to(source).as_posix(), digest(path), size])
    return _identity(entries), 'directory'


def _snowflake(value):
    if type(value) is int:
        value = str(value)
    return value if isinstance(value, str) and re.fullmatch(r'[0-9]{1,20}', value) and 0 < int(value) < 2**64 else ''


def _read_json(path):
    if path.stat().st_size > MAX_JSON:
        raise UserError('JSON exceeds the 64 MiB per-file parsing limit; original remains preserved.')
    return _artifact_json(path.read_text(encoding='utf-8-sig'))


def _time(raw, zone):
    result = {'original': raw, 'timezone': None, 'precision': None, 'basis': 'unrecognized timestamp'}
    pattern = r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?'
    match = re.fullmatch(pattern, raw)
    if not match:
        return None, result
    fraction, offset = match.groups()
    result['precision'] = ('fractional_seconds:' + str(len(fraction))) if fraction else 'second'
    if fraction and len(fraction) > 6:
        result['basis'] = 'sub-microsecond normalization unsupported; original retained'
        return None, result
    try:
        parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError:
        result['basis'] = 'invalid calendar timestamp'
        return None, result
    if offset:
        result.update(timezone=offset, basis='explicit source UTC offset')
        value = parsed.astimezone(timezone.utc)
    elif zone is not None:
        candidates = {parsed.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc)
                      for fold in (0, 1)
                      if parsed.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None) == parsed}
        result['timezone'] = zone.key
        if len(candidates) != 1:
            result['basis'] = 'examiner timezone produces ambiguous or nonexistent local time'
            return None, result
        value = candidates.pop()
        result['basis'] = 'examiner-supplied timezone'
    else:
        result['basis'] = 'timezone absent from source and not supplied by examiner'
        return None, result
    return value.isoformat(timespec='microseconds' if fraction else 'seconds').replace('+00:00', 'Z'), result


def _records(path):
    if path.suffix.lower() == '.json':
        rows = _read_json(path)
        if not isinstance(rows, list):
            raise UserError('Unsupported messages.json layout: expected an array of message objects.')
        for index, row in enumerate(rows):
            yield {'json_pointer': '/' + str(index), 'record': index + 1}, row
    else:
        with path.open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream, strict=True)
            fields = reader.fieldnames
            if not fields or len(fields) != len(set(fields)) or not FIELDS <= set(fields):
                raise UserError('Unsupported CSV header: unique ID, Timestamp, Contents and Attachments columns are required.')
            for index, row in enumerate(reader, 1):
                yield {'csv_record': index, 'physical_line_end': reader.line_num}, row


def _validate(row):
    if not isinstance(row, dict) or not FIELDS <= set(row) or None in row:
        raise UserError('Unsupported message row: ID, Timestamp, Contents and Attachments fields are required.')
    if not _snowflake(row['ID']):
        raise UserError('Message ID is not an exact unsigned Discord identifier.')
    if not isinstance(row['Timestamp'], str) or not isinstance(row['Contents'], str):
        raise UserError('Message Timestamp and Contents must be strings.')
    if not isinstance(row['Attachments'], str):
        raise UserError('Unsupported Attachments shape; expected the package CDN-reference string.')
    if len(json_text(row).encode()) > MAX_RECORD:
        raise UserError('Message exceeds the 1 MiB record limit.')


def import_discord_package(root, db, source, label=None, *, timezone_name=None,
                           max_bytes=20 * 1024**3, max_files=100000):
    """Preserve a package and index supported messages into the existing case.

    Explicitly configured timezone affects interpretation, so it is part of the
    rerun identity. A repeated unchanged package/config returns its existing run.
    The result's source_id is the existing run/source selector, not another DB.
    """
    if type(max_bytes) is not int or max_bytes < 1 or type(max_files) is not int or max_files < 1:
        raise UserError('Intake byte/file limits must be positive integers.')
    try:
        zone = ZoneInfo(timezone_name) if timezone_name else None
    except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
        raise UserError('Supply a valid IANA timezone, or omit it to preserve timezone-less values undated.') from exc
    source = Path(source).expanduser()
    root = Path(root)
    if source.is_dir() and (source.resolve() == root.resolve() or source.resolve() in root.resolve().parents):
        raise UserError('The package directory must not contain the case workspace.')
    with lease(root, db):
        identity, source_kind = _source_identity(source, max_bytes, max_files)
        config = {'input_identity': identity, 'input_kind': source_kind, 'timezone': timezone_name}
        for previous in db.execute("SELECT * FROM runs WHERE engine=? AND status IN ('complete','partial') ORDER BY started_at DESC", (PARSER,)):
            detail = json.loads(previous['detail'])
            if detail.get('configuration') == config:
                return {**detail['result'], 'status': 'already_imported', 'retained_status': previous['status']}
        archive_hash = None
        if source_kind == 'zip':
            # Core's archive intake preserves extracted members but not ZIP bytes.
            # Assemble both once, then use the ordinary immutable intake boundary.
            with tempfile.TemporaryDirectory(prefix='lawliet-discord-') as temporary:
                stage = Path(temporary)
                (stage / 'original').mkdir()
                archive = stage / 'original' / source.name
                copied = 0
                with source.open('rb') as incoming, archive.open('xb') as outgoing:
                    while chunk := incoming.read(1024**2):
                        copied += len(chunk)
                        if copied > max_bytes:
                            raise UserError('Discord archive grew beyond the intake byte limit while copying.')
                        outgoing.write(chunk)
                if digest(archive) != identity:
                    raise UserError('Discord archive changed before preservation; retry with a stable input.')
                extracted = stage / 'extracted'
                extracted.mkdir()
                remaining = max_bytes - archive.stat().st_size
                if remaining < 1 or max_files < 2:
                    raise UserError('Intake limits must cover both retained ZIP and extracted members.')
                extract_archive(archive, extracted, remaining, max_files - 1)
                eid, retained_files, retained_bytes = import_evidence(root, db, stage, 'unknown', label or 'Discord account data package', max_bytes, max_files, expand_archives=False)
            archive_hash = identity
            db.execute('UPDATE evidence SET input_path=?,container_sha256=? WHERE id=?', (str(source.absolute()), identity, eid))
            audit(db, 'discord_package.archive_preserved', {'evidence_id': eid, 'input_path': str(source.absolute()), 'sha256': identity, 'archive_path': 'original/' + source.name})
            db.commit()
        else:
            eid, retained_files, retained_bytes = import_evidence(root, db, source, 'unknown', label or 'Discord account data package', max_bytes, max_files, expand_archives=False)
        return _parse(root, db, eid, config, zone, retained_files, retained_bytes, archive_hash)


def _parse(root, db, eid, config, zone, retained_files, retained_bytes, archive_hash):
    run = uuid.uuid4().hex[:12]
    owner = ownership()
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)',
               (run, eid, PARSER, now(), 'running', json_text({'runner_ownership': owner})))
    begin_run_index(db, run)
    audit(db, 'analysis.started', {'run_id': run, 'evidence_id': eid, 'engine': PARSER, 'runner_ownership': owner})
    db.commit()
    files = list(db.execute('SELECT * FROM files WHERE evidence_id=? ORDER BY path', (eid,)))
    issues, issue_total, reports, metadata_files = [], 0, [], set()
    metadata_cache = {}
    count = undated = skipped = observed = 0
    evidence_root = root / 'evidence' / eid

    def issue(path, message, location=None):
        nonlocal issue_total
        issue_total += 1
        if len(issues) < MAX_ISSUES:
            issues.append({'path': path, 'location': location, 'error': message})

    def reference(file):
        return {'file_id': file['id'], 'path': file['path'], 'sha256': file['sha256']}

    def metadata_json(file):
        metadata_files.add(file['path'])
        if file['path'] in metadata_cache:
            return metadata_cache[file['path']]
        try:
            if file['size'] > MAX_RECORD:
                raise UserError('Metadata exceeds the 1 MiB limit; retained source remains available.')
            value = _read_json(evidence_root / file['path'])
            if not isinstance(value, dict):
                raise UserError('Expected a metadata JSON object.')
            metadata_cache[file['path']] = value
            return value
        except (ValueError, UserError, OSError, RecursionError) as exc:
            issue(file['path'], str(exc))
            metadata_cache[file['path']] = {}
            return {}

    try:
        if config['input_kind'] == 'directory' and _identity([[f['path'], f['sha256'], f['size']] for f in files]) != config['input_identity']:
            raise UserError('Package changed between identity check and intake; evidence retained, parsing refused.')
        by_parent, accounts = {}, {}
        for file in files:
            item = Path(file['path'])
            siblings = by_parent.setdefault(item.parent, {})
            if item.name.lower() in siblings:
                issue(file['path'], 'Case-insensitive duplicate metadata/transcript filename; ambiguous metadata will not be selected.')
                siblings[item.name.lower()] = None
            else:
                siblings[item.name.lower()] = file
            if item.parent.name.lower() == 'account' and item.name.lower() == 'user.json':
                accounts.setdefault(item.parent.parent, []).append(file)
        transcripts = [f for f in files if Path(f['path']).name.lower() in {'messages.json', 'messages.csv'} and Path(f['path']).parent.parent.name.lower() == 'messages']
        if not transcripts:
            issue('', 'No supported Messages/<channel>/messages.json or messages.csv transcript found; preserved package may be empty or an unsupported format.')
        db.execute('SAVEPOINT discord_records')
        for file in transcripts:
            if observed >= MAX_RECORDS:
                issue(file['path'], 'Total parsing limit of 1,000,000 message records reached; remaining source is preserved.')
                break
            path = Path(file['path'])
            package_root = path.parent.parent.parent
            siblings = by_parent[path.parent]
            channel_file = siblings.get('channel.json')
            channel = metadata_json(channel_file) if channel_file else {}
            channel_id = _snowflake(channel.get('id'))
            folder_id = _snowflake(path.parent.name.removeprefix('c'))
            if channel_id and folder_id and channel_id != folder_id:
                issue(file['path'], 'Channel metadata ID conflicts with the channel folder; no channel identity selected.')
                channel_id = ''
            elif not channel_id:
                channel_id = folder_id
            account_candidates = accounts.get(package_root, [])
            account_file = account_candidates[0] if len(account_candidates) == 1 else None
            account = metadata_json(account_file) if account_file else {}
            if len(account_candidates) > 1:
                issue(file['path'], 'Multiple account metadata files; sender account ID not selected.')
            account_id = _snowflake(account.get('id'))
            channel_name = channel.get('name') if isinstance(channel.get('name'), str) else ''
            channel_label = channel_name or channel_id or path.parent.name
            channel_ref = reference(channel_file) if channel_file else None
            account_ref = reference(account_file) if account_file else None
            report = {**reference(file), 'format': path.suffix.lower().lstrip('.'), 'records': 0, 'skipped_records': 0, 'undated_records': 0, 'channel_id': channel_id, 'account_id': account_id,
                      'metadata_missing': [name for name, value in [('account_id', account_id), ('channel_id', channel_id)] if not value]}
            reports.append(report)
            try:
                for location, row in _records(evidence_root / path):
                    observed += 1
                    if observed > MAX_RECORDS:
                        issue(file['path'], 'Total parsing limit reached; remaining source is preserved.', location)
                        break
                    try:
                        _validate(row)
                    except UserError as exc:
                        skipped += 1
                        report['skipped_records'] += 1
                        issue(file['path'], str(exc), location)
                        continue
                    when, time_info = _time(row['Timestamp'], zone)
                    attachments = row['Attachments'].split()
                    conversation = 'channel:' + channel_id if channel_id else 'unlinked-source:' + file['path']
                    data = {'schema': PARSER, 'original': row, 'source_kind': 'discord_account_package',
                            'timestamp_details': time_info, 'source_time_precision': time_info['precision'],
                            'source_record': location, 'source_sha256': file['sha256'],
                            'channel_metadata_source': channel_ref, 'account_metadata_source': account_ref,
                            'channel_type': channel.get('type') if type(channel.get('type')) is int else None,
                            'message': metadata('discord', conversation, account_id, '', 'outgoing',
                                label=channel_label, account_id=account_id, channel_id=channel_id,
                                source_row_id=_snowflake(row['ID']), timestamp_field='Timestamp',
                                direction_basis='Discord account package documents these as requester-sent messages; source claim, not independently authenticated.',
                                sender_basis='Account/user.json id' if account_id else 'Account ID unavailable; sender not inferred.',
                                attachment_status='references_only_not_acquired', attachment_references=attachments,
                                row_count_note='Separate transcripts can repeat message IDs; records are preserved source observations, not distinct-message totals.',
                                scope_note='Account package contains requester-sent messages only; recipients\' messages and deleted messages are not represented.'),
                            'limitations': LIMITATIONS[:4]}
                    scope_message(data, eid, 'discord-package:' + package_root.as_posix() + ':' + account_id)
                    locator = 'json_pointer=' + location['json_pointer'] if 'json_pointer' in location else 'csv_record=' + str(location['csv_record']) + ';physical_line_end=' + str(location['physical_line_end'])
                    added = add_artifact(db, eid, file['id'], 'messages', when, row['Timestamp'],
                                         'Discord · outgoing · ' + channel_label, row['Contents'], locator, PARSER, data, run_id=run)
                    count += added
                    report['records'] += added
                    if when is None:
                        undated += added
                        report['undated_records'] += added
            except (ValueError, UserError, OSError, csv.Error, RecursionError) as exc:
                issue(file['path'], str(exc))
                report['error'] = str(exc)
        status = 'partial' if issue_total else 'complete'
        result = {'status': status, 'evidence_id': eid, 'run_id': run, 'source_id': run, 'parser': PARSER,
                  'records': count, 'retained_files': retained_files, 'retained_bytes': retained_bytes,
                  'archive_sha256': archive_hash, 'limitations': LIMITATIONS,
                  'coverage': {'message_files': len(transcripts), 'processed_files': len(reports),
                      'messages_indexed': count, 'records_skipped': skipped, 'undated_records': undated,
                      'empty_supported_transcripts': sum(r['records'] == 0 and r['skipped_records'] == 0 and 'error' not in r for r in reports),
                      'other_preserved_files': len(files) - len(transcripts) - len(metadata_files),
                      'attachments_acquired': 0, 'issue_count': issue_total, 'issues': issues,
                      'issues_truncated': issue_total > len(issues), 'reports': reports}}
        detail = {'runner_ownership': owner, 'configuration': config, 'result': result,
                  'coverage': result['coverage'], 'limitations': LIMITATIONS}
        db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?', (status, now(), count, json_text(detail), run))
        audit(db, 'discord_package.imported', {'evidence_id': eid, 'run_id': run, 'records': count, 'status': status, 'configuration': config, 'issue_count': issue_total})
        db.execute('RELEASE discord_records')
        db.commit()
        return result
    except (ValueError, UserError, OSError, csv.Error, RecursionError, sqlite3.Error) as exc:
        db.rollback()
        db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?', ('failed', now(), 0, json_text({'runner_ownership': owner, 'configuration': config, 'error': str(exc)}), run))
        audit(db, 'discord_package.failed', {'evidence_id': eid, 'run_id': run, 'error': str(exc), 'original_retained': True})
        db.commit()
        raise UserError(f'Discord import failed; original evidence {eid} and run {run} retained. {exc}') from exc
