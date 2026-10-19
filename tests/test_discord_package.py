"""Synthetic, independently asserted account-package messages and source locators."""
import csv
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.core import UserError, connect, create_case, digest, verify
from lawliet_mobile.discord_package import PARSER, import_discord_package
from lawliet_mobile.messages import conversations


@unittest.skipUnless(os.name == 'posix', 'POSIX case ownership')
class DiscordPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'A')
        self.package = self.base / 'package'
        self.package.mkdir()

    def put(self, relative, data):
        path = self.package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
        return path

    def row(self, identifier='1300000000000000001', timestamp='2026-10-17 14:35:02+02:00', content='Known outgoing message 😀', attachments=''):
        return {'ID': identifier, 'Timestamp': timestamp, 'Contents': content, 'Attachments': attachments}

    def standard(self):
        self.put('Account/user.json', {'id': '1200000000000000001', 'username': 'synthetic-owner', 'email': 'private-not-copied@example.invalid'})
        self.put('Messages/c1100000000000000001/channel.json', {'id': '1100000000000000001', 'type': 1, 'recipients': ['1200000000000000001', '1200000000000000002']})
        return self.put('Messages/c1100000000000000001/messages.json', [self.row()])

    def do_import(self, source=None, **kwargs):
        with connect(self.workspace, 'A') as (root, db):
            return import_discord_package(root, db, source or self.package, **kwargs)

    def all_rows(self):
        with connect(self.workspace, 'A') as (_, db):
            return [dict(r) for r in db.execute('SELECT * FROM artifacts ORDER BY source_ref,body')]

    def test_current_json_exact_fields_provenance_and_multichannel_scope(self):
        source = self.standard()
        self.put('Messages/c1100000000000000002/channel.json', {'id': '1100000000000000002', 'name': 'Case review', 'type': 0, 'guild': {'id': '1000000000000000001', 'name': 'Synthetic server'}})
        self.put('Messages/c1100000000000000002/messages.json', [self.row('1300000000000000002', '2026-10-17T12:35:03.123Z', 'Distinct second channel')])
        before = {str(p): digest(p) for p in self.package.rglob('*') if p.is_file()}
        result = self.do_import()
        self.assertEqual((result['status'], result['records']), ('complete', 2))
        with connect(self.workspace, 'A') as (root, db):
            rows = list(db.execute('SELECT a.*,f.sha256,f.path FROM artifacts a JOIN files f ON f.id=a.file_id ORDER BY timestamp'))
            row = rows[0]
            self.assertEqual(row['timestamp'], '2026-10-17T12:35:02Z')
            self.assertEqual(row['timestamp_raw'], '2026-10-17 14:35:02+02:00')
            self.assertEqual(row['source_ref'], 'json_pointer=/0')
            self.assertEqual(row['sha256'], digest(source))
            self.assertEqual(row['body'], self.row()['Contents'])
            data = json.loads(row['data'])
            self.assertEqual(data['original'], self.row())
            self.assertEqual(data['message']['sender'], '1200000000000000001')
            self.assertEqual(data['message']['direction'], 'outgoing')
            self.assertEqual(data['message']['recipient'], '')
            self.assertEqual(data['timestamp_details']['timezone'], '+02:00')
            self.assertNotIn('private-not-copied', row['data'])
            self.assertEqual(data['account_metadata_source']['path'], 'Account/user.json')
            self.assertEqual(data['channel_metadata_source']['path'], 'Messages/c1100000000000000001/channel.json')
            self.assertEqual(rows[1]['timestamp'], '2026-10-17T12:35:03.123000Z')
            self.assertEqual(len(conversations(db, app='discord', run=result['run_id'])), 2)
            self.assertTrue(verify(root, db)['ok'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifact_runs WHERE run_id=?', (result['run_id'],)).fetchone()[0], 2)
        self.assertEqual(before, {str(p): digest(p) for p in self.package.rglob('*') if p.is_file()})

    def test_legacy_csv_multiline_and_attachment_references(self):
        self.standard().unlink()
        path = self.package / 'Messages/c1100000000000000001/messages.csv'
        row = self.row(content='First line, quoted\nSecond line "hello"', attachments='https://cdn.discordapp.com/attachments/1/a.png https://cdn.discordapp.com/attachments/2/b.pdf')
        with path.open('w', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['ID', 'Timestamp', 'Contents', 'Attachments'])
            writer.writeheader()
            writer.writerow(row)
        with patch('socket.create_connection', side_effect=AssertionError('No network allowed')):
            result = self.do_import()
        indexed = self.all_rows()[0]
        self.assertEqual(indexed['body'], row['Contents'])
        self.assertEqual(indexed['source_ref'], 'csv_record=1;physical_line_end=3')
        data = json.loads(indexed['data'])
        self.assertEqual(data['message']['attachment_references'], row['Attachments'].split())
        self.assertEqual(data['message']['attachment_status'], 'references_only_not_acquired')
        self.assertEqual(result['coverage']['attachments_acquired'], 0)

    def test_zip_original_and_extracted_bytes_preserved_and_replay(self):
        source = self.standard()
        package_zip = self.base / 'discord-data.zip'
        with zipfile.ZipFile(package_zip, 'w') as archive:
            for item in self.package.rglob('*'):
                if item.is_file():
                    archive.write(item, 'wrapper/' + item.relative_to(self.package).as_posix())
        original_hash = digest(package_zip)
        first = self.do_import(package_zip)
        second = self.do_import(package_zip)
        self.assertEqual(second['status'], 'already_imported')
        self.assertEqual((second['run_id'], second['evidence_id']), (first['run_id'], first['evidence_id']))
        self.assertEqual(first['archive_sha256'], original_hash)
        with connect(self.workspace, 'A') as (root, db):
            evidence = db.execute('SELECT * FROM evidence').fetchone()
            self.assertEqual(evidence['input_path'], str(package_zip))
            self.assertEqual(evidence['container_sha256'], original_hash)
            self.assertEqual(digest(root / 'evidence' / first['evidence_id'] / 'original/discord-data.zip'), original_hash)
            item = db.execute("SELECT * FROM files WHERE path LIKE '%messages.json'").fetchone()
            self.assertEqual(item['sha256'], digest(source))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0], 1)
            self.assertTrue(verify(root, db)['ok'])

    def test_timezone_missing_and_declared_are_distinct_runs(self):
        source = self.standard()
        source.write_text(json.dumps([self.row(timestamp='2026-10-17 08:15:30')]))
        first = self.do_import()
        self.assertEqual(first['coverage']['undated_records'], 1)
        self.assertIsNone(self.all_rows()[0]['timestamp'])
        second = self.do_import(timezone_name='America/New_York')
        self.assertNotEqual(first['run_id'], second['run_id'])
        with connect(self.workspace, 'A') as (_, db):
            row = db.execute('SELECT a.timestamp,a.data FROM artifacts a JOIN artifact_runs r ON r.artifact_id=a.id WHERE r.run_id=?', (second['run_id'],)).fetchone()
            self.assertEqual(row['timestamp'], '2026-10-17T12:15:30Z')
            self.assertEqual(json.loads(row['data'])['timestamp_details']['basis'], 'examiner-supplied timezone')
        self.assertEqual(self.do_import(timezone_name='America/New_York')['status'], 'already_imported')

    def test_dst_gap_ambiguity_invalid_and_excess_precision_remain_undated(self):
        source = self.standard()
        values = ['2026-03-08 02:30:00', '2026-11-01 01:30:00', '2026-02-31 08:00:00Z', '2026-10-17T08:00:00.123456789Z', 'not a timestamp']
        source.write_text(json.dumps([self.row(str(1300000000000000000 + i), raw) for i, raw in enumerate(values)]))
        result = self.do_import(timezone_name='America/New_York')
        self.assertEqual((result['records'], result['coverage']['undated_records']), (5, 5))
        self.assertTrue(all(row['timestamp'] is None for row in self.all_rows()))
        self.assertEqual({row['timestamp_raw'] for row in self.all_rows()}, set(values))

    def test_partial_malformed_unsupported_and_good_rows_are_explicit(self):
        self.standard()
        self.put('Messages/c1100000000000000002/messages.json', {'messages': [self.row()]})
        self.put('Messages/c1100000000000000003/messages.json', [self.row('1300000000000000003'), {'Contents': 'missing ID'}, self.row(identifier=1.3)])
        result = self.do_import()
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['records'], 2)
        self.assertEqual(result['coverage']['records_skipped'], 2)
        self.assertEqual(result['coverage']['issue_count'], 3)
        self.assertEqual(len(self.all_rows()), 2)
        with connect(self.workspace, 'A') as (root, db):
            self.assertTrue(verify(root, db)['ok'])

    def test_duplicate_json_keys_not_silently_selected(self):
        source = self.standard()
        source.write_text('[{"ID":"1300000000000000001","ID":"1300000000000000002","Timestamp":"2026-10-17T00:00:00Z","Contents":"a","Attachments":""}]')
        result = self.do_import()
        self.assertEqual((result['status'], result['records']), ('partial', 0))
        self.assertIn('Duplicate JSON', result['coverage']['issues'][0]['error'])

    def test_empty_supported_transcript_differs_from_unsupported_package(self):
        self.put('Messages/c1100000000000000001/messages.json', [])
        result = self.do_import()
        self.assertEqual((result['status'], result['records'], result['coverage']['empty_supported_transcripts']), ('complete', 0, 1))
        self.put('Messages/c1100000000000000001/messages.json', {'unexpected': []})
        result = self.do_import()
        self.assertEqual((result['status'], result['records']), ('partial', 0))
        other = self.base / 'unknown'
        other.mkdir()
        (other / 'notes.txt').write_text('Unrecognized export')
        result = self.do_import(other)
        self.assertEqual(result['coverage']['message_files'], 0)
        self.assertEqual(result['status'], 'partial')

    def test_unknown_account_and_conflicting_channel_remain_unlinked(self):
        self.put('Messages/c1100000000000000001/channel.json', {'id': '1100000000000000002'})
        self.put('Messages/c1100000000000000001/messages.json', [self.row()])
        result = self.do_import()
        data = json.loads(self.all_rows()[0]['data'])
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(data['message']['sender'], '')
        self.assertEqual(data['message']['channel_id'], '')
        self.assertTrue(data['message']['conversation'].startswith('unlinked-source:'))

    def test_zip_traversal_and_symlinks_rejected_before_case_intake(self):
        for name in ['../escape', '/absolute', 'a\\bad']:
            archive_path = self.base / 'bad.zip'
            with zipfile.ZipFile(archive_path, 'w') as archive:
                archive.writestr(name, 'no')
            with self.assertRaisesRegex(UserError, 'Unsafe archive path'):
                self.do_import(archive_path)
        symlink = self.package / 'link'
        symlink.symlink_to(self.base)
        with self.assertRaisesRegex(UserError, 'symlink'):
            self.do_import()
        with connect(self.workspace, 'A') as (_, db):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 0)

    def test_limits_and_timezone_rejected_and_large_json_preserved(self):
        self.standard()
        for kwargs in [{'max_bytes': 1}, {'max_files': 1}, {'max_bytes': True}, {'timezone_name': 'Unknown/Zone'}]:
            with self.assertRaises(UserError):
                self.do_import(**kwargs)
        with patch('lawliet_mobile.discord_package.MAX_JSON', 1):
            result = self.do_import()
        self.assertEqual((result['status'], result['records']), ('partial', 0))
        self.assertTrue(any('64 MiB' in x['error'] for x in result['coverage']['issues']))
        with connect(self.workspace, 'A') as (root, db):
            self.assertTrue(verify(root, db)['ok'])

    def test_csv_incomplete_row_is_reported(self):
        self.standard().unlink()
        source = self.package / 'Messages/c1100000000000000001/messages.csv'
        source.write_text('ID,Timestamp,Contents,Attachments\n1300000000000000001,2026-10-17T00:00:00Z,good,\n1300000000000000002,bad\n')
        result = self.do_import()
        self.assertEqual((result['status'], result['records'], result['coverage']['records_skipped']), ('partial', 1, 1))

    def test_database_failure_preserves_input_and_audited_failed_run(self):
        self.standard()
        with patch('lawliet_mobile.discord_package.add_artifact', side_effect=sqlite3.OperationalError('synthetic database failure')):
            with self.assertRaisesRegex(UserError, 'original evidence .* retained'):
                self.do_import()
        with connect(self.workspace, 'A') as (root, db):
            self.assertEqual(db.execute('SELECT status FROM runs').fetchone()[0], 'failed')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(self.do_import()['records'], 1)

    def test_same_message_id_across_reports_retains_both_observations(self):
        self.standard()
        path = self.package / 'Messages/c1100000000000000001/messages.csv'
        with path.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=sorted(self.row()))
            writer.writeheader()
            writer.writerow(self.row())
        result = self.do_import()
        self.assertEqual(result['records'], 2)
        with connect(self.workspace, 'A') as (_, db):
            grouped = conversations(db, app='discord', run=result['run_id'])
            self.assertEqual((len(grouped), grouped[0]['records']), (1, 2))
            self.assertEqual(db.execute('SELECT COUNT(DISTINCT file_id) FROM artifacts').fetchone()[0], 2)

    def test_interrupted_import_recovery_keeps_original_and_retries_once(self):
        self.standard()
        ready = self.base / 'insert-ready'
        script = '''from pathlib import Path
import sys
from lawliet_mobile.core import connect
import lawliet_mobile.discord_package as package
real_add = package.add_artifact
def hold(*args, **kwargs):
    result = real_add(*args, **kwargs)
    Path(sys.argv[3]).write_text('ready')
    sys.stdin.read()
    return result
package.add_artifact = hold
with connect(Path(sys.argv[1]), 'A') as (root, db):
    package.import_discord_package(root, db, Path(sys.argv[2]))
'''
        child = subprocess.Popen([sys.executable, '-c', script, str(self.workspace), str(self.package), str(ready)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 5
        while not ready.exists():
            if child.poll() is not None:
                self.fail(child.communicate()[1].decode())
            if time.monotonic() > deadline:
                self.fail('Child failed to reach controlled interruption')
            time.sleep(.01)
        with self.assertRaisesRegex(UserError, 'still owns'):
            self.do_import()
        child.kill()
        child.communicate(timeout=5)
        result = self.do_import()
        self.assertEqual(result['records'], 1)
        with connect(self.workspace, 'A') as (root, db):
            self.assertEqual([r[0] for r in db.execute('SELECT status FROM runs ORDER BY rowid')], ['interrupted', 'complete'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 1)
            self.assertTrue(verify(root, db)['ok'])


if __name__ == '__main__':
    unittest.main()
