"""Synthetic customer-export intake; no device, network, or provider credentials."""
import base64
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from lawliet_mobile.core import UserError, connect, create_case, digest, select_artifacts, verify
from lawliet_mobile.media import preview
from lawliet_mobile.messages import import_chat


PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aZXkAAAAASUVORK5CYII=')


class WhatsAppCustomerIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'customer')

    def bundle(self, members, name='export.zip'):
        path = self.base / name
        with zipfile.ZipFile(path, 'w') as archive:
            for relative, contents in members.items():
                archive.writestr(relative, contents)
        return path

    def test_text_multiline_originals_and_explicit_date_order(self):
        path = self.base / 'chat.txt'
        path.write_text('\ufeff[12/10/2026, 09:10:11] Jamie: first\nsecond\n[12/10/2026, 09:11:00] Encryption notice\n')
        original = digest(path)
        with connect(self.workspace, 'customer') as (root, db):
            result = import_chat(root, db, path, 'dmy', 'America/New_York')
            rows = select_artifacts(db, run=result['run_id'])
            message = next(row for row in rows if row['category'] == 'messages')
            self.assertEqual(message['body'], 'first\nsecond')
            self.assertEqual(message['source_ref'], 'lines=1-2')
            self.assertEqual(message['source_sha256'], original)
            self.assertEqual(message['timestamp'], '2026-10-12T13:10:11.000000Z')
            self.assertEqual(message['data']['source_time_precision'], 'second')
            self.assertEqual(message['data']['message']['direction'], 'unknown')
            self.assertEqual(result['chat_records'], 2)
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(digest(path), original)

    def test_zip_matching_media_missing_and_omitted_provenance_and_preview(self):
        path = self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: photo.png (file attached)\ncaption\n10/17/2026, 10:01 - Sam: <attached: missing.jpg>\n10/17/2026, 10:02 - Jamie: <Media omitted>\n', 'photo.png': PNG})
        original = digest(path)
        with connect(self.workspace, 'customer') as (root, db):
            result = import_chat(root, db, path, 'mdy', 'America/New_York', reuse=True)
            self.assertEqual(result['status'], 'complete')
            self.assertEqual((result['chat_records'], result['media_records'], result['records']), (3, 1, 4))
            rows = select_artifacts(db, run=result['run_id'], category='messages')
            self.assertEqual([row['data']['message']['attachment_status'] for row in rows], ['available', 'not_acquired', 'omitted_from_export'])
            attachment = rows[0]['data']['attachment']
            file = db.execute('SELECT * FROM files WHERE id=?', (attachment['file_id'],)).fetchone()
            self.assertEqual(attachment['sha256'], file['sha256'])
            self.assertEqual(attachment['source_file'], 'photo.png')
            self.assertEqual(attachment['bytes'], len(PNG))
            self.assertEqual(file['evidence_id'], result['evidence_id'])
            media = select_artifacts(db, run=result['run_id'], category='media')[0]
            shown = preview(root, db, media['id'])
            self.assertEqual(shown['sha256'], attachment['sha256'])
            self.assertEqual(Path(shown['path']).read_bytes(), PNG)
            self.assertEqual(db.execute('SELECT container_sha256 FROM evidence WHERE id=?', (result['evidence_id'],)).fetchone()[0], original)
            retained_archive = result['original_archive']
            retained_path = root / 'evidence' / result['evidence_id'] / retained_archive['path']
            self.assertEqual(retained_path.read_bytes(), path.read_bytes())
            self.assertEqual(digest(retained_path), original)
            self.assertEqual(retained_archive['sha256'], original)
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(digest(path), original)

    def test_ambiguous_filenames_never_choose_an_attachment(self):
        path = self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: <attached: photo.png>\n', 'one/photo.png': PNG, 'two/photo.png': PNG})
        with connect(self.workspace, 'customer') as (root, db):
            result = import_chat(root, db, path, 'mdy')
            attachment = select_artifacts(db, run=result['run_id'], category='messages')[0]['data']['attachment']
            self.assertEqual(attachment['status'], 'ambiguous_path')
            self.assertNotIn('file_id', attachment)
            self.assertEqual(attachment['candidate_paths'], ['one/photo.png', 'two/photo.png'])

    def test_attachment_markers_do_not_follow_paths_or_urls(self):
        path = self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: <attached: ../outside.png>\n10/17/2026, 10:01 - Jamie: <attached: https://example.invalid/photo.png>\n'})
        with connect(self.workspace, 'customer') as (root, db):
            result = import_chat(root, db, path, 'mdy')
            rows = select_artifacts(db, run=result['run_id'])
            self.assertEqual([row['data']['attachment']['status'] for row in rows], ['unsupported_reference', 'unsupported_reference'])

    def test_archive_traversal_is_rejected_before_publication(self):
        path = self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: hello\n', '../escape': b'bad'})
        with connect(self.workspace, 'customer') as (root, db):
            with self.assertRaisesRegex(UserError, 'Unsafe archive path'):
                import_chat(root, db, path, 'mdy')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 0)
            self.assertEqual(list((root / 'evidence').glob('*')), [])
        self.assertFalse((self.base / 'escape').exists())

    def test_timestamp_unknown_invalid_and_dst_ambiguous_stay_undated(self):
        path = self.base / 'dates.txt'
        path.write_text('17/10/2026, 09:00 - Jamie: invalid with chosen mdy\n11/01/2026, 01:30 - Jamie: DST ambiguity\n10/17/26, 09:00 - Jamie: century not supplied\n')
        with connect(self.workspace, 'customer') as (root, db):
            result = import_chat(root, db, path, 'mdy', 'America/New_York')
            rows = select_artifacts(db, run=result['run_id'])
            self.assertTrue(all(row['timestamp'] is None for row in rows))
            self.assertEqual(result['undated_records'], 3)
            self.assertEqual({row['data']['timestamp_semantics'] for row in rows}, {'Invalid calendar date', 'Ambiguous or nonexistent local time', 'Unsupported date or two-digit year; original retained'})
            for zone in ('Not/AZone', '/absolute/timezone'):
                with self.assertRaisesRegex(UserError, 'Unknown timezone'):
                    import_chat(root, db, path, 'mdy', zone)
            with self.assertRaisesRegex(UserError, 'date order'):
                import_chat(root, db, path, 'guess')

    def test_unchanged_opt_in_replay_does_not_duplicate_and_changed_input_is_distinct(self):
        path = self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: hello\n', 'photo.png': PNG})
        with connect(self.workspace, 'customer') as (root, db):
            first = import_chat(root, db, path, 'mdy', 'UTC', reuse=True)
            counts = tuple(db.execute('SELECT (SELECT COUNT(*) FROM evidence), (SELECT COUNT(*) FROM runs), (SELECT COUNT(*) FROM artifacts), (SELECT COUNT(*) FROM audit)').fetchone())
            replay = import_chat(root, db, path, 'mdy', 'UTC', reuse=True)
            self.assertTrue(replay['reused'])
            self.assertEqual((first['evidence_id'], first['run_id']), (replay['evidence_id'], replay['run_id']))
            self.assertEqual(counts, tuple(db.execute('SELECT (SELECT COUNT(*) FROM evidence), (SELECT COUNT(*) FROM runs), (SELECT COUNT(*) FROM artifacts), (SELECT COUNT(*) FROM audit)').fetchone()))
            second = import_chat(root, db, path, 'mdy', 'America/New_York', reuse=True)
            self.assertNotEqual(first['evidence_id'], second['evidence_id'])
            self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: changed\n'})
            changed = import_chat(root, db, path, 'mdy', 'UTC', reuse=True)
            self.assertNotEqual(first['evidence_id'], changed['evidence_id'])

    def test_directory_replay_and_integrity_tampering(self):
        path = self.base / 'export'
        path.mkdir()
        (path / '_chat.txt').write_text('10/17/2026, 10:00 - Jamie: hello\n')
        (path / 'photo.png').write_bytes(PNG)
        before = {file.name: digest(file) for file in path.iterdir()}
        with connect(self.workspace, 'customer') as (root, db):
            first = import_chat(root, db, path, 'mdy', reuse=True)
            self.assertTrue(import_chat(root, db, path, 'mdy', reuse=True)['reused'])
            self.assertEqual(before, {file.name: digest(file) for file in path.iterdir()})
            (root / 'evidence' / first['evidence_id'] / 'photo.png').write_bytes(b'tampered')
            with self.assertRaisesRegex(UserError, 'integrity'):
                import_chat(root, db, path, 'mdy', reuse=True)

    def test_multiple_chats_require_explicit_selection_and_failure_is_retained(self):
        path = self.bundle({'one.txt': '10/17/2026, 10:00 - Jamie: one\n', 'two.txt': '10/17/2026, 10:00 - Sam: two\n'})
        with connect(self.workspace, 'customer') as (root, db):
            with self.assertRaisesRegex(UserError, 'one recognizable'):
                import_chat(root, db, path, 'mdy')
            run = db.execute('SELECT * FROM runs').fetchone()
            self.assertEqual(run['status'], 'failed')
            self.assertIn('one recognizable', json.loads(run['detail'])['error'])
            result = import_chat(root, db, path, 'mdy', chat_path='two.txt')
            self.assertEqual(select_artifacts(db, run=result['run_id'])[0]['body'], 'two')
            self.assertTrue(verify(root, db)['ok'])

    def test_directory_symlink_and_oversized_inputs_rejected(self):
        path = self.base / 'export'
        path.mkdir()
        transcript = path / '_chat.txt'
        transcript.write_text('10/17/2026, 10:00 - Jamie: hello\n')
        with connect(self.workspace, 'customer') as (root, db):
            with self.assertRaisesRegex(UserError, 'size'):
                import_chat(root, db, path, 'mdy', max_bytes=2)
            (path / 'link.txt').symlink_to(transcript)
            with self.assertRaisesRegex(UserError, 'symlinks'):
                import_chat(root, db, path, 'mdy')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 0)

    def test_container_is_retained_after_external_original_is_removed_and_is_not_attachment(self):
        path = self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: <attached: bundle.zip>\n'})
        # Use the real source filename as a deliberately misleading attachment marker.
        path = self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: <attached: ' + path.name + '>\n'})
        original = path.read_bytes()
        with connect(self.workspace, 'customer') as (root, db):
            result = import_chat(root, db, path, 'mdy')
            row = select_artifacts(db, run=result['run_id'], category='messages')[0]
            self.assertEqual(row['data']['attachment']['status'], 'not_acquired')
            retained = root / 'evidence' / result['evidence_id'] / result['original_archive']['path']
            path.unlink()
            self.assertEqual(retained.read_bytes(), original)
            self.assertTrue(verify(root, db)['ok'])

    def test_archive_limits_include_original_container_and_reserved_path_is_refused(self):
        path = self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: hello\n'})
        with connect(self.workspace, 'customer') as (root, db):
            with self.assertRaisesRegex(UserError, 'original WhatsApp ZIP'):
                import_chat(root, db, path, 'mdy', max_bytes=path.stat().st_size)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 0)
        self.bundle({'_chat.txt': '10/17/2026, 10:00 - Jamie: hello\n', '_lawliet_original_archive/fake.zip': b'fake'})
        with connect(self.workspace, 'customer') as (root, db):
            with self.assertRaisesRegex(UserError, 'reserved original-container'):
                import_chat(root, db, path, 'mdy')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
