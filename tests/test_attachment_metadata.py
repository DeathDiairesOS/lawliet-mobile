import sqlite3, unittest, tempfile, json
from pathlib import Path
from lawliet_mobile import media
from lawliet_mobile.core import create_case, connect, import_evidence, select_artifacts
from lawliet_mobile.parsers import native_analyze

class AttachmentMetadataTests(unittest.TestCase):

    def db(self):
        d = sqlite3.connect(':memory:')
        self.addCleanup(d.close)
        d.executescript('CREATE TABLE attachment(filename,total_bytes,created_date,transfer_name,status,file_id,raw_attachment,arbitrary);CREATE TABLE message_attachment_join(message_id,attachment_id);')
        d.execute('INSERT INTO attachment VALUES(?,?,?,?,?,?,?,?)', ('a.png', 4, 700000000, 'raw', 'spoof', 99, 'spoof', b'\x00x'))
        d.execute('INSERT INTO message_attachment_join VALUES(1,1)')
        return d

    def test_raw_namespace_preserves_types_collision_safe(self):
        row = next(media.attachment_rows(self.db()))
        got = media.resolve_attachment(row, [{'id': 3, 'logical_path': 'a.png', 'sha256': 'correct', 'size': 4}])
        self.assertEqual(got['status'], 'available')
        self.assertEqual(got['file_id'], 3)
        self.assertEqual(got['raw_attachment']['status'], 'spoof')
        self.assertEqual(got['raw_attachment']['file_id'], 99)
        self.assertEqual(got['raw_attachment']['raw_attachment'], 'spoof')
        self.assertEqual(got['raw_attachment']['arbitrary'], {'blob_bytes': 2})
        self.assertEqual(got['created_date'], 700000000)
        self.assertEqual(got['transfer_name'], 'raw')
        self.assertEqual(got['message_row_ids'], ['1'])

    def test_external_and_invalid_no_resolution(self):
        for name, want in [('https://fixture.invalid/a.png', 'external_reference'), ('HTTP://fixture.invalid/a', 'external_reference'), ('https://user:pass@fixture.invalid/a', 'unsupported_reference'), ('https://fixture.invalid:99999/a', 'unsupported_reference'), ('https:///a', 'unsupported_reference'), ('../a', 'unsupported_reference'), ('/etc/a', 'unsupported_reference'), ('a\\b', 'unsupported_reference'), ('', 'unsupported_reference'), (None, 'unsupported_reference'), (3, 'unsupported_reference'), (b'a', 'unsupported_reference'), ('file:///a', 'unsupported_reference')]:
            row = {'filename': name, 'expected_bytes': 1}
            result = media.resolve_attachment(row, [])
            self.assertEqual(result['status'], want, name)
            self.assertIsNone(result['file_id'])

    def test_existing_missing_ambiguous_and_mismatch(self):
        files = [{'id': 1, 'logical_path': 'a.png', 'size': 4, 'sha256': 'x'}, {'id': 2, 'logical_path': 'HomeDomain/a.png', 'size': 4, 'sha256': 'y'}]
        for path, size, state in [('a.png', 4, 'available'), ('a.png', 9, 'size_mismatch'), ('missing.png', 4, 'not_acquired'), ('~/a.png', 4, 'ambiguous_path')]:
            self.assertEqual(media.resolve_attachment({'filename': path, 'expected_bytes': size}, files)['status'], state)

    def test_nonstring_filename_full_native_path_no_loss_or_crash(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            p = base / 'sms.db'
            db = sqlite3.connect(p)
            db.executescript('CREATE TABLE message(text,date,handle_id,is_from_me);CREATE TABLE handle(id);INSERT INTO handle VALUES("x");INSERT INTO message VALUES("x",1,1,0);CREATE TABLE attachment(filename,total_bytes,created_date);CREATE TABLE message_attachment_join(message_id,attachment_id);INSERT INTO attachment VALUES(123,4,NULL);INSERT INTO message_attachment_join VALUES(1,1);')
            db.commit()
            db.close()
            create_case(base / 'cases', 'test')
            with connect(base / 'cases', 'test') as (root, c):
                eid = import_evidence(root, c, p, 'ios')[0]
                native_analyze(root, c, eid)
                rows = select_artifacts(c, category='attachments', limit=None)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['data']['attachment']['filename'], 123)
                self.assertIsNone(rows[0]['data']['attachment']['raw_attachment']['created_date'])
                self.assertEqual(rows[0]['data']['attachment']['status'], 'unsupported_reference')
                self.assertIsNone(rows[0]['timestamp'])

    def test_large_blob_projected_length_only_limit_restored(self):
        d = self.db()
        d.execute('UPDATE attachment SET arbitrary=zeroblob(?)', (16 * 1024 ** 2,))
        before = d.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)

        def no_blob_driver_rows(cursor, row):
            self.assertFalse(any((isinstance(v, bytes) for v in row)), 'BLOB payload materialized at Python boundary')
            return row
        d.row_factory = no_blob_driver_rows
        rows = list(media.attachment_rows(d))
        self.assertEqual(rows[0]['raw_attachment']['arbitrary'], {'blob_bytes': 16 * 1024 ** 2})
        self.assertEqual(d.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), before)

    def test_oversize_text_refused_limit_restored(self):
        d = self.db()
        d.execute("UPDATE attachment SET transfer_name=replace(hex(zeroblob(?)), '00', 'xx')", (5 * 1024 ** 2,))
        before = d.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        with self.assertRaisesRegex(sqlite3.DataError, 'source coverage incomplete'):
            list(media.attachment_rows(d))
        self.assertEqual(d.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), before)

    def test_generator_early_close_restores_limit(self):
        d = self.db()
        before = d.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        g = media.attachment_rows(d)
        next(g)
        self.assertEqual(d.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), min(before, 8 * 1024 ** 2))
        g.close()
        self.assertEqual(d.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), before)

    def test_oversize_text_actual_native_reports_incomplete_source(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            p = base / 'sms.db'
            d = self.db()
            d.execute('UPDATE attachment SET transfer_name=hex(zeroblob(?))', (5 * 1024 ** 2,))
            d.commit()
            dest = sqlite3.connect(p)
            d.backup(dest)
            dest.close()
            create_case(base / 'cases', 'oversize')
            with connect(base / 'cases', 'oversize') as (root, db):
                eid = import_evidence(root, db, p, 'ios')[0]
                result = native_analyze(root, db, eid)
                self.assertEqual(result['status'], 'partial')
                self.assertTrue(any((e['source'] == 'sms.db' and 'source coverage incomplete' in e['error'] for e in result['errors'])))
                self.assertEqual(select_artifacts(db, category='attachments', limit=None), [])
if __name__ == '__main__':
    unittest.main(verbosity=2)
