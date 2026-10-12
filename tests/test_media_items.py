import json
import tempfile
import unittest
from pathlib import Path

from lawliet_mobile.core import create_case, connect, import_evidence, add_artifact, select_artifacts, verify
from lawliet_mobile.app_backend import handle


class MediaItemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.ws = self.base / 'cases'
        create_case(self.ws, 'A')

    def observation(self, parser, content=b'\xff\xd8\xffphoto', name='photo.jpg', model='Test Camera'):
        folder = self.base / ('input-' + str(len(list(self.base.glob('input-*')))))
        folder.mkdir()
        source = folder / name
        source.write_bytes(content)
        with connect(self.ws, 'A') as (root, db):
            eid = import_evidence(root, db, source, 'android')[0]
            file = dict(db.execute('SELECT * FROM files WHERE evidence_id=?', (eid,)).fetchone())
            data = ({'media': {'file_id': file['id'], 'mime': 'image/jpeg'}} if parser.startswith('native/')
                    else {'MIMEType': 'image/jpeg', 'Model': model, 'ImageWidth': 400, 'ImageHeight': 300})
            add_artifact(db, eid, file['id'], 'media', None, None, name,
                         'image/jpeg' if parser.startswith('native/') else 'JPEG · 400 × 300',
                         'native-file' if parser.startswith('native/') else 'ExifTool metadata', parser, data)
            aid = db.execute('SELECT id FROM artifacts WHERE evidence_id=?', (eid,)).fetchone()[0]
            db.commit()
        return eid, aid

    def call(self, action, **kwargs):
        return handle(self.ws, {'action': action, 'case': 'A', **kwargs})

    def test_one_media_item_preserves_both_original_observations_and_preview_identity(self):
        _, native = self.observation('native/0.1.5')
        _, exif = self.observation('exiftool')
        result = self.call('records', category='media')
        self.assertEqual(len(result['records']), 1)
        row = result['records'][0]
        self.assertEqual(row['id'], native)
        self.assertEqual(row['body'], 'image/jpeg')
        self.assertEqual(row['display_body'], 'JPEG · 400 × 300')
        self.assertEqual({r['id'] for r in row['media_item']['observations']}, {native, exif})
        self.assertEqual(row['media_item']['observation_count'], 2)
        self.assertEqual(self.call('source-stats')['categories']['media'], 1)
        with connect(self.ws, 'A') as (root, db):
            self.assertEqual(len(select_artifacts(db, category='media')), 2)
            self.assertTrue(verify(root, db)['ok'])

    def test_same_name_with_different_bytes_remains_two_items(self):
        self.observation('native/0.1.5', content=b'\xff\xd8\xfffirst')
        self.observation('exiftool', content=b'\xff\xd8\xffsecond')
        self.assertEqual(len(self.call('records', category='media')['records']), 2)

    def test_parser_evidence_and_search_scope_do_not_leak_other_observations(self):
        eid, native = self.observation('native/0.1.5')
        _, exif = self.observation('exiftool', model='Distinct metadata sentinel')
        for scope in ({'evidence': eid}, {'parser': 'native/0.1.5'}):
            row = self.call('records', category='media', **scope)['records'][0]
            self.assertEqual([r['id'] for r in row['media_item']['observations']], [native])
        row = self.call('records', category='media', query='Distinct metadata sentinel')['records'][0]
        self.assertEqual([r['id'] for r in row['media_item']['observations']], [exif])
        self.assertEqual(self.call('records', category='media', query='no-such-value')['records'], [])

    def test_grouping_precedes_pagination_and_keeps_scoped_export_consistent(self):
        for index in range(102):
            content = b'\xff\xd8\xff' + str(index).encode()
            self.observation('native/0.1.5', content)
            self.observation('exiftool', content)
        first = self.call('records', category='media')
        second = self.call('records', category='media', offset=100)
        self.assertEqual(len(first['records']), 100)
        self.assertTrue(first['has_more'])
        self.assertEqual(len(second['records']), 2)
        self.assertFalse(second['has_more'])
        self.assertFalse({r['id'] for r in first['records']} & {r['id'] for r in second['records']})
        destination = self.base / 'media.jsonl'
        self.call('export', category='media', path=str(destination))
        exported = [json.loads(s) for s in destination.read_text().splitlines()]
        self.assertEqual(len(exported), 102)
        self.assertTrue(all(r['media_item']['observation_count'] == 2 for r in exported))

    def test_report_only_media_with_same_title_is_not_grouped(self):
        self.observation('report-import/1')
        self.observation('report-import/1')
        rows = self.call('records', category='media')['records']
        self.assertEqual(len(rows), 2)
        self.assertTrue(all('media_item' not in row for row in rows))

    def test_observation_details_are_bounded_and_disclose_truncation(self):
        self.observation('native/0.1.5')
        for _ in range(22):
            self.observation('exiftool')
        row = self.call('records', category='media')['records'][0]
        self.assertEqual(len(row['media_item']['observations']), 20)
        self.assertEqual(row['media_item']['observation_count'], 23)
        self.assertTrue(row['media_item']['observations_truncated'])

    def test_run_scoped_stats_and_media_selection_preserve_run_membership(self):
        _, native = self.observation('native/0.1.5')
        eid, exif = self.observation('exiftool')
        from lawliet_mobile.core import begin_run_index
        with connect(self.ws, 'A') as (_, db):
            db.execute("INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES('EXIF',?,'exiftool','2026-10-11','complete')", (eid,))
            begin_run_index(db, 'EXIF')
            db.execute("INSERT INTO artifact_runs(run_id,artifact_id) VALUES('EXIF',?)", (exif,))
            db.commit()
        self.assertEqual(self.call('source-stats', run='EXIF')['categories']['media'], 1)
        row = self.call('records', category='media', run='EXIF')['records'][0]
        self.assertEqual(row['id'], exif)
        self.assertEqual([x['id'] for x in row['media_item']['observations']], [exif])

    def trash_receipt(self, file_id, **changes):
        with connect(self.ws, 'A') as (root, db):
            source = db.execute('SELECT * FROM files WHERE id=?', (file_id,)).fetchone()
            data = {'format': 'ancalor-android-trash-acquisition-v1', 'source_kind': 'trash',
                    'method': 'read-only-adb-pull', 'remote_path': '/sdcard/Android/.Trash/gallery/photo.jpg',
                    'bytes': source['size'], 'source_sha256_before': source['sha256'],
                    'source_sha256_after': source['sha256'], 'acquired_sha256': source['sha256']}
            data.update(changes)
            path = self.base / ('receipt-' + str(file_id) + '.json')
            path.write_text(json.dumps(data))
            eid = import_evidence(root, db, path, 'android')[0]
            return db.execute('SELECT id FROM files WHERE evidence_id=?', (eid,)).fetchone()[0]

    def test_trash_view_requires_receipt_and_keeps_source_scope(self):
        live_eid, _ = self.observation('native/0.1.5')
        trash_eid, _ = self.observation('native/0.1.5')
        self.assertEqual(self.call('records', category='media', media_state='trash')['records'], [])
        with connect(self.ws, 'A') as (_, db):
            fid = db.execute('SELECT id FROM files WHERE evidence_id=?', (trash_eid,)).fetchone()[0]
        rid = self.trash_receipt(fid)
        self.call('record-media-trash-source', file_id=fid, receipt_file_id=rid)
        row = self.call('records', category='media', media_state='trash')['records'][0]
        self.assertEqual(row['media_item']['source_contexts'][0]['source_kind'], 'trash')
        self.assertEqual(row['media_item']['observation_count'], 1)
        self.assertEqual(self.call('source-stats')['categories']['trash_photos'], 1)
        self.assertEqual(self.call('records', category='media', media_state='trash', evidence=live_eid)['records'], [])
        self.assertEqual(self.call('source-stats', evidence=live_eid)['categories']['trash_photos'], 0)

    def test_filename_or_missing_media_never_implies_deleted_and_bad_receipt_refused(self):
        eid, _ = self.observation('native/0.1.5', name='deleted_photo.jpg')
        with connect(self.ws, 'A') as (_, db):
            fid = db.execute('SELECT id FROM files WHERE evidence_id=?', (eid,)).fetchone()[0]
        rid = self.trash_receipt(fid, acquired_sha256='wrong')
        from lawliet_mobile.core import UserError
        with self.assertRaises(UserError):
            self.call('record-media-trash-source', file_id=fid, receipt_file_id=rid)
        self.assertEqual(self.call('records', category='media', media_state='trash')['records'], [])
        with self.assertRaises(UserError):
            self.call('records', category='media', media_state='permanently-deleted')
