import unittest
from lawliet_mobile.media_time import capture_time

class MediaTimeTests(unittest.TestCase):
    def test_owned_photo_time_and_original_fields(self):
        fields = {'DateTimeOriginal':'2026:10:11 21:10:56', 'OffsetTimeOriginal':'-04:00', 'SubSecTimeOriginal':'343'}
        original = fields.copy()
        value, detail = capture_time(fields)
        self.assertEqual(value, '2026-10-12T01:10:56.343000Z')
        self.assertEqual(detail['status'], 'normalized')
        self.assertEqual(fields, original)
    def test_inline_utc_and_digitized_time(self):
        self.assertEqual(capture_time({'DateTimeOriginal':'2026-10-11T21:10:56.1234567Z'})[0], '2026-10-11T21:10:56.123456Z')
        self.assertTrue(capture_time({'DateTimeOriginal':'2026-10-11T21:10:56.1234567Z'})[1]['fraction_truncated'])
        self.assertEqual(capture_time({'CreateDate':'2026:10:11 21:10:56','OffsetTimeDigitized':'+05:30'})[0], '2026-10-11T15:40:56.000000Z')
    def test_missing_offsets_and_conflicts_remain_undated(self):
        base = {'DateTimeOriginal':'2026:10:11 21:10:56'}
        for extra in [{}, {'OffsetTime':'+00:00'}, {'OffsetTimeOriginal':'+24:00'}, {'OffsetTimeOriginal':'+14:30'}, {'OffsetTimeOriginal':True}, {'OffsetTimeOriginal':'+00:00','SubSecTimeOriginal':'invalid'}]:
            self.assertIsNone(capture_time({**base,**extra})[0])
        self.assertIsNone(capture_time({'DateTimeOriginal':'2026-10-11T21:10:56Z','OffsetTimeOriginal':'-04:00'})[0])
        self.assertIsNone(capture_time({'DateTimeOriginal':'2026-10-11T21:10:56.123Z','SubSecTimeOriginal':'124'})[0])
        self.assertIsNone(capture_time({'DateTimeOriginal':'2026:02:30 21:10:56','OffsetTimeOriginal':'+00:00'})[0])

    def test_real_exiftool_timezone_gps_and_grouped_preview(self):
        import base64, shutil, subprocess, tempfile
        from pathlib import Path
        from lawliet_mobile.core import create_case, connect, import_evidence, iter_artifacts, verify
        from lawliet_mobile.tools import external_analyze
        from lawliet_mobile.parsers import native_analyze
        from lawliet_mobile.media import preview
        tool=shutil.which('exiftool')
        if not tool:self.skipTest('Optional ExifTool is unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);image=base/'pixel.png'
            image.write_bytes(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg=='))
            subprocess.run([tool,'-overwrite_original','-DateTimeOriginal=2026:10:11 21:10:56','-OffsetTimeOriginal=-04:00','-SubSecTimeOriginal=343','-GPSLatitude=40.5','-GPSLatitudeRef=N','-GPSLongitude=73.5','-GPSLongitudeRef=W',str(image)],check=True,capture_output=True)
            ws=base/'cases';create_case(ws,'qa')
            with connect(ws,'qa') as (root,db):
                eid=import_evidence(root,db,image,'android')[0];native_analyze(root,db,eid)
                external_analyze(root,db,ws,eid,'exiftool')
                rows=list(iter_artifacts(db,category='media',media_items=True))
                self.assertEqual(len(rows),1)
                self.assertEqual(rows[0]['timestamp'],'2026-10-12T01:10:56.343000Z')
                self.assertEqual(rows[0]['data']['GPSLatitude'],40.5)
                self.assertEqual(rows[0]['data']['GPSLongitude'],-73.5)
                self.assertEqual(preview(root,db,rows[0]['id'])['sha256'],rows[0]['source_sha256'])
                self.assertEqual(len(list(iter_artifacts(db,category='media',media_items=True,since='2026-10-12T01:10:56.000000Z',until='2026-10-12T01:10:57.000000Z'))),1)
                self.assertTrue(verify(root,db)['ok'])
