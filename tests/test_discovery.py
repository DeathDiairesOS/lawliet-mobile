import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.core import connect, create_case, import_evidence, verify, UserError
from lawliet_mobile.discovery import preview
from lawliet_mobile.app_backend import handle


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.ws=self.base/'cases';create_case(self.ws,'qa')
        source=self.base/'input';source.mkdir()
        # Deliberately incomplete files: discovery may identify headers but must
        # not claim these are valid databases/images/packages or parse them.
        for name,data in {'one.db':b'SQLite format 3\x00'+b'\x00'*64,
                          'one.db-wal':b'\x37\x7f\x06\x82'+b'\x00'*32,
                          'photo.bin':b'\xff\xd8\xff'+b'fixture',
                          'sample.apk':b'PK\x03\x04fixture',
                          'fake.db':b'not SQLite',
                          'unrelated.backup':b'not necessarily Signal'}.items():
            (source/name).write_bytes(data)
        with connect(self.ws,'qa') as (root,db):
            self.eid=import_evidence(root,db,source,'android',expand_archives=False)[0]

    def test_preview_reads_headers_without_running_or_mutating(self):
        with connect(self.ws,'qa') as (root,db):
            before=verify(root,db)
            with patch('subprocess.Popen',side_effect=AssertionError('No execution')):
                result=preview(root,db,self.ws,self.eid)
            self.assertTrue(result['inspection_complete'])
            self.assertEqual(result['format_indicators']['sqlite_header'],1)
            self.assertEqual(result['format_indicators']['apk_candidate'],1)
            self.assertEqual(result['format_indicators']['unclassified'],1)
            self.assertEqual([t['tool'] for t in result['tasks']],['aleapp','exiftool'])
            self.assertTrue(all(t['input_scope']=='evidence' for t in result['tasks']))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],0)
            self.assertEqual(before,verify(root,db))

    def test_recovery_scope_and_custom_dependency_status(self):
        with connect(self.ws,'qa') as (root,db):
            result=preview(root,db,self.ws,self.eid,'sqlite-recovery')
            self.assertEqual(len(result['tasks']),1)
            self.assertEqual(result['tasks'][0]['file']['path'],'one.db')
            # Simulate no executable through any supported discovery location,
            # including the macOS fallback used when GUI PATH is restricted.
            with patch('lawliet_mobile.tools.tool_executable',return_value=None):
                result=preview(root,db,self.ws,self.eid,'custom',['exiftool'])
            self.assertEqual(result['tasks'][0]['state'],'missing_tool')
            self.assertIsNotNone(result['tasks'][0]['availability_error'])
            for profile,tools in [('custom',[]),('custom',['mvt']),('standard',['native'])]:
                with self.assertRaises(UserError):preview(root,db,self.ws,self.eid,profile,tools)

    def test_limits_and_unsafe_files_are_explicit(self):
        with connect(self.ws,'qa') as (root,db):
            result=preview(root,db,self.ws,self.eid,max_files=1)
            self.assertFalse(result['inspection_complete'])
            self.assertTrue(all(t['state']=='blocked_incomplete_inspection' for t in result['tasks']))
            file=db.execute('SELECT * FROM files WHERE evidence_id=? ORDER BY id LIMIT 1',(self.eid,)).fetchone()
            path=root/'evidence'/self.eid/file['path'];path.unlink()
            path.symlink_to(self.base/'outside')
            result=preview(root,db,self.ws,self.eid)
            self.assertEqual(result['problem_count'],1)
            self.assertFalse(result['inspection_complete'])
            self.assertEqual(result['problems'][0]['file_id'],file['id'])

    def test_pending_profiles_are_not_mock_integrations(self):
        for profile in ['application','threat-hunting']:
            result=handle(self.ws,{'action':'analysis-plan','case':'qa','evidence':self.eid,'profile':profile})
            self.assertEqual(result['tasks'],[])
            self.assertIn('no implemented execution adapter',result['warnings'][0])

    def test_contacts_export_with_collection_logs_uses_native_reader(self):
        source=self.base/'contacts';source.mkdir()
        (source/'contacts.vcf').write_text('BEGIN:VCARD\nVERSION:3.0\nFN:Fixture\nEND:VCARD\n')
        (source/'collection.json').write_text('{"profile":"contacts-provider"}')
        (source/'query.log').write_text('Synthetic acquisition log')
        with connect(self.ws,'qa') as (root,db):
            eid=import_evidence(root,db,source,'android')[0]
            result=preview(root,db,self.ws,eid)
            self.assertEqual([t['tool'] for t in result['tasks']],['native'])
