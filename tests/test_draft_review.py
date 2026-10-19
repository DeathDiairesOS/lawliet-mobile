"""Native draft reader checked against actual synthetic backend report output."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests import test_customer_report as customer_report_fixture
from tests import test_redacted_package as redacted_fixture
from lawliet_mobile.core import connect
from lawliet_mobile.investigation_report import build_customer_draft


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'Requires native Swift compiler')
class DraftReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'draft-review'
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run(['swiftc',str(root/'desktop/DraftReview.swift'),
            str(root/'tests/DraftReviewCheck.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=60)
        if result.returncode:raise AssertionError(result.stderr)

    def setUp(self):
        fixture=customer_report_fixture.CustomerReportTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.fixture=fixture
        with connect(fixture.ws,'A') as (root,db):
            self.folder=Path(build_customer_draft(root,db,fixture.iid)['path']).resolve()

    def check(self,mode,folder=None):
        result=subprocess.run([str(self.binary),mode,str(folder or self.folder)],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('passed: '+mode,result.stdout)

    def remanifest(self,name):
        path=self.folder/name;manifest=self.folder/'manifest.json';value=json.loads(manifest.read_text())
        for entry in value['files']:
            if entry['path']==name:
                entry['bytes']=path.stat().st_size;entry['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(value))

    def test_actual_draft_preserves_unknowns_and_source_links(self):self.check('valid')
    def test_actual_redacted_derivative_retains_sources_and_limits(self):
        fixture=redacted_fixture.RedactionTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        with connect(fixture.ws,'A') as (root,db):
            result=fixture.create(root,db)
        self.check('redacted',Path(result['path']))
    def test_wrong_case_is_rejected(self):self.check('wrong-case')
    def test_modified_output_is_rejected(self):
        (self.folder/'report.txt').write_text('tampered');self.check('tampered')
    def test_extra_files_are_rejected(self):
        (self.folder/'thumbnail.jpg').write_bytes(b'unmanifested');self.check('extra')
    def test_symlinked_file_and_folder_are_rejected(self):
        source=self.folder/'report.txt';outside=self.folder.parent/'outside.txt';source.rename(outside);source.symlink_to(outside)
        self.check('symlink-file');link=self.folder.parent/'link';link.symlink_to(self.folder,target_is_directory=True);self.check('symlink-folder',link)
    def test_unresolved_citation_is_rejected_even_with_valid_hash(self):
        p=self.folder/'technical-annex.json';value=json.loads(p.read_text());value['entries'][0]['artifact_ids']=['missing'];p.write_text(json.dumps(value));self.remanifest(p.name);self.check('citation')
    def test_unsupported_schema_is_rejected(self):
        p=self.folder/'manifest.json';value=json.loads(p.read_text());value['format']='future-v99';p.write_text(json.dumps(value));self.check('schema')
    def test_large_preview_is_reported_without_silent_truncation(self):
        p=self.folder/'report.txt';p.write_text('x'*(1024*1024+1));self.remanifest(p.name);self.check('large')

    def examination(self, outcome='no_matches'):
        from lawliet_mobile.app_backend import handle
        from lawliet_mobile.investigation import get
        with connect(self.fixture.ws,'A') as (_,db):
            ids=get(db,self.fixture.iid)['scope']['evidence_ids']
        result=handle(self.fixture.ws, {'action':'investigation-from-examination','case':'A',
            'objective':'Review the selected supplied index','evidence_ids':ids,'outcome':outcome,
            'examiner':'Synthetic examiner','examination_scope':'Selected supplied text index only',
            'limitations':'This is not a complete phone extraction; app-private data unavailable.',
            'queries':['absent fixture term'] if outcome=='no_matches' else []})
        draft=handle(self.fixture.ws, {'action':'customer-report-draft','case':'A',
            'investigation_id':result['investigation_id']})
        self.folder=Path(draft['path']).resolve()

    def test_actual_no_match_draft_preserves_query_provenance_without_fake_findings(self):
        self.examination();self.check('examination-no-matches')

    def test_actual_inconclusive_draft_with_no_searches_is_explicit(self):
        self.examination('inconclusive');self.check('examination-inconclusive')

    def test_contradictory_no_match_summary_is_refused(self):
        self.examination()
        p=self.folder/'technical-annex.json';value=json.loads(p.read_text())
        value['examination']['queries'][0]['returned_records']=1
        p.write_text(json.dumps(value));self.remanifest(p.name);self.check('false-no-match')

    def test_unknown_examination_schema_is_refused(self):
        self.examination()
        p=self.folder/'technical-annex.json';value=json.loads(p.read_text())
        value['examination']['schema_version']=99
        p.write_text(json.dumps(value));self.remanifest(p.name);self.check('examination-version')
