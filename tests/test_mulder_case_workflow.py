import csv,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,import_evidence
try:
    from mulder.server.tools.phone import _parse_tsv_file,list_ancalor_files,import_ancalor_leapp_review
except ModuleNotFoundError as error:
    if error.name != "mulder":
        raise
    _parse_tsv_file = list_ancalor_files = import_ancalor_leapp_review = None
import inspect
list_ancalor_files=inspect.unwrap(list_ancalor_files)
import_ancalor_leapp_review=inspect.unwrap(import_ancalor_leapp_review)
@unittest.skipUnless(_parse_tsv_file, "Requires the patched Mulder integration runtime")
class MulderWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.ws=self.base/'lawliet-review';create_case(self.ws,'qa');self.case=self.ws/'qa'
        self.ctx=SimpleNamespace(db=SimpleNamespace(db_path=self.base/'active.db'))
    def test_large_field_exact_unicode_and_ceiling(self):
        path=self.base/'large.tsv';body='Unicode 😀\nquoted " value\t'+('x'*180000)
        with path.open('w',newline='') as out:csv.writer(out,delimiter='\t').writerows([['ID','Value'],['1',body]])
        self.assertEqual(_parse_tsv_file(path)[0]['Value'],body)
        path.write_text('ID\tValue\n1\t'+('x'*(8*1024**2+1)))
        with self.assertRaises(csv.Error):_parse_tsv_file(path)
    def test_inventory_hash_ids_pagination_and_literal_query(self):
        source=self.base/'com.example.trade.apk';source.write_bytes(b'not executable fixture')
        with connect(self.ws,'qa') as (root,db):import_evidence(root,db,source,'android')
        with patch('mulder.server.tools.phone.get_ctx',return_value=self.ctx):
            r=list_ancalor_files(str(self.case),'TRADE',0,1)
            self.assertEqual(r['total'],1);self.assertEqual(r['files'][0]['size'],22)
            self.assertEqual(len(r['files'][0]['sha256']),64)
            self.assertEqual(list_ancalor_files(str(self.case),'%',0,1)['total'],0)
            self.assertEqual(list_ancalor_files(str(self.case),'',1,1)['files'],[])
            for bad in [True,-1,1001]:
                with self.assertRaises(ValueError):list_ancalor_files(str(self.case),limit=bad)
    def test_retained_report_import_same_case_and_external_refusal(self):
        report=self.base/'retained-tools'/'run'/'report';report.mkdir(parents=True)
        (report/'Messages.tsv').write_text('Timestamp\tBody\n2023-09-20T20:09:49Z\tSynthetic report\n')
        with patch('mulder.server.tools.phone.get_ctx',return_value=self.ctx):
            result=import_ancalor_leapp_review(str(self.case),str(report))
            self.assertTrue(result['integrity']['ok']);self.assertEqual(result['case_path'],str(self.case))
            with self.assertRaises(ValueError):import_ancalor_leapp_review(str(self.case),str(self.base))
            link=self.base/'retained-tools'/'link';link.symlink_to(report)
            with self.assertRaises(ValueError):import_ancalor_leapp_review(str(self.case),str(link))

    def test_supplied_password_zip_exact_bytes_and_wrong_password(self):
        import shutil,subprocess,hashlib
        from mulder.server.tools.case import _extract_zip
        tool=shutil.which('7z')
        if not tool:self.skipTest('7z required to create encrypted fixture')
        source=self.base/'fixture.txt';source.write_bytes(b'Unicode fixture bytes \xf0\x9f\x98\x80')
        archive=self.base/'fixture.zip'
        subprocess.run([tool,'a','-tzip','-mem=ZipCrypto','-pfixture-password',str(archive),str(source)],check=True,capture_output=True)
        before=hashlib.sha256(archive.read_bytes()).hexdigest()
        dest=self.base/'decoded';dest.mkdir()
        _extract_zip(archive,dest,'fixture-password')
        self.assertEqual((dest/'fixture.txt').read_bytes(),source.read_bytes())
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),before)
        bad=self.base/'wrong';bad.mkdir()
        with self.assertRaises(RuntimeError):_extract_zip(archive,bad,'wrong-password')
    def test_password_zip_traversal_and_links_refused(self):
        import zipfile,stat
        from mulder.server.tools.case import _extract_zip
        for name,mode in [('../escape.txt',stat.S_IFREG),('link',stat.S_IFLNK)]:
            archive=self.base/'unsafe.zip'
            with zipfile.ZipFile(archive,'w') as z:
                info=zipfile.ZipInfo(name);info.external_attr=(mode|0o644)<<16;z.writestr(info,'content')
            dest=self.base/'unsafe';dest.mkdir(exist_ok=True)
            with self.assertRaises(ValueError):_extract_zip(archive,dest,'fixture-password')
