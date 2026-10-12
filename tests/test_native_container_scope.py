import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from lawliet_mobile.core import create_case,connect,import_evidence,UserError
from lawliet_mobile.parsers import native_analyze,VERSION

class NativeContainerScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'A')
    def hashes(self,root):return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
    def refuse(self,source):
        with connect(self.ws,'A') as (root,db):
            eid=import_evidence(root,db,source,'android')[0];before=self.hashes(root/'evidence')
            with self.assertRaisesRegex(UserError,'Unsupported native input'):native_analyze(root,db,eid)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],0);self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0);self.assertEqual(before,self.hashes(root/'evidence'))
    def test_case_insensitive_declared_extensions_and_archive_name(self):
        for ext in ['ufdr','UfD','UFDX']:
            source=self.base/('input.'+ext);source.write_bytes(b'synthetic proprietary sentinel');self.refuse(source);self.assertEqual(source.read_bytes(),b'synthetic proprietary sentinel')
        source=self.base/'expanded.UFDR'
        with zipfile.ZipFile(source,'w') as archive:archive.writestr('readable.txt','synthetic inner file')
        self.refuse(source)
    def test_mixed_nested_source_refuses_entire_native_request(self):
        source=self.base/'mixed';(source/'nested').mkdir(parents=True);(source/'nested/input.ufdx').write_bytes(b'unsupported')
        db=sqlite3.connect(source/'mmssms.db');db.executescript("CREATE TABLE sms(_id,body,date,type,address);INSERT INTO sms VALUES(1,'otherwise readable',1700000000000,1,'test');");db.close()
        self.refuse(source)
    def test_double_extension_text_is_not_proprietary_claim(self):
        source=self.base/'note.ufdr.txt';source.write_text('A note referencing proprietary formats')
        with connect(self.ws,'A') as (root,db):
            eid=import_evidence(root,db,source,'unknown')[0];result=native_analyze(root,db,eid)
            self.assertEqual(result['engine'],VERSION);self.assertEqual(result['status'],'complete')
    def test_actual_stdio_retains_bytes_without_analysis_run(self):
        source=self.base/'original.UFDR';source.write_bytes(b'synthetic not actual UFDR');before=source.read_bytes()
        request={'workspace':str(self.ws),'case':'A','action':'import-evidence','path':str(source),'platform':'unknown','engine':'native'}
        result=subprocess.run([sys.executable,'-m','lawliet_mobile.app_backend'],input=json.dumps(request),text=True,capture_output=True)
        payload=json.loads(result.stdout);self.assertTrue(payload['ok']);self.assertEqual(payload['result']['status'],'processing_failed');self.assertIn('Unsupported native input',payload['result']['message'])
        with connect(self.ws,'A') as (root,db):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],0);self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0);self.assertEqual(next((root/'evidence').rglob('original.UFDR')).read_bytes(),before)
        self.assertEqual(source.read_bytes(),before)
