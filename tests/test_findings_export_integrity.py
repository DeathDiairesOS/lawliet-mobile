"""Three-file findings export integrity under in-process failure injection."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, audit, connect, create_case, digest, select_artifacts
from lawliet_mobile.findings import add_finding, export_findings


class FindingsExportIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.ws=self.base/'cases'
        create_case(self.ws,'A')
        self.source=self.base/'source.jsonl'
        self.source.write_text(json.dumps({'category':'messages','body':'saved body','data':{}})+'\n')
        handle(self.ws,{'case':'A','action':'import','path':str(self.source),'format':'jsonl'})
        self.note='=FORMULA\nraw\ttext\x1b\u202eé'
        with connect(self.ws,'A') as (_,db):
            self.aid=select_artifacts(db)[0]['id']
            self.finding=add_finding(db,self.aid,self.note,'Examiner\x1b')

    def paths(self,path):
        return (path,Path(str(path)+'.coverage.json'),Path(str(path)+'.receipt.json'))

    def test_formats_exact_values_three_hashes_and_api(self):
        with connect(self.ws,'A') as (root,db):
            for fmt in ('jsonl','text'):
                path=self.base/fmt
                before=digest(self.source)
                result=export_findings(root,db,path,fmt)
                self.assertEqual(set(result),{'path','records','sha256','receipt_path','coverage_path'})
                self.assertTrue(all(isinstance(result[key],str) for key in ('path','receipt_path','coverage_path')))
                out,coverage_path,receipt_path=self.paths(path)
                coverage=json.loads(coverage_path.read_text());receipt=json.loads(receipt_path.read_text())
                self.assertEqual(receipt['format'],'ancalor-findings-export-v1')
                self.assertEqual(receipt['document_format'],fmt)
                self.assertEqual(receipt['sha256'],digest(out))
                self.assertEqual(coverage['export_sha256'],digest(out))
                self.assertEqual(receipt['coverage_sha256'],digest(coverage_path))
                event=json.loads(db.execute("SELECT detail FROM audit WHERE action='findings.exported' ORDER BY id DESC LIMIT 1").fetchone()[0])
                for key,item in (('sha256',out),('coverage_sha256',coverage_path),('receipt_sha256',receipt_path)):
                    self.assertEqual(event[key],digest(item))
                if fmt=='jsonl':
                    row=json.loads(out.read_text());self.assertEqual(row['note'],self.note)
                    self.assertEqual(row['snapshot'],self.finding['snapshot'])
                else:
                    text=out.read_text();self.assertIn('  | =FORMULA',text)
                    self.assertIn('raw\ttext\\u001b\\u202eé',text)
                    self.assertNotIn('\x1b',text);self.assertNotIn('\u202e',text)
                self.assertEqual(digest(self.source),before)

    def test_existing_and_live_or_dangling_symlinks_all_three_paths(self):
        with connect(self.ws,'A') as (root,db):
            for fmt in ('jsonl','text'):
                for index in range(3):
                    for mode in ('existing','live','dangling'):
                        path=self.base/(fmt+str(index)+mode);paths=self.paths(path);protected=paths[index]
                        target=self.base/(path.name+'-target')
                        if mode=='existing':protected.write_bytes(b'KEEP')
                        else:
                            if mode=='live':target.write_bytes(b'KEEP')
                            protected.symlink_to(target)
                        with self.assertRaises(FileExistsError if mode=='existing' else UserError):
                            export_findings(root,db,path,fmt)
                        if mode=='dangling':self.assertTrue(protected.is_symlink());self.assertFalse(target.exists())
                        else:self.assertEqual(protected.read_bytes(),b'KEEP')
                        for item in paths:
                            if item!=protected:self.assertFalse(item.exists())

    def test_original_input_case_evidence_and_both_sidecar_sources_protected(self):
        for index,suffix in enumerate(('.coverage.json','.receipt.json')):
            source=self.base/('protected'+str(index)+suffix)
            source.write_text(json.dumps({'category':'messages','body':suffix,'data':{}})+'\n')
            handle(self.ws,{'case':'A','action':'import','path':str(source),'format':'jsonl'})
        with connect(self.ws,'A') as (root,db):
            before=digest(self.source)
            for fmt in ('jsonl','text'):
                for path in (self.source,root/'case.sqlite',root/'evidence'/'new',self.base/'protected0',self.base/'protected1'):
                    with self.assertRaises(UserError):export_findings(root,db,path,fmt)
            self.assertEqual(digest(self.source),before)

    def test_partial_writes_all_three_clean_only_owned_files(self):
        original=Path.open
        class Partial:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):self.stream.close()
            def write(self,data):self.stream.write(data[:7]);raise OSError('partial write')
        with connect(self.ws,'A') as (root,db):
            before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            for fmt in ('jsonl','text'):
                for index in range(3):
                    path=self.base/(fmt+str(index));paths=self.paths(path);target=paths[index]
                    def opening(item,*args,**kwargs):
                        stream=original(item,*args,**kwargs)
                        return Partial(stream) if item==target and args[0]=='x' else stream
                    with patch.object(Path,'open',opening),self.assertRaises(OSError):export_findings(root,db,path,fmt)
                    self.assertFalse(any(item.exists() for item in paths))
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before)

    def test_racing_exclusive_creation_preserves_unowned_files(self):
        original=Path.open
        with connect(self.ws,'A') as (root,db):
            for fmt in ('jsonl','text'):
                for index in range(3):
                    path=self.base/(fmt+str(index));paths=self.paths(path);target=paths[index]
                    def opening(item,*args,**kwargs):
                        if item==target and args[0]=='x':
                            with original(item,'w') as out:out.write('OTHER WRITER')
                        return original(item,*args,**kwargs)
                    with patch.object(Path,'open',opening),self.assertRaises(FileExistsError):export_findings(root,db,path,fmt)
                    self.assertEqual(target.read_text(),'OTHER WRITER')
                    self.assertTrue(all(not item.exists() for item in paths if item!=target))

    def test_hash_failures_all_three_clean_group(self):
        with connect(self.ws,'A') as (root,db):
            for fmt in ('jsonl','text'):
                for index in range(3):
                    path=self.base/(fmt+str(index));paths=self.paths(path);target=paths[index]
                    def hashing(item):
                        if Path(item)==target:raise OSError('hash failure')
                        return digest(item)
                    with patch('lawliet_mobile.findings.digest',hashing),self.assertRaises(OSError):export_findings(root,db,path,fmt)
                    self.assertFalse(any(item.exists() for item in paths))

    def test_output_and_receipt_serialization_failures_clean_group(self):
        from lawliet_mobile.findings import json_text
        with connect(self.ws,'A') as (root,db):
            for fmt in ('jsonl','text'):
                for phase in ('output','receipt'):
                    path=self.base/(fmt+phase)
                    def encode(value):
                        if (phase=='receipt' and value.get('format')=='ancalor-findings-export-v1') or (phase=='output' and 'snapshot' in value and 'sha256' in value):
                            raise TypeError('serialization failure')
                        return json_text(value)
                    patches=[patch('lawliet_mobile.findings.json_text',encode)]
                    if phase=='output' and fmt=='text':patches.append(patch('lawliet_mobile.findings.text_finding',side_effect=TypeError('render failure')))
                    import contextlib
                    with contextlib.ExitStack() as stack:
                        for item in patches:stack.enter_context(item)
                        with self.assertRaises(TypeError):export_findings(root,db,path,fmt)
                    self.assertFalse(any(item.exists() for item in self.paths(path)))

    def test_audit_failure_retains_prior_pending_events(self):
        def fail(db,action,detail):audit(db,action,detail);raise RuntimeError('audit failure')
        with connect(self.ws,'A') as (root,db):
            audit(db,'test.pending',{'retained':True})
            before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            for fmt in ('jsonl','text'):
                path=self.base/fmt
                with patch('lawliet_mobile.findings.audit',fail),self.assertRaises(RuntimeError):export_findings(root,db,path,fmt)
                self.assertFalse(any(item.exists() for item in self.paths(path)))
                self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='test.pending'").fetchone()[0],1)

    def test_outer_release_failure_cleans_group(self):
        class ConnectionProxy:
            def __init__(self,db):self.db=db;self.failed=False
            def execute(self,sql,*args):
                if sql=='RELEASE SAVEPOINT findings_export' and not self.failed:
                    self.failed=True;raise RuntimeError('injected release failure before commit')
                return self.db.execute(sql,*args)
        with connect(self.ws,'A') as (root,db):
            before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            for fmt in ('jsonl','text'):
                path=self.base/fmt
                with self.assertRaises(RuntimeError):export_findings(root,ConnectionProxy(db),path,fmt)
                self.assertFalse(any(item.exists() for item in self.paths(path)))
                self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before)

    def test_pagination_and_empty_exports_preserve_counts(self):
        with connect(self.ws,'A') as (root,db):
            for n in range(101):add_finding(db,self.aid,'extra '+str(n))
            for fmt in ('jsonl','text'):
                path=self.base/('pages'+fmt);result=export_findings(root,db,path,fmt)
                self.assertEqual(result['records'],102)
                if fmt=='jsonl':self.assertEqual(len(path.read_text().splitlines()),102)
                else:self.assertEqual(path.read_text().count('\nFINDING '),102)
        create_case(self.ws,'empty')
        with connect(self.ws,'empty') as (root,db):
            for fmt in ('jsonl','text'):
                path=self.base/('empty'+fmt);result=export_findings(root,db,path,fmt)
                self.assertEqual(result['records'],0)
                coverage=json.loads(Path(result['coverage_path']).read_text())
                self.assertEqual(coverage['coverage_context']['observations'],[])
                self.assertEqual(coverage['export_scope']['records'],0)
                self.assertFalse(coverage['scope_sufficient_for_state_counts'])

    def test_coverage_serialization_failure_cleans_output(self):
        with connect(self.ws,'A') as (root,db):
            for fmt in ('jsonl','text'):
                path=self.base/fmt
                with patch('lawliet_mobile.portable_coverage.bounded_json',side_effect=UserError('metadata budget')),self.assertRaises(UserError):
                    export_findings(root,db,path,fmt)
                self.assertFalse(any(item.exists() for item in self.paths(path)))
