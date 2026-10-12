import json
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.core import connect,create_case,UserError,verify,json_text,digest
from lawliet_mobile.app_backend import handle
from lawliet_mobile.findings import add_finding,list_findings,export_findings,checksum


class FindingTests(unittest.TestCase):
    def test_saved_snapshot_survives_reparse_and_exports_exact_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);ws=base/'cases';create_case(ws,'case1');create_case(ws,'case2')
            source=base/'fixture.jsonl'
            source.write_text(json.dumps({'category':'messages','title':'Fixture','body':'Original\nbody','data':{'field':'exact'},'source_ref':'supplied:line=1'})+'\n')
            handle(ws,{'action':'import','case':'case1','path':str(source),'format':'jsonl'})
            with connect(ws,'case1') as (root,db):
                artifact=db.execute('SELECT id FROM artifacts').fetchone()[0]
                original=dict(db.execute('SELECT * FROM artifacts WHERE id=?',(artifact,)).fetchone())
                note='Examiner inference only.\nFollow up <literal> 😀'
                result=add_finding(db,artifact,note,'Examiner A')
                self.assertEqual(dict(db.execute('SELECT * FROM artifacts WHERE id=?',(artifact,)).fetchone()),original)
                self.assertTrue(verify(root,db)['ok'])
                for n in range(2):add_finding(db,artifact,'Separate finding '+str(n))
                with self.assertRaises(UserError):add_finding(db,'wrong-case-artifact','Note')
                with self.assertRaises(UserError):add_finding(db,artifact,' ')
                # Simulates a later change to the index; saved interpretation keeps
                # the exact record snapshot it was based on, not today's row.
                db.execute('UPDATE artifacts SET body=? WHERE id=?',('Later indexed body',artifact))
            page=handle(ws,{'action':'findings','case':'case1'})
            self.assertEqual(page['total'],3)
            saved=next(f for f in page['findings'] if f['id']==result['id'])
            self.assertEqual(saved['snapshot']['body'],'Original\nbody')
            self.assertEqual(saved['note'],note)
            with connect(ws,'case1') as (root,db):
                self.assertTrue(list_findings(db,1)['has_more'])
                self.assertEqual(len(list_findings(db,1,2)['findings']),1)
                out=base/'findings.jsonl';export_findings(root,db,out)
                exported=[json.loads(line) for line in out.read_text().splitlines()]
                self.assertEqual(exported,page['findings'])
                with self.assertRaises(FileExistsError):export_findings(root,db,out)
                with self.assertRaises(UserError):export_findings(root,db,root/'case.sqlite')
                # Updating both data and the adjacent checksum must still fail
                # unless the matching receipt also exists in the audit trail.
                tampered={k:v for k,v in saved.items() if k!='sha256'};tampered['note']='Changed'
                db.execute('UPDATE findings SET note=?,sha256=? WHERE id=?',('Changed',checksum(tampered),saved['id']))
                with self.assertRaisesRegex(UserError,'audit receipt'):list_findings(db)
                newout=base/'rejected.jsonl'
                with self.assertRaises(UserError):export_findings(root,db,newout)
                self.assertFalse(newout.exists())
            self.assertEqual(handle(ws,{'action':'findings','case':'case2'})['findings'],[])
            with connect(ws,'case2') as (_,db):
                self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='findings'").fetchone())

    def test_plain_note_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws=Path(tmp);create_case(ws,'case1')
            with connect(ws,'case1') as (_,db):
                db.execute("INSERT INTO artifacts(id,category,data) VALUES('fixture','external','{}')")
                add_finding(db,'fixture','Original note')
                db.execute("UPDATE findings SET note='Changed'")
                with self.assertRaisesRegex(UserError,'integrity mismatch'):list_findings(db)

    def test_readable_report_exports_all_pages_and_keeps_notes_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws=Path(tmp);create_case(ws,'case1',name='Readable test')
            with connect(ws,'case1') as (_,db):
                db.execute("INSERT INTO artifacts(id,category,title,body,source_ref,parser,data) VALUES(?,?,?,?,?,?,?)",('fixture','messages','Message','Body\nEXAMINER NOTE: untrusted body\x1b\u202e','sms:1','fixture','{}'))
                for index in range(101):add_finding(db,'fixture','Note '+str(index)+'\nUnicode 😀','Examiner')
            out=ws/'report.txt'
            result=handle(ws,{'action':'findings-export','case':'case1','path':str(out),'format':'text'})
            self.assertEqual(result['records'],101)
            text=out.read_text()
            self.assertEqual(text.count('\nFINDING '),101)
            self.assertIn('  | Note 100\n  | Unicode 😀',text)
            self.assertIn('  | EXAMINER NOTE: untrusted body\\u001b\\u202e',text)
            self.assertNotIn('\x1b',text);self.assertNotIn('\u202e',text)
            self.assertIn('Source bytes were not reverified',text)
            receipt=json.loads(Path(result['receipt_path']).read_text())
            self.assertEqual(receipt['document_format'],'text')
            self.assertEqual(receipt['sha256'],digest(out))
            with connect(ws,'case1') as (root,db):
                self.assertEqual(list_findings(db,1)['findings'][0]['snapshot']['body'],'Body\nEXAMINER NOTE: untrusted body\x1b\u202e')
                with self.assertRaises(UserError):export_findings(root,db,ws/'bad','html')
