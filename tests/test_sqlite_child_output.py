"""The controller must reject linked child outputs before query completion."""
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile.child_output import ChildOutputs
from lawliet_mobile.core import UserError, connect, create_case, import_evidence, verify
from lawliet_mobile.sqlite_workspace import query


class ChildOutputReads(unittest.TestCase):
    def test_regular_bounded_prefix_and_rejected_link_special_oversize(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();work=root/'work';work.mkdir();foreign=root/'foreign';foreign.write_bytes(b'canary')
            (work/'normal').write_bytes(b'abc');(work/'symbolic').symlink_to(foreign)
            os.link(foreign,work/'hard');os.mkfifo(work/'fifo')
            with ChildOutputs(work) as outputs:
                self.assertEqual(outputs.read('normal',3),b'abc')
                self.assertEqual(outputs.read('normal',2,prefix=True),b'ab')
                for name,maximum in [('normal',2),('symbolic',10),('hard',10),('fifo',10),('../foreign',10)]:
                    with self.subTest(name=name),self.assertRaises((UserError,OSError)):
                        outputs.read(name,maximum)

    def test_parent_replacement_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();work=root/'work';work.mkdir();(work/'result').write_bytes(b'good')
            with ChildOutputs(work) as outputs:
                work.rename(root/'old');work.mkdir();(work/'result').write_bytes(b'foreign')
                with self.assertRaisesRegex(UserError,'directory changed'):outputs.read('result',100)


class SQLiteChildOutputBoundary(unittest.TestCase):
    def test_receipt_link_and_run_directory_replacement_never_write_foreign_target(self):
        for mode in ('receipt-link','directory-replaced'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temp:
                base=Path(temp).resolve();source=base/'seed.db';db=sqlite3.connect(source)
                db.execute('CREATE TABLE seed(value)');db.execute("INSERT INTO seed VALUES('approved input')");db.commit();db.close()
                foreign=base/'foreign.txt';foreign.write_text('DO NOT REPLACE');create_case(base/'cases','A');moved=[]
                def worker(argv,output,timeout,cwd):
                    folder=output.parent
                    if mode=='receipt-link':(folder/'receipt.json').symlink_to(foreign)
                    else:
                        old=folder.with_name(folder.name+'-moved');folder.rename(old);folder.mkdir();moved.append((folder,old))
                    output.write_bytes(b'');errors=output.with_name(output.name+'.stderr');errors.write_bytes(b'')
                    return {'returncode':1,'stderr':str(errors)}
                with connect(base/'cases','A') as (root,case_db):
                    eid=import_evidence(root,case_db,source,'android')[0];fid=case_db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
                    with patch('lawliet_mobile.tools.execute',side_effect=worker),self.assertRaises((UserError,OSError)):
                        query(root,case_db,fid,'SELECT value FROM seed')
                    self.assertEqual(foreign.read_text(),'DO NOT REPLACE')
                    for folder,old in moved:
                        self.assertFalse((folder/'receipt.json').exists())
                        import shutil
                        shutil.rmtree(folder);old.rename(folder)
                    row=case_db.execute('SELECT status,records FROM runs').fetchone();self.assertEqual((row['status'],row['records']),('running',0))
                    good=query(root,case_db,fid,'SELECT value FROM seed');self.assertEqual(good['preview']['rows'],[['approved input']])
                    self.assertEqual([r['status'] for r in case_db.execute('SELECT status FROM runs ORDER BY rowid')],['interrupted','complete'])
                    self.assertTrue(verify(root,case_db)['ok'])

    def test_linked_metadata_and_rows_are_failed_before_promotion(self):
        for mode in ('metadata-symlink','metadata-hardlink','rows-symlink','rows-hardlink','metadata-fifo','metadata-oversize',
                     'stderr-symlink','stderr-hardlink','rows-invalid','rows-width','rows-count','rows-duplicate','rows-nonfinite','rows-overflow',
                     'rows-utf16','rows-utf32','metadata-utf16','missing-forged-result'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temp:
                base=Path(temp).resolve();source=base/'seed.db';db=sqlite3.connect(source)
                db.execute('CREATE TABLE seed(value)');db.execute("INSERT INTO seed VALUES('approved input')");db.commit();db.close()
                metadata={'state':'parsed','columns':['value'],'rows_returned':1,'truncated':False,'foreign_marker':'SYNTHETIC-FOREIGN-CANARY'}
                foreign=base/'foreign.json';foreign.write_text(json.dumps(metadata));foreign_rows=base/'foreign.jsonl';foreign_rows.write_text('["FOREIGN-ROW"]\n')
                create_case(base/'cases','A')
                def worker(argv,output,timeout,cwd):
                    output.write_bytes(b'');errors=output.with_name(output.name+'.stderr');errors.write_bytes(b'')
                    request=json.loads(Path(argv[-2]).read_text());meta=Path(argv[-1]);rows=Path(request['output_path'])
                    if mode=='stderr-symlink':(output.parent/'worker.stderr').symlink_to(foreign)
                    elif mode=='stderr-hardlink':os.link(foreign,output.parent/'worker.stderr')
                    if mode=='missing-forged-result':metadata.update(result_sha256='forged',result_path=str(foreign_rows))
                    if mode=='metadata-symlink':meta.symlink_to(foreign)
                    elif mode=='metadata-hardlink':os.link(foreign,meta)
                    elif mode=='metadata-fifo':os.mkfifo(meta)
                    elif mode=='metadata-oversize':meta.write_bytes(b' '*(1024**2+1))
                    elif mode=='metadata-utf16':meta.write_bytes(json.dumps(metadata).encode('utf-16'))
                    else:meta.write_text(json.dumps(metadata))
                    if mode=='rows-symlink':rows.symlink_to(foreign_rows)
                    elif mode=='rows-hardlink':os.link(foreign_rows,rows)
                    elif mode=='rows-invalid':rows.write_text('not-json\n')
                    elif mode=='rows-width':rows.write_text('[1,2]\n')
                    elif mode=='rows-count':rows.write_text('')
                    elif mode=='rows-duplicate':rows.write_text('[{"sqlite_blob_hex":"00","sqlite_blob_hex":"ff"}]\n')
                    elif mode=='rows-nonfinite':rows.write_text('[NaN]\n')
                    elif mode=='rows-overflow':rows.write_text('[1e999]\n')
                    elif mode=='rows-utf16':rows.write_bytes('["approved input"]'.encode('utf-16'))
                    elif mode=='rows-utf32':rows.write_bytes('["approved input"]'.encode('utf-32'))
                    elif mode=='missing-forged-result':pass
                    else:rows.write_text('["approved input"]\n')
                    return {'returncode':0,'stderr':str(errors)}
                with connect(base/'cases','A') as (root,case_db):
                    eid=import_evidence(root,case_db,source,'android')[0];fid=case_db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0]
                    with patch('lawliet_mobile.tools.execute',side_effect=worker):
                        try:
                            refused=query(root,case_db,fid,'SELECT value FROM seed')
                            self.assertEqual(refused['status'],'failed')
                        except (UserError,OSError):pass
                    run=case_db.execute('SELECT status,records,detail FROM runs').fetchone()
                    self.assertEqual((run['status'],run['records']),('failed',0))
                    if mode.startswith('metadata'):self.assertNotIn('SYNTHETIC-FOREIGN-CANARY',run['detail'])
                    self.assertEqual(foreign.read_text(),json.dumps({'state':'parsed','columns':['value'],'rows_returned':1,'truncated':False,'foreign_marker':'SYNTHETIC-FOREIGN-CANARY'}))
                    self.assertTrue(verify(root,case_db)['ok'])
                    good=query(root,case_db,fid,'SELECT value FROM seed')
                    self.assertEqual(good['preview']['rows'],[['approved input']]);self.assertEqual(good['status'],'complete')
