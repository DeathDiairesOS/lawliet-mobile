import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile.core import connect, create_case, UserError
from lawliet_mobile.report import write_jsonl_export, write_export, write_report


class ExportBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base/'cases'
        create_case(self.ws, 'A')
        self.parent = self.base/'exports'; self.parent.mkdir()
        self.foreign = self.base/'foreign'; self.foreign.mkdir()
        self.path = self.parent/'rows.jsonl'

    def check_no_receipt(self, db):
        self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='export.created'").fetchone()[0], 0)

    def replace_or_fail(self, operation, failure=UserError):
        if os.name == 'nt':
            # Windows denies replacement while the owned handles are open.
            # After asserting that boundary, inject a failure to exercise the
            # same receipt rollback and owned-file cleanup as the POSIX case.
            with self.assertRaises(PermissionError):
                operation()
            raise failure('Controlled failure after Windows refused replacement')
        operation()

    def test_parent_replaced_with_link_during_streaming(self):
        moved=self.base/'moved'
        def rows():
            yield {'body':'synthetic'}
            self.replace_or_fail(lambda: self.parent.rename(moved))
            self.parent.symlink_to(self.foreign, target_is_directory=True)
        with connect(self.ws,'A') as (root,db):
            with self.assertRaises((UserError,OSError)):
                write_jsonl_export(root,db,self.path,rows(),{})
            self.check_no_receipt(db)
        self.assertEqual(list(self.foreign.iterdir()),[])
        self.assertEqual(list((self.parent if os.name == 'nt' else moved).iterdir()),[])
        if os.name == 'nt': self.assertFalse(moved.exists())

    def test_parent_replaced_with_ordinary_directory(self):
        moved=self.base/'moved'
        def rows():
            yield {'body':'synthetic'}
            self.replace_or_fail(lambda: self.parent.rename(moved));self.parent.mkdir()
            (self.parent/'CANARY').write_text('unowned')
        with connect(self.ws,'A') as (root,db):
            with self.assertRaises(UserError):write_jsonl_export(root,db,self.path,rows(),{})
            self.check_no_receipt(db)
        self.assertEqual([p.name for p in self.parent.iterdir()],[] if os.name == 'nt' else ['CANARY'])
        if os.name == 'nt': self.assertFalse(moved.exists())
        else: self.assertEqual(list(moved.iterdir()),[])

    def test_failure_cleanup_preserves_replaced_file(self):
        def fail(db, action, detail):
            self.replace_or_fail(self.path.unlink, RuntimeError);self.path.write_text('FOREIGN_REPLACEMENT')
            raise RuntimeError('controlled audit failure')
        with connect(self.ws,'A') as (root,db):
            with patch('lawliet_mobile.report.audit',side_effect=fail):
                with self.assertRaises(RuntimeError):write_jsonl_export(root,db,self.path,iter([{'body':'synthetic'}]),{})
            self.check_no_receipt(db)
        if os.name == 'nt': self.assertFalse(self.path.exists())
        else: self.assertEqual(self.path.read_text(),'FOREIGN_REPLACEMENT')
        self.assertFalse(Path(str(self.path)+'.coverage.json').exists())
        self.assertEqual([p.name for p in self.parent.iterdir()],[] if os.name == 'nt' else [self.path.name])

    def test_companion_collision_after_stream_does_not_publish_data(self):
        companion=Path(str(self.path)+'.coverage.json')
        def rows():
            yield {'body':'synthetic'}
            companion.write_text('UNOWNED_RECEIPT')
        with connect(self.ws,'A') as (root,db):
            with self.assertRaises(FileExistsError):write_jsonl_export(root,db,self.path,rows(),{})
            self.check_no_receipt(db)
        self.assertFalse(self.path.exists())
        self.assertEqual(companion.read_text(),'UNOWNED_RECEIPT')
        self.assertEqual([p.name for p in self.parent.iterdir()],[companion.name])

    def test_nested_output_and_file_permissions(self):
        import stat
        path=self.parent/'nested'/'further'/'rows.jsonl'
        with connect(self.ws,'A') as (root,db):
            result=write_jsonl_export(root,db,path,iter([{'body':'café 東京\nsecond'}]),{})
        self.assertEqual(json.loads(path.read_text())['body'],'café 東京\nsecond')
        for output in (path, Path(result['coverage_path'])):
            state = output.lstat()
            self.assertTrue(stat.S_ISREG(state.st_mode))
            self.assertEqual(state.st_nlink, 1)
            if os.name == 'nt':
                self.assertFalse(getattr(state, 'st_file_attributes', 0) & 0x400)
                # Windows inherits ACLs; POSIX mode bits cannot certify privacy.
            else:
                self.assertEqual(stat.S_IMODE(state.st_mode),0o600)
        self.assertEqual({p.name for p in path.parent.iterdir()},{path.name,path.name+'.coverage.json'})

    def test_preexisting_parent_link_and_dangling_output_refused(self):
        alias=self.base/'alias';alias.symlink_to(self.foreign,target_is_directory=True)
        with connect(self.ws,'A') as (root,db):
            with self.assertRaises(UserError):write_jsonl_export(root,db,alias/'rows',iter(()),{})
            self.path.symlink_to(self.foreign/'missing')
            with self.assertRaises(UserError):write_jsonl_export(root,db,self.path,iter(()),{})
            self.check_no_receipt(db)
        self.assertEqual(list(self.foreign.iterdir()),[])

    def test_stage_replacement_does_not_hash_foreign_data_or_remove_it(self):
        def rows():
            yield {'body':'synthetic'}
            stage=next(self.parent.glob('.lawliet-export-*'))
            self.replace_or_fail(stage.unlink);stage.write_text('FOREIGN_STAGE')
        with connect(self.ws,'A') as (root,db):
            with self.assertRaises(UserError):write_jsonl_export(root,db,self.path,rows(),{})
            self.check_no_receipt(db)
        remaining=list(self.parent.iterdir())
        self.assertEqual(len(remaining),0 if os.name == 'nt' else 1)
        if os.name != 'nt': self.assertEqual(remaining[0].read_text(),'FOREIGN_STAGE')

    def test_post_publish_parent_change_rolls_back_and_cleans_anchored_output(self):
        from lawliet_mobile.report import audit as real_audit
        moved=self.base/'moved'
        def redirect(db,action,detail):
            real_audit(db,action,detail)
            self.replace_or_fail(lambda: self.parent.rename(moved));self.parent.symlink_to(self.foreign,target_is_directory=True)
            (self.foreign/self.path.name).write_text('FOREIGN')
        with connect(self.ws,'A') as (root,db):
            with patch('lawliet_mobile.report.audit',side_effect=redirect):
                with self.assertRaises((UserError,OSError)):write_jsonl_export(root,db,self.path,iter([{'body':'synthetic'}]),{})
            self.check_no_receipt(db)
        if os.name == 'nt':
            self.assertEqual(list(self.foreign.iterdir()),[])
            self.assertEqual(list(self.parent.iterdir()),[])
            self.assertFalse(moved.exists())
        else:
            self.assertEqual((self.foreign/self.path.name).read_text(),'FOREIGN')
            self.assertEqual(list(moved.iterdir()),[])

    def test_all_paired_formats_preserve_foreign_replacement_on_failure(self):
        for format_name in ['jsonl','json','csv','html']:
            with self.subTest(format=format_name):
                path=self.parent/('rows.'+format_name)
                def fail(db, action, detail):
                    self.replace_or_fail(path.unlink, RuntimeError);path.write_text('UNOWNED')
                    raise RuntimeError('controlled')
                with connect(self.ws,'A') as (root,db):
                    with patch('lawliet_mobile.report.audit',side_effect=fail):
                        with self.assertRaises(RuntimeError):
                            if format_name=='html':write_report(root,db,path)
                            else:write_export(root,db,path,format_name,[])
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action IN ('export.created','report.created')").fetchone()[0],0)
                if os.name == 'nt': self.assertFalse(path.exists())
                else: self.assertEqual(path.read_text(),'UNOWNED')
                self.assertFalse(Path(str(path)+'.coverage.json').exists())

    def test_all_paired_formats_detect_companion_replacement_after_publish(self):
        for format_name in ['jsonl','json','csv','html']:
            with self.subTest(format=format_name):
                path=self.parent/('companion.'+format_name);companion=Path(str(path)+'.coverage.json')
                from lawliet_mobile.report import audit as original
                def replace(db,action,detail):
                    original(db,action,detail)
                    self.replace_or_fail(companion.unlink);companion.write_text('UNOWNED_COMPANION')
                with connect(self.ws,'A') as (root,db):
                    with patch('lawliet_mobile.report.audit',side_effect=replace):
                        with self.assertRaises(UserError):
                            if format_name=='html':write_report(root,db,path)
                            else:write_export(root,db,path,format_name,[])
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action IN ('export.created','report.created')").fetchone()[0],0)
                self.assertFalse(path.exists())
                if os.name == 'nt': self.assertFalse(companion.exists())
                else: self.assertEqual(companion.read_text(),'UNOWNED_COMPANION')
