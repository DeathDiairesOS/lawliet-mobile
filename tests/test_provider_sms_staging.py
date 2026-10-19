"""Collector initialization must refuse foreign staging before writes or ADB."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import UserError,connect,create_case
from lawliet_mobile.provider_sms import collect_sms,_create_collection_staging

class ProviderStagingTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.base=Path(tmp.name).resolve();self.workspace=self.base/'cases'
        create_case(self.workspace,'A');create_case(self.workspace,'B')
        self.case=self.workspace/'A';self.foreign=self.workspace/'B'/'staging';self.foreign.mkdir()
        self.protected=self.foreign/'protected.txt';self.protected.write_bytes(b'FOREIGN ORIGINAL')
        self.tool=self.base/'adb.py';self.tool.write_text('# synthetic tool, must not run\n')
    def refuse(self):
        before=sorted(str(p.relative_to(self.foreign)) for p in self.foreign.rglob('*'))
        with patch('lawliet_mobile.provider_sms.command',return_value=[sys.executable,str(self.tool)]),patch('lawliet_mobile.provider_sms.execute',side_effect=AssertionError('Device command reached')) as execute:
            with connect(self.workspace,'A') as (root,db):
                with self.assertRaisesRegex(UserError,'staging cannot be created safely'):
                    collect_sms(root,db,self.workspace,'FIXTURE')
                self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],0)
                self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='collection.started'").fetchone()[0],0)
            execute.assert_not_called()
        self.assertEqual(self.protected.read_bytes(),b'FOREIGN ORIGINAL')
        self.assertEqual(sorted(str(p.relative_to(self.foreign)) for p in self.foreign.rglob('*')),before)
    def test_collections_root_symlink_refused_before_registration_or_foreign_entries(self):
        path=self.case/'collections'
        if path.exists():path.rmdir()
        path.symlink_to(self.foreign,target_is_directory=True);self.refuse()
    def test_regular_collections_path_preserved_and_refused(self):
        path=self.case/'collections'
        if path.exists():path.rmdir()
        path.write_bytes(b'EXISTING PATH');self.refuse();self.assertEqual(path.read_bytes(),b'EXISTING PATH')
    def test_existing_generated_identifier_is_not_reused(self):
        parent=self.case/'collections';parent.mkdir(exist_ok=True)
        old=parent/'000000000001';old.mkdir();sentinel=old/'retained.txt';sentinel.write_bytes(b'OLD ATTEMPT')
        with self.assertRaises(UserError):_create_collection_staging(self.case,'000000000001')
        self.assertEqual(sentinel.read_bytes(),b'OLD ATTEMPT');self.assertEqual(list(old.iterdir()),[sentinel])
    def test_new_staging_permissions_and_empty_journal(self):
        folder,payload,journal=_create_collection_staging(self.case,'000000000001')
        self.assertEqual(folder,self.case/'collections/000000000001')
        self.assertEqual(journal.read_bytes(),b'')
        self.assertEqual(folder.stat().st_mode&0o777,0o700)
        self.assertEqual(payload.stat().st_mode&0o777,0o700)
        self.assertEqual(journal.stat().st_mode&0o777,0o600)
