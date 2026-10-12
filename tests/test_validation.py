import json
import plistlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,import_evidence,UserError
from lawliet_mobile.parsers import native_analyze, VERSION
from lawliet_mobile.validation import validate_case,preflight


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'qa')
    def test_source_reconciliation_and_mismatch_detection(self):
        source=self.base/'sms.db'
        with closing(sqlite3.connect(source)) as c, c:
            c.executescript("CREATE TABLE message(text TEXT,date INTEGER,handle_id INTEGER,is_from_me INTEGER);CREATE TABLE handle(id TEXT);INSERT INTO message VALUES('Expected text',700000000,1,0);INSERT INTO handle VALUES('+12025550100');")
        with connect(self.ws,'qa') as (root,db):
            eid=import_evidence(root,db,source,'ios')[0];native_analyze(root,db,eid)
            report=validate_case(root,db,self.ws,eid,VERSION)
            check=next(c for c in report['checks'] if c['check']=='ios_messages_reconciliation')
            self.assertEqual(check['status'],'pass');self.assertEqual(check['plaintext_comparisons'],1)
            self.assertTrue(Path(report['path']).is_file())
            db.execute("UPDATE artifacts SET body='wrong',timestamp='2026-01-01T00:00:00.000000Z' WHERE category='messages'")
            report=validate_case(root,db,self.ws,eid,VERSION)
            check=next(c for c in report['checks'] if c['check']=='ios_messages_reconciliation')
            self.assertEqual(check['status'],'needs_review');self.assertEqual(check['mismatches'][0]['fields'],['plaintext','timestamp'])
    def test_manifest_missing_payload_even_when_finished(self):
        source=self.base/'backup';source.mkdir()
        (source/'Manifest.plist').write_bytes(plistlib.dumps({'IsEncrypted':False}))
        (source/'Status.plist').write_bytes(plistlib.dumps({'SnapshotState':'finished'}))
        with closing(sqlite3.connect(source/'Manifest.db')) as c, c:
            c.executescript("CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER);INSERT INTO Files VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','HomeDomain','Library/missing.db',1);")
        with connect(self.ws,'qa') as (root,db):
            eid=import_evidence(root,db,source,'ios')[0]
            report=validate_case(root,db,self.ws,eid)
            check=next(c for c in report['checks'] if c['check']=='ios_backup_inventory');self.assertEqual(check['status'],'incomplete');self.assertEqual(check['missing_count'],1)
    def test_storage_preflight_reserves_both_copies(self):
        with patch('lawliet_mobile.validation.shutil.disk_usage') as usage,patch('lawliet_mobile.validation.doctor',return_value={'tools':[{'tool':'adb','available':True}]}):
            usage.return_value.free=3*1024**3
            self.assertTrue(preflight(self.ws,'android',1024**3)['ready'])
            usage.return_value.free-=1
            self.assertFalse(preflight(self.ws,'android',1024**3)['ready'])
    def test_integrity_failure_blocks_validation(self):
        source=self.base/'file';source.write_text('original')
        with connect(self.ws,'qa') as (root,db):
            eid=import_evidence(root,db,source,'auto')[0]
            (root/'evidence'/eid/'file').write_text('changed')
            with self.assertRaisesRegex(UserError,'integrity'):validate_case(root,db,self.ws,eid)
