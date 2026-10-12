"""Opt-in real LEAPP tests. Set LAWLIET_ILEAPP / LAWLIET_ALEAPP to entry points.

Run with a Python interpreter containing upstream dependencies. No downloads,
device access, or dependency installation are performed by these tests.
"""
import hashlib
import os
import plistlib
import sqlite3
import tempfile
import unittest
import json
import zlib
from contextlib import closing
from pathlib import Path

from lawliet_mobile.core import connect, create_case, import_evidence, select_artifacts, verify
from lawliet_mobile.tools import configure, external_analyze


class RealLeappTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lawliet-real-leapp-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / "cases"
        create_case(self.workspace, "integration")

    def analyze(self, source, platform, engine, marker, input_type, expected_time=None):
        configure(self.workspace, engine, os.environ[f"LAWLIET_{engine.upper()}"])
        with connect(self.workspace, "integration") as (root, db):
            eid, _, _ = import_evidence(root, db, source, platform)
            result = external_analyze(root, db, self.workspace, eid, engine)
            self.assertEqual(result["status"], "complete")
            self.assertGreater(result["new_records"], 0)
            argv = result["detail"]["argv"]
            self.assertEqual(argv[argv.index("-t") + 1], input_type)
            records = select_artifacts(db, query=marker)
            self.assertEqual(len(records), 1, result)
            record = records[0]
            self.assertEqual(record["parser"], engine)
            self.assertIsNone(record["source_sha256"])
            self.assertEqual(record["timestamp"], expected_time)
            path, line = record["source_ref"].rsplit(":line=", 1)
            self.assertTrue((root / path).is_file())
            self.assertGreater(int(line), 1)
            self.assertTrue(record["data"])
            self.assertTrue(verify(root, db)["ok"])
            return record

    def safari(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
                CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
                CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER,
                    visit_time REAL, title TEXT, redirect_source INTEGER,
                    redirect_destination INTEGER, origin INTEGER);
                INSERT INTO history_items VALUES(1, 'https://leapp-validation.example/safari', 1);
                INSERT INTO history_visits VALUES(1, 1, 813592800, 'Synthetic LEAPP validation', NULL, NULL, 0);
            """)

    @unittest.skipUnless(os.environ.get("LAWLIET_ILEAPP"), "Set LAWLIET_ILEAPP for real iLEAPP")
    def test_ileapp_filesystem(self):
        source = self.base / "ios"
        self.safari(source / "private/var/mobile/Library/Safari/History.db")
        self.analyze(source, "ios", "ileapp", "leapp-validation.example/safari", "fs")

    @unittest.skipUnless(os.environ.get("LAWLIET_ILEAPP"), "Set LAWLIET_ILEAPP for real iLEAPP")
    def test_ileapp_enclosed_hashed_backup(self):
        source = self.base / "enclosing" / "backup"
        logical = "Library/Safari/History.db"
        file_id = hashlib.sha1(f"HomeDomain-{logical}".encode()).hexdigest()
        self.safari(source / file_id[:2] / file_id)
        (source / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
        with closing(sqlite3.connect(source / "Manifest.db")) as db, db:
            db.execute("CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
            db.execute("INSERT INTO Files VALUES(?, 'HomeDomain', ?, 1, NULL)", (file_id, logical))
        self.analyze(source.parent, "ios", "ileapp", "leapp-validation.example/safari", "itunes")

    @unittest.skipUnless(os.environ.get("LAWLIET_ALEAPP"), "Set LAWLIET_ALEAPP for real ALEAPP")
    def test_aleapp_filesystem(self):
        source = self.base / "android"
        backup = source / "data/data/com.riteshsahu.SMSBackupRestore/files/sms-validation.xml"
        backup.parent.mkdir(parents=True)
        backup.write_text('''<?xml version="1.0" encoding="UTF-8"?>
<smses count="1" backup_date="1791640800000" type="full" backup_set="synthetic">
  <sms date="1791640800000" type="1" address="+1-202-555-0100"
       body="https://leapp-validation.example/message" read="1" />
</smses>
''')
        self.analyze(source, "android", "aleapp", "leapp-validation.example/message", "fs",
                     "2026-10-10T14:00:00.000000Z")

    @unittest.skipUnless(os.environ.get("LAWLIET_ALEAPP"), "Set LAWLIET_ALEAPP for real ALEAPP")
    def test_aleapp_telephony_message_mapping(self):
        source = self.base / 'telephony'
        payload = source / 'apps/com.android.providers.telephony/d_f/000000_sms_backup'
        payload.parent.mkdir(parents=True)
        payload.write_bytes(zlib.compress(json.dumps([{'date': '1791640800000', 'type': '1',
            'body': 'telephony-mapping.example', 'address': '+12025550100'}]).encode()))
        record = self.analyze(source, 'android', 'aleapp', 'telephony-mapping.example', 'fs', '2026-10-10T14:00:00.000000Z')
        self.assertEqual(record['category'], 'messages')
        self.assertEqual(record['data']['message']['app'], 'sms')

    @unittest.skipUnless(os.environ.get("LAWLIET_ALEAPP"), "Set LAWLIET_ALEAPP for real ALEAPP")
    def test_aleapp_legacy_whatsapp_message_mapping(self):
        source = self.base / 'whatsapp'
        payload = source / 'data/data/com.whatsapp/databases/msgstore.db'
        payload.parent.mkdir(parents=True)
        with closing(sqlite3.connect(payload)) as db, db:
            db.executescript("""CREATE TABLE messages(_id INTEGER, timestamp INTEGER, received_timestamp INTEGER,
                key_remote_jid TEXT, key_from_me INTEGER, data TEXT, remote_resource TEXT, media_url TEXT);
                INSERT INTO messages VALUES(1,1791640800000,0,'12025550100@s.whatsapp.net',0,
                  'whatsapp-mapping.example',NULL,NULL);""")
        record = self.analyze(source, 'android', 'aleapp', 'whatsapp-mapping.example', 'fs', '2026-10-10T14:00:00.000000Z')
        self.assertEqual(record['category'], 'messages')
        self.assertEqual(record['data']['message']['app'], 'whatsapp')
