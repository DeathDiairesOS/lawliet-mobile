import contextlib
import csv
import base64
import io
import json
import os
import plistlib
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from pathlib import Path

from lawliet_mobile.cli import main
from lawliet_mobile.correlate import shared_entities
from lawliet_mobile.core import UserError, audit, connect, create_case, digest, extract_archive, import_evidence, select_artifacts, verify
from lawliet_mobile.demo import create_demo, transaction
from lawliet_mobile.parsers import native_analyze, timestamp
from lawliet_mobile.report import write_export, write_report
from lawliet_mobile.tools import collect, configure, devices, execute, external_analyze


class MobileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / "cases"
        create_case(self.workspace, "test")

    def sms_database(self, name="mmssms.db", body="hello"):
        path = self.base / name
        with transaction(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE sms(_id INTEGER,date INTEGER,address TEXT,body TEXT,type INTEGER)")
            db.execute("INSERT INTO sms VALUES(1,1791640800000,'+1-202-555-0100',?,1)", (body,))
        return path

    def test_ios_conversations_use_stored_chat_links_and_preserve_body_gaps(self):
        from lawliet_mobile.messages import conversations
        source = self.base / 'sms.db'
        with transaction(sqlite3.connect(source)) as db:
            db.executescript("""CREATE TABLE handle(id TEXT); INSERT INTO handle VALUES('555');
              CREATE TABLE message(date INTEGER,text TEXT,handle_id INTEGER,is_from_me INTEGER,service TEXT,attributedBody BLOB);
              INSERT INTO message VALUES(813592800,'plain body',1,0,'iMessage',NULL);
              INSERT INTO message VALUES(813592801,NULL,1,1,'iMessage',X'010203');
              CREATE TABLE chat_message_join(chat_id INTEGER,message_id INTEGER);
              INSERT INTO chat_message_join VALUES(10,1); INSERT INTO chat_message_join VALUES(20,2);""")
        with connect(self.workspace, 'test') as (root, db):
            eid, _, _ = import_evidence(root, db, source, 'ios')
            self.assertEqual(native_analyze(root, db, eid)['new_records'], 2)
            self.assertEqual(len(conversations(db, app='imessage')), 2)
            rows = select_artifacts(db, app='imessage')
            self.assertEqual(rows[0]['data']['message']['chat_ids'], ['10'])
            self.assertEqual(rows[1]['body'], '')
            self.assertEqual(rows[1]['data']['message']['body_status'], 'opaque_body_not_decoded')
            self.assertEqual(rows[1]['data']['message']['rich_event']['state'], 'not_decoded')
            self.assertTrue(rows[1]['title'].startswith('Undecoded message event · '))
            self.assertEqual(rows[1]['data']['attributedBody'], {'blob_bytes': 3})

    def test_android_native_and_idempotence(self):
        source = self.sms_database()
        original_hash = digest(source)
        with connect(self.workspace, "test") as (root, db):
            eid, count, _ = import_evidence(root, db, source)
            self.assertEqual(count, 1)
            first = native_analyze(root, db, eid)
            second = native_analyze(root, db, eid)
            self.assertEqual(first["new_records"], 1)
            self.assertEqual(second["new_records"], 0)
            record = select_artifacts(db)[0]
            self.assertEqual(record["timestamp"], "2026-10-10T14:00:00.000000Z")
            self.assertEqual(record["source_sha256"], original_hash)
            self.assertEqual(record["source_ref"], "sms:_id=1")
            self.assertTrue(verify(root, db)["ok"])
        self.assertEqual(digest(source), original_hash)

    def test_cross_device_entity_pivots(self):
        create_demo(self.workspace, "pivot")
        with connect(self.workspace, "pivot") as (_, db):
            result = shared_entities(db, kind="url")
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["value"], "https://parcel-review.example/verify")
            self.assertEqual(result[0]["evidence_sources"], 2)
            self.assertEqual(result[0]["records"], 3)
            self.assertEqual(shared_entities(db, minimum=3), [])
    def test_synthetic_ios_hashed_backup_and_cross_device_search(self):
        result = create_demo(self.workspace, "demo")
        self.assertEqual(sum(r["new_records"] for r in result["runs"]), 15)
        with connect(self.workspace, "demo") as (root, db):
            records = select_artifacts(db, query="parcel-review.example")
            self.assertEqual(len(records), 3)
            self.assertEqual(len({r["evidence_id"] for r in records}), 2)
            ios = next(r for r in records if "iMessage" in r["title"])
            self.assertIn("Library/SMS/sms.db", ios["logical_path"])
            self.assertEqual(ios["timestamp"], "2026-10-10T14:02:00.000000Z")
            self.assertTrue(verify(root, db)["ok"])

    def test_wal_data_is_read_and_evidence_unchanged(self):
        folder = self.base / "wal-fixture"
        folder.mkdir()
        source = folder / "mmssms.db"
        writer = sqlite3.connect(source)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE sms(_id INTEGER,date INTEGER,address TEXT,body TEXT,type INTEGER)")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute("INSERT INTO sms VALUES(1,1791640800000,'555','only in WAL',1)")
        writer.commit()
        self.assertGreater(Path(str(source) + "-wal").stat().st_size, 0)
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, folder, "android")
            native_analyze(root, db, eid)
            records = select_artifacts(db)
            self.assertEqual(records[0]["body"], "only in WAL")
            self.assertTrue(records[0]["data"]["source_sidecars"])
            self.assertTrue(verify(root, db)["ok"])

    def test_modified_missing_and_untracked_evidence_detected(self):
        source = self.sms_database()
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, source)
            copied = root / "evidence" / eid / source.name
            copied.write_bytes(b"changed")
            self.assertFalse(verify(root, db)["ok"])
            with self.assertRaises(UserError):
                native_analyze(root, db, eid)
            copied.unlink()
            (copied.parent / "untracked.txt").write_text("extra")
            reasons = {r["reason"] for r in verify(root, db)["failures"]}
            self.assertIn("missing or unsafe", reasons)
            self.assertIn("untracked or unsafe file", reasons)

    def test_audit_tamper_detected(self):
        with connect(self.workspace, "test") as (root, db):
            audit(db, "test.action", {"x": 1})
            self.assertTrue(verify(root, db)["ok"])
            db.execute("UPDATE audit SET detail='tampered' WHERE id=1")
            self.assertFalse(verify(root, db)["ok"])

    def test_zip_traversal_rejected_and_intake_cleaned(self):
        archive = self.base / "bad.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("../escape.txt", "bad")
        with connect(self.workspace, "test") as (root, db):
            with self.assertRaises(UserError):
                import_evidence(root, db, archive)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)
            self.assertEqual(list((root / "evidence").iterdir()), [])
        self.assertFalse((self.base / "escape.txt").exists())

    def test_archive_links_and_size_limits(self):
        archive = self.base / "link.tar"
        with tarfile.open(archive, "w") as tar:
            item = tarfile.TarInfo("link")
            item.type, item.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(item)
        target = self.base / "extract"
        target.mkdir()
        with self.assertRaises(UserError):
            extract_archive(archive, target)
        archive = self.base / "big.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("file", "A" * 100)
        with self.assertRaises(UserError):
            extract_archive(archive, target, max_bytes=20)

    def test_zip_duplicate_rejected(self):
        archive = self.base / "duplicate.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("a.txt", "a")
            zipped.writestr("./a.txt", "b")
        target = self.base / "extract"
        target.mkdir()
        with self.assertRaises(UserError):
            extract_archive(archive, target)

    def test_safe_archive_and_container_hash(self):
        source = self.sms_database()
        archive = self.base / "good.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.write(source, "data/mmssms.db")
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, archive, "android")
            self.assertEqual(db.execute("SELECT container_sha256 FROM evidence WHERE id=?", (eid,)).fetchone()[0], digest(archive))
            self.assertEqual(native_analyze(root, db, eid)["new_records"], 1)

    def test_encrypted_backup_explicitly_rejected(self):
        folder = self.base / "encrypted"
        folder.mkdir()
        (folder / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": True}))
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, folder)
            with self.assertRaisesRegex(UserError, "Encrypted"):
                native_analyze(root, db, eid)

    def test_timezone_unknown_not_guessed(self):
        self.assertIsNone(timestamp("2026-10-10 10:00:00"))
        self.assertEqual(timestamp("2026-10-10T10:00:00-04:00"), "2026-10-10T14:00:00.000000Z")
        self.assertIsNone(timestamp("nonsense"))
        self.assertIsNone(timestamp(float("inf")))

    def test_sql_search_is_literal_and_report_escapes_evidence(self):
        malicious = '<script>alert(1)</script> __ROWS__ =SUM(1,2)'
        source = self.sms_database(body=malicious)
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, source)
            native_analyze(root, db, eid)
            self.assertEqual(select_artifacts(db, query="' OR 1=1 --"), [])
            self.assertEqual(select_artifacts(db, query="%"), [])
            report = Path(write_report(root, db, root / "reports/report.html")["path"]).read_text()
            self.assertNotIn('<script>alert(1)</script>', report)
            self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', report)
            self.assertIn('__ROWS__', report)
            with self.assertRaises(UserError):
                write_report(root, db, root / "evidence" / eid / "overwrite.html")
            with self.assertRaises(UserError):
                write_report(root, db, source)

    def test_csv_formula_escaped_json_preserves_raw(self):
        source = self.sms_database(body="=SUM(1,2)")
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, source)
            native_analyze(root, db, eid)
            records = select_artifacts(db)
            path = root / "export.csv"
            write_export(root, db, path, "csv", records)
            with path.open(newline="") as handle:
                self.assertEqual(next(csv.DictReader(handle))["body"], "'=SUM(1,2)")
            path = root / "export.json"
            write_export(root, db, path, "json", records)
            self.assertEqual(json.loads(path.read_text())[0]["body"], "=SUM(1,2)")

    def test_android_text_triage(self):
        folder = self.base / "triage"
        folder.mkdir()
        (folder / "logcat.txt").write_text("1791640800.500 100 101 I ActivityManager: test activity\nmalformed\n")
        (folder / "packages.txt").write_text("package:/data/app/example/base.apk=com.example.app\n")
        (folder / "getprop.txt").write_text("[ro.product.model]: [Test Phone]\n[ro.build.version.release]: [16]\n")
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, folder, "android")
            result = native_analyze(root, db, eid)
            self.assertEqual(result["new_records"], 3)
            self.assertEqual({r["category"] for r in select_artifacts(db)}, {"apps", "device", "logs"})

    def test_external_tsv_adapter_retains_provenance_and_unknown_time(self):
        # A protocol fixture tests adapter behavior; it does not validate LEAPP itself.
        fake = self.base / "fake_aleapp.py"
        fake.write_text("import sys,pathlib\np=pathlib.Path(sys.argv[sys.argv.index('-o')+1]); (p/'Messages.tsv').write_text('Timestamp\\tBody\\n2026-10-10 14:00:00\\tfixture text\\n')\n")
        configure(self.workspace, "aleapp", fake)
        source = self.sms_database()
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, source, "android")
            result = external_analyze(root, db, self.workspace, eid, "aleapp")
            self.assertEqual(result["new_records"], 1)
            record = select_artifacts(db)[0]
            self.assertIsNone(record["timestamp"])
            self.assertIsNone(record["source_sha256"])
            self.assertIn("Messages.tsv:line=2", record["source_ref"])
            self.assertTrue(verify(root, db)["ok"])

    def test_external_failure_is_persisted(self):
        fake = self.base / "failing.py"
        fake.write_text("import sys\nsys.exit(7)\n")
        configure(self.workspace, "aleapp", fake)
        source = self.sms_database()
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, source, "android")
            with self.assertRaises(UserError):
                external_analyze(root, db, self.workspace, eid, "aleapp")
            self.assertEqual(db.execute("SELECT status FROM runs").fetchone()[0], "failed")

    @unittest.skipUnless(shutil.which("exiftool"), "ExifTool is optional")
    def test_real_exiftool_adapter(self):
        image = self.base / "pixel.png"
        image.write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a0foAAAAASUVORK5CYII="))
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, image)
            result = external_analyze(root, db, self.workspace, eid, "exiftool")
            self.assertEqual(result["new_records"], 1)
            record = select_artifacts(db)[0]
            self.assertEqual(record["category"], "media")
            self.assertEqual(record["data"]["FileType"], "PNG")
            self.assertEqual(record["source_sha256"], digest(image))
            self.assertTrue(verify(root, db)["ok"])

    def test_subprocess_timeout(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            execute([sys.executable, "-c", "import time; time.sleep(10)"], self.base / "timeout.log", timeout=0.05)

    def test_external_timeout_retains_command_details(self):
        fake = self.base / "slow_aleapp.py"
        fake.write_text("import time; time.sleep(10)\n")
        configure(self.workspace, "aleapp", fake)
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, self.sms_database(), "android")
            with self.assertRaises(subprocess.TimeoutExpired):
                external_analyze(root, db, self.workspace, eid, "aleapp", timeout=0.05)
            run = db.execute("SELECT * FROM runs").fetchone()
            self.assertEqual(run["status"], "failed")
            detail = json.loads(run["detail"])
            self.assertIn(str(fake.resolve()), detail["argv"])
            self.assertTrue(Path(detail["stderr"]).exists())
            self.assertNotEqual(detail["returncode"], 0)

    def test_android_collection_protocol(self):
        fake = self.base / "adb_fixture.py"
        fake.write_text("""import sys,pathlib,zipfile
a=sys.argv[1:]
if a[0]=='devices': print('List of devices attached\\nTESTSERIAL device model:Fixture')
elif a[2:]==['shell','getprop']: print('[ro.product.model]: [Fixture Phone]')
elif a[2:]==['shell','pm','list','packages','-f']: print('package:/data/app/base.apk=com.example.fixture')
elif a[2]=='logcat': print('1791640800.500 100 101 I TestTag: collection fixture')
elif a[2]=='bugreport':
    with zipfile.ZipFile(a[3],'w') as z: z.writestr('bugreport.txt','fixture')
else: sys.exit(9)
""")
        configure(self.workspace, "adb", fake)
        discovered = devices(self.workspace)
        self.assertTrue(any(r.get("serial") == "TESTSERIAL" for r in discovered))
        with connect(self.workspace, "test") as (root, db):
            result = collect(root, db, self.workspace, "android", "TESTSERIAL")
            self.assertEqual(result["status"], "complete")
            self.assertEqual(native_analyze(root, db, result["evidence_id"])["new_records"], 3)
            self.assertTrue(verify(root, db)["ok"])
            self.assertEqual(len(json.loads((Path(result["path"]) / "collection.json").read_text())["commands"]), 4)

    def test_ios_collection_protocol(self):
        fake = self.base / "ios_fixture.py"
        fake.write_text("""import sys,pathlib,sqlite3,plistlib
a=sys.argv[1:]
assert a[0:4]==['-u','TESTUDID','backup','--full']
p=pathlib.Path(a[4])/'TESTUDID'; p.mkdir()
(p/'Manifest.plist').write_bytes(plistlib.dumps({'IsEncrypted':False}))
(p/'Status.plist').write_bytes(plistlib.dumps({'SnapshotState':'finished'}))
m=sqlite3.connect(p/'Manifest.db'); m.execute('CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)'); m.commit(); m.close()
d=sqlite3.connect(p/'sms.db')
d.executescript("CREATE TABLE handle(id TEXT); INSERT INTO handle VALUES('555'); CREATE TABLE message(date INTEGER,text TEXT,handle_id INTEGER,is_from_me INTEGER,service TEXT); INSERT INTO message VALUES(813592800,'fixture',1,0,'SMS');")
d.commit(); d.close()
""")
        configure(self.workspace, "idevicebackup2", fake)
        with connect(self.workspace, "test") as (root, db):
            result = collect(root, db, self.workspace, "ios", "TESTUDID")
            self.assertEqual(result["status"], "complete")
            self.assertEqual(native_analyze(root, db, result["evidence_id"])["new_records"], 1)
            self.assertTrue(verify(root, db)["ok"])

    def test_ios_success_exit_without_finished_backup_is_failed(self):
        fake = self.base / "empty_backup.py"
        fake.write_text("pass\n")
        configure(self.workspace, "idevicebackup2", fake)
        with connect(self.workspace, "test") as (root, db):
            with self.assertRaisesRegex(UserError, "finished device backup"):
                collect(root, db, self.workspace, "ios", "TESTUDID")
            log = json.loads(next((root / "collections").glob("*/collection.json")).read_text())
            self.assertEqual(log["status"], "failed")
            self.assertIsNone(log["evidence_id"])
            self.assertEqual(len(log["commands"]), 1)
            self.assertEqual(db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)

    def test_collection_serial_cannot_escape_backup_directory(self):
        with connect(self.workspace, "test") as (root, db):
            for serial in ["../outside", "..\\outside"]:
                with self.subTest(serial=serial), self.assertRaises(UserError):
                    collect(root, db, self.workspace, "ios", serial)
            self.assertFalse((root / "collections").exists())

    def test_android_missing_bugreport_is_partial(self):
        fake = self.base / "missing_bugreport.py"
        fake.write_text("print('[ro.product.model]: [Fixture]')\n")
        configure(self.workspace, "adb", fake)
        with connect(self.workspace, "test") as (root, db):
            result = collect(root, db, self.workspace, "android", "TESTSERIAL")
            self.assertEqual(result["status"], "partial")
            self.assertIn("bugreport ZIP", result["errors"][0]["error"])
            self.assertTrue(verify(root, db)["ok"])

    def test_android_all_commands_timeout_retains_attempts(self):
        fake = self.base / "slow_adb.py"
        fake.write_text("import time; time.sleep(10)\n")
        configure(self.workspace, "adb", fake)
        with connect(self.workspace, "test") as (root, db):
            with self.assertRaisesRegex(UserError, "Every Android collection command failed"):
                collect(root, db, self.workspace, "android", "TESTSERIAL", timeout=0.05)
            log = json.loads(next((root / "collections").glob("*/collection.json")).read_text())
            self.assertEqual(log["status"], "failed")
            self.assertEqual(len(log["commands"]), 4)
            for run in log["commands"]:
                self.assertEqual(run["error"], "timeout")
                self.assertTrue(Path(run["stderr"]).exists())
                self.assertIn("TESTSERIAL", run["argv"])

    def test_discovery_timeout_does_not_hide_other_platform(self):
        fake = self.base / "discovery.py"
        fake.write_text("print('TESTUDID')\n")
        configure(self.workspace, "adb", fake)
        configure(self.workspace, "idevice_id", fake)
        real_execute = execute

        def discover(argv, output, timeout):
            if "devices" in argv:
                raise subprocess.TimeoutExpired(argv, timeout)
            return real_execute(argv, output, timeout)

        with patch("lawliet_mobile.tools.execute", side_effect=discover):
            rows = devices(self.workspace)
        self.assertEqual(rows[0]["status"], "discovery_failed")
        self.assertEqual(rows[1]["serial"], "TESTUDID")

    def test_cli_json_and_global_flags_after_subcommand(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["case", "show", "test", "--workspace", str(self.workspace), "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["case"]["case_id"], "test")

    def test_symlink_and_recursive_import_rejected(self):
        source = self.sms_database()
        link = self.base / "link"
        link.symlink_to(source)
        with connect(self.workspace, "test") as (root, db):
            with self.assertRaises(UserError):
                import_evidence(root, db, link)
            with self.assertRaises(UserError):
                import_evidence(root, db, self.base)

    def test_corrupt_database_yields_partial_not_clean(self):
        source = self.base / "bad.db"
        source.write_bytes(b"SQLite format 3\x00" + b"broken" * 100)
        with connect(self.workspace, "test") as (root, db):
            eid, _, _ = import_evidence(root, db, source)
            result = native_analyze(root, db, eid)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(len(result["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
