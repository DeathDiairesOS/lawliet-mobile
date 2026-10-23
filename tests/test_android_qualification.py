"""Field fidelity against frozen raw evidence and an independent answer manifest."""
import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from lawliet_mobile.core import (
    UserError, connect, create_case, import_evidence, select_artifacts, verify,
)
from lawliet_mobile.acquisition import case_coverage
from lawliet_mobile.desktop_smoke import (
    build_fixture, check_raw_sources, compare_records, tree_hashes,
)
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.report import write_jsonl_export


class AndroidQualification(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.fixture = build_fixture(self.base / "raw")
        self.workspace = self.base / "cases"

    def assert_answers(self, actual, oracle):
        result = compare_records(actual, oracle)
        self.assertTrue(result["passed"], json.dumps(result, ensure_ascii=False, indent=2))
        self.assertEqual(result["comparison"]["matched_records"], len(oracle["records"]))
        return result

    def import_case(self, case_id="A", *, missing=False, source=None):
        create_case(self.workspace, case_id)
        path = source or self.fixture["missing_path" if missing else "path"]
        with connect(self.workspace, case_id) as (root, db):
            return import_evidence(root, db, path, "android")[0]

    def test_frozen_bytes_raw_sql_and_handwritten_utc_answers(self):
        self.assertEqual(self.fixture["corpus_sha256"],
                         "6ac86a307f18af7f3a5443599ac3df519a6e046a0d27d5e80df139cfa8b6aefb")
        self.assertEqual(self.fixture["oracle_sha256"],
                         "f83e56d4a5239d38b9e3203e4a8a0b7cfe73c79f689b5f0150e7a5e019215c7b")
        self.assertEqual(check_raw_sources(self.fixture["path"])["sms_records"], 4)
        self.assertEqual(check_raw_sources(self.fixture["missing_path"], missing_wal=True)["sms_records"], 3)
        # Independent integer arithmetic, not lawliet_mobile.parsers.timestamp.
        from datetime import datetime, timedelta, timezone
        for row in self.fixture["oracle"]["records"]:
            if row["timestamp"] is not None:
                milliseconds = int(row["timestamp_raw"])
                seconds, fraction = divmod(milliseconds, 1000)
                when = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                    seconds=seconds, microseconds=fraction * 1000)
                self.assertEqual(when.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                                 row["timestamp"])
        with self.assertRaises(FileExistsError):
            build_fixture(self.base / "raw")

    def test_all_fields_timeline_export_integrity_and_rerun_after_restart(self):
        eid = self.import_case()
        oracle = self.fixture["oracle"]
        with connect(self.workspace, "A") as (root, db):
            before = tree_hashes(root / "evidence" / eid)
            self.assertEqual(before, oracle["files"])
            result = native_analyze(root, db, eid)
            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["new_records"], 11)
            rows = select_artifacts(db, limit=None)
            comparison = self.assert_answers(rows, oracle)
            self.assertEqual(comparison["field_fingerprint_sha256"],
                             "7582c414dcf1e24856c97f1b7244ee4c806ab4daa9363e63a7bf2f8aa7018dd1")
            self.assertEqual({r["source_ref"] for r in select_artifacts(
                db, since=oracle["timeline"]["since"], until=oracle["timeline"]["until"], limit=None)},
                set(oracle["timeline"]["source_refs"]))
            invalid = next(r for r in rows if r["source_ref"] == "sms:_id=3")
            self.assertIsNone(invalid["timestamp"])
            self.assertEqual(invalid["data"]["message"]["direction"], "unknown")
            export = write_jsonl_export(root, db, root / "exports" / "qualification.jsonl",
                                        iter(rows), {"evidence": eid})
            exported = [json.loads(line) for line in Path(export["path"]).read_text(
                encoding="utf-8").splitlines()]
            self.assert_answers(exported, oracle)
            companion = json.loads(Path(export["coverage_path"]).read_text(encoding="utf-8"))
            self.assertEqual(companion["export_sha256"],
                             hashlib.sha256(Path(export["path"]).read_bytes()).hexdigest())
            self.assertTrue(any(item["state"] == "unresolved" and item["category"] == "messages"
                                for item in companion["coverage_context"]["observations"]))
            self.assertTrue(all(row["data"]["sqlite_wal_coverage"]["pairing"] == "unverified"
                                for row in exported if row["category"] == "messages"))
            self.assertTrue(verify(root, db)["ok"])
            self.assertEqual(tree_hashes(root / "evidence" / eid), before)
            identities = {r["id"] for r in rows}
        # New connection, with no reused in-memory parser or database state.
        with connect(self.workspace, "A") as (root, db):
            self.assert_answers(select_artifacts(db, limit=None), oracle)
            rerun = native_analyze(root, db, eid)
            self.assertEqual(rerun["new_records"], 0)
            self.assertEqual({r["id"] for r in select_artifacts(db, limit=None)}, identities)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 2)
            self.assertEqual(tree_hashes(root / "evidence" / eid), before)
            self.assertTrue(verify(root, db)["ok"])
        self.assertEqual(tree_hashes(self.fixture["path"]), oracle["files"])

    def test_missing_wal_is_visible_and_no_committed_record_is_invented(self):
        eid = self.import_case(missing=True)
        with connect(self.workspace, "A") as (root, db):
            result = native_analyze(root, db, eid)
            rows = select_artifacts(db, limit=None)
            self.assert_answers(rows, self.fixture["missing_oracle"])
            self.assertNotIn("sms:_id=4", {row["source_ref"] for row in rows})
            self.assertTrue(any("no WAL companion" in item["reason"]
                                for item in result["unparsed_candidates"]))
            export = write_jsonl_export(root, db, root / "exports" / "missing.jsonl",
                                        iter(rows), {"evidence": eid})
            coverage = json.loads(Path(export["coverage_path"]).read_text(encoding="utf-8"))
            self.assertTrue(any(item["state"] == "unresolved" and item["category"] == "messages"
                                for item in coverage["coverage_context"]["observations"]))
            exported = [json.loads(line) for line in Path(export["path"]).read_text(
                encoding="utf-8").splitlines()]
            self.assertTrue(all("no WAL companion" in row["data"]["sqlite_wal_coverage"]["reason"]
                                for row in exported if row["category"] == "messages"))
            self.assertTrue(verify(root, db)["ok"])
            self.assertEqual(tree_hashes(root / "evidence" / eid),
                             self.fixture["missing_oracle"]["files"])
        self.assertEqual(tree_hashes(self.fixture["missing_path"]), self.fixture["missing_oracle"]["files"])

    def test_cross_case_evidence_scope_is_not_reused(self):
        eid_a = self.import_case("A")
        eid_b = self.import_case("B")
        with connect(self.workspace, "A") as (root, db):
            native_analyze(root, db, eid_a)
            records_a = select_artifacts(db, limit=None)
            self.assertEqual(select_artifacts(db, evidence=eid_b), [])
            with self.assertRaisesRegex(UserError, "Unknown evidence"):
                native_analyze(root, db, eid_b)
        with connect(self.workspace, "B") as (root, db):
            self.assertEqual(select_artifacts(db, limit=None), [])
            native_analyze(root, db, eid_b)
            records_b = select_artifacts(db, limit=None)
            self.assert_answers(records_b, self.fixture["oracle"])
            self.assertFalse({r["id"] for r in records_a} & {r["id"] for r in records_b})
            self.assertEqual({r["evidence_id"] for r in records_b}, {eid_b})
            self.assertTrue(verify(root, db)["ok"])

    def test_missing_import_and_retained_evidence_are_refused(self):
        create_case(self.workspace, "A")
        with connect(self.workspace, "A") as (root, db):
            with self.assertRaisesRegex(UserError, "Evidence not found"):
                import_evidence(root, db, self.base / "not-acquired", "android")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)
            eid = import_evidence(root, db, self.fixture["path"], "android")[0]
            stored = root / "evidence" / eid / "sdcard/Pictures/pixel.png"
            stored.unlink()
            self.assertFalse(verify(root, db)["ok"])
            with self.assertRaisesRegex(UserError, "Integrity check failed"):
                native_analyze(root, db, eid)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 0)
        self.assertEqual(tree_hashes(self.fixture["path"]), self.fixture["oracle"]["files"])

    def test_malformed_sqlite_is_partial_and_export_retains_the_failure(self):
        source = self.base / "malformed-input"
        shutil.copytree(self.fixture["path"], source)
        call_path = next(row["logical_path"] for row in self.fixture["oracle"]["records"]
                         if row["category"] == "calls")
        path = source / call_path
        path.write_bytes(path.read_bytes()[:100])
        before = tree_hashes(source)
        eid = self.import_case(source=source)
        with connect(self.workspace, "A") as (root, db):
            result = native_analyze(root, db, eid)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(len(result["errors"]), 1)
            self.assertEqual(result["errors"][0]["source"], call_path)
            self.assertTrue(result["errors"][0]["error"])
            expected = copy.deepcopy(self.fixture["oracle"])
            expected["records"] = [r for r in expected["records"] if r["category"] != "calls"]
            records = select_artifacts(db, limit=None)
            self.assert_answers(records, expected)
            export = write_jsonl_export(root, db, root / "exports" / "partial.jsonl",
                                        iter(records), {"evidence": eid})
            coverage = json.loads(Path(export["coverage_path"]).read_text(encoding="utf-8"))
            # Portable coverage deliberately withholds raw error text and paths
            # of unrepresented sources. Require failure state, not hidden detail.
            self.assertTrue(any(item["state"] == "parser-failed" and item["module"] == "native"
                                for item in coverage["coverage_context"]["observations"]))
            internal = case_coverage(root, db)
            self.assertIn(call_path, json.dumps(internal))
            self.assertIn(result["errors"][0]["error"], json.dumps(internal))
            persisted = json.loads(db.execute(
                "SELECT detail FROM runs WHERE id=?", (result["run_id"],)).fetchone()[0])
            self.assertEqual(persisted["errors"], result["errors"])
            self.assertEqual(tree_hashes(root / "evidence" / eid), before)
            self.assertTrue(verify(root, db)["ok"])
        self.assertEqual(tree_hashes(source), before)

    def test_comparator_rejects_missing_extra_duplicate_and_misrepresented_values(self):
        eid = self.import_case()
        with connect(self.workspace, "A") as (root, db):
            native_analyze(root, db, eid)
            records = select_artifacts(db, limit=None)
        for label, mutate, field in (
            ("missing", lambda r: r.pop(), "missing_records"),
            ("duplicate", lambda r: r.append(copy.deepcopy(r[0])), "duplicate_records"),
            ("extra", lambda r: r.append(dict(r[0], source_ref="invented")), "unexpected_records"),
            ("timestamp", lambda r: r[0].update(timestamp="2024-01-01T00:00:00.000000Z"), "field_mismatches"),
            ("hash", lambda r: r[0].update(source_sha256="0" * 64), "field_mismatches"),
            ("parser version", lambda r: r[0].update(parser="native/0.1.13"), "field_mismatches"),
            ("null is not missing", lambda r: r[-1].pop("timestamp"), "field_mismatches"),
        ):
            with self.subTest(label=label):
                changed = copy.deepcopy(records)
                mutate(changed)
                result = compare_records(changed, self.fixture["oracle"])
                self.assertFalse(result["passed"])
                self.assertGreater(result["comparison"][field], 0)
                self.assertNotEqual(result["field_fingerprint_sha256"],
                                    result["expected_field_fingerprint_sha256"])

    def test_real_process_interruption_reconciles_and_reanalysis_is_exact(self):
        eid = self.import_case()
        ready = self.base / "parser-paused-after-real-insert"
        # Only the test checkpoint is injected: real imports, writes, ownership,
        # process death, journal rollback and subsequent reanalysis all execute.
        code = """import sys
from pathlib import Path
from lawliet_mobile.core import connect
import lawliet_mobile.parsers as stage
real = stage.add_artifact
def checkpoint(*args, **kwargs):
    result = real(*args, **kwargs)
    Path(sys.argv[3]).write_text('ready', encoding='utf-8')
    sys.stdin.read()
    return result
stage.add_artifact = checkpoint
with connect(Path(sys.argv[1]), 'A') as (root, db):
    stage.native_analyze(root, db, sys.argv[2])
"""
        process = subprocess.Popen(
            [sys.executable, "-c", code, str(self.workspace), eid, str(ready)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 15
            while not ready.exists():
                if process.poll() is not None:
                    self.fail(process.communicate(timeout=5)[1].decode(errors="replace"))
                if time.monotonic() > deadline:
                    self.fail("Parser did not reach the bounded real-insert checkpoint.")
                time.sleep(0.02)
            with connect(self.workspace, "A") as (root, db):
                self.assertEqual(db.execute("SELECT status FROM runs").fetchone()[0], "running")
                self.assertEqual(db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0], 0)
                with self.assertRaisesRegex(UserError, "still owns"):
                    native_analyze(root, db, eid)
            process.kill()
            process.communicate(timeout=10)
            with connect(self.workspace, "A") as (root, db):
                self.assertEqual(db.execute("SELECT status FROM runs").fetchone()[0], "running")
                result = native_analyze(root, db, eid)
                self.assertEqual(result["new_records"], 11)
                self.assertEqual([tuple(r) for r in db.execute(
                    "SELECT status,records FROM runs ORDER BY rowid")], [("interrupted", 0), ("complete", 11)])
                self.assertEqual(db.execute(
                    "SELECT COUNT(*) FROM audit WHERE action='analysis.abandoned'").fetchone()[0], 1)
                self.assert_answers(select_artifacts(db, limit=None), self.fixture["oracle"])
                self.assertEqual(native_analyze(root, db, eid)["new_records"], 0)
                self.assertEqual(tree_hashes(root / "evidence" / eid), self.fixture["oracle"]["files"])
                self.assertTrue(verify(root, db)["ok"])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
        self.assertEqual(tree_hashes(self.fixture["path"]), self.fixture["oracle"]["files"])


if __name__ == "__main__":
    unittest.main()
