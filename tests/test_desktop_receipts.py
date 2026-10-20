"""A green UI receipt must not hide divergent evidence or failed assertions."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "desktop_receipt_gate", Path(__file__).resolve().parents[1] / "tools/check_desktop_receipts.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class DesktopReceiptGateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.result = {
            "schema_version": 2, "ok": True, "corpus_sha256": "a" * 64,
            "oracle_sha256": "c" * 64, "expected_field_fingerprint_sha256": "b" * 64,
            "field_fingerprint_sha256": "b" * 64,
            "originals_unchanged": True,
            "collection_verification": {"ok": True, "source_hashes_verified": True, "report_verified": True,
                "profiles": ["sms-provider", "contacts-provider", "files", "triage", "trash-photos"],
                "records_checked": 10, "field_fingerprint_sha256": "e" * 64},
            "comparison": {"expected_records": 3, "actual_records": 3, "matched_records": 3,
                           "missing_records": 0, "unexpected_records": 0, "field_mismatches": 0},
            "restart": {"ok": True, "initial_pid": 100, "reopened_pid": 101,
                        "new_process": True, "approval_persisted": True, "export_verified": True, "collection_verified": True},
        }
        for host, system in (("macos-15-intel", "macOS"), ("windows-latest", "Windows"),
                             ("ubuntu-24.04", "Linux")):
            folder = self.root / ("desktop-smoke-" + host)
            folder.mkdir()
            (folder / "environment.json").write_text(
                json.dumps({"commit": "abc123", "runner_os": system}), encoding="utf-8")
            self.write(host, self.result)

    def write(self, host, result):
        (self.root / ("desktop-smoke-" + host) / "result.json").write_text(
            json.dumps(result), encoding="utf-8")

    def test_same_native_results_pass(self):
        self.assertTrue(gate.check_receipts(self.root, "abc123")["ok"])

    def test_green_flag_cannot_hide_forensic_or_restart_failure(self):
        mutations = [
            {"corpus_sha256": "c" * 64},
            {"field_fingerprint_sha256": "c" * 64},
            {"oracle_sha256": "d" * 64},
            {"expected_field_fingerprint_sha256": "d" * 64},
            {"originals_unchanged": False},
            {"collection_verification": {}},
            {"collection_verification": {**self.result["collection_verification"], "records_checked": 0}},
            {"collection_verification": {**self.result["collection_verification"], "field_fingerprint_sha256": "f" * 64}},
            {"restart": {**self.result["restart"], "collection_verified": False}},
            {"comparison": {**self.result["comparison"], "missing_records": 1}},
            {"comparison": {**self.result["comparison"], "field_mismatches": 1}},
            {"restart": {**self.result["restart"], "reopened_pid": 100}},
            {"restart": {**self.result["restart"], "approval_persisted": False}},
            {"restart": {**self.result["restart"], "export_verified": False}},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed = {**copy.deepcopy(self.result), **mutation}
                self.write("windows-latest", changed)
                self.assertFalse(gate.check_receipts(self.root, "abc123")["ok"])

    def test_missing_host_or_wrong_commit_fails(self):
        self.assertFalse(gate.check_receipts(self.root, "different-commit")["ok"])
        (self.root / "desktop-smoke-windows-latest" / "result.json").unlink()
        self.assertFalse(gate.check_receipts(self.root, "abc123")["ok"])


if __name__ == "__main__":
    unittest.main()
