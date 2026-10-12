"""Development coordination checks; no evidence, GUI, provider or device access."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "tools/watch_handoff.py"
spec = importlib.util.spec_from_file_location("watch_handoff", SCRIPT)
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


class HandoffWatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.handoff = self.root / "handoff.json"
        self.directory = self.root / "watch"
        self.document = {"sessions": {"ui": {"status": "working"},
                                      "other_active_session": {"status": "first"}}}
        self.save()
        self.worker = watch.Watcher(self.handoff, self.directory)

    def save(self):
        watch.write_json(self.handoff, self.document)

    def test_only_other_entry_triggers_pending_review(self):
        original = self.handoff.read_bytes()
        first = self.worker.poll()["revision"]
        self.assertEqual(original, self.handoff.read_bytes())
        self.assertTrue(watch.status(self.directory)["pending_review"])
        watch.acknowledge(self.directory, first)
        self.document["sessions"]["ui"]["status"] = "own update"
        self.save()
        self.assertEqual(self.worker.poll()["revision"], first)
        self.assertFalse(watch.status(self.directory)["pending_review"])
        self.document["sessions"]["other_active_session"]["status"] = "new contract"
        self.save()
        self.assertNotEqual(self.worker.poll()["revision"], first)
        self.assertTrue(watch.status(self.directory)["pending_review"])
        with self.assertRaises(ValueError):
            watch.acknowledge(self.directory, first)

    def test_restart_retains_review_and_detects_changed_entry(self):
        revision = self.worker.poll()["revision"]
        watch.acknowledge(self.directory, revision)
        restarted = watch.Watcher(self.handoff, self.directory)
        self.assertEqual(restarted.poll()["revision"], revision)
        self.assertFalse(watch.status(self.directory)["pending_review"])
        self.document["sessions"]["other_active_session"]["status"] = "second"
        self.save()
        restarted.poll()
        self.assertTrue(watch.status(self.directory)["pending_review"])
        events = (self.directory / "events.jsonl").read_text().splitlines()
        self.assertEqual(len(events), 2)

    def test_brief_status_reports_delta_without_full_verification_dump(self):
        revision = self.worker.poll()["revision"]
        watch.acknowledge(self.directory, revision)
        first = watch.brief_status(watch.status(self.directory))
        self.assertEqual(first["changed_fields"], [])
        self.document["sessions"]["other_active_session"]["current_task"] = "single workflow"
        self.save(); self.worker.poll()
        changed = watch.brief_status(watch.status(self.directory))
        self.assertEqual(changed["changed_fields"], ["current_task"])
        self.assertTrue(changed["pending_review"])
        self.assertNotIn("latest_entry", changed)

    def test_partial_write_missing_entry_and_recovery_preserve_snapshot(self):
        revision = self.worker.poll()["revision"]
        self.handoff.write_text('{"sessions":')
        self.assertIsNotNone(self.worker.poll()["error"])
        self.assertEqual(self.worker.state["revision"], revision)
        self.worker.poll()
        self.save()
        recovered = self.worker.poll()
        self.assertIsNone(recovered["error"])
        self.assertEqual(recovered["latest_entry"]["status"], "first")
        del self.document["sessions"]["other_active_session"]
        self.save()
        self.assertIsNotNone(self.worker.poll()["error"])
        events = [json.loads(line)["event"] for line in
                  (self.directory / "events.jsonl").read_text().splitlines()]
        self.assertEqual(events, ["update", "read_error", "read_recovered", "read_error"])

    def test_rollback_is_a_new_unreviewed_revision(self):
        first = self.worker.poll()["revision"]
        watch.acknowledge(self.directory, first)
        self.document["sessions"]["other_active_session"]["status"] = "second"
        self.save()
        self.worker.poll()
        self.document["sessions"]["other_active_session"]["status"] = "first"
        self.save()
        self.assertNotEqual(self.worker.poll()["revision"], first)
        self.assertTrue(watch.status(self.directory)["pending_review"])

    def test_journal_rotates_and_never_executes_content(self):
        marker = self.root / "must-not-exist"
        self.document["sessions"]["other_active_session"]["command"] = f"touch {marker}"
        self.save()
        journal = self.directory / "events.jsonl"
        journal.write_bytes(b"x" * watch.MAX_BYTES)
        self.worker.poll()
        self.assertTrue((self.directory / "events.jsonl.1").exists())
        self.assertFalse(marker.exists())
        self.assertEqual(json.loads(journal.read_text())["event"], "update")

    def test_live_worker_single_instance_update_and_stop(self):
        command = [sys.executable, str(SCRIPT), "run", "--handoff", str(self.handoff),
                   "--state-dir", str(self.directory), "--interval", "0.1"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.wait_for(lambda: watch.running(self.directory) and self.worker.state_path.exists())
            duplicate = subprocess.run(command, capture_output=True, timeout=5)
            self.assertEqual(duplicate.returncode, 0, duplicate.stderr.decode())
            self.document["sessions"]["other_active_session"]["status"] = "live change"
            self.save()
            self.wait_for(lambda: watch.status(self.directory)["latest_entry"]["status"] == "live change")
            result = watch.status(self.directory)
            self.assertTrue(result["running"])
            self.assertTrue(result["pending_review"])
            (self.directory / "stop").touch()
            _, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertFalse(watch.status(self.directory)["running"])
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.025)
        self.fail("watcher did not reach expected state")


if __name__ == "__main__":
    unittest.main()
