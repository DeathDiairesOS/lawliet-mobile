"""Stored SQLite flags qualify direction; malformed flags do not assign roles."""
import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from lawliet_mobile import parsers
from lawliet_mobile.core import create_case, connect, import_evidence, select_artifacts, verify


class IOSDirectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path = self.base / "sms.db"

    def fixture(self, values, *, affinity="", missing=False):
        with closing(sqlite3.connect(self.path)) as db, db:
            flag = "" if missing else ",is_from_me " + affinity
            db.executescript("CREATE TABLE handle(id TEXT); INSERT INTO handle VALUES ('source-handle');"
                             "CREATE TABLE message(text TEXT,date INTEGER,handle_id INTEGER" + flag + ");")
            for i, value in enumerate(values):
                row = ("body " + str(i), 1, 1) if missing else ("body " + str(i), 1, 1, value)
                db.execute("INSERT INTO message VALUES(" + ",".join("?" for _ in row) + ")", row)

    def records(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            return list(parsers.parse_database(db, "Library/SMS/sms.db"))

    def test_supported_flags_assign_only_the_source_role(self):
        self.fixture([0, 1])
        incoming, outgoing = [r[-1]["message"] for r in self.records()]
        self.assertEqual((incoming["direction"], incoming["sender"], incoming["recipient"]),
                         ("incoming", "source-handle", ""))
        self.assertEqual((outgoing["direction"], outgoing["sender"], outgoing["recipient"]),
                         ("outgoing", "", "source-handle"))

    def test_invalid_flags_preserve_raw_values_without_assigning_roles(self):
        values = [2, -1, None, "0", "1", "", 0.0, 1.0, 0.5, b"0"]
        self.fixture(values)
        rows = self.records()
        self.assertEqual(len(rows), len(values))
        for i, (value, record) in enumerate(zip(values, rows)):
            raw = record[-1]
            self.assertEqual((raw["message"]["direction"], raw["message"]["sender"],
                              raw["message"]["recipient"]), ("unknown", "", ""))
            self.assertEqual(record[4], "body " + str(i))
            expected = {"blob_bytes": 1} if isinstance(value, bytes) else value
            self.assertEqual(raw["is_from_me"], expected)
            self.assertIs(type(raw["is_from_me"]), type(expected))

    def test_absent_column_does_not_invent_an_incoming_flag(self):
        self.fixture([None], missing=True)
        raw = self.records()[0][-1]
        self.assertNotIn("is_from_me", raw)
        self.assertEqual((raw["message"]["direction"], raw["message"]["sender"],
                          raw["message"]["recipient"]), ("unknown", "", ""))

    def test_integer_affinity_follows_the_actual_stored_flag(self):
        self.fixture(["0", "1", "unexpected", 0.5], affinity="INTEGER")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT typeof(is_from_me) FROM message").fetchall(),
                             [("integer",), ("integer",), ("text",), ("real",)])
        self.assertEqual([r[-1]["message"]["direction"] for r in self.records()],
                         ["incoming", "outgoing", "unknown", "unknown"])

    def test_import_keeps_unknown_roles_and_original_bytes(self):
        self.fixture([None, "0", 2, 0, 1])
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        create_case(self.base / "cases", "direction")
        with connect(self.base / "cases", "direction") as (root, db):
            evidence = import_evidence(root, db, self.path, "ios")[0]
            parsers.native_analyze(root, db, evidence)
            records = select_artifacts(db, limit=None)
            self.assertEqual(len(records), 5)
            unknown = [r for r in records if r["data"]["message"]["direction"] == "unknown"]
            self.assertEqual(len(unknown), 3)
            self.assertTrue(all(r["data"]["message"]["sender"] == r["data"]["message"]["recipient"] == ""
                                for r in unknown))
            self.assertTrue(verify(root, db)["ok"])
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), digest)
