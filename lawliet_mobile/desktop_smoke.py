"""Frozen, independently specified Android evidence for bounded desktop validation.

This module does not use production parsers or timestamp conversion. The corpus
contains only synthetic records. SQLite/WAL bytes are frozen once, not regenerated
on each OS, and raw SQL is checked on disposable copies before LAWLIET sees them.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sqlite3
import tempfile
from collections import defaultdict
from contextlib import closing
from pathlib import Path, PurePosixPath


_ASSET = Path(__file__).with_name("desktop_assets") / "android-qualification-v1.json"
_FIELDS = ("category", "body", "title", "timestamp", "timestamp_raw", "logical_path",
           "source_ref", "source_sha256", "parser")
_MISSING = {"missing_field": True}


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def tree_hashes(directory):
    root = Path(directory)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def _manifest():
    manifest = json.loads(_ASSET.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "lawliet-android-corpus/1" or manifest.get("synthetic") is not True:
        raise ValueError("Unsupported synthetic Android corpus.")
    if set(manifest["payloads"]) != set(manifest["oracle"]["files"]):
        raise ValueError("Synthetic file inventory differs from its independent oracle.")
    for name, payload in manifest["payloads"].items():
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
            raise ValueError("Invalid synthetic corpus path.")
        digest = hashlib.sha256(base64.b64decode(payload["base64"], validate=True)).hexdigest()
        if digest != payload["sha256"] or digest != manifest["oracle"]["files"][name]:
            raise ValueError("Synthetic payload does not match its frozen SHA-256.")
    return manifest


def check_raw_sources(directory, *, missing_wal=False):
    """Assert hand-authored input events using direct SQL, only on working copies."""
    manifest = _manifest()
    seed = manifest["seed"]
    source = Path(directory)
    before = tree_hashes(source)
    expected_hashes = dict(manifest["oracle"]["files"])
    if missing_wal:
        del expected_hashes[seed["sms_path"] + "-wal"]
    if before != expected_hashes:
        raise ValueError("Raw synthetic evidence inventory/hash mismatch.")
    expected_sms = [row for row in seed["sms_rows"]
                    if not missing_wal or row[0] not in seed["wal_only_sms_ids"]]
    queries = (
        (seed["sms_path"], "SELECT _id,thread_id,address,date,type,body FROM sms ORDER BY _id", expected_sms),
        (seed["contacts_path"], "SELECT _id,raw_contact_id,mimetype_id,data1 FROM data ORDER BY _id", seed["contact_rows"]),
        (seed["calls_path"], "SELECT _id,number,date,duration,type FROM calls ORDER BY _id", seed["call_rows"]),
    )
    with tempfile.TemporaryDirectory(prefix="lawliet-independent-oracle-") as tmp:
        work = Path(tmp) / "working-copy"
        shutil.copytree(source, work)
        for logical_path, sql, expected in queries:
            with closing(sqlite3.connect((work / logical_path).as_uri() + "?mode=ro", uri=True)) as db:
                actual = [list(row) for row in db.execute(sql)]
            if actual != expected:
                raise ValueError(f"Independent raw SQL differs from input events: {logical_path}")
    if tree_hashes(source) != before:
        raise ValueError("Independent raw validation modified source evidence.")
    return {"passed": True, "sms_records": len(expected_sms),
            "contact_field_observations": len(seed["contact_rows"]), "call_records": len(seed["call_rows"]),
            "originals_unchanged": True}


def build_fixture(directory):
    """Materialize identical raw bytes and a missing-WAL negative control.

    Creates fresh subdirectories only; refuses to overwrite an existing fixture.
    The oracle stays outside imported evidence and is never derived from app output.
    """
    manifest = _manifest()
    root = Path(directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    source, missing = root / "synthetic-evidence", root / "synthetic-missing-wal"
    source.mkdir()
    missing.mkdir()
    wal = manifest["seed"]["sms_path"] + "-wal"
    for name, payload in manifest["payloads"].items():
        raw = base64.b64decode(payload["base64"], validate=True)
        for folder in (source, missing):
            if folder == missing and name == wal:
                continue
            destination = folder.joinpath(*PurePosixPath(name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
    raw_validation = check_raw_sources(source)
    missing_raw_validation = check_raw_sources(missing, missing_wal=True)
    oracle = copy.deepcopy(manifest["oracle"])
    missing_oracle = copy.deepcopy(oracle)
    del missing_oracle["files"][wal]
    missing_oracle["records"] = [
        row for row in missing_oracle["records"]
        if not (row["logical_path"] == manifest["seed"]["sms_path"]
                and row["source_ref"] in {f"sms:_id={i}" for i in manifest["seed"]["wal_only_sms_ids"]})
    ]
    for row in missing_oracle["records"]:
        if row["logical_path"] == manifest["seed"]["sms_path"]:
            row["fields"]["data.sqlite_wal_coverage.wal_present"] = False
            row["fields"]["data.sqlite_wal_coverage.pairing"] = "not_available"
            # No sidecars key is emitted when none was acquired.
            del row["fields"]["data.source_sidecars"]
    missing_oracle["timeline"]["source_refs"] = ["sms:_id=2"]
    missing_oracle["limitations"].append("WAL intentionally withheld: committed SMS 4 is unavailable.")
    return {
        "synthetic": True, "case_id": "DESKTOP-SMOKE", "path": str(source), "oracle": oracle,
        "oracle_sha256": canonical_sha256(oracle), "corpus_sha256": canonical_sha256(oracle["files"]),
        "missing_case_id": "DESKTOP-MISSING-WAL", "missing_path": str(missing), "missing_oracle": missing_oracle,
        "raw_validation": raw_validation, "missing_raw_validation": missing_raw_validation,
    }


def _field(record, dotted):
    value = record
    parts = dotted.split(".")
    while parts:
        if not isinstance(value, dict):
            return _MISSING
        # Android property keys themselves contain dots.
        remainder = ".".join(parts)
        if remainder in value:
            return value[remainder]
        value = value.get(parts.pop(0), _MISSING)
    return value


def _key(record):
    return (str(record.get("logical_path", "")), str(record.get("source_ref", "")))


def compare_records(actual_records, oracle):
    """Compare every material expected field; report extra, missing and duplicate rows.

    Fingerprints exclude generated case/evidence IDs and host paths. They include
    exact original values, source references/hashes, normalized times and selected
    nested parser fields. A missing key is distinct from a present null.
    """
    expected = oracle["records"]
    expected_by_key = {_key(row): row for row in expected}
    if len(expected_by_key) != len(expected):
        raise ValueError("Independent oracle contains a duplicate record key.")
    actual_by_key = defaultdict(list)
    actual_projections, expected_projections, differences = [], [], []
    for original in actual_records:
        row = dict(original)
        if isinstance(row.get("data"), str):
            row["data"] = json.loads(row["data"])
        actual_by_key[_key(row)].append(row)
        template = expected_by_key.get(_key(row), {})
        actual_projections.append({**{name: row.get(name, _MISSING) for name in _FIELDS},
                                   "fields": {name: _field(row, name) for name in template.get("fields", {})}})
    matched = missing = unexpected = mismatches = duplicate = 0
    for key, template in expected_by_key.items():
        expected_projections.append({**{name: template[name] for name in _FIELDS},
                                     "fields": template["fields"]})
        candidates = actual_by_key.get(key, [])
        if not candidates:
            missing += 1
            differences.append({"record": list(key), "issue": "missing_record"})
            continue
        if len(candidates) > 1:
            duplicate += len(candidates) - 1
            unexpected += len(candidates) - 1
            differences.append({"record": list(key), "issue": "duplicate_record", "count": len(candidates)})
        row = candidates[0]
        record_mismatches = 0
        fields = {name: template[name] for name in _FIELDS} | template["fields"]
        for name, wanted in fields.items():
            actual = _field(row, name)
            if actual != wanted or type(actual) is not type(wanted):
                record_mismatches += 1
                differences.append({"record": list(key), "field": name, "expected": wanted, "actual": actual})
        mismatches += record_mismatches
        matched += int(record_mismatches == 0 and len(candidates) == 1)
    for key, rows in actual_by_key.items():
        if key not in expected_by_key:
            unexpected += len(rows)
            differences.append({"record": list(key), "issue": "unexpected_record", "count": len(rows)})
    order = lambda row: json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    expected_fingerprint = canonical_sha256(sorted(expected_projections, key=order))
    actual_fingerprint = canonical_sha256(sorted(actual_projections, key=order))
    return {"comparison": {"expected_records": len(expected), "actual_records": len(actual_records),
                           "matched_records": matched, "missing_records": missing, "unexpected_records": unexpected,
                           "duplicate_records": duplicate, "field_mismatches": mismatches},
            "field_fingerprint_sha256": actual_fingerprint,
            "expected_field_fingerprint_sha256": expected_fingerprint, "differences": differences,
            "passed": not differences and actual_fingerprint == expected_fingerprint}
