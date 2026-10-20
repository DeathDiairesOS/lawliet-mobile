"""Synthetic host transport fixtures, not Linux worker execution qualification.

Windows host publication/recovery tests consume this transport because Linux
worker nofollow/UID/mount checks must execute on Linux. A separate POSIX parity
test compares these framed semantics with the real worker implementation.
"""
import hashlib
import json
import sqlite3
import sys

from lawliet_mobile.child_output import ChildOutputs
from lawliet_mobile.core import json_text
from lawliet_mobile.parsed_import import iter_report_records
from lawliet_mobile.report_container import bindings_for
from lawliet_mobile.report_container_codec import validate
from lawliet_mobile.report_container_worker import MAX_ARTIFACTS, MAX_LINE, MAX_ROWS


def move_closed_case(fixture, destination):
    """Model a real case move: close SQLite before renaming on every platform."""
    previous = fixture.root
    fixture.db.commit()
    fixture.db.close()
    previous.rename(destination)
    fixture.root = destination
    if hasattr(fixture, "folder"):
        fixture.folder = destination / fixture.folder.relative_to(previous)
    fixture.db = sqlite3.connect(destination / "case.sqlite")
    fixture.db.row_factory = sqlite3.Row
    fixture.addCleanup(fixture.db.close)


def report_transport(source_path, request, raw_request, profile):
    source = request["source"]
    with ChildOutputs(source_path.parent) as inputs:
        original = inputs.read(source_path.name, 32 * 1024**2)
    if len(original) != source["bytes"] or hashlib.sha256(original).hexdigest() != source["sha256"]:
        raise ValueError("Synthetic report source hash differs.")
    bindings = bindings_for(raw_request, request, profile)
    def encode(value):
        return json.dumps(value, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("utf-8") + b"\n"
    lines, total = [], 0
    for record, mapped in iter_report_records(
            source_path, source["format_name"], source["evidence_id"],
            source["sha256"], source["filename"]):
        category, timestamp, original_time, title, body, metadata = mapped
        line = encode({
            "kind": "artifact", "seq": len(lines) + 1, "record": record,
            "evidence_id": source["evidence_id"], "file_id": source["file_id"],
            "category": str(category), "timestamp": timestamp,
            "timestamp_raw": str(original_time) if original_time is not None else None,
            "title": str(title), "body": str(body), "source_ref": f"report:record={record}",
            "parser": bindings["parser"], "data_json": json_text(metadata),
        })
        if len(lines) + 1 > MAX_ROWS or len(line) > MAX_LINE or total + len(line) > MAX_ARTIFACTS:
            raise ValueError("Synthetic report normalized output cap.")
        lines.append(line); total += len(line)
    if not lines and source["format_name"] != "tsv":
        raise ValueError("No records found in this report.")
    middle = b"".join(lines)
    output = encode({"kind": "header", **bindings}) + middle + encode({
        "kind": "final", "protocol": bindings["protocol"],
        "request_sha256": bindings["request_sha256"],
        "source_manifest_sha256": bindings["source_manifest_sha256"],
        "status": "complete", "artifact_count": len(lines), "artifact_bytes": total,
        "artifacts_sha256": hashlib.sha256(middle).hexdigest(),
        "runtime": {"python_version": sys.version.split()[0], "sqlite_version": sqlite3.sqlite_version},
    })
    validate(output, bindings)
    return output
