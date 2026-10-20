#!/usr/bin/env python3
"""Compare native desktop qualification receipts; never read case evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

HOSTS = {"windows-latest", "macos-15", "ubuntu-24.04"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def check_receipts(directory: Path, commit: str):
    """Require independent native runs against the same corpus and answer set."""
    errors, hosts = [], {}
    for host in sorted(HOSTS):
        folder = directory / ("desktop-smoke-" + host)
        try:
            result = json.loads((folder / "result.json").read_text(encoding="utf-8"))
            env = json.loads((folder / "environment.json").read_text(encoding="utf-8"))
            if not isinstance(result, dict) or not isinstance(env, dict):
                raise ValueError("Receipt and environment must be JSON objects")
            if env.get("commit") != commit:
                errors.append(f"{host}: source commit does not match {commit}")
            if env.get("runner_os") != {
                "windows-latest": "Windows", "macos-15": "macOS",
                "ubuntu-24.04": "Linux",
            }[host]:
                errors.append(f"{host}: native host identity is missing or inconsistent")
            if result.get("ok") is not True or result.get("schema_version") != 2:
                errors.append(f"{host}: qualification did not complete successfully")
            for key in ("corpus_sha256", "oracle_sha256", "field_fingerprint_sha256",
                        "expected_field_fingerprint_sha256"):
                if not SHA256.fullmatch(str(result.get(key, ""))):
                    errors.append(f"{host}: missing or invalid {key}")
            if result.get("field_fingerprint_sha256") != result.get("expected_field_fingerprint_sha256"):
                errors.append(f"{host}: compared fields differ from the independent answer manifest")
            comparison = result.get("comparison", {})
            expected = comparison.get("expected_records")
            if type(expected) is not int or expected <= 0:
                errors.append(f"{host}: no expected records were checked")
            for key in ("actual_records", "matched_records"):
                if comparison.get(key) != expected:
                    errors.append(f"{host}: {key} does not match expected record count")
            for key in ("missing_records", "unexpected_records", "field_mismatches"):
                if comparison.get(key) != 0:
                    errors.append(f"{host}: nonzero or missing {key}")
            if result.get("originals_unchanged") is not True:
                errors.append(f"{host}: original evidence integrity was not established")
            restart = result.get("restart", {})
            for key in ("ok", "new_process", "approval_persisted", "export_verified"):
                if restart.get(key) is not True:
                    errors.append(f"{host}: restart check {key} did not pass")
            pids = [restart.get(k) for k in ("initial_pid", "reopened_pid")]
            if any(type(pid) is not int or pid <= 0 for pid in pids) or pids[0] == pids[1]:
                errors.append(f"{host}: restart did not record two different process IDs")
            hosts[host] = {
                "environment": env,
                "corpus_sha256": result.get("corpus_sha256"),
                "oracle_sha256": result.get("oracle_sha256"),
                "field_fingerprint_sha256": result.get("field_fingerprint_sha256"),
                "expected_field_fingerprint_sha256": result.get("expected_field_fingerprint_sha256"),
                "comparison": comparison,
                "restart": restart,
                "originals_unchanged": result.get("originals_unchanged"),
            }
        except (OSError, ValueError, TypeError, AttributeError) as error:
            errors.append(f"{host}: cannot validate receipt: {error}")
    for key in ("corpus_sha256", "oracle_sha256", "field_fingerprint_sha256"):
        if len(hosts) != len(HOSTS) or len({h.get(key) for h in hosts.values()}) != 1:
            errors.append(f"Native hosts disagree on {key}, or a host is missing")
    return {
        "schema_version": 1, "ok": not errors, "commit": commit,
        "scope": "Synthetic Android import, native parsing, desktop review and local report export",
        "excludes": ["physical acquisition", "external parsers", "AI reasoning", "independent human examiner sign-off"],
        "hosts": hosts, "errors": errors,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipts", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = check_receipts(args.receipts, args.commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": result["ok"], "commit": args.commit,
                      "hosts": sorted(result["hosts"]), "errors": result["errors"]}, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
