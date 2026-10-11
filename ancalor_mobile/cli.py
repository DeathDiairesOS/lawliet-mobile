"""Ancalor Mobile command-line interface. Standard library only."""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .core import UserError, case_dir, connect, create_case, import_evidence, select_artifacts, verify
from .correlate import shared_entities
from .demo import create_demo
from .parsers import native_analyze, timestamp
from .report import write_export, write_report
from .tools import TOOLS, collect, configure, devices, doctor, external_analyze


def clean(value):
    # Evidence text must not emit terminal escape/control sequences.
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value if value is not None else ""))


def table(headers, rows, widths=None):
    rows = [[clean(v) for v in row] for row in rows]
    widths = widths or [min(42, max([len(h)] + [len(row[i]) for row in rows])) for i, h in enumerate(headers)]
    def line(row):
        return "  ".join((v if len(v) <= width else v[:max(width - 1, 0)] + "…").ljust(width) for v, width in zip(row, widths))
    print(line(headers))
    print("  ".join("─" * width for width in widths))
    for row in rows:
        print(line(row))
    if not rows:
        print("No records.")


def emit(value, json_mode=False):
    if json_mode:
        print(json.dumps(value, indent=2, ensure_ascii=False, default=str))
    elif isinstance(value, dict):
        for key, item in value.items():
            print(f"{key.replace('_', ' ').capitalize():20} {clean(json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list)) else item)}")
    else:
        print(clean(value))


def utc_argument(value):
    if len(value) == 10:
        value += "T00:00:00Z"
    result = timestamp(value)
    if not result:
        raise argparse.ArgumentTypeError("Use YYYY-MM-DD or a timezone-aware ISO timestamp.")
    return result


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Must be positive.")
    return number


def parser():
    p = argparse.ArgumentParser(prog="ancalor", description="ANCALOR MOBILE · lightweight, local mobile evidence triage",
                                epilog="Start here: ancalor demo | ancalor doctor\nNo server. No required third-party packages. Original evidence is copied and hashed.", formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"Ancalor Mobile {__version__}")
    p.add_argument("--workspace", default=os.environ.get("ANCALOR_WORKSPACE", "ancalor-cases"), help="case workspace (default: ./ancalor-cases)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="command", required=True)
    case = sub.add_parser("case", help="create and inspect cases").add_subparsers(dest="action", required=True)
    create = case.add_parser("create", help="create a private case directory")
    create.add_argument("id")
    create.add_argument("--name")
    create.add_argument("--examiner")
    case.add_parser("list", help="list cases")
    show = case.add_parser("show", help="case summary, evidence inventory, and coverage")
    show.add_argument("id")
    intake = sub.add_parser("import", help="copy and hash a backup, folder, ZIP/TAR, or file")
    intake.add_argument("path")
    intake.add_argument("--case", required=True)
    intake.add_argument("--platform", choices=["auto", "ios", "android"], default="auto")
    intake.add_argument("--label")
    intake.add_argument("--max-gib", type=positive, default=20)
    intake.add_argument("--max-files", type=positive, default=100000)
    analyze = sub.add_parser("analyze", help="parse evidence with native or optional CLI engines")
    analyze.add_argument("--case", required=True)
    analyze.add_argument("--evidence", help="evidence ID (default: all in case)")
    analyze.add_argument("--engine", choices=["native", "ileapp", "aleapp", "exiftool"], default="native")
    analyze.add_argument("--timeout", type=positive, default=900, help="external engine timeout in seconds")
    for name in ("timeline", "search"):
        cmd = sub.add_parser(name, help="query normalized artifacts" if name == "search" else "chronological case timeline")
        if name == "search":
            cmd.add_argument("query", help="literal case-insensitive text search")
        cmd.add_argument("--case", required=True)
        cmd.add_argument("--category")
        cmd.add_argument("--evidence")
        cmd.add_argument("--since", type=utc_argument)
        cmd.add_argument("--until", type=utc_argument)
        cmd.add_argument("--limit", type=positive, default=100)
        cmd.add_argument("--format", choices=["table", "json", "jsonl", "csv"], default="table")
        cmd.add_argument("--out", help="export path (requires a non-table format)")
    inspect = sub.add_parser("inspect", help="show a record's original fields and provenance")
    inspect.add_argument("id")
    inspect.add_argument("--case", required=True)
    pivot = sub.add_parser("correlate", help="find URLs, domains, and phone-like strings shared across evidence sources")
    pivot.add_argument("--case", required=True)
    pivot.add_argument("--kind", choices=["all", "url", "domain", "phone"], default="all")
    pivot.add_argument("--min-sources", type=positive, default=2)
    evidence = sub.add_parser("evidence", help="list imported evidence files and hashes")
    evidence.add_argument("--case", required=True)
    evidence.add_argument("--evidence")
    integrity = sub.add_parser("verify", help="verify evidence SHA-256 hashes and audit chain")
    integrity.add_argument("--case", required=True)
    audit_cmd = sub.add_parser("audit", help="display case operation history")
    audit_cmd.add_argument("--case", required=True)
    report = sub.add_parser("report", help="generate a standalone searchable HTML investigation report")
    report.add_argument("--case", required=True)
    report.add_argument("--out")
    sub.add_parser("doctor", help="check Python and optional tool availability")
    tool = sub.add_parser("tools", help="manage optional external CLI adapters").add_subparsers(dest="action", required=True)
    tool.add_parser("list")
    conf = tool.add_parser("configure")
    conf.add_argument("name", choices=list(TOOLS))
    conf.add_argument("path", help="executable or Python entry point (e.g. ileapp.py)")
    sub.add_parser("devices", help="list devices through ADB and libimobiledevice")
    acquire = sub.add_parser("collect", help="collect a logical iOS backup or Android triage; live collection changes device state")
    acquire.add_argument("platform", choices=["ios", "android"])
    acquire.add_argument("--case", required=True)
    acquire.add_argument("--serial", required=True, help="explicit Android serial or iOS UDID")
    acquire.add_argument("--timeout", type=positive, default=900)
    demo = sub.add_parser("demo", help="create and analyze a fictional two-device case, offline")
    demo.add_argument("--case", default="demo")
    return p


def dispatch(args):
    workspace, json_mode = args.workspace, args.json
    if args.command == "case":
        if args.action == "create":
            emit({"case": args.id, "path": str(create_case(workspace, args.id, args.name, args.examiner))}, json_mode)
        elif args.action == "list":
            rows = []
            parent = Path(workspace).expanduser().resolve()
            if parent.exists():
                for path in sorted(parent.iterdir()):
                    if not (path / "case.sqlite").is_file():
                        continue
                    with connect(workspace, path.name) as (_, db):
                        meta = dict(db.execute("SELECT key,value FROM meta"))
                        rows.append({"case": path.name, "name": meta["name"], "created_at": meta["created_at"], "artifacts": db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]})
            if json_mode:
                emit(rows, True)
            else:
                table(["CASE", "NAME", "ARTIFACTS", "CREATED"], [[r["case"], r["name"], r["artifacts"], r["created_at"]] for r in rows])
        else:
            with connect(workspace, args.id) as (root, db):
                result = {"case": dict(db.execute("SELECT key,value FROM meta")), "path": str(root),
                          "evidence": [dict(r) for r in db.execute("SELECT * FROM evidence")],
                          "artifacts": dict(db.execute("SELECT category,COUNT(*) FROM artifacts GROUP BY category")),
                          "runs": [dict(r) for r in db.execute("SELECT * FROM runs ORDER BY started_at")]}
                if json_mode:
                    emit(result, True)
                else:
                    print(f"\nANCALOR MOBILE / {clean(result['case']['name'])}\n")
                    emit({"case": args.id, "examiner": result["case"]["examiner"] or "Unspecified", "path": str(root), "artifacts": sum(result["artifacts"].values())})
                    print("\nEvidence")
                    table(["ID", "PLATFORM", "LABEL", "ENCRYPTED"], [[r["id"], r["platform"], r["label"], bool(r["encrypted"])] for r in result["evidence"]])
                    print("\nArtifact coverage")
                    table(["CATEGORY", "RECORDS"], list(result["artifacts"].items()))
                    print("\nAnalysis runs")
                    table(["RUN", "ENGINE", "STATUS", "NEW RECORDS"], [[r["id"], r["engine"], r["status"], r["records"]] for r in result["runs"]])
        return 0
    if args.command == "demo":
        result = create_demo(workspace, args.case)
        if json_mode:
            emit(result, True)
        else:
            print("\nANCALOR MOBILE / SYNTHETIC TWO-DEVICE INVESTIGATION\n")
            emit({"case": result["case"], "artifacts": sum(r["new_records"] for r in result["runs"]), "report": result["report"]["path"]})
            print("\nTry next:")
            for cmd in result["next"]:
                print("  " + cmd)
            print("\nAll demo records are fictional. .example URLs and 555 numbers are test data.")
        return 0
    if args.command in {"doctor", "tools"}:
        if args.command == "tools" and args.action == "configure":
            emit(configure(workspace, args.name, args.path), json_mode)
        else:
            result = doctor(workspace)
            if json_mode:
                emit(result, True)
            else:
                print(f"\nANCALOR MOBILE {__version__} / Python {result['python']} / zero required packages\n")
                table(["ENGINE / TOOL", "STATUS", "PURPOSE"], [["native", "READY", "Baseline mobile database parsing"]] + [[r["tool"], "FOUND" if r["available"] else "OPTIONAL / MISSING", r["purpose"]] for r in result["tools"]])
                print("\nCore commands work offline. Tool presence does not establish device compatibility.")
        return 0
    if args.command == "devices":
        result = devices(workspace)
        if json_mode:
            emit(result, True)
        else:
            table(["PLATFORM", "SERIAL", "STATUS"], [[r["platform"], r.get("serial", "—"), r["status"]] for r in result])
        return 0
    with connect(workspace, args.case) as (root, db):
        if args.command == "import":
            identifier, files, size = import_evidence(root, db, args.path, args.platform, args.label, args.max_gib * 1024**3, args.max_files)
            emit({"evidence_id": identifier, "files": files, "bytes": size, "next": f"ancalor analyze --case {args.case} --evidence {identifier}"}, json_mode)
        elif args.command == "analyze":
            identifiers = [args.evidence] if args.evidence else [r[0] for r in db.execute("SELECT id FROM evidence ORDER BY imported_at")]
            if not identifiers:
                raise UserError("No evidence imported. Use import or collect first.")
            results = []
            for identifier in identifiers:
                if not json_mode:
                    print(f"Analyzing {clean(identifier)} with {args.engine}…", file=sys.stderr)
                try:
                    result = native_analyze(root, db, identifier) if args.engine == "native" else external_analyze(root, db, workspace, identifier, args.engine, args.timeout)
                    results.append({"evidence_id": identifier, **result})
                except (UserError, subprocess.TimeoutExpired, OSError) as exc:
                    results.append({"evidence_id": identifier, "status": "failed", "error": str(exc)})
            emit(results, True) if json_mode else [emit(r) for r in results]
            return 1 if any(r["status"] != "complete" for r in results) else 0
        elif args.command in {"timeline", "search"}:
            records = select_artifacts(db, getattr(args, "query", None), args.category, args.evidence, args.since, args.until, args.limit)
            if args.out:
                if args.format == "table":
                    raise UserError("Use --format json, jsonl, or csv with --out.")
                emit({"path": write_export(root, db, args.out, args.format, records), "records": len(records)}, json_mode)
            elif json_mode or args.format == "json":
                emit(records, True)
            elif args.format == "jsonl":
                for row in records:
                    print(json.dumps(row, ensure_ascii=False))
            elif args.format == "csv":
                raise UserError("CSV export requires --out; JSONL can stream to stdout.")
            else:
                table(["UTC TIME", "CATEGORY", "TITLE", "CONTENT", "RECORD ID"], [[(r["timestamp"] or "undated")[:19].replace("T", " "), r["category"], r["title"], r["body"], r["id"]] for r in records], [19, 10, 32, 48, 24])
                print(f"\n{len(records)} records shown (limit {args.limit}). Full fields: inspect <record-id> --case {args.case}")
        elif args.command == "correlate":
            result = shared_entities(db, args.min_sources, args.kind)
            if json_mode:
                emit(result, True)
            else:
                table(["TYPE", "SHARED ENTITY", "SOURCES", "RECORDS"], [[r["kind"], r["value"], r["evidence_sources"], r["records"]] for r in result], [8, 65, 7, 7])
                print("\nExact textual pivots, not attribution or maliciousness verdicts. --json includes record IDs.")
        elif args.command == "inspect":
            record = db.execute("SELECT a.*,f.logical_path,f.sha256 AS source_sha256 FROM artifacts a LEFT JOIN files f ON f.id=a.file_id WHERE a.id=?", (args.id,)).fetchone()
            if not record:
                raise UserError("Artifact not found. Copy an ID from timeline or search.")
            result = dict(record)
            result["data"] = json.loads(result["data"])
            emit(result, json_mode)
        elif args.command == "evidence":
            query = "SELECT evidence_id,path,logical_path,sha256,size FROM files"
            rows = [dict(r) for r in db.execute(query + (" WHERE evidence_id=?" if args.evidence else "") + " ORDER BY evidence_id,path", (args.evidence,) if args.evidence else ())]
            if json_mode:
                emit(rows, True)
            else:
                table(["EVIDENCE", "LOGICAL PATH", "BYTES", "SHA-256"], [[r["evidence_id"], r["logical_path"], r["size"], r["sha256"]] for r in rows], [12, 65, 10, 64])
        elif args.command == "verify":
            result = verify(root, db)
            emit(result, json_mode)
            return 0 if result["ok"] else 1
        elif args.command == "audit":
            rows = [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id")]
            if json_mode:
                emit(rows, True)
            else:
                table(["#", "UTC TIME", "ACTION", "DETAIL"], [[r["id"], r["at"], r["action"], r["detail"]] for r in rows], [4, 25, 24, 90])
        elif args.command == "report":
            emit(write_report(root, db, args.out or root / "reports" / "investigation.html"), json_mode)
        elif args.command == "collect":
            emit(collect(root, db, workspace, args.platform, args.serial, args.timeout), json_mode)
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Global switches may appear before or after subcommands.
    global_args, other = [], []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--json":
            global_args.append(token)
        elif token == "--workspace" and index + 1 < len(argv):
            global_args.extend(argv[index:index + 2])
            index += 1
        elif token.startswith("--workspace="):
            global_args.append(token)
        else:
            other.append(token)
        index += 1
    args = parser().parse_args(global_args + other)
    try:
        return dispatch(args)
    except KeyboardInterrupt:
        emit({"error": "Interrupted. Any completed records and operation logs were retained."}, args.json)
        return 130
    except (UserError, OSError, sqlite3.DatabaseError, ValueError, subprocess.SubprocessError) as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        else:
            print("Error: " + clean(str(exc)), file=sys.stderr)
        return 1
