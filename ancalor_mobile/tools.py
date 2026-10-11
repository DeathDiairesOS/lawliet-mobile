"""Optional CLI adapters and explicit, logged device collection."""
from __future__ import annotations

import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from .core import UserError, add_artifact, audit, digest, import_evidence, json_text, now, verify
from .parsers import timestamp

TOOLS = {
    "ileapp": ("iOS artifact parsing", "MIT", ["ileapp"]),
    "aleapp": ("Android artifact parsing", "MIT", ["aleapp"]),
    "exiftool": ("Media metadata", "Artistic or GPL", ["exiftool"]),
    "adb": ("Android logical triage collection", "Apache-2.0 + dependency notices", ["adb"]),
    "idevice_id": ("iOS device discovery", "LGPL-2.1+", ["idevice_id"]),
    "idevicebackup2": ("iOS logical backup collection", "LGPL-2.1+", ["idevicebackup2"]),
}


def config_path(workspace):
    return Path(workspace).expanduser().resolve() / "tools.json"


def configuration(workspace):
    path = config_path(workspace)
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError("expected an object")
        return value
    except (ValueError, OSError) as exc:
        raise UserError(f"Cannot read tool configuration: {exc}")


def configure(workspace, name, path):
    target = Path(path).expanduser().resolve()
    if not target.is_file():
        raise UserError(f"Tool path does not exist: {target}")
    if target.suffix != ".py" and not os.access(target, os.X_OK):
        raise UserError("Tool must be executable, or a Python .py entry point.")
    settings = configuration(workspace)
    settings[name] = str(target)
    destination = config_path(workspace)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json_text(settings) + "\n")
    return {"tool": name, "path": str(target)}


def command(workspace, name):
    configured = configuration(workspace).get(name)
    executable = configured or next((p for alias in TOOLS[name][2] if (p := shutil.which(alias))), None)
    if not executable or not Path(executable).is_file():
        raise UserError(f"{name} is not installed/configured. Use: ancalor tools configure {name} /path/to/tool")
    return [sys.executable, executable] if executable.endswith(".py") else [executable]


def doctor(workspace):
    rows = []
    for name, (purpose, license_name, _) in TOOLS.items():
        try:
            cmd = command(workspace, name)
            path, available = cmd[-1], True
        except UserError:
            path, available = "", False
        rows.append({"tool": name, "available": available, "path": path, "purpose": purpose, "license": license_name})
    return {"python": sys.version.split()[0], "native_engine": "available", "runtime_dependencies": 0,
            "tools": rows, "note": "Presence checks only; device/OS compatibility must be validated separately."}


def execute(argv, output, timeout=300, cwd=None):
    """No shell; logs on disk; stop process groups on cancellation/timeout."""
    output.parent.mkdir(parents=True, exist_ok=True)
    error_path = output.with_name(output.name + ".stderr")
    started = time.monotonic()
    with output.open("wb") as stdout, error_path.open("wb") as stderr:
        child = subprocess.Popen(argv, cwd=cwd, stdout=stdout, stderr=stderr,
                                 stdin=subprocess.DEVNULL, start_new_session=(os.name != "nt"))
        try:
            returncode = child.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            if os.name != "nt":
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            child.wait()
            raise
    return {"argv": argv, "returncode": returncode, "elapsed_seconds": round(time.monotonic() - started, 3), "stdout": str(output), "stderr": str(error_path)}


def external_analyze(root, db, workspace, evidence_id, engine, timeout=900):
    evidence = db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not evidence:
        raise UserError(f"Unknown evidence: {evidence_id}")
    if evidence["encrypted"]:
        raise UserError("This adapter requires a decrypted extraction; encrypted-backup credentials are not accepted in process arguments.")
    expected = {"ileapp": "ios", "aleapp": "android"}.get(engine)
    if expected and evidence["platform"] not in {expected, "unknown"}:
        raise UserError(f"{engine} does not match this evidence platform ({evidence['platform']}).")
    if not verify(root, db)["ok"]:
        raise UserError("Evidence integrity check failed; run verify.")
    cmd = command(workspace, engine)
    run_id = uuid.uuid4().hex[:12]
    output = root / "runs" / run_id
    output.mkdir(parents=True)
    db.execute("INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES(?,?,?,?,?)", (run_id, evidence_id, engine, now(), "running"))
    audit(db, "analysis.started", {"run_id": run_id, "engine": engine, "evidence_id": evidence_id, "executable_sha256": digest(cmd[-1])})
    db.commit()
    count, status, detail = 0, "failed", {}
    try:
        with tempfile.TemporaryDirectory(prefix="ancalor-adapter-") as tmp:
            input_path = Path(tmp) / "input"
            shutil.copytree(root / "evidence" / evidence_id, input_path)
            report_dir = output / "output"
            report_dir.mkdir()
            if engine in {"ileapp", "aleapp"}:
                input_type = "itunes" if engine == "ileapp" and any(input_path.rglob("Manifest.db")) else "fs"
                # Folder backups can have an enclosing directory inside an archive.
                if input_type == "itunes":
                    manifests = list(input_path.rglob("Manifest.db"))
                    if len(manifests) != 1:
                        raise UserError("Multiple iOS backups found; import each backup separately.")
                    input_path = manifests[0].parent
                detail = execute(cmd + ["-t", input_type, "-i", str(input_path), "-o", str(report_dir)], output / "stdout.log", timeout)
                if detail["returncode"] != 0:
                    raise UserError(f"{engine} exited {detail['returncode']}. See {detail['stderr']}.")
                for tsv in sorted(report_dir.rglob("*.tsv")):
                    with tsv.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
                        reader = csv.DictReader(handle, delimiter="\t")
                        for number, row in enumerate(reader, start=2):
                            normalized = {str(k).lower().strip(): v for k, v in row.items() if k is not None}
                            raw = next((v for k, v in normalized.items() if k in {"timestamp", "date", "datetime", "date/time", "time", "date time"} and v), None)
                            # Do not manufacture an evidence-file link from a report name.
                            count += add_artifact(db, evidence_id, None, "external", timestamp(raw), raw, tsv.stem,
                                                  " · ".join(f"{k}: {v}" for k, v in row.items() if v),
                                                  f"runs/{run_id}/output/{tsv.relative_to(report_dir).as_posix()}:line={number}", engine, row)
                detail["note"] = "Imported TSV rows. Rows without timezone-aware timestamps remain undated. Original reports retained. Source-file hashes require native records or a dedicated artifact mapping."
            else:
                detail = execute(cmd + ["-json", "-r", "-n", str(input_path)], output / "metadata.json", timeout)
                if detail["returncode"] != 0:
                    raise UserError(f"ExifTool exited {detail['returncode']}. See {detail['stderr']}.")
                if (output / "metadata.json").stat().st_size > 128 * 1024**2:
                    raise UserError("ExifTool JSON exceeds 128 MiB; select a smaller media extraction.")
                source_files = {r["path"]: r for r in db.execute("SELECT * FROM files WHERE evidence_id=?", (evidence_id,))}
                for row in json.loads((output / "metadata.json").read_text()):
                    original = row.get("SourceFile", "")
                    relative = Path(original).relative_to(input_path).as_posix()
                    source = source_files.get(relative)
                    row["SourceFile"] = relative
                    raw = row.get("DateTimeOriginal") or row.get("CreateDate")
                    # EXIF local times are not UTC without an explicit offset.
                    when = timestamp(raw) if raw and "T" in str(raw) else None
                    count += add_artifact(db, evidence_id, source["id"] if source else None, "media", when, raw,
                                          row.get("FileName", relative), f"{row.get('FileType', '')} · {row.get('ImageWidth', '?')} × {row.get('ImageHeight', '?')}",
                                          "ExifTool metadata", engine, row)
        status = "complete"
    except BaseException as exc:
        status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
        detail["error"] = str(exc)
        raise
    finally:
        db.execute("UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?", (now(), status, count, json_text(detail), run_id))
        audit(db, "analysis.finished", {"run_id": run_id, "status": status, "new_records": count})
        db.commit()
    return {"run_id": run_id, "engine": engine, "status": status, "new_records": count, "detail": detail}


def devices(workspace):
    result = []
    with tempfile.TemporaryDirectory(prefix="ancalor-discovery-") as tmp:
        for platform, name, args in [("android", "adb", ["devices", "-l"]), ("ios", "idevice_id", ["-l"])]:
            try:
                cmd = command(workspace, name)
            except UserError:
                result.append({"platform": platform, "status": "tool_missing", "tool": name})
                continue
            run = execute(cmd + args, Path(tmp) / name, 20)
            if run["returncode"]:
                result.append({"platform": platform, "status": "discovery_failed", "tool": name})
                continue
            lines = (Path(tmp) / name).read_text(errors="replace").splitlines()
            found = 0
            for line in lines:
                if not line.strip() or line.startswith("List of devices"):
                    continue
                fields = line.split()
                result.append({"platform": platform, "serial": fields[0], "status": fields[1] if platform == "android" and len(fields) > 1 else "connected", "detail": " ".join(fields[2:])})
                found += 1
            if not found:
                result.append({"platform": platform, "status": "no_devices", "tool": name})
    return result


def collect(root, db, workspace, platform, serial, timeout=900):
    if not serial or serial.startswith("-") or any(c.isspace() for c in serial):
        raise UserError("Supply a valid device serial/UDID from devices.")
    run_id = uuid.uuid4().hex[:12]
    folder = root / "collections" / run_id
    folder.mkdir(parents=True)
    commands, errors, evidence_id = [], [], None
    audit(db, "collection.started", {"collection_id": run_id, "platform": platform, "serial": serial,
                                         "method": "logical backup" if platform == "ios" else "ADB triage", "device_changes": "Live collection changes device state; command logs retained."})
    db.commit()
    try:
        if platform == "ios":
            cmd = command(workspace, "idevicebackup2")
            backup = folder / "backup"
            backup.mkdir()
            commands.append(execute(cmd + ["-u", serial, "backup", "--full", str(backup)], folder / "backup.log", timeout))
            if commands[-1]["returncode"]:
                raise UserError(f"iOS backup failed. Check {folder / 'backup.log.stderr'} and the phone's trust/unlock state.")
            evidence_id, _, _ = import_evidence(root, db, backup, "ios", f"iOS backup · {serial}")
        else:
            cmd = command(workspace, "adb") + ["-s", serial]
            for args, filename in [(["shell", "getprop"], "getprop.txt"), (["shell", "pm", "list", "packages", "-f"], "packages.txt"), (["logcat", "-d", "-v", "epoch"], "logcat.txt"), (["bugreport", str(folder / "bugreport.zip")], "bugreport.log")]:
                try:
                    run = execute(cmd + args, folder / filename, timeout)
                    commands.append(run)
                    if run["returncode"]:
                        errors.append({"command": args, "returncode": run["returncode"]})
                except subprocess.TimeoutExpired:
                    errors.append({"command": args, "error": "timeout"})
            # Keep triage output as collected evidence; it is not a full app-data extraction.
            if not any(r["returncode"] == 0 for r in commands):
                raise UserError("Every Android collection command failed. Check USB debugging and host authorization.")
            (folder / "collection.json").write_text(json_text({"platform": platform, "serial": serial, "method": "ADB triage", "commands": commands, "errors": errors}) + "\n")
            evidence_id, _, _ = import_evidence(root, db, folder, "android", f"Android triage · {serial}")
        status = "partial" if errors else "complete"
    except BaseException as exc:
        status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
        errors.append({"error": str(exc)})
        raise
    finally:
        (folder / "collection.json").write_text(json_text({"collection_id": run_id, "platform": platform, "serial": serial, "status": status, "commands": commands, "errors": errors, "evidence_id": evidence_id}) + "\n")
        audit(db, "collection.finished", {"collection_id": run_id, "status": status, "evidence_id": evidence_id, "errors": errors})
        db.commit()
    return {"collection_id": run_id, "status": status, "evidence_id": evidence_id, "path": str(folder), "errors": errors}
