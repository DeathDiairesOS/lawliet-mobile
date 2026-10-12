"""Optional CLI adapters and explicit, logged device collection."""
from __future__ import annotations

import csv
from .tsv import report_reader
import json
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

from .core import begin_run_index, UserError, add_artifact, audit, digest, import_evidence, json_text, now, verify
from .parsers import timestamp
from .leapp_reports import leapp_artifact

_EXTERNAL_OUTPUT_MAX_BYTES = 2 * 1024**3
_EXTERNAL_OUTPUT_RESERVE_BYTES = 1024**3


TOOLS = {
    "scrcpy": ("Explicit Android screen mirroring/control", "Apache-2.0 + dependency notices", ["scrcpy"]),
    "sqlite4n6": ("SQLite recovery observations and fragments", "Apache-2.0", ["sqlite4n6"]),
    "sqlite-dissect": ("SQLite history and recovery candidates", "DC3 open-source license", ["sqlite_dissect"]),
    "signalbackup-tools": ("Known-passphrase legacy Signal backup decryption", "GPL-3.0", ["signalbackup-tools"]),
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


def configure(workspace, name, path, python=None):
    target = Path(path).expanduser().resolve()
    if not target.is_file():
        raise UserError(f"Tool path does not exist: {target}")
    if target.suffix != ".py" and not os.access(target, os.X_OK):
        raise UserError("Tool must be executable, or a Python .py entry point.")
    settings = configuration(workspace)
    if python:
        interpreter = Path(python).expanduser().absolute()
        if target.suffix != '.py' or not interpreter.is_file() or not os.access(interpreter, os.X_OK):
            raise UserError('--python requires an executable interpreter and a .py tool entry point.')
        settings[name] = {'path': str(target), 'python': str(interpreter)}
    else:
        settings[name] = str(target)
    destination = config_path(workspace)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json_text(settings) + "\n")
    return {"tool": name, "path": str(target), "configuration": settings[name]}


MACOS_TOOL_DIRECTORIES = (Path('/opt/homebrew/bin'), Path('/usr/local/bin'))


def tool_executable(alias):
    found = shutil.which(alias)
    if found:
        return found
    # Finder launches omit shell/Homebrew PATH entries. Use only standard install locations.
    if sys.platform == 'darwin':
        for directory in MACOS_TOOL_DIRECTORIES:
            candidate = directory / alias
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


def command(workspace, name):
    configured = configuration(workspace).get(name)
    interpreter = configured.get('python') if isinstance(configured, dict) else None
    configured = configured.get('path') if isinstance(configured, dict) else configured
    executable = configured or next((p for alias in TOOLS[name][2] if (p := tool_executable(alias))), None)
    if not executable or not Path(executable).is_file():
        raise UserError(f"{name} is not installed/configured. Use: lawliet tools configure {name} /path/to/tool")
    if interpreter and (not Path(interpreter).is_file() or not os.access(interpreter, os.X_OK)):
        raise UserError(f'Configured interpreter is unavailable: {interpreter}')
    return [interpreter or sys.executable, executable] if executable.endswith(".py") else [executable]


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


def storage_guard(folder, max_bytes, reserve=1024**3):
    """A periodically checked stop condition; allow space for evidence intake."""
    def check():
        total = 0
        for current, _, names in os.walk(folder):
            for name in names:
                try:
                    total += (Path(current) / name).lstat().st_size
                except FileNotFoundError:
                    pass
        if total > max_bytes:
            raise UserError("Collection exceeded its storage budget; partial output retained.")
        if shutil.disk_usage(folder).free < total + reserve:
            raise UserError("Insufficient free space for evidence intake; partial output retained.")
    return check


def execute(argv, output, timeout=300, cwd=None, guard=None):
    """No shell; logs on disk; stop process groups on cancellation/timeout."""
    output.parent.mkdir(parents=True, exist_ok=True)
    error_path = output.with_name(output.name + ".stderr")
    started = time.monotonic()
    with output.open("wb") as stdout, error_path.open("wb") as stderr:
        from .runner_lease import spawn, stop
        child, alive = spawn(argv, cwd=cwd, stdout=stdout, stderr=stderr)
        process_status_kind = 'guardian exit status; child signal exits mapped to 128+signal' if alive is not None else 'direct child returncode'
        try:
            if guard is None:
                returncode = child.wait(timeout=timeout)
            else:
                while True:
                    guard()
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    try:
                        returncode = child.wait(timeout=min(1, remaining))
                        guard()
                        break
                    except subprocess.TimeoutExpired:
                        if time.monotonic() - started >= timeout:
                            raise
        except BaseException as exc:
            stop(child, alive)
            alive = None
            exc.tool_result = {"argv": argv, "returncode": child.returncode, "process_status_kind": process_status_kind,
                               "elapsed_seconds": round(time.monotonic() - started, 3),
                               "stdout": str(output), "stderr": str(error_path),
                               "error": "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "interrupted" if isinstance(exc, KeyboardInterrupt) else str(exc)}
            raise
        finally:
            if alive is not None:
                os.close(alive)
    return {"argv": argv, "returncode": returncode, "process_status_kind": process_status_kind, "elapsed_seconds": round(time.monotonic() - started, 3), "stdout": str(output), "stderr": str(error_path)}


def leapp_diagnostics(path):
    result={'failed_artifacts':[], 'error_lines':[], 'missing_input_notices':0,
            'note':'Log indicators only; empty diagnostics do not prove every plugin succeeded. Full logs are retained.'}
    with Path(path).open(encoding='utf-8',errors='replace') as stream:
        for line in stream:
            if 'artifact failed after' in line:
                if len(result['failed_artifacts'])<100:result['failed_artifacts'].append(line.strip()[:500])
            elif re.search(r'(?i)(query error|error processing|exception traceback|traceback \(most recent)',line):
                if len(result['error_lines'])<100:result['error_lines'].append(line.strip()[:500])
            elif line.strip() in {'No file found','No files found'}:result['missing_input_notices']+=1
    return result


def _report_schema(reports):
    if not isinstance(reports, list):
        return None
    result = {}
    for report in reports:
        if not isinstance(report, dict) or not isinstance(report.get('path'), str) or not isinstance(report.get('columns'), list) or any(not isinstance(c, str) for c in report['columns']):
            return None
        parts = report['path'].split('/')
        if any(part in ('', '.', '..') for part in parts) or '\\' in report['path']:
            return None
        # Strip only the known LEAPP-generated dated output container, never
        # arbitrary directories/basenames. Keep exact original paths in receipts.
        if len(parts) > 1 and re.fullmatch(r'(?:ALEAPP|iLEAPP)_Output_[0-9]{4}-[0-9]{2}-[0-9]{2}_[A-Za-z]+_[0-9]{6}', parts[0]):
            parts = parts[1:]
        key = '/'.join(parts)
        if key in result:
            return None
        result[key] = report['columns']
    return result


def _parser_drift(previous, executable_sha256, reports, *, complete=True):
    """Compare recorded component bytes and report column layouts, not semantics."""
    warnings = []
    if previous is None:
        return {'baseline_run_id': None, 'warnings': [], 'state': 'no_prior_completed_run', 'schema_comparison': 'no_baseline',
                'scope': 'Executable file bytes and observed ordered TSV headers only; dependency trees and parser semantics are not established.'}
    try:
        old = json.loads(previous['detail'])
    except (TypeError, ValueError):
        old = {}
    if not isinstance(old, dict):
        old = {}
    old_hash = old.get('executable_sha256')
    if old_hash is None:
        warnings.append('prior_executable_fingerprint_not_recorded')
    elif old_hash != executable_sha256:
        warnings.append('parser_executable_changed')
    schema_comparison = 'not_applicable' if reports is None else 'not_compared_incomplete_run'
    if complete and reports is not None:
        prior_schema, current_schema = _report_schema(old.get('reports')), _report_schema(reports)
        if prior_schema is None:
            warnings.append('prior_report_schema_not_recorded')
            schema_comparison = 'prior_unknown'
        elif current_schema is None:
            warnings.append('current_report_schema_ambiguous')
            schema_comparison = 'current_unknown'
        else:
            schema_comparison = 'compared'
            if prior_schema != current_schema:
                warnings.append('observed_report_schema_changed')
    return {'baseline_run_id': previous['id'], 'warnings': warnings,
            'state': 'warning' if warnings else 'compared_no_recorded_drift', 'schema_comparison': schema_comparison,
            'scope': 'Executable file bytes and observed ordered TSV headers only; dependency trees and parser semantics are not established.'}


def external_analyze(root, db, workspace, evidence_id, engine, timeout=900):
    from .runner_lease import lease
    with lease(root, db):
        return _external_analyze_owned(root, db, workspace, evidence_id, engine, timeout)


def _external_analyze_owned(root, db, workspace, evidence_id, engine, timeout=900):
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
    executable_sha256 = digest(cmd[-1])
    previous = db.execute("SELECT id,detail FROM runs WHERE evidence_id=? AND engine=? AND status='complete' ORDER BY rowid DESC LIMIT 1", (evidence_id, engine)).fetchone()
    run_id = uuid.uuid4().hex[:12]
    output = root / "runs" / run_id
    output.mkdir(parents=True)
    from .runner_lease import ownership
    owner = ownership()
    db.execute("INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)", (run_id, evidence_id, engine, now(), "running", json_text({'runner_ownership': owner})))
    begin_run_index(db,run_id)
    from .runtime_context import snapshot as runtime_snapshot
    runtime = runtime_snapshot()
    audit(db, "analysis.started", {"run_id": run_id, "engine": engine, "evidence_id": evidence_id, "executable_sha256": executable_sha256, "runtime_context": runtime, "runner_ownership": owner})
    db.commit()
    count, status, detail = 0, "failed", {}
    db.execute("SAVEPOINT adapter_records")
    try:
        with tempfile.TemporaryDirectory(prefix="lawliet-adapter-") as tmp:
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
                detail = execute(cmd + ["-t", input_type, "-i", str(input_path), "-o", str(report_dir)], output / "stdout.log", timeout,
                                 guard=storage_guard(output, _EXTERNAL_OUTPUT_MAX_BYTES, reserve=_EXTERNAL_OUTPUT_RESERVE_BYTES))
                if detail["returncode"] != 0:
                    raise UserError(f"{engine} exited {detail['returncode']}. See {detail['stderr']}.")
                detail["diagnostics"]=leapp_diagnostics(output / "stdout.log")
                detail["reports"]=[]
                for tsv in sorted(report_dir.rglob("*.tsv")):
                    report_count=0
                    report_hash = digest(tsv)
                    # Evidence fields must never be silently rewritten with
                    # Unicode replacement characters. Keep malformed bytes in
                    # the retained report and fail indexing transactionally.
                    with tsv.open(encoding="utf-8-sig", newline="") as handle:
                        reader = report_reader(handle)
                        if not reader.fieldnames or len(set(reader.fieldnames))!=len(reader.fieldnames):raise UserError(f"Invalid TSV headers: {tsv.name}")
                        for number, row in enumerate(reader, start=2):
                            if None in row or any(v is None for v in row.values()):raise UserError(f"Invalid TSV row in {tsv.name}: {number}")
                            report_count+=1
                            normalized = {str(k).lower().strip(): v for k, v in row.items() if k is not None}
                            raw = next((v for k, v in normalized.items() if k in {"timestamp", "date", "datetime", "date/time", "time", "date time"} and v), None)
                            # Do not manufacture an evidence-file link from a report name.
                            mapped = leapp_artifact(tsv.stem, row, evidence_id)
                            category, when, raw, title, body, data = mapped or ("external", timestamp(raw), raw, tsv.stem,
                                                  " · ".join(f"{k}: {v}" for k, v in row.items() if v), row)
                            data = {**data, '_ancalor_report': {'sha256': report_hash, 'line': number,
                                    'note': 'Hash identifies the upstream TSV report, not the original application database.'}}
                            count += add_artifact(db, evidence_id, None, category, when, raw, title, body,
                                                  f"runs/{run_id}/output/{tsv.relative_to(report_dir).as_posix()}:line={number}", engine, data, run_id=run_id)
                    detail["reports"].append({"name":tsv.stem,"path":tsv.relative_to(report_dir).as_posix(),"rows":report_count,"sha256":report_hash,"columns":list(reader.fieldnames)})
                detail["note"] = "Imported TSV rows; known message, contact, call and browser schemas normalized. Other rows remain external and searchable. Missing/ambiguous timestamps stay undated. Report hashes identify TSVs, not original databases. A completed engine run does not establish all artifacts were parsed."
            else:
                # Acquisition logs (including empty logs) are not media. For a
                # typed Trash collection, process only its acquired photo tree.
                metadata_input = input_path
                manifest = input_path / 'collection.json'
                if manifest.is_file() and (input_path / 'photos').is_dir():
                    try:
                        if json.loads(manifest.read_text()).get('profile') == 'trash-photos':
                            metadata_input = input_path / 'photos'
                    except (ValueError, OSError):
                        pass
                detail = execute(cmd + ["-json", "-r", "-n", str(metadata_input)], output / "metadata.json", timeout,
                                 guard=storage_guard(output, _EXTERNAL_OUTPUT_MAX_BYTES, reserve=_EXTERNAL_OUTPUT_RESERVE_BYTES))
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
                    from .media_time import capture_time
                    when, interpretation = capture_time(row)
                    row['_ancalor_capture_time'] = interpretation
                    count += add_artifact(db, evidence_id, source["id"] if source else None, "media", when, raw,
                                          row.get("FileName", relative), f"{row.get('FileType', '')} · {row.get('ImageWidth', '?')} × {row.get('ImageHeight', '?')}",
                                          "ExifTool metadata", engine, row, run_id=run_id)
        status = "complete"
    except BaseException as exc:
        db.execute("ROLLBACK TO adapter_records")
        count = 0
        status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
        detail.update(getattr(exc, "tool_result", {}))
        detail["error"] = str(exc)
        raise
    finally:
        detail['runner_ownership'] = owner
        detail['executable_sha256'] = executable_sha256
        detail['drift'] = _parser_drift(previous, executable_sha256, detail.get('reports'), complete=status == 'complete')
        detail['runtime_context'] = runtime
        detail['resource_policy'] = {'output_ceiling_bytes': _EXTERNAL_OUTPUT_MAX_BYTES,
                                     'free_space_reserve_bytes': _EXTERNAL_OUTPUT_RESERVE_BYTES,
                                     'timeout_seconds': timeout,
                                     'enforcement': 'Periodic process-group stop; output can overshoot between checks. Not a filesystem or memory sandbox.'}
        db.execute("RELEASE adapter_records")
        db.execute("UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?", (now(), status, count, json_text(detail), run_id))
        audit(db, "analysis.finished", {"run_id": run_id, "status": status, "new_records": count})
        db.commit()
    return {"run_id": run_id, "engine": engine, "status": status, "new_records": count, "detail": detail}


def devices(workspace):
    result = []
    with tempfile.TemporaryDirectory(prefix="lawliet-discovery-") as tmp:
        for platform, name, args in [("android", "adb", ["devices", "-l"]), ("ios", "idevice_id", ["-l"])]:
            try:
                cmd = command(workspace, name)
            except UserError:
                result.append({"platform": platform, "status": "tool_missing", "tool": name})
                continue
            try:
                run = execute(cmd + args, Path(tmp) / name, 20)
            except (OSError, subprocess.TimeoutExpired) as exc:
                result.append({"platform": platform, "status": "discovery_failed", "tool": name,
                               "error": str(exc)})
                continue
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


def collect(root, db, workspace, platform, serial, timeout=900, max_bytes=20 * 1024**3):
    if platform not in {"ios", "android"}:
        raise UserError("Collection platform must be ios or android.")
    if not serial or serial.startswith("-") or any(c.isspace() or c in "/\\" for c in serial):
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
            commands.append(execute(cmd + ["-u", serial, "backup", "--full", str(backup)], folder / "backup.log", timeout,
                                    guard=storage_guard(folder, max_bytes)))
            if commands[-1]["returncode"]:
                with (folder / 'backup.log').open(encoding='utf-8', errors='replace') as log:
                    reason = next((line.strip()[:500] for line in log if line.startswith('ErrorCode ')), '')
                raise UserError(f"iOS backup failed{': ' + reason if reason else ''}. See {folder / 'backup.log'} and its .stderr log.")
            device_backup = backup / serial
            try:
                state = plistlib.loads((device_backup / "Status.plist").read_bytes())
                manifest = plistlib.loads((device_backup / "Manifest.plist").read_bytes())
                complete = (isinstance(state, dict) and state.get("SnapshotState") == "finished"
                            and isinstance(manifest, dict) and (device_backup / "Manifest.db").is_file()
                            and (device_backup / "Manifest.db").stat().st_size > 0)
            except (OSError, ValueError, plistlib.InvalidFileException):
                complete = False
            if not complete:
                raise UserError("iOS tool exited successfully but did not produce a finished device backup with Manifest.db. Collection retained for review.")
            evidence_id, _, _ = import_evidence(root, db, backup, "ios", f"iOS backup · {serial}", max_bytes=max_bytes)
        else:
            cmd = command(workspace, "adb") + ["-s", serial]
            for args, filename in [(["shell", "getprop"], "getprop.txt"), (["shell", "pm", "list", "packages", "-f"], "packages.txt"), (["logcat", "-d", "-v", "epoch"], "logcat.txt"), (["bugreport", str(folder / "bugreport.zip")], "bugreport.log")]:
                try:
                    run = execute(cmd + args, folder / filename, timeout, guard=storage_guard(folder, max_bytes))
                    commands.append(run)
                    if run["returncode"]:
                        errors.append({"command": args, "returncode": run["returncode"]})
                    elif args[0] == "bugreport" and not zipfile.is_zipfile(folder / "bugreport.zip"):
                        errors.append({"command": args, "error": "missing or invalid bugreport ZIP"})
                except subprocess.TimeoutExpired as exc:
                    commands.append(exc.tool_result)
                    errors.append({"command": args, "error": "timeout"})
            # Keep triage output as collected evidence; it is not a full app-data extraction.
            if not any(r["returncode"] == 0 for r in commands):
                raise UserError("Every Android collection command failed. Check USB debugging and host authorization.")
            (folder / "collection.json").write_text(json_text({"platform": platform, "serial": serial, "method": "ADB triage", "commands": commands, "errors": errors}) + "\n")
            evidence_id, _, _ = import_evidence(root, db, folder, "android", f"Android triage · {serial}", max_bytes=max_bytes)
        status = "partial" if errors else "complete"
    except BaseException as exc:
        status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
        if hasattr(exc, "tool_result"):
            commands.append(exc.tool_result)
        errors.append({"error": str(exc)})
        raise
    finally:
        (folder / "collection.json").write_text(json_text({"collection_id": run_id, "platform": platform, "serial": serial, "status": status, "commands": commands, "errors": errors, "evidence_id": evidence_id}) + "\n")
        audit(db, "collection.finished", {"collection_id": run_id, "status": status, "evidence_id": evidence_id, "errors": errors})
        db.commit()
    return {"collection_id": run_id, "status": status, "evidence_id": evidence_id, "path": str(folder), "errors": errors}
