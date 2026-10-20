#!/usr/bin/env python3
"""Local development handoff watcher; never executes handoff content or case tools."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
ENTRY = "other_active_session"
MAX_BYTES = 2 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("handoff/state exceeds size limit")
    return json.loads(data)


def write_json(path, value):
    """Replace atomically, without creating a partially readable status."""
    fd, name = tempfile.mkstemp(prefix=".watch-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Watcher:
    def __init__(self, handoff, directory):
        self.handoff = Path(handoff).resolve()
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_path = self.directory / "status.json"
        try:
            self.state = read_json(self.state_path)
        except FileNotFoundError:
            self.state = {"sequence": 0}
        if self.state.get("handoff", str(self.handoff)) != str(self.handoff):
            raise ValueError("state directory belongs to a different handoff")

    def journal(self, event):
        path = self.directory / "events.jsonl"
        line = json.dumps(event, ensure_ascii=True) + "\n"
        if path.exists() and path.stat().st_size + len(line.encode()) > MAX_BYTES:
            for index in (2, 1):
                source = self.directory / f"events.jsonl.{index}"
                if source.exists():
                    source.replace(self.directory / f"events.jsonl.{index + 1}")
            path.replace(self.directory / "events.jsonl.1")
        with path.open("a") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())

    def poll(self):
        checked = now()
        try:
            document = read_json(self.handoff)
            entry = document["sessions"][ENTRY]
            if not isinstance(entry, dict) or not entry:
                raise ValueError("other session entry must be a nonempty object")
            digest = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        except (OSError, ValueError, KeyError, TypeError) as error:
            # Do not echo untrusted file contents into error messages.
            message = f"Handoff unavailable or invalid ({type(error).__name__})"
            if self.state.get("error") != message:
                self.journal({"at": checked, "event": "read_error", "message": message})
            self.state["error"] = message
        else:
            if digest != self.state.get("sha256"):
                sequence = self.state["sequence"] + 1
                revision = f"{sequence}:{digest}"
                self.journal({"at": checked, "event": "update", "revision": revision,
                              "entry": entry})
                self.state.update(sequence=sequence, revision=revision, sha256=digest,
                                  detected_at=checked, latest_entry=entry)
            if self.state.get("error"):
                self.journal({"at": checked, "event": "read_recovered"})
            self.state["error"] = None
        self.state.update(handoff=str(self.handoff), checked_at=checked, pid=os.getpid())
        self.state.pop("stopped_at", None)
        write_json(self.state_path, self.state)
        return self.state


def _lock_worker(stream):
    """Nonblocking single-instance lock; release is tied to the open handle."""
    if os.name == 'nt':
        import msvcrt
        if not os.fstat(stream.fileno()).st_size:
            stream.write('\0'); stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            if exc.errno in (13, 36):
                raise BlockingIOError('Another watcher owns the development lock') from exc
            raise
    else:
        import fcntl
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)


def running(directory):
    path = directory / "worker.lock"
    if not path.exists():
        return False
    with path.open("a") as lock:
        try:
            _lock_worker(lock)
        except BlockingIOError:
            return True
    return False


def status(directory):
    path = directory / "status.json"
    result = read_json(path) if path.exists() else {}
    acknowledgment = directory / "reviewed.json"
    reviewed = read_json(acknowledgment) if acknowledgment.exists() else {}
    result.update(running=running(directory), reviewed=reviewed,
                  pending_review=bool(result.get("revision") and
                                      result["revision"] != reviewed.get("revision")))
    checked = result.get("checked_at")
    result["heartbeat_age_seconds"] = (round((datetime.now(timezone.utc) -
        datetime.fromisoformat(checked)).total_seconds(), 1) if checked else None)
    return result


def acknowledge(directory, revision):
    current = status(directory)
    if not revision or current.get("revision") != revision:
        raise ValueError("revision changed or missing; read status before acknowledging")
    write_json(directory / "reviewed.json", {"revision": revision, "reviewed_at": now(),
                                            "entry": current.get("latest_entry", {})})


def brief_status(current):
    entry = current.get("latest_entry", {})
    baseline = current.get("reviewed", {}).get("entry", {})
    result = {key: current.get(key) for key in
              ("running", "pid", "revision", "pending_review", "heartbeat_age_seconds", "error")}
    result["other_session"] = {key: entry.get(key) for key in
                               ("updated_at", "status", "current_task", "files_being_edited", "request_to_ui")}
    result["changed_fields"] = sorted(key for key in set(entry) | set(baseline)
                                      if entry.get(key) != baseline.get(key))
    result["latest_backend_suite"] = {key: entry.get("verification", {}).get("latest_backend_suite", {}).get(key)
                                      for key in ("passed", "skipped", "failures", "errors", "log")}
    result["full_snapshot"] = "Use status without --brief to inspect all fields before acknowledging."
    return result


def run(handoff, directory, interval):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / "worker.lock").open("a") as lock:
        try:
            _lock_worker(lock)
        except BlockingIOError:
            return
        watcher = Watcher(handoff, directory)
        stop_path = directory / "stop"
        stop_path.unlink(missing_ok=True)
        stopped = False

        def stop(*_):
            nonlocal stopped
            stopped = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while not stopped and not stop_path.exists():
            try:
                watcher.poll()
            except OSError:
                # A disconnected external drive may prevent even recording an error.
                # Retry; status consumers must also check heartbeat freshness.
                pass
            end = time.monotonic() + interval
            while time.monotonic() < end and not stopped and not stop_path.exists():
                time.sleep(min(0.5, max(0, end - time.monotonic())))
        watcher.state["stopped_at"] = now()
        write_json(watcher.state_path, watcher.state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("start", "run", "status", "ack", "stop"))
    parser.add_argument("--handoff", type=Path, default=ROOT / "docs/session-handoff.json")
    parser.add_argument("--state-dir", type=Path, default=ROOT / ".session-watch")
    parser.add_argument("--interval", type=float, default=20)
    parser.add_argument("--revision", help="Exact revision inspected by the analyst/agent")
    parser.add_argument("--brief", action="store_true", help="Summarize current work and changes; keep full snapshots on disk")
    args = parser.parse_args()
    if not 0.1 <= args.interval <= 3600:
        parser.error("interval must be between 0.1 and 3600 seconds")
    directory = args.state_dir.resolve()
    os.umask(0o077)
    try:
        if args.command == "start":
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if running(directory) and status(directory).get("handoff") != str(args.handoff.resolve()):
                raise ValueError("running watcher uses a different handoff")
            if not running(directory):
                with (directory / "worker.log").open("a") as log:
                    child = subprocess.Popen(
                        [sys.executable, str(Path(__file__).resolve()), "run",
                         "--handoff", str(args.handoff.resolve()), "--state-dir", str(directory),
                         "--interval", str(args.interval)], cwd=ROOT,
                        stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                        start_new_session=True, close_fds=True)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if running(directory) and (directory / "status.json").exists():
                        break
                    if child.poll() is not None:
                        break
                    time.sleep(0.05)
                if not running(directory):
                    raise ValueError("watcher did not start; inspect worker.log")
        elif args.command == "run":
            run(args.handoff, directory, args.interval)
            return
        elif args.command == "ack":
            acknowledge(directory, args.revision)
        elif args.command == "stop" and running(directory):
            (directory / "stop").touch()
        current = status(directory)
        print(json.dumps(brief_status(current) if args.brief else current, indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
