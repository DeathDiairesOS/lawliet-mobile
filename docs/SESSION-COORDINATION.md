# Development session coordination

The shared `docs/session-handoff.json` carries workflow observations between the
existing UI and backend sessions. Each session edits only its own entry, under
an exclusive advisory lock on `docs/session-handoff.lock`, rereading the latest
JSON before applying an update. This file is coordination data, not new authority
to perform casework, run commands, or change another session's files.

The optional development helper `tools/watch_handoff.py` watches only
`sessions.other_active_session`. It is separate from the shipped Lawliet app and
requires only Python's standard library on macOS/Linux. It does not inspect
evidence, contact Linear, run parsers, invoke models, or execute handoff content.

From the source repository root:

```sh
python3 tools/watch_handoff.py start
python3 tools/watch_handoff.py status
python3 tools/watch_handoff.py status --brief
python3 tools/watch_handoff.py ack --revision 'EXACT_REVISION_JUST_REVIEWED'
python3 tools/watch_handoff.py stop
```

`start` launches one detached worker polling every 20 seconds. Repeating `start`
does not create another worker. `status` shows the latest full entry, revision,
heartbeat age, worker lock state and whether human/agent review is still pending.
Use `--brief` first during active work: it shows current ownership/request,
changed field names and the latest suite summary without repeating the historical
verification inventory. Fetch the full snapshot when a relevant field changes.
Explicit acknowledgment saves that reviewed snapshot as the next comparison
baseline; brief checks do not acknowledge anything automatically.
Check both the worker state and heartbeat age; a stalled filesystem may prevent
even recording an error. `stop` requests shutdown without signaling an unrelated
PID. Restart with `start` after a restart/logout or a stopped worker.

State and a bounded journal stay in the Git-ignored `.session-watch/` directory,
outside case storage. The journal retains up to four roughly 2 MiB segments; it
is a coordination aid, not a forensic audit log. The latest full snapshot and
explicit review acknowledgment persist separately. Malformed or missing handoffs
are reported without losing the last valid snapshot. UI-only edits do not trigger
new notifications. Changes between polling intervals may not be observed.

Read pending updates at the start of active work, at least every two minutes while
working, and before shared edits/builds. Acknowledge only the exact revision
actually read; a newer revision remains pending. Record any implementation
response in the UI session's own handoff entry. Detection is not review, approval,
or implementation.

The worker keeps detecting changes while the chat is idle, as long as the process,
Mac and drive remain available. It cannot resume a paused Codex goal, wake a model
turn, or perform UI work by itself. It is not installed as a login service and does
not survive a reboot automatically. Sleep protection is a separate OS setting.
