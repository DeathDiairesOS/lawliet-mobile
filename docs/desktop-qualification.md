# Desktop forensic workflow qualification

## Claim under test

Given the frozen synthetic Android corpus in
`lawliet_mobile/desktop_assets/android-qualification-v1.json`, the installed shared
desktop must preserve the source bytes, expose the expected native-parser records,
and let an examiner trace a saved finding through report review and local export.
The same expected fields must survive an application restart on each tested host.

The same native test also discovers a synthetic Android transport and executes
SMS, contacts, selected shared files, diagnostics/package inventory and accessible
Trash collection through the actual GUI forms. It automatically parses ten fixed
source observations, searches the acquired message, creates a source-bound finding,
approves and exports its report, and reopens it in a different application process.
Both device-discovery tools are replaced explicitly for this test, so no real
Android or iPhone is contacted.

This qualifies the host software path, not physical USB, Android permissions,
complete device extraction, external parser accuracy or AI reasoning. A synthetic
examiner declaration tests the approval gate, not independent human sign-off.
The established Swift application is separate from this shared-desktop check.

## Result, 20 October 2026

At `59c4f35`, **all three native CI hosts and the aggregate comparison passed** in
[run 39475712473](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39475712473).
Each returned all eleven frozen imported observations and ten acquired observations
with the expected fields. The missing-WAL control returned ten imported records.
All originals and collected source hashes verified. Both reports retained their
exact selected citation and seven-member export package. Findings, approval and
reports survived a fresh native process, without additional collection commands.

| Native execution | Environment | Result |
| --- | --- | --- |
| Windows | Windows Server 2025, Python 3.11, WebView2 | Collection, parsing, review, export and restart passed |
| macOS | macOS 15.7.9 Intel, Python 3.11, Cocoa/WebKit | Same workflow passed |
| Linux | Ubuntu 24.04 x86_64, Python 3.11, Qt/Xvfb | Same workflow passed |

The [machine-readable comparison](desktop-qualification-result.json) retains the
exact source commit, host/dependency versions, original and acquired field
fingerprints, restart assertions and receipt hashes. The acquisition fingerprint
is `c5d8ce901a6e0868e4d67ecac8ac6ea0568d7d3748f1aebb8143afcadc0895e7`.
Generated collection identifiers and host-observation times are deliberately not
compared across independent acquisitions; exact recorded source hashes are checked
within each case and report.

A separate local Apple Silicon run at `9a6c16e` also passed the complete native
workflow and fresh-process restart on macOS 26.7.1/Python 3.13.14. All 115 installed
runtime/assets files matched that commit. It ran from an installed wheel outside
the checkout, using an isolated synthetic workspace. Runtime code is unchanged
between that commit and `59c4f35`; only the CI diagnostic timer changed.

## Test basis

The corpus contains frozen raw bytes and explicit expected source values. SQLite
databases and their WAL companion are supplied together. The oracle is checked
using direct SQLite reads on a disposable copy before application results are
compared. LAWLIET output is not used to generate the expected answers. The corpus
is synthetic and contains no device or customer data.

Nine files (46,028 raw bytes) represent four SMS records, two contact-field
observations for one contact, one call, two installed applications, one device and
one image. One SMS exists only in the WAL; another has an invalid timestamp and
an unknown direction value. The controls include Unicode, literal HTML and
instruction-like content. The missing-WAL variant has ten expected observations,
not eleven. These are source observations, not eleven distinct people or files.

The packaged manifest is approximately 76 KB. No forensic engine, new desktop
framework or runtime dependency was added for this qualification.

The test keeps facts, source uncertainty and interpretation distinct. In
particular, a readable WAL does not establish its acquisition association with
the database: the parser's pairing limitation must remain visible. Unknown
timestamps must not become invented events.

This follows the intended-use and limitation principles in the
[SWGDE tool-testing guidance](https://www.swgde.org/documents/published-complete-listing/18-q-001-minimum-requirements-for-testing-tools-used-in-digital-and-multimedia-forensics/)
and the assertion/test-case structure of the
[NIST mobile forensic tool specification](https://www.nist.gov/system/files/documents/2021/02/24/Mobile%20Device%20Forensic%20Tool%20Test%20Specification%20V%203.1.pdf).
It is not a certification or a claim of exhaustive compliance with those documents.

## Assertions

| Claim | Required observation |
| --- | --- |
| Preserved input | All supplied source hashes match before and after processing, including companions; the source directory gains no SQLite sidecars |
| Correct indexed records | Expected and actual field sets agree, with zero missing, extra or misrepresented records |
| Traceable evidence | Displayed records retain their original values, source file/hash, record identifier and relevant limitations |
| Useful desktop workflow | Native forms create/import, search, timeline, source inspection, finding and report controls execute successfully |
| Honest incomplete results | Missing input produces a visible error; missing-WAL analysis retains its limitation |
| Case isolation | A separate case cannot return the selected case's records or findings |
| Safe content rendering | Instruction-like and HTML-looking evidence remains literal text |
| Examiner release gate | Export is unavailable before review/approval; approved/exported bytes remain bound to the reviewed manifest |
| Durable state | A different application process reopens the case, findings and approved report; exported hashes still agree |
| Host agreement | All three native receipts identify the same source commit, corpus and canonical compared record fields |

The native test substitutes predetermined synthetic paths for the operating
system's file picker. It exercises the application's import/export handlers and
approval controls, but does not qualify OS picker accessibility. Linux uses Qt
under Xvfb, a real native renderer with a virtual display.

Backend checks separately terminate a real analysis subprocess after its first
record insert, inspect its interrupted state in a new process, finish analysis
and rerun it without adding duplicates. They also test malformed SQLite input,
exact JSONL fields, fixed UTC date-range queries and cross-case separation.

Receipt checks deliberately reject an empty export, the wrong selected message
from the same database, incorrect source-preview bytes, changed originals and
mismatched host/commit/record fingerprints. The displayed source-byte check covers
the requested 4,096-byte window; the inventory hashes cover each complete file.

## Reproduce

Install the desktop extra appropriate for the host as described in
[desktop.md](desktop.md). Record the exact Git commit and dependency environment.
Use new, dedicated directories for each run; never point the test at casework.

```sh
python -m unittest tests.test_android_qualification tests.test_desktop_bridge \
  tests.test_case_storage_boundaries tests.test_export_boundaries \
  tests.test_examination_report tests.test_html_pair_integrity -v

lawliet-desktop --workspace /absolute/path/to/new-synthetic-cases \
  --smoke-test /absolute/path/to/new-receipts/result.json \
  --smoke-collection /absolute/path/to/lawliet-mobile/tests/fixtures/collection_adb.py
```

On Windows use native absolute paths and the environment's
`lawliet-desktop.exe`. On a Linux CI host, wrap the native command in `xvfb-run`
and pass `--renderer qt`. Run the installed entry point outside the source
checkout when verifying packaging.

The output retains the main result, a fresh-process result and restart log. Its
sibling fixture directory preserves only the synthetic input, expected-answer
manifest and local synthetic export, allowing inspection after the run. Synthetic
collection uses a real subprocess with fixed responses, not physical USB. No test
calls an external model or sends a customer report.

`.github/workflows/desktop.yml` records the commit, OS, Python, SQLite, renderer
and installed package versions, then compares the native receipts using
`tools/check_desktop_receipts.py`. GitHub retains only synthetic receipt files,
not the case folders. A single green host or a mismatched corpus cannot satisfy
the aggregate check.

## Backend regressions and remaining scope

The broad Windows job at `5e0dc1e` ran 1,407 tests on Python 3.11 and reported
36 failures and 151 errors, including subtest entries. Its workflow was advisory,
so the workflow's green conclusion did not establish a passing Windows suite.
The exact classification is retained in
[windows-review-failure-classification.json](windows-review-failure-classification.json).

After the selected boundary-test corrections, the Python 3.11 broad Windows run
at `f60ee2d` executed 1,426 tests: 29 failures, 132 errors and 360 skips. The 26
selected failure entries were cleared; 161 entries remained at that historical
revision. Its
[completed Windows job](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39436495158/job/118674758127)
remains available for comparison.

At `59c4f35`, all six required broad backend jobs passed in
[run 39475712672](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39475712672).
Each executed 1,458 tests with zero failures or errors:

| Host | Python 3.11 skips | Python 3.14 skips |
| --- | ---: | ---: |
| Windows | 386 | 378 |
| macOS | 261 | 253 |
| Linux | 306 | 306 |

The historical classification is not a current failure count. Windows test
failures now fail CI, just like macOS and Linux; the focused Windows job provides
faster acquisition/integrity feedback. The full discovery includes all focused
tests, so the matrix no longer runs those selected suites a second time.

A subsequent main run at `80fe3c6` exposed an intermittent Windows/Python 3.14
decoder-cleanup failure in
[run 39477556480](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39477556480).
The test retained a handle to the exact synthetic Signal decoder descendant;
that handle was still unsignaled when output inspection began, despite an empty
Job Object accounting count. The assertion prevented import in the test. This
failed run supersedes any claim that the earlier green matrix establishes stable
cleanup on main. The other five broad jobs, the focused Windows job, the native
desktop workflow and Apple Silicon installation passed at this revision.

An earlier fast Windows job at `33c5ba6` exposed a test-fixture reader
thread's code-page decoding exception despite passing assertions. The fixture
now captures `mklink` diagnostic bytes without decoding them. Earlier periodic
`faulthandler` stack dumps were watchdog diagnostics; that timer was subsequently
removed after the native crash described below.

The final focused Windows job at `9a6c16e` executed 128 tests: 125 passed and three
POSIX-only tests skipped, with no exception traces. This includes protected
permissions for new Signal and archive staging folders under a deliberately
permissive test parent, plus refusal paths preserving existing-folder permissions.
The [job log](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39474770942/job/118807768623)
and its SHA-256 are retained in the machine-readable comparison.

A separate full Python 3.11 run at `9a6c16e` exited with a native access violation
while the periodic watchdog was printing a frame at its exact 180-second deadline.
That failed attempt is retained. Its pattern is consistent with
[CPython's asynchronous frame-dump race](https://github.com/python/cpython/issues/116008);
without a native crash dump, the precise cause remains an inference. CI now omits
that periodic timer, retaining fatal-crash diagnostics, all tests, verbose progress
and the 20-minute job timeout.
The full rerun at `59c4f35` completed on both Windows versions without exception
tracebacks or native fatal errors. The tested application code is identical to
`9a6c16e`; the mitigation changes CI diagnostics only.

The fixes preserve UTF-8 source bytes and receipts, pin Windows collection parents,
stage parser inputs with protected permissions, publish archives without replacing
foreign destinations, transport Signal secrets outside argv/environment, and wait
for owned decoder descendants before consuming output. Existing collectors and
parsers are reused; no new runtime dependency was added.

Review-boundary tests must assert the protection actually provided by each host.
Windows retained handles deny certain replacement attempts that POSIX permits
before detecting them. Tests assert those denied attempts, preserved foreign
files and rollback; they do not relax the production evidence protections.

The portable iOS tests execute a synthetic backup subprocess, validate Apple's
hashed backup layout, parse a known Unicode SMS and verify its source hash. They
also cover failed/incomplete backups, timeouts and receipt-publication failures.
They do not qualify physical iPhone USB or the iOS native GUI acquisition path.

Skipped tests include operating-system-specific syscall contracts, absent optional
dependencies and isolated Mulder endpoints. Linux workers are tested on Linux;
their host staging/codec contracts run on Windows too. Passing those contracts
does not qualify a live Windows Docker deployment or an upstream Signal decoder.
The restricted Mulder collection endpoint remains macOS-only. No physical device,
paid model provider, complete extraction or universal tool coverage is claimed.
