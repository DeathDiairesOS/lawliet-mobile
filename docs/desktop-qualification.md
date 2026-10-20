# Desktop forensic workflow qualification

## Claim under test

Given the frozen synthetic Android corpus in
`lawliet_mobile/desktop_assets/android-qualification-v1.json`, the installed shared
desktop must preserve the source bytes, expose the expected native-parser records,
and let an examiner trace a saved finding through report review and local export.
The same expected fields must survive an application restart on each tested host.

This is a bounded existing-evidence workflow. It does not qualify physical phone
acquisition, every Android schema, recovered/deleted records, external parsers,
AI reasoning, or every desktop configuration. A synthetic examiner declaration
tests the software approval gate; it is not independent human examiner sign-off.
The established Swift application is separate from this shared-desktop check.

## Result, 20 October 2026

The installed shared application at `53dc5bc` passed on **macOS, Windows and
Linux**, using the same frozen evidence and independently specified expected
fields. Each returned all eleven expected observations, zero missing/extra/
duplicate records and zero field mismatches. The withheld-WAL control returned
the expected ten. Original hashes, the selected finding's exact source citation,
the complete seven-member report package and persistence through a new native
process all passed.

The [machine-readable comparison](desktop-qualification-result.json) retains
platforms, dependency versions, receipt hashes, exact counts and verification
results. It compares the actual returned records against the repository oracle,
not just each runner's success flag.

| Execution | Environment | Result |
| --- | --- | --- |
| Local installed native window | macOS 26.7.1 arm64, Python 3.13.14, SQLite 3.54.0, system WebKit | Passed; all 111 installed runtime/assets files matched the tested commit |
| Hosted installed native window | Windows Server 2025, Python 3.11.9, SQLite 3.45.1, WebView2 | Passed; 115 selected tests, one skip |
| Hosted installed native window | Ubuntu 24.04 x86_64, Python 3.11.17, SQLite 3.45.1, Qt/Xvfb | Passed; 115 selected tests, four skips |

The same 115 selected backend/controller checks also passed locally on macOS
with Python 3.14.5 (four platform-specific skips). The native macOS window used
the separately verified Python 3.13 environment listed above.

The hosted results are in
[run 39437995604](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39437995604).
Hosted macOS and the CI aggregate were still queued without an assigned runner
at publication. The local macOS result is not a claim that those CI jobs passed.
The macOS CI baseline is explicitly `macos-15`, matching the separate
[successful fresh-install check](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39436495017).

A separate manual macOS pass used the real native folder picker, imported the
corpus, searched the WAL-only message and opened its retained source bytes.
Read-only checks of that persisted case independently matched all eleven
observations and all nine file hashes. This supplements the scripted path
selection described below; Windows and Linux native picker accessibility remain
outside the automated test.

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
  --smoke-test /absolute/path/to/new-receipts/result.json
```

On Windows use native absolute paths and the environment's
`lawliet-desktop.exe`. On a Linux CI host, wrap the native command in `xvfb-run`
and pass `--renderer qt`. Run the installed entry point outside the source
checkout when verifying packaging.

The output retains the main result, a fresh-process result and restart log. Its
sibling fixture directory preserves only the synthetic input, expected-answer
manifest and local synthetic export, allowing inspection after the run. No test
acquires a phone, calls an external model or sends a customer report.

`.github/workflows/desktop.yml` records the commit, OS, Python, SQLite, renderer
and installed package versions, then compares the native receipts using
`tools/check_desktop_receipts.py`. GitHub retains only synthetic receipt files,
not the case folders. A single green host or a mismatched corpus cannot satisfy
the aggregate check.

## Windows baseline and remaining scope

The broad Windows job at `5e0dc1e` ran 1,407 tests on Python 3.11 and reported
36 failures and 151 errors, including subtest entries. Its workflow was advisory,
so the workflow's green conclusion did not establish a passing Windows suite.
The exact classification is retained in
[windows-review-failure-classification.json](windows-review-failure-classification.json).

After the selected boundary-test corrections, the Python 3.11 broad Windows run
at `f60ee2d` executed 1,426 tests: 29 failures, 132 errors and 360 skips. The 26
selected failure entries are cleared; the remaining 161 entries require separate
work. This broad suite is not passing. Its
[completed Windows job](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39436495158/job/118674758127)
remains available independently of the scoped native workflow.

Review-boundary tests must assert the protection actually provided by each host.
Windows retained handles deny certain replacement attempts that POSIX permits
before detecting them. Tests assert those denied attempts, preserved foreign
files and rollback; they do not relax the production evidence protections.

Collection, optional container and other unsupported Windows paths retain their
visible broad-suite failures. The required desktop qualification job is separate
and must pass. Neither a scoped desktop pass nor corrected test fixtures establish
general Windows backend or device-acquisition support.
