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

## Test basis

The corpus contains frozen raw bytes and explicit expected source values. SQLite
databases and their WAL companion are supplied together. The oracle is checked
using direct SQLite reads on a disposable copy before application results are
compared. LAWLIET output is not used to generate the expected answers. The corpus
is synthetic and contains no device or customer data.

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

Review-boundary tests must assert the protection actually provided by each host.
Windows retained handles deny certain replacement attempts that POSIX permits
before detecting them. Tests assert those denied attempts, preserved foreign
files and rollback; they do not relax the production evidence protections.

Collection, optional container and other unsupported Windows paths retain their
visible broad-suite failures. The required desktop qualification job is separate
and must pass. Neither a scoped desktop pass nor corrected test fixtures establish
general Windows backend or device-acquisition support.
