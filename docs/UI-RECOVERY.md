# Native UI recovery — 2026-10-11

The native SwiftUI/AppKit source is restored in `desktop/` on the internal disk.
This is a reconciled, tested reconstruction, not a claim of byte-for-byte identity
with the failed-drive workspace. The backend remains owned by the other session.

Saved literal source, exact patches, and a restricted interpreter of string edits
recovered 105 UI edit operations. No historical shell commands, imports, parser
invocations or acquisition commands were executed. Unsupported operations were
recorded rather than guessed. Missing search-context components were rebuilt from
this session's behavioral handoff. Existing logo assets were copied from the
installed application. The replay helper and detailed reconstruction diagnostics
are retained under `build/`; the resulting source is in the repository.

## Build and run

```sh
python3 desktop/build.py --bundle-id com.lawliet.mobile.recovery
```

The candidate is `dist/Lawliet Mobile.app`. Its separate bundle identifier isolates
its preferences from the installed application. This session has not replaced
`~/Applications/Lawliet Mobile.app`. The default workspace is the sibling
`lawliet-cases` directory; `--workspace` and `--output` can override defaults.
The build bundles Python source and records the selected Python interpreter path;
it does not bundle a Python runtime or optional forensic tools.

## Restored behavior

- Case queue, metadata editing, follow-up tasks, activity and workspace errors.
- Compact native navigation, retained report tables, artifact inspector, source
  references, original fields, media review and saved findings.
- Applied search chips and a pending-search notice; exports and pagination cannot
  silently use criteria different from the displayed results.
- Source-wide search preserves the query and removes category/report/app/date
  restrictions. Timeline presets remain in the restored source.
- UTC display preserves fractional seconds; original timestamp strings remain
  available. Naive timestamps are not labeled UTC.
- Retained parser results open without another import or parser execution.
- Mulder output import is initially selected; autonomous `mulder investigate`
  remains separate from Codex/MCP. Existing authorization/version gates remain.
- **Open existing case…** opens a folder containing `case.sqlite`. This is useful
  for Mulder's nested `lawliet-review` output cases. It changes the selected
  workspace to the case's parent; it does not consolidate cases, copy evidence or
  rerun tools. The queue still lists direct children of its selected workspace.
- A failed case inventory clears the previous case's displayed artifacts,
  counts, previews and case controls before showing recovery actions.

## Validation

Seven native Foundation/transport tests passed: submitted query identity, filter
disclosure, timestamp precision, process backpressure, bounded diagnostics,
nonzero/structured errors and listing timeout. Eleven desktop backend and case
management tests passed separately. The full concurrently changing backend suite
was not rerun by this session.

Native compilation and code-signature verification passed. The candidate opened
the retained synthetic `large-leapp` case with 50,001 indexed rows; displayed 100
rows per page; searched `LARGE_ROW_00101` beyond that first page; showed the
original report record reference; blocked export/Next during pending edits;
retained date chips with Filters collapsed; and restored a match through Search
entire source. A nonexistent search returned zero rows, not a claim that evidence
was absent from the phone. The launch panel showed both disclosure gates off and
Start disabled. Restart restored the local workspace/case selection.

The failure-path fixture is a deliberately invalid database under
`build/ui-error-fixture`, outside real case storage. It exercises the persistent
workspace error view and the removal of stale case state. No new case acquisition,
parser execution, evidence import, finding approval or model call was performed.

## Remaining work

The coverage-ledger viewer, explicit WhatsApp century input and source-linked draft
preparation were added in the follow-ups below. Customer release remains pending.
A successful parser/hash check must never become examiner verification.

The explicit `year_century` backend option now has a deliberate WhatsApp
import control. New report-release controls, the device-state worksheet, GUI
coverage of every import/acquisition workflow, and multi-workspace case cataloging
remain pending. Existing runtime candidate versions must not bypass the legacy
Mulder output import's supported-schema gate. Historical UI checks do not qualify
the newly reconstructed source; only checks recorded above were repeated here.


## Coverage and date interpretation — 2026-10-12

**Coverage & review** is available from the sidebar and case overview. Its six
compact summaries keep collection, decryption, parsing, review, examiner
verification and search observations independent. Counts apply to the whole case;
axis/state/evidence filters select a separate, paginated table of at most 100
observations. The details panel shows reason, source, original fields, supporting
reference, origin, actor and unknown dimensions without converting an operator
assertion into authenticated signoff. Empty filtered results retain case totals
and disclose their limited meaning. The view reads data only; it does not record
review, approve findings or release reports.

The backend session supplied the paginated `coverage-ledger` interface. The GUI
validates schema, page position, filter identity, count consistency and pagination
before showing results. An unsupported/unbounded response or failed request shows
Coverage unavailable, not a fake empty ledger. Case/workspace identity guards
prevent delayed responses from another case replacing the displayed results.

WhatsApp intake now has an optional **Declared year century** field. Blank remains
unspecified; a valid entry is explicitly forwarded as an integer to the existing
parser. Invalid values are shown inline and block Import. Selecting a different
file or case clears this new field. Timezone is still separately supplied; missing
century/timezone are never guessed.

Three focused native model tests passed against a saved output from a temporary
synthetic backend case: independent axes/pagination, rejected malformed/stale
responses, and explicit century validation. The candidate compiled and its native
view showed the existing 50,001-row source as one collection and one parsing
observation with zero recorded review/verification. These counts describe
observations, not message totals or acquisition completeness.

An isolated synthetic case under `build/ui-coverage-workspace` exercised 105
observations: first 100, then five, with whole-case counts unchanged. Parser-failed
and attributed review observations remained visible; verification stayed zero.
Native filters correctly produced zero matches while retaining whole-case totals.

Actual GUI WhatsApp import used an authored test export in that isolated case,
explicit century 2000 and timezone UTC. The retained record has
`2026-10-10T14:00:00.000000Z`, parser `whatsapp-export/2`, source `lines=1-1`,
original date text and the supplied interpretation fields. Invalid 2026 disabled
Import before processing. No customer case was approved, released or modified by
these tests. The installed application remains untouched; this is the local
candidate build.

## Focus and efficiency — 2026-10-12

The shared active workflow is now the completed Android13 retained native case:
`DFIR-46-HICKMAN-A13-RECOVERED-20261011/04-mulder-runs/1791762470/lawliet-review/NATIVE-tc-40d3b6ec`.
The existing task dashboard is `docs/task-progress.json`; the current work/ownership
and ordered workflow gates are in `sessions.ui.shared_focus_request` in the shared
handoff. Additional UI forms wait until this case's examiner workflow is complete.
The backend session acknowledged this focus after its active batch reached a checkpoint.

Native build caching hashes Swift sources, compiler/SDK identity, build arguments
and the resulting executable. Missing/modified binaries, changed source content,
flags or tool identity trigger recompilation. Backend source is freshly packaged
and the signature verified on every build. Use `--rebuild` for a forced native
compile. The measured first build took 16.209 seconds; the unchanged native rebuild
took 0.272 seconds. Both measurements are local observations, not universal timing.
Four cache checks and seven watcher checks passed. Brief handoff checks now show
current ownership, changed fields and one suite summary; full snapshots stay on
disk and are reviewed when relevant changes arrive.

The existing Android case was opened in the GUI without reacquisition or parsing.
Its retained index contains 87 message rows, 113 contact rows and 242 browser rows;
the earlier backend material comparison scored 75 Chrome visits, not every browser
record. Literal message search returned seven matching rows with an SMS record
reference. The seven-day source-anchored timeline showed 90 matching dated rows and
disclosed exclusion of undated data. Ten existing source-linked technical findings
opened through Saved findings.

The existing **Readable text report** export produced an internal summary under
`build/android13-internal-findings.txt`, with ten saved snapshots/interpretations,
a SHA-256 receipt and a coverage companion. Both receipt hashes were verified.
This reused the current export function rather than introducing another reporting
framework. It is an unapproved technical review artifact: source bytes were not
reverified during export, and no independent signoff or customer release occurred.
No extra test findings were inserted into the acquired lab case.

At this earlier checkpoint, the remaining focused gaps were finding creation/reopen rehearsal in a
synthetic case, a source-linked customer draft/review interface using the stable
backend contract, and independent examiner acceptance. The acquired case currently
has saved findings but no investigation-ledger ID for `customer-report-draft`;
that adapter gap is recorded for backend coordination. Technical export success
does not close those gates.

### Native draft review contribution

The native sidebar now opens **Draft report review** for an existing Lawliet
`ancalor-customer-bundle-v1` folder. The read-only viewer checks the supported
manifest/annex formats, case association, listed-file byte counts and SHA-256
hashes before rendering observations, interpretations, tasks, hypotheses and
questions with their indexed source snapshots. Original record locators, source
hashes, raw timestamps, source tiers, missing parser-run links and attachment
states remain visible. Search is literal; entries render in pages of 50. Reports
render as native plain text without fetching URLs or attachments.

These checks establish local bundle consistency only. They do not authenticate
the manifest, verify the case audit or current retained source bytes, approve
findings, redact evidence or release a report. Select the canonical local folder;
symlinked report paths/files are refused. Limits are 32 MiB per bundle file,
64 MiB total, 10,000 entries/citations and 1 MiB for readable text preview. Large
or unsupported output produces an explicit error rather than silent truncation.

Validation: 16 focused native-model/build/context/coverage checks passed, including
eight draft-reader cases using actual backend-generated synthetic output. Native
walkthrough opened case A, displayed three entries and one cited snapshot, checked
`selected.txt` / `line=1`, unknown raw time, missing attachments, query filtering
and readable report. No acquired-case approval, release or new processing ran.
At that checkpoint the canonical Android13 case still needed an investigation
ledger binding; the next update supersedes that gap. Logs:
`build/draft-review-tests.log`, `build/draft-review-build.log`;
synthetic rehearsal paths: `build/draft-review-synthetic.json`.

### Case-manager and examiner workflow audit

The backend session supplied `investigation-from-findings` and a stable Android013
draft fixture. The GUI now selects exact saved findings and an explicit objective,
uses that binding plus `customer-report-draft`, and opens the result for review.
The synthetic finding-to-draft flow actually ran in the native application. The
retained Android draft opened read-only with ten entries and ten source snapshots;
all seventeen evidence files and case.sqlite remained unchanged in before/after
SHA-256 comparisons. Draft preparation is not an agent run, approval or release.

Case-wide queries, native conversation selection, visible scope/sort, hideable
navigation, source filename/hash fields and honest empty agent states now support
the compact examiner workflow. Thirty focused regression tests passed, and native
compilation/signature verification passed. The research, actual click-through
matrix, exact limits and ordered follow-ups are in [UI-UX-AUDIT.md](UI-UX-AUDIT.md).
That document is the current validation account; older sections above describe
earlier checkpoints rather than current feature gaps.

### Installed launch location corrected

After the user reported an easystore workspace error, the older installed app at
`~/Applications/Lawliet Mobile.app` was updated from the tested candidate. Its
production bundle identifier remains `com.lawliet.mobile`; the default workspace
now uses internal storage. The original bundle is preserved at
`build/installed-before-local-workspace.app.backup`. Native payload equality was
checked on temporary copies with signatures removed; the actual installed bundle
remains signed and its signature passed verification. No active backend source was
repackaged for this update.

The recovered cases are nested analysis outputs, so the top-level case directory
does not itself list their databases. **Open existing case…** selected the retained
Android013 case directly. Restart restored its local parent workspace and selected
case, with 87 messages, 113 contacts and 242 browser records. All seventeen evidence
files and case.sqlite remained unchanged. Installation/restart receipt:
`build/local-installed-app-update.json`. Earlier statements that the installed app
was untouched refer to the preceding audit checkpoints.

### Unified case catalog and draft history

The installed launch correction is extended by the UI-owned catalog/history slice.
The queue discovers nested case databases without moving evidence, uses path-qualified
case identity and keeps folder references independent of the new-case destination.
Draft history reopens existing bundles in the native source-linked reader. Design,
limits and validation are documented in [CASE-CATALOG.md](CASE-CATALOG.md).
