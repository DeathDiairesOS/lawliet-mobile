# Lawliet Mobile

**Local mobile evidence triage. Desktop review and CLI. Android and iOS.**

The core CLI uses the Python standard library. No daemon, database server, container
or cloud service is required. The backend uses Python 3.11+. The optional shared
desktop GUI uses pywebview and the platform web renderer; it opens an application
window, with no browser or local HTTP server. Windows also requires IANA timezone
data. Optional forensic tools extend collection and parsing.

The established native Swift app and setup script remain macOS-only. A shared
Windows/macOS/Linux desktop is now available for testing; see
[desktop installation and capability boundaries](docs/desktop.md). Windows
backend qualification is still in progress, and Windows CLI CI remains advisory.
Do not interpret a successful workflow badge as complete Windows qualification.

This is an initial working release with a limited native support matrix. Physical
collection validation is method-specific; successful collection does not establish
device-wide completeness or independent field fidelity.

## Apple Silicon setup

Use an Apple Silicon Mac running macOS 13 or newer. First install Apple's
command-line developer tools (`xcode-select --install`) and [Homebrew](https://brew.sh).
Clone the source, then:

```sh
git clone https://github.com/DeathDiairesOS/lawliet-mobile.git
cd lawliet-mobile
./setup.sh --plan
./setup.sh
open "$HOME/Applications/LAWLIET.app"
```

Setup installs missing Homebrew prerequisites, creates separate Python 3.13
environments for LAWLIET, ALEAPP, iLEAPP, MVT and patched Mulder, configures tool
paths, builds the desktop app, and runs native/LEAPP synthetic record checks.
It also initializes the Mulder MCP protocol and checks its mobile tool listing.
No model requests or phone actions occur during setup. For native review alone,
use `./setup.sh --profile core`. `--no-app` installs only the CLI/tool environments.

Runtime files default to `~/Library/Application Support/LAWLIET/runtime`, cases to
`~/Documents/LAWLIET/cases`, and the app to `~/Applications/LAWLIET.app`. These
locations are independent of the clone. `--runtime`, `--workspace` and `--app`
override them. Keep the Python/runtime directories available after setup; do not
select a real evidence directory as the runtime location.

Restricted endpoint helper scripts under `tools/` use the same runtime default.
For a custom installation, pass `--runtime` or set `LAWLIET_RUNTIME`. They validate
the setup-generated `bin/mulder` launcher; an explicitly present development
candidate retains precedence and must pass validation.

Use `./setup.sh --verify` to check an existing install without downloading tools.
The runtime contains `installation.json`, `verification.json` and `codex-mcp.toml`.
Merge the generated MCP snippet into your local Codex configuration, preserving
existing settings. Sign into Codex separately. Setup never writes credentials or
replaces Codex configuration. Use `runtime/bin/lawliet` for the installed CLI with
`--workspace` pointing to the configured cases location.

`setup/mobile-macos-arm64.json` pins upstream source commits, patch integrity and
Python dependency versions. Homebrew packages are rolling releases; actual versions
are recorded. Python distribution artifacts are not yet locked by individual hashes.
Failed downloads, dependency conflicts and failed checks stop setup with a nonzero
exit. Reruns reuse pinned source and existing packages. Modified managed sources
are rejected instead of reset. Choose a new runtime directory to test an upgrade
independently. Cases are not deleted by setup.

This mobile profile does not install the broader SIFT/Linux toolchain or Mulder's
rule/symbol collections. Optional MCP operations may remain unavailable. Synthetic
checks do not validate USB permissions, phone authorization, model login or parser
accuracy on customer extractions. Test those routes separately before customer use.
Experimental parser changes outside this repository are not included in the pinned
upstream checkouts.

## Recovered development workspace

The October 2026 recovery restores backend source and validation tooling from the
committed baseline, installed application, and reviewed session material. It is
not asserted byte-identical to the lost workspace. Machine-specific recovery
receipts and live coordination records are retained locally and excluded from
the publishing set. Synthetic tests do not replace independent examiner review.

Current validation uses **Codex driving the Mulder MCP server over stdio**.
The downstream `1.5.2+lawliet.1` patch is retained in
`integrations/mulder/lawliet.patch`. This workflow invokes forensic tools directly;
it does not run Mulder's separate `investigate` model orchestrator. The legacy
application engine-launch adapter and its baseline output-import version gate do
not automatically accept the development candidate.

### Investigation pipeline and repository layout

The intended investigation route is:

`Case brief -> preserved evidence -> Codex agent -> Mulder MCP tools -> retained outputs and indexed artifacts -> examiner review -> customer draft`

Codex is the agent runtime, using the selected model for reasoning. Mulder's MCP
server exposes forensic tools; the separate `mulder investigate` orchestrator is
not automatically used by this route. The desktop currently reviews retained
cases and includes a legacy engine-launch adapter. An in-app Codex investigation
launcher is proposed integration work, not an implemented capability.

The native **Agent investigation** screen defaults to **Collect with agent**.
Enter an objective, exact Android serial, examiner and selected methods, then
authorize the saved plan. Copy its prepared request to a Codex chat connected to
the dedicated collection endpoint. The screen monitors durable collection state;
successful outputs are preserved, parsed and shown in the existing case views
without a second import. **Codex + Mulder** remains available for retained-evidence
investigation. Preparing or copying either request does not launch a chat or grant
permission to send evidence to a remote provider. The upstream `investigate`
launcher and output importer remain explicitly labeled legacy/separate routes.

### Agent collection: one scoped workflow

`Examiner-approved plan -> Codex -> Mulder collection tools -> existing LAWLIET collectors -> preserved evidence -> existing parsers/index -> LAWLIET review`

This route exposes exactly three MCP tools: `get_lawliet_collection`,
`run_lawliet_collection` and `query_lawliet_collection`. They accept a saved plan
ID, with bounded search parameters for queries. The model cannot authorize a new
plan, select another case or device, or pass arbitrary shell commands. The
standard Mulder analysis profile does not expose these collection tools.

Supported methods reuse the existing collectors: SMS provider reads, contacts
provider reads, explicit shared-storage file copies, diagnostic triage, accessible
Samsung Trash photos, and separately selected legacy telephony backup. Triage
collects device properties, package inventory, the available logcat buffer and a
bug report; it never invokes a backup. The legacy backup option may require a
device prompt and may be unsupported. Existing Android permissions still apply;
these methods do not provide full-filesystem access or unlock private application
storage. Existing-root private-app collection remains a separate advanced workflow.

Shared-folder buttons select DCIM, Pictures, Download, Documents, Movies or Music;
the exact paths are shown before authorization. Custom paths remain bounded and
explicit. The desktop defaults to a 1 GiB per-profile storage threshold and 180
seconds per command, with choices up to 20 GiB and 900 seconds. Provider outputs
remain capped at 64 MiB. CLI/API defaults and older saved plans retain their
original limits. Polling storage guards can overshoot; these are stop thresholds,
not hard quotas or measured capacity guarantees.

Provider SMS is indexed directly; other acquired evidence uses the existing native
parser. Results distinguish indexed records, acquired payload files and retained
files including logs. A bounded coverage summary links to the preserved collection
manifest. Logcat, package and device records are normalized; bugreport ZIP contents
remain preserved raw and are not comprehensively parsed by this workflow. Access
denials, unsupported backups, missing diagnostics and parser failures remain visible.

Configure an **already installed, qualified** Mulder launcher once:

```sh
python3 -m lawliet_mobile --workspace /path/to/cases agent-collection configure \
  --mulder-launcher /path/to/mulder-launcher
```

The GUI's **Connection setup and prepared request** section supplies the exact
case-bound MCP configuration. The endpoint is initially macOS-only, uses the
reviewed source contract and permits local ADB traffic only. A trusted local ADB
server must already be available; the endpoint does not start a privileged
service or download dependencies. Do not connect a broad, differently bound MCP
server as a substitute. Use `agent-collection --help` for CLI authorization,
status and deterministic execution of an already authorized plan.

Plans survive process restarts. Repeating a completed plan returns its retained
results without recollecting. An abandoned active collection is marked interrupted
and requires examination before a new plan; automatic continuation of an
interrupted collection and in-app agent launch/cancellation are not implemented.
The agent can search only that plan's evidence with pagination and inspect source
record IDs, files, hashes and processing runs. Ordinary case views retain earlier
acquisitions too. Collection logs, Mulder audit records and failed attempts remain
available in the case. Evidence text is data, never agent instructions.

Validation includes real Mulder stdio calls to an actual synthetic ADB subprocess,
automatic SMS/contact/media parsing, follow-up queries, source-hash checks,
denial handling, restart/replay checks and native GUI inspection. It requires no
phone or paid model; it does not qualify a physical device or model's reasoning.
Set `LAWLIET_WORKFLOW_LAUNCHER` to the reviewed launcher when running
`tests/test_agent_collection_e2e.py` through unittest, or use its `--output` and
`--launcher` arguments to retain a synthetic case for GUI inspection.

On 17 October 2026, the complete route was also exercised against an authorized
Samsung SM-A176U running Android 16. It retained two SMS records, six contacts and
two small shared files. All 98 preserved evidence files passed integrity checks;
49 independent consistency checks matched the parsed fields to retained provider
responses and source files. The shared-files profile also indexed 448 application
inventory entries and one device record; these are not 449 acquired user files,
and no media was found in the selected folder. The installed native application
displayed the results and provenance, and its packaged endpoint reused the
completed plan after restart without recollection. This qualifies that bounded
workflow on the observed configuration, not complete phone coverage or field
accuracy against independently prepared device seeds. Local validation receipts
and acquired content remain outside the publishing set.

A subsequent broader run on the same Samsung completed diagnostics, SMS,
contacts, six explicit shared folders and accessible Samsung Trash. It preserved
a valid bugreport ZIP, indexed 245,460 log observations, retained seven shared
files (21,902,020 bytes) and one Trash photo (3,958,335 bytes), and returned two SMS
records and six contacts. The two inventory collections represent 448 distinct
application IDs, not 896 different applications. All 160 retained evidence files
passed integrity checks. Independent read-only checks matched every indexed log
timestamp and source line, the Trash acquisition hashes and the approved command
scope. These observations qualify the selected methods on this configuration;
they do not establish acquisition completeness, historical log coverage, private
chat access, or general recovery of deleted data. Legacy backup was tested with
synthetic supported/failed inputs rather than requested on this Android 16 phone.

Generated collection connection settings allow 60 seconds for startup and 7,200
seconds per MCP call so broader multi-profile collections have time to finish.
The saved plan's narrower per-command limits still apply; the MCP timeout is not
a total acquisition guarantee. Configuring a server does not restart an
already-connected Codex session.

Useful existing MCP pivots include `query_ancalor_review`, `list_ancalor_files`,
source/media/SQLite inspection, and `import_ancalor_leapp_review` for retained
LEAPP reports without rerunning the parser. Before reporting, use available
source statistics and evidence/tool coverage audits to identify unexamined inputs;
a suggested tool is not necessarily installed or relevant. The patched server
pins the active case during registered tool work, refuses case changes while
jobs are unfinished, and restricts completed job retrieval to its owning case.
Generic evidence readers accept the selected evidence root and proven case-owned
outputs, not the shared case directory. Unclaimed legacy output requires explicit
reimport. The retained LEAPP importer and native, chat and export review routes
also check the active case's authorized input roots before importing. These are
application checks, not an operating-system filesystem sandbox;
some upstream adapter-specific paths still require separate scope qualification.
Use one server per case for examination.

Generic timestamp indexing now preserves original values, timezone offsets and
microsecond precision. Only explicit, unambiguous offsets qualify as UTC anchors;
unknown zones, date-only values and differing times in one window remain undated.
Old index hints remain preserved and searchable but excluded from UTC filtering
until the explicit, audited `reindex_timestamps` operation processes retained text
in batches of at most 1,000 windows. This does not rerun parsers or recover omitted
timestamps. Timeline results are paginated window anchors, not individual events;
use LAWLIET's normalized artifact timeline for record-level examination. Separate
pages can shift while indexing continues. Mulder's MCP `check_finalize_readiness` and `finalize_report` now accept an
explicit `examination` payload for `no_matches` or `inconclusive` outcomes. This
scoped zero-finding route requires audited, source-scoped searches, fresh index
rechecks, a narrative and coverage audits. It refuses existing positive or invalid
findings; the normal positive-report gates stay intact. Generated Markdown, HTML
and JSON provenance remain unreviewed. The separate autonomous `investigate`
workflow retains its upstream finding gates and is not qualified for negative cases.

In the native app, **Report history → Scoped examination** records a no-match or
inconclusive examination without creating a saved finding. Select evidence, state
the scope and limitations, and enter literal searches of indexed titles/bodies.
A no-match outcome requires indexed records and actual zero-result searches.
Inconclusive reports may record unavailable/unparsed evidence without searching.
Source bytes, scoped index and processing state are bound to the report; changes
require a new examination. Examine the query receipts and limitations in Report
review, then use the existing separate examiner approval and local export controls.
This native flow and the Mulder report route retain their own provenance; no
automatic import of the new Mulder outcome sidecar is claimed. Neither route
establishes that a device is free of compromise. Failed native preparation rolls
back; failed-attempt history is not yet durably recorded.

Setup verification checks the imported Mulder checkout, exact saved patch and
required MCP schemas, rather than accepting its version banner alone. It also
checks all seven restricted profiles for their exact tool surfaces. Qualification
requires a managed Git checkout with the patch staged, matching working source
bytes, and no assume-unchanged or skip-worktree source flags; setup creates this
layout with `git apply --index`. For a supported
local launcher, run `python3 tools/verify_mcp.py /path/to/mulder-launcher` to create
a read-only qualification result on standard output. This starts isolated
temporary MCP sessions without calling forensic tools, devices or models.
Existing connected servers keep their loaded code until restarted. Source
fingerprinting does not attest to the entire dependency environment or replace
forensic method validation.

Each finding must retain references to supporting records, tool runs and source
files where available. Parser output, model interpretation and examiner review
remain separate. Collection, parsing, search and review coverage are recorded
independently. A successful tool call is not a verified forensic conclusion.

| Directory | Versioned purpose |
|---|---|
| `lawliet_mobile/` | Evidence backend, native parsers, adapters, provenance and report preparation |
| `desktop/` | Native macOS UI, assets and build script |
| `integrations/` | Downstream patches and portable integration configuration examples |
| `tests/` | Synthetic fixtures, regression checks and optional runtime integration tests |
| `docs/` | Portable contracts, usage guides and documented limitations |
| `tools/` | Development, recovery and repository-preparation utilities |

Evidence, case databases, forensic runtime installations, generated applications,
logs, credentials and machine-specific coordination receipts stay outside the
publishing set. The existing runtime/case directories are not relocated by
repository preparation.

Before staging a commit, run `python3 tools/repository_preflight.py` to inspect
the tracked/non-ignored publishing set for generated paths, local paths, large
files, credential-shaped content and tracked whitespace errors. It does not
stage, delete or upload files and is not an exhaustive secret audit.

Run baseline checks with `python3 -m unittest discover -s tests`. Tests requiring
the patched external Mulder runtime skip when it is absent. Installing that
runtime enables those checks; skipped checks are not validation passes.

Native Python parsing requires no third-party package. Mulder, ALEAPP, iLEAPP,
MVT and YARA have separate runtime dependencies and licenses. An advertised MCP
tool is not evidence that its binary, assets or workflow have been validated.
Synthetic checks and developer comparisons are not independent examiner signoff.

For a local source/validation snapshot with a verified restore:

```sh
python3 tools/create_recovery_snapshot.py \
  --workspace /path/to/lawliet-mobile \
  --validation /path/to/lawliet-validation \
  --destination /path/to/snapshots
```

The snapshot receipt describes its exclusions. A snapshot on the same disk does
not provide protection against loss of that disk; keep an approved separate copy.

## Fresh-machine acceptance

A fresh clone is the acceptance target. Use Python 3.11+ for the backend. Building
the native macOS desktop also requires Apple's command-line developer tools
(`xcode-select --install`) and a Swift compiler. The native desktop is macOS-only;
the backend CLI has separate platform coverage.

1. Clone this repository and record the Git commit being tested.
2. Run `python3 tools/repository_preflight.py` and
   `python3 -m unittest discover -s tests`. Record failures and skips separately.
3. Run `python3 -m lawliet_mobile demo --workspace /path/to/test-cases --json`, then
   `python3 -m lawliet_mobile verify --case demo --workspace /path/to/test-cases --json`.
4. Build with `python3 desktop/build.py --workspace /path/to/cases --output "/path/to/LAWLIET.app"`.
   Keep the selected Python interpreter available: the app records its path.
5. Install/configure the tools required by the accepted workflow. Run
   `python3 -m lawliet_mobile doctor --workspace /path/to/cases --json`. Presence
   checks do not establish compatibility or successful parsing.
6. Test Android USB discovery, authorization, view-only mirroring, explicit
   control, disconnect and in-app audit review against a test phone. ADB/scrcpy
   need their own installed executables; use explicit workspace tool paths when
   Finder's PATH differs from Terminal's. Test iPhone routes separately and grant
   only the macOS permissions requested by that workflow.
7. Test one representative extraction per supported platform through the actual
   selected parser and Mulder MCP route. Reconcile source/parsed counts, field
   values, timestamps and hashes; inspect failed/skipped modules and duplicates.
8. Exercise search, date filters, original evidence inspection, saved findings,
   report review/redaction and exports. Confirm that unsupported inputs and
   incomplete runs retain explicit limitations instead of producing success.

For manual setup instead of the installer, the patched Mulder integration uses revision
`5321847887fe1fcb5399cec0a1703db9c513bac8` and the patch at
`integrations/mulder/lawliet.patch`. In a separate upstream checkout, run
`git checkout --detach 5321847887fe1fcb5399cec0a1703db9c513bac8`, then
`git apply --check /path/to/lawliet-mobile/integrations/mulder/lawliet.patch` and
`git apply /path/to/lawliet-mobile/integrations/mulder/lawliet.patch`.
Install that patched checkout and Lawliet into the same forensic virtual
environment. Confirm `mulder --version` reports `1.5.2+lawliet.1` before enabling
`integrations/mulder/codex-config.example.toml` with the actual executable path.
Tool assets and external parser dependencies require separate upstream setup.
An advertised MCP operation is not a validated or installed capability.

The current desktop's legacy engine-launch adapter is gated for baseline 1.5.2;
it must not be used as a substitute for the patched Codex/MCP workflow. Codex's
MCP configuration is separate from Lawliet's desktop preferences. A future in-app
Codex job runner needs its own implementation and acceptance checks.

A passing baseline test suite with skipped optional checks is not a guarantee
that the full forensic workflow works on a particular machine. Acceptance should
record the app/source commit, Python/model versions, Mulder patch, parser/rule
versions, device/OS versions, test results and unresolved limitations.

## Try it in a minute

```bash
git clone https://github.com/DeathDiairesOS/lawliet-mobile.git
cd lawliet-mobile
python3 -m lawliet_mobile demo
python3 -m lawliet_mobile timeline --case demo
python3 -m lawliet_mobile search parcel-review.example --case demo
python3 -m lawliet_mobile correlate --case demo
python3 -m lawliet_mobile verify --case demo
```

Open `lawliet-cases/demo/reports/investigation.html` in a browser. The report has
local search, category filters, expandable original fields, source references,
hashes, analysis coverage, and print styles. It makes no network requests.

The demo creates **15 fictional artifacts across an iPhone backup and an Android
filesystem extraction**. Reserved `.example` domains and 555 numbers are test data.
It does not connect to a phone or download anything. Use `demo --case demo2` for
another fresh run; existing cases are never replaced.

On macOS/Linux you can also run `./lawliet`. Optional installation:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/lawliet-mobile --help
```

Installation uses setuptools as a build dependency. Direct module/script use
requires no installation and no external packages. Windows: use `py -m
lawliet_mobile` and `.venv\Scripts\python.exe` as appropriate.

## A real investigation

### Reviewing app evidence

The native **Import** menu accepts WhatsApp text/ZIP/folder exports, Discord
account data packages (JSON or legacy CSV), and candidate legacy Android Signal
backups. Supplied decoded databases/extractions use **Acquired evidence · import
& analyze**. These routes populate the existing searchable artifacts, conversations
and timeline; they do not obtain private messages merely because an app is installed.

```sh
./lawliet import-chat /path/to/chat.zip --case CASE-001 --date-order dmy --timezone America/New_York --reuse
./lawliet import-discord /path/to/package.zip --case CASE-001
./lawliet check-signal /path/to/signal.backup
./lawliet decrypt-signal /path/to/signal.backup --case CASE-001
```

WhatsApp imports preserve the supplied container, transcript, media and source
hashes. Exact, unambiguous attachment filenames link to acquired media; missing,
omitted and ambiguous references remain explicit. Exports can omit history and
media. Discord packages contain the requesting account's sent messages, not the
whole conversation or deleted messages. Attachment URLs are retained without
network retrieval. Offset-free timestamps remain undated unless the examiner
declares a timezone; WhatsApp date order and two-digit year interpretation are
also explicit. Unchanged import replay can reuse intact evidence and the same
interpretation. Partial parsing remains selectable in the source picker.

Signal requires an independently installed compatible `signalbackup-tools` and
the known legacy 30-digit passphrase. Its original and working input hashes are
checked, decoder output is preserved, and credentials are excluded from argv and
logs. New folder-based on-device backups and Secure Backups are not supported by
this adapter. The controlled decoder tests qualify process handling and indexing,
not decryption of a real customer backup; no compatible live decoder was available
for the October 17 intake qualification.

**All artifacts** combines indexed sources in the selected case. Applications,
Device and System logs are directly accessible when their records exist, alongside
messages, contacts, media and retained parser reports. The compact table has
resizable/hideable columns, keyboard selection and a source inspector. The Cards
option and automatic media previews remain available. Results are paginated;
source totals and displayed/filter counts have distinct meanings. Native package
records are inventory observations, not proof that an app was used.

These routes have synthetic record, provenance, failure and case-isolation tests.
They still need representative exports/backups from the actual customer device
and app versions, independently recorded expected content, and examiner review
before making completeness or commercial release claims.

Assess a customer question against one explicitly selected evidence source before
deciding the next collection or analysis step:

```bash
./lawliet case-assess --case CASE-001 --evidence EVIDENCE-ID --scenario messages
./lawliet case-assess --case CASE-001 --evidence EVIDENCE-ID --scenario whatsapp --run RUN-ID
```

Scenarios cover messages, WhatsApp, Signal, files, suspicious activity (`incident`)
and recovery candidates (`deleted`). The assessment summarizes indexed records,
dates, retained references, processing failures and recorded coverage gaps. It
does not collect data, invoke a model/parser, verify current evidence hashes or
approve findings. Available records do not establish an answered question or
complete phone history. The native app exposes evidence-scoped assessments under
**Coverage & review → Assess customer question…**; the CLI additionally supports
an exact analysis-run selection.

See [commercial forensic requirements](docs/commercial-forensics-requirements.md)
for the researched priorities, current qualification limits and acceptance evidence.

```bash
./lawliet case create CASE-001 --name "Mobile investigation" --examiner "Analyst"
./lawliet import /path/to/iphone-backup --case CASE-001 --platform ios
./lawliet import /path/to/android-extraction.zip --case CASE-001 --platform android
./lawliet analyze --case CASE-001
./lawliet case show CASE-001
./lawliet timeline --case CASE-001 --category messages
./lawliet search "example.com" --case CASE-001
./lawliet correlate --case CASE-001 --kind url
./lawliet inspect RECORD_ID --case CASE-001
./lawliet timeline --case CASE-001 --since 2026-10-01 --until 2026-10-11 \
  --limit 100000 --format jsonl --out timeline.jsonl
./lawliet report --case CASE-001
./lawliet verify --case CASE-001
./lawliet audit --case CASE-001 --json
```

`--workspace /path/to/cases` and `--json` work before or after subcommands.
`LAWLIET_WORKSPACE` also sets the workspace. The default is `./lawliet-cases`.
Search is literal and case-insensitive. `--since` and `--until` are inclusive:
date-only boundaries mean **00:00:00 UTC**, so use the next day to include a full
day. Times with unknown timezones stay undated. Default query limit: 100 records.

Paired JSONL, JSON, CSV and HTML exports stage private files through an anchored,
non-symlink directory handle. Existing names are never overwritten; detected
parent/output changes fail without a success audit receipt. Failure cleanup removes
only the files created by that operation and preserves foreign replacements.
The data and coverage files publish sequentially: a hard kill or power loss can
leave a partial pair. Inspect both files and their digest/audit receipt before use;
choose new output names after an interrupted export. These checks do not provide
OS isolation against a privileged concurrent process or immutable storage.

## Verify a received review package

A recipient can check an existing references-only customer draft or local release
without opening the originating case database:

```sh
python3 tools/verify_review_package.py /path/to/package
python3 tools/verify_review_package.py /path/to/package \
  --expected-manifest-sha256 DIGEST_FROM_A_SEPARATE_TRUSTED_CHANNEL
```

The command reads the package only. It checks the declared inventory, file hashes,
annex/exhibit correspondence, entry citations and chronology identities. It refuses
unsupported versions, unexpected members, symbolic/hard links and changes detected
during verification. Current limits are 32 MiB per file and 64 MiB per package;
these are input refusal bounds, not measured performance guarantees. Source paths
and URLs remain inert references and original evidence is never opened.

Without a separately supplied manifest digest, success establishes internal
consistency only. It does not authenticate the sender, original evidence, recorded
examiner declaration, conclusions or redaction sufficiency. Missing recorded
locators are counted explicitly. This check does not replace a second examiner's
reproduction or secure recipient transfer. Output is JSON; refusal returns exit 1.

The desktop JSON backend accepts record offsets only as nonnegative integers
within SQLite’s signed 64-bit range. Invalid cursor types are refused instead of
being coerced to another page. Its record pages remain fixed at 100 rows.

Message and contact Investigator views retain at most 100,000 source records and
128 MiB of their full serialized UTF-8 JSON, including bodies, titles and provenance.
Rows are checked incrementally; a budget failure refuses the projection rather
than returning a partial clean result. These are presentation-input limits, not
OS memory or query-time enforcement: one SQLite row must be decoded before it is
measured, and projection/response serialization adds overhead. Use a narrower
scope or Source records when the projection is refused. Paginated source records
and streaming JSONL exports remain separate routes; a record count alone does not
guarantee that the Investigator byte budget will fit.

## Native support matrix

These are schema-based baseline parsers, not blanket claims of support for every
phone, app version, or OS version. Only artifacts present in the extraction can
be parsed.

| Artifact | Source/schema | Output and timestamp meaning |
|---|---|---|
| iOS SMS/iMessage | `sms.db`, `message` + `handle` | Plaintext messages, direction, handle; message date in Apple seconds or nanoseconds |
| iOS calls | `ZCALLRECORD` | Address, duration, call date in Apple seconds |
| Safari browsing | `history_visits` + `history_items` | Visit URL/title and Apple-epoch visit time |
| iOS contacts | `ABPerson` | Name/organization; modification timestamp, not contact creation |
| Android SMS | `sms` with `body` | Message, address, type; Unix milliseconds |
| Android calls | `calls` with `number` | Number/duration and Unix-millisecond date |
| Android contacts | `data` + optional `mimetypes` | Raw contact data rows; no invented timestamp |
| Chrome URLs | `urls.last_visit_time` | Last recorded URL visit (not complete browsing history); WebKit epoch microseconds |
| Android collected logs | `logcat.txt`, epoch format | PID/TID, severity, tag, original line and UTC timestamp |
| Android package inventory | `packages.txt` | Package names and available APK paths; undated |
| Android device metadata | `getprop.txt` | System property inventory; undated |

Native XML imports accept UTF-8 SMS Backup & Restore message and call exports.
Raw attributes, source hashes and record locators are retained. MMS text parsing
does not establish acquired attachments: absent parts, absent nontext payloads
and encoded payloads that were not decoded appear as separate coverage gaps.
SMS type 6 is queued; undocumented MMS message-box values remain unknown.
Known empty exports and unsupported XML roots remain distinct.

XML parsing requires Expat 2.7.2 or newer and refuses DTD/entity declarations.
Declared bounds are 128 MiB, 100,000 top-level records, 250,000 elements and depth
32. One optional stylesheet declaration of at most 2,048 UTF-8 bytes is retained
as inert metadata; stylesheets are never loaded or executed. Other processing
instructions are refused. These are rejection boundaries, not measured capacity
or phone-completeness guarantees. Synthetic checks do not qualify device exports.

Finder/iTunes `Manifest.db` maps hashed payload names back to logical paths.
Matching SQLite WAL/SHM sidecars are copied into the analysis working directory;
their hashes are included in artifact provenance. Native parsing does not recover
deleted data, decode iMessage attributed-body blobs, assemble MMS/attachments,
decrypt backups, or render a malware verdict. Encrypted iOS backups are detected
and explicitly rejected by the analysis adapters until a decrypted extraction is
provided.

## Optional tools

```bash
./lawliet doctor
./lawliet tools configure ileapp /path/to/iLEAPP/ileapp.py
./lawliet tools configure aleapp /path/to/ALEAPP/aleapp.py
./lawliet analyze --case CASE-001 --evidence IOS_EVIDENCE_ID --engine ileapp
./lawliet analyze --case CASE-001 --evidence ANDROID_EVIDENCE_ID --engine aleapp
./lawliet analyze --case CASE-001 --engine exiftool
```

Installed executables on PATH are detected automatically. Configured Python entry
points default to Lawliet's Python interpreter; configure a dedicated interpreter
using `tools configure NAME PATH --python /path/to/python`, or use a prebuilt executable.
Tools are installed only when you explicitly run the setup installer.

| Adapter | Integration in this release | Upstream project/license |
|---|---|---|
| iLEAPP | CLI invocation, preserved reports, TSV record ingestion | [iLEAPP](https://github.com/abrignoni/iLEAPP), MIT |
| ALEAPP | CLI invocation, preserved reports, TSV record ingestion | [ALEAPP](https://github.com/abrignoni/ALEAPP), MIT |
| ExifTool | CLI invocation, JSON metadata ingestion and evidence-file mapping | [ExifTool](https://github.com/exiftool/exiftool), Artistic or GPL |
| ADB | Device discovery, explicit serial selection, logical triage collection | [ADB](https://developer.android.com/tools/adb), AOSP Apache-2.0 plus dependency notices |
| libimobiledevice | iOS discovery and `idevicebackup2` logical backup | [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice), LGPL-2.1+ for these utilities |

LEAPP TSV imports preserve original fields and report-line references. They do
**not** fabricate source-database hashes. A timestamp is normalized only when a
timezone-aware ISO value can be interpreted. Full per-artifact LEAPP mappings are
a future extension. Re-running a native parser on unchanged evidence is
idempotent; external reports currently belong to distinct runs and can yield
duplicate records across reruns.

External tools receive disposable copies of imported evidence. Their output,
error logs, command arguments, entry-point hash, exit status, and elapsed time are
retained under `runs/`. Dependency trees are not yet fingerprinted. `doctor`
checks tool presence, not compatibility or forensic correctness. ExifTool's
adapter has been exercised against the installed tool. Setup also runs real LEAPP
parsers against synthetic known records and checks retained imports/provenance.
Representative customer extraction validation remains separate.

## Connecting a phone

```bash
./lawliet devices
./lawliet collect android --case CASE-001 --serial ANDROID_SERIAL
./lawliet collect ios --case CASE-001 --serial IOS_UDID
./lawliet analyze --case CASE-001
```

Connect the device by USB. Android needs USB debugging and host authorization;
iOS generally needs an unlocked device and an approved trust pairing. Collection
is explicit and logged. Lawliet never initiates collection when importing or
running a demo. Discovery through ADB may start its local service.

For readable Android contacts, select **Contacts · readable provider**, or run:

```bash
./lawliet collect android --case CASE-001 --serial ANDROID_SERIAL \
  --profile contacts-provider --android-user 0
```

The collector binds every query to one Android user. Without `--android-user`,
it observes the current user before collection and checks it again afterward.
It retains raw name, phone and email responses and a generated vCard; that file
is a derivative, not the original contacts database. Live reads are not an atomic
snapshot. The profile excludes contact photos, notes, groups and other users.

For Codex-driven collection through Mulder, `tools/mulder_android_contacts.py`
starts a separate contacts-only MCP endpoint for an existing parent case. It
exposes contact collection, retained-record queries and file listing, with an
explicit serial/user, bounded collection and a local ADB transport. It does not
start Mulder's autonomous investigation command. Successful contacts, SMS,
shared-storage or diagnostic capture does not establish full filesystem access.

For a readable Android SMS provider, select **SMS · readable provider** in the
acquisition dialog, or explicitly run:

```bash
./lawliet collect android --case CASE-001 --serial ANDROID_SERIAL \
  --profile sms-provider --max-sms 1000 --sms-prefix 'LM-SEED'
```

This optional profile queries only `content://sms` through authorized ADB, with
no permission grants or collector installation. A literal `--sms-prefix` restricts
the provider-side selection; omit it to request all available SMS up to the cap.
`--android-user` selects a specific Android user; otherwise the current user is
recorded and fixed for collection. Profiles and provider record IDs remain in
provenance. Permission denial is a failure, not an empty mailbox.

The default limit is 1,000 records and at most 64 MiB, including collection logs.
Typed hexadecimal observations preserve Unicode, newlines and NULL separately
from the text `NULL`. Raw responses, their hashes, generated JSONL, command history
and collection limitations are retained. The indexed source is host-generated
JSONL, **not an acquired original SQLite database**. The
[Android SMS field contract](https://developer.android.com/reference/android/provider/Telephony.TextBasedSmsColumns)
defines the preserved fields; `date_sent` is retained separately from `date`.
The provider is queried per record, without a transaction-wide snapshot. A changed
record ID inventory is partial; unchanged IDs cannot prove content stayed stable.
MMS, RCS, private app messages and deleted-record recovery are outside this scope.
Synthetic CLI/native GUI fidelity tests passed. A Samsung SM-A176U on Android 16
also yielded two SMS observations through the real CLI; the native GUI export
matched all nine raw fields independently decoded from the retained device
responses, and evidence hashes verified. This small observed-data check does not
qualify independently seeded field fidelity, other devices, MMS or RCS.

Android collection gathers `getprop`, package inventory, an existing logcat buffer,
and a bugreport. It does **not** acquire private app databases or a full filesystem;
the bugreport ZIP is retained, but deep bugreport parsing is not implemented.
iOS collection uses `idevicebackup2 backup --full`; "full" means a full **logical
backup**, not a full filesystem extraction. Encrypted backups can be collected
but must be decrypted separately for analysis.

This iPhone method cannot request only messages or contacts. The storage budget
is a stop threshold, not a selective-acquisition filter; stopping an oversized
backup can leave an incomplete collection. For a small review, reuse an existing
case or import a supplied export. The desktop hides Android-only scopes for an
iPhone and reports collection and parsing status separately. A completed backup
with incomplete native analysis is reported as partial overall.

Upstream [pymobiledevice3](https://doronz88.github.io/pymobiledevice3/cli/backup2/)
now supports filtered backup retention through `--only` / `--only-regex`. This is
not integrated or device-qualified in LAWLIET yet. The first backup still sends
all eligible bytes; filtering avoids saving rejected payloads. A database-only
profile must preserve SQLite sidecars when supplied, retain the original manifest
and record intentional omissions. The `messages` preset includes attachments;
it is not a database-only storage profile. Do not confuse a retained-byte limit
with a guarantee that the device's backup free-space check will pass.

Installed-app metadata can be read separately using the official
[ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller) utility.
An October 2026 direct USB test returned 352 unique application identifiers in a
136,838-byte XML plist, which was hashed and imported through the existing derived
report route. This tested inventory retrieval and GUI review, not a new built-in
one-click collector or private application content acquisition. Contacts can also
be supplied as a native iPhone vCard export without a full backup.

Live collection changes device state. Commands have timeouts; failures and partial
collections are recorded. No unlocking, root installation, jailbreak, reset,
restore, app installation, or log clearing is performed. Test acquisition against
your supported device/OS matrix before relying on it in casework.

## Android screen interaction

The macOS desktop app provides a **Connected device** sidebar entry for explicit
USB discovery, view-only mirroring and investigator-enabled control using scrcpy.
Live video opens in a managed scrcpy window. See [setup, audit scope and forensic
limitations](docs/ANDROID-MIRRORING.md). ADB/scrcpy may modify device state; inputs
inside the scrcpy window are not individually audited.

## Evidence handling

- Inputs are copied into a private case directory; analysis works on temporary copies.
- Each imported file has SHA-256, byte count, physical path, and logical path.
- Archives have an original-container SHA-256 and an extracted-file inventory.
- ZIP/TAR traversal, links, special files, duplicate files, and size-limit violations are rejected.
- Default intake limits: 20 GiB and 100,000 files; override deliberately with `--max-gib` / `--max-files`.
- Every analysis starts with a case integrity check. `verify` detects modified, missing, and untracked evidence files.
- Audit entries have a local SHA-256 chain. This detects inconsistent edits, but is **not** an independently signed custody record or an immutable ledger.
- The case database and reports are not encrypted. Use encrypted storage and appropriate access controls for case data.
- HTML escapes evidence text; terminal output removes control sequences. CSV neutralizes leading spreadsheet formula characters; JSON/JSONL preserve raw values.
- Nothing uploads evidence. Git ignores case workspaces and demo output by default; never commit case data.

## Validation and next steps

```bash
python3 -m unittest discover -s tests -v
```

Tests cover native iOS/Android fixtures, hashed backups, WAL-only records,
idempotence, provenance, timestamp behavior, integrity/tampering, unsafe archives,
report escaping, export behavior, tool failures/timeouts, and optional ExifTool.

Next priorities: real device acquisition validation; representative LEAPP extraction acceptance;
versioned schema fixtures from supported mobile OS/app versions; structured SAF /
UnifiedLogs and SQLite Dissect adapters; endpoint/mobile case correlation.
The mobile installer provisions the MVT CLI for the tool environment. The patched
`run_mvt_android` MCP tool accepts evidence within the active case's evidence root:
AndroidQF directories/ZIPs, unencrypted Android Backup files/directories, and
bugreport ZIPs. It validates the input layout and dispatches to the matching MVT
command using a bounded working copy. This route currently requires **MVT
2026.10.5**; other versions are refused pending qualification. Optional IOC files
must be explicitly supplied local STIX2 bundles. Automatic indicator downloads
and update checks are disabled.

Original hashes, command logs, JSON module output and an indexing-outcome receipt
are retained. Indexed rows identify the output file and zero-based record index.
Readable partial output does not establish module completeness or a clean phone;
errors remain in the receipt. The default input budget is 64 MiB (512 MiB maximum).
Output stopping is polled and is not a hard operating-system storage quota. Keep
one case per server while tools run. Actual synthetic CLI/MCP checks cover these
routes. Native **MVT observations** imports one retained `run_mvt_android` output
folder after checking its manifest, receipt and explicit case association. It
preserves source files, offers paginated search, verifies original JSON records
and hashes on selection, and saves source-linked examiner findings. Partial
errors, empty results and unverified module completion remain visible; an output
hash authenticates retained parser bytes, not phone authorship. Other output
versions and real-device compromise-detection acceptance remain unqualified.
Alert rows show the original message, upstream level, module and matched indicator;
the complete JSON remains in the verified details. Counts are output observations:
MVT may repeat one match in both `alerts.json` and a module detection report.
Actual local synthetic positive/no-match checks verified both seeded matches and
zero alerts respectively, including retained hashes and LAWLIET source references.
Those checks do not establish detection completeness or that a phone is clean.
AndroidQF **acquisition** remains a research candidate.
MVT's [license](https://license.mvt.re/1.1/) requires explicit data-owner consent.

Native **Report history → Review draft → Review & export** now connects the
existing source/audit checks to explicit examiner approval and local export.
Approval starts with blank name/declaration fields and binds the reviewed manifest
hash; export rechecks sources and investigation state before and after copying.
Selected-literal derivatives open for separate review and approval. Exact string
masking does not claim semantic redaction or attachment/media redaction. Export
creates a new local folder and sends nothing. Original drafts remain unchanged,
and the recorded declaration does not authenticate the operator's identity.

No upstream tool is bundled. Before shipping optional binaries, review the exact
versions, dependency licenses, and distribution obligations. This private initial
repository does not grant a redistribution license for Lawliet's own code.

### Opt-in ExifTool container endpoint

`python3 lawliet --workspace /path/to/review-workspace tools isolate-exiftool
--image <qualified-image-sha256> --tool-root /path/to/exiftool-tree
--socket /path/to/existing/docker.sock --docker /path/to/docker` selects the
qualified local ExifTool container profile for that workspace. The supported
image ID is `lawliet_mobile.container_runner.IMAGE`. It must already exist;
this route does not pull images, start Docker, or fall back to a host parser.

For Mulder, use `python3 tools/mulder_parser_container.py --db-dir
/path/to/existing/mulder-case-store --case-id EXISTING_CASE --socket
/path/to/existing/docker.sock`. This separate endpoint exposes only
`run_lawliet_exiftool_review`, `query_ancalor_review`, and `list_ancalor_files`.
It parses explicitly selected imported evidence in an existing case-local
review directory. The general offline endpoint remains unchanged.

The trusted controller may access the specified local Docker API. The parser
has no daemon socket mount, network, writable input, or writable root filesystem;
it uses a 64 MiB memory limit, 16 PID limit, 0.25 CPU allocation, and bounded
stdout. Durable ownership labels and a case lease prevent retry while an
orphaned daemon worker remains live. Uncertain daemon cleanup retains the lease
or refuses retry. ALEAPP/iLEAPP container execution is still unqualified.

Archive reuse now verifies the source archive SHA256 and the exact decoded
file/directory inventory, including output SHA256 values. Changed, missing or
injected content, legacy receipts without fingerprints, and changed limits
cannot inherit an `already_extracted` result. Existing output is preserved;
use a fresh empty destination for a new extraction. Verification checks byte
and file limits before hashing, bounds receipts to 32 MiB, and uses a
600-second verification deadline. This is byte consistency, not evidence
authentication or a memory-isolation guarantee.

Retained SQLite queries now participate in the case ownership lease. A guardian
stops the worker if its caller dies; if both caller and guardian die, the live
worker retains the lease and prevents retry until it exits. Recovery requires
the original lease inode and matching audited ownership, retains interrupted
output, and does not promote it to completed results. Legacy unaudited running
jobs still require explicit investigation. Working copies stay in the private
case run directory, and the worker source SHA256 is recorded and checked after
execution. This POSIX lifecycle control does not add OS memory or network
isolation to the existing SQLite heap, function, query and output limits.

Parsed JSONL, TSV and LEAPP-folder imports use the same POSIX case lease before
copying reports. Their durable start records bind the exact import engine to
its ownership receipt. A concurrent parser/import is refused. After an import
process dies, a later lease holder can mark its matching run interrupted and
retry; uncommitted artifact rows roll back and retained reports remain separate.
Legacy or mismatched running jobs remain blocked for explicit investigation.
This protects job lifecycle consistency; it adds no parser timeout or OS sandbox.

Native baseline parsing also records case-lease ownership before indexing. A
live native job excludes another parser/import in that case. After process death,
matching audited ownership permits an interrupted run to be retained and a new
analysis to proceed. This changes job lifecycle metadata, not the native parser
version or its supported schemas. Existing handled-error and rerun behavior is
preserved; this is a POSIX lifecycle boundary, not a parser sandbox.

Native `0.1.12` converts integral epoch values without an intermediate floating
point number. Nanoseconds round to the nearest representable microsecond, with
half-microsecond ties rounded to even; the original numeric value is retained.
iOS message records disclose the source `date` field, existing magnitude-based
unit selection, normalization availability, conversion method and nanosecond
rounding residual. Stored REAL values remain approximate. The selected unit does
not establish measurement accuracy or prove sent, received, read or human
activity time. Earlier native results remain historical and are not rewritten.

Native SQLite reads cap each text/BLOB value or SQLite-encoded row at 8 MiB.
An oversized value leaves that source incomplete with a logged byte limit;
other readable sources can still be indexed. Values are not silently shortened.
The run retains its resource policy and original source bytes. This bound does
not establish a process memory ceiling, an overall job deadline, or commercial
case-volume capacity. It uses SQLite's existing per-connection limit API.

Parsed-report rows, completed-run metadata and completion audit now publish in
one SQLite transaction. Database quota/storage failures roll back those rows
and record a failed zero-row run when metadata storage remains available. Failed
startup registration rolls back its unaudited transaction. If the failure state
itself cannot be stored, the error explicitly marks the retained run unresolved;
free storage and inspect it before retry. The tests use small SQLite page quotas,
not an exhausted host drive; this does not guarantee logging on a full device.

Native case-database storage failures stop processing. Counts exclude artifact
writes rolled back by SQLite, and failed registration/final-state writes roll
back instead of leaving uncommitted state for a later caller to accept. After
capacity is restored, owned interrupted work can retry without duplicate rows.
The controls use real SQLite page quotas on small fixtures; they do not fill or
qualify recovery of a full host filesystem.

The SQLite query controller reads child metadata and result files through an
anchored directory with no-follow, regular-file, single-link and byte-limit
checks. It checks UTF-8 JSONL row types, widths and counts before completion;
child-supplied result paths and hashes cannot substitute for a controller-read
result. Metadata is capped at 1 MiB. Retained diagnostics and receipts publish
exclusively rather than following child-created destination links. Refused
outputs remain failed or, if finalization itself is unsafe, owned interrupted
work for a new-run retry. These controls were tested with synthetic substituted
worker outputs; they do not establish containment of a compromised worker or
qualify the separate macOS sandbox prototype.

### Opt-in SQLite container jobs

The SQLite workspace can use the qualified existing Linux ARM64 Python runtime.
Configure the tool workspace explicitly; this setting applies to every case in
that workspace. LAWLIET checks the local image before recording a new query and
never pulls an image or falls back to host SQL after opting in.

```sh
python3 lawliet --workspace /path/to/cases tools isolate-sqlite \
  --image sha256:4701f9885ba369bf50a80ae4b5e1f637be3aa961dbb9b676d295e98fb2c01075 \
  --socket /absolute/path/to/docker.sock --docker /absolute/path/to/docker
```

This profile accepts at most64MiB of selected SQLite database/WAL/journal copies.
It uses a read-only root and input mounts, private process namespace, no network,
UID65534, no capabilities, a256MiB memory limit,16process limit and128MiB temporary
filesystem. The worker receives no case database, home directory, Docker socket,
host environment or case-lease descriptor. The host validates the bounded result
stream before publishing rows and retains bounded raw output and diagnostics.
WAL pairing remains unverified; query rows are observations, not findings.

A separate Mulder endpoint exposes exactly SQL queries, retained-record queries
and file listing. It requires a pre-existing Mulder case and configured container
profile; missing configuration refuses execution. Existing offline, Android SMS
and ExifTool endpoints retain their tool sets.

```sh
python3 tools/mulder_sqlite_container.py --runtime /path/to/runtime \
  --db-dir /path/to/mulder-cases --case-id CASE-ID \
  --socket /absolute/path/to/docker.sock
```

Recovery checks audited daemon ownership before permitting another runner.
An active or uncertain job blocks retry, including a job whose host run already
has a terminal status. An ambiguous create response with no known container ID
requires explicit reconciliation; an empty inventory alone does not prove that
an in-flight create failed. This profile covers SQLite queries only; it does not
isolate native or LEAPP parsing. The installed desktop app is not replaced by
building or testing the separate QA bundle.

### Opt-in native parser container jobs

The native parser can run in a bounded Linux worker while the trusted host owns
case locking, retained evidence and final CaseDB publication. Configure an
existing local runtime explicitly:

```sh
python3 lawliet --workspace /path/to/cases tools isolate-native \
  --image sha256:4701f9885ba369bf50a80ae4b5e1f637be3aa961dbb9b676d295e98fb2c01075 \
  --socket "$HOME/.docker/run/docker.sock" --docker /path/to/docker
```

This stores `native_workspace_container` in that workspace's tool settings. It
never downloads an image, starts Docker, or falls back to host parsing after an
isolation refusal. The entire supplied retained evidence inventory must fit
32 MiB and 1,000 files; it does not silently select a smaller subset. Worker
memory, scratch, elapsed time and output have separate bounds, so fitting the
input cap does not guarantee a successful parse.

For Mulder, use the separate three-tool endpoint:

```sh
python3 tools/mulder_native_container.py --runtime /path/to/runtime \
  --db-dir /path/to/mulder-databases --case-id EXISTING-CASE \
  --socket "$HOME/.docker/run/docker.sock"
```

It exposes `run_ancalor_native_review`, `query_ancalor_review` and
`list_ancalor_files`, bound to the existing selected Mulder case. The matching
review workspace must be configured before intake. The worker receives read-only
copies of the selected inventory and pinned parser sources, with no host CaseDB,
lease descriptor or Docker socket. The host validates the complete bounded
transport, rechecks source hashes, settles the daemon worker and atomically
publishes artifacts with run membership and an audit entry. An incomplete or
invalid transport publishes no prefix of its records. Repeat runs retain their
membership while reporting only newly inserted records.

A successful container run retains the native parser's existing coverage and
per-source limitations, including partial results and WAL pairing uncertainty.
It does not recover unavailable attachment payloads, establish independent case
truth or qualify ALEAPP/iLEAPP and other external parsers. Recovery checks daemon
ownership even for terminal run rows; an ambiguous create outcome requires
reconciliation before retry.
An audited job with an empty daemon inventory and no exact audited settlement
also requires reconciliation when its local marker is missing, including after
a staging failure. Missing metadata is not proof that a worker stopped.

The restricted native Mulder endpoint also binds input selection to the active
parent case metadata `evidence_root`: files inside that declared directory, or
the exact declared file, can be imported. Missing roots and outside paths are
refused before creating a review case. This canonical-path guard does not claim
protection against concurrent host path replacement.

### Contained single-report import

The opt-in report decoder uses the same existing pinned Python image, without
pulling an image or installing another parser. Configure the review workspace:

```sh
python3 lawliet --workspace /path/to/review-workspace tools isolate-reports \
  --image sha256:4701f9885ba369bf50a80ae4b5e1f637be3aa961dbb9b676d295e98fb2c01075 \
  --socket "$HOME/.docker/run/docker.sock" --docker /path/to/docker
```

For investigations through Mulder, start the separate endpoint for an existing
parent case:

```sh
python3 tools/mulder_report_container.py --runtime /path/to/runtime \
  --db-dir /path/to/mulder-databases --case-id EXISTING-CASE \
  --socket "$HOME/.docker/run/docker.sock"
```

Its three tools are `run_lawliet_report_import`, `query_ancalor_review` and
`list_ancalor_files`. Select an already retained file ID from the active case and
explicitly choose `jsonl` or `tsv`. The endpoint verifies and snapshots those
bytes with the original schema-selecting filename. It accepts no arbitrary raw
report path and never falls back to host decoding. Existing standard, SMS,
ExifTool, SQL and native tool registrations remain unchanged.

The manual CLI exposes the same explicit decoder choice:

```sh
python3 lawliet --workspace /path/to/cases import-report /path/to/report.tsv \
  --case EXISTING-CASE --format tsv --contained
```

Limits are one 32 MiB input file, 100,000 records, 16 MiB of artifact frames,
8 MiB per frame, 256 MiB of worker memory, 128 MiB of scratch and 90 seconds.
Normalized data can exceed the input size; fitting the input cap does not
guarantee acceptance. Oversized or malformed output retains the report and
publishes zero records. The complete validated output, artifact membership and
terminal audit are committed together. Through Mulder, imports are bound to the
selected retained file in that case. Identical bytes from different retained
files produce separate derived sources and conversation scopes. Repeating the
same retained-file request reuses only a verified completed import under the
same execution profile and reports that no decoder ran again. This occurrence
separation does not establish that reports came from different real accounts
or devices.

Raw-path CLI requests have no retained-file origin binding. Each contained CLI
invocation creates a new occurrence, including repeated requests for the same
path; its result explicitly says reuse is unavailable. Use the retained-file
Mulder endpoint when repeat-safe source occurrence tracking is required.

This contains interpretation of a supplied derived report. It does not run
ALEAPP/iLEAPP, verify their claims against a phone, or qualify whole-folder
report imports. Host mode and folder imports retain their separately recorded
scope. Parent-death and cancellation preserve history; unresolved daemon
ownership requires reconciliation before retry. The installed app is separate
from the recorded source and QA build versions.
