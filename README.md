# Lawliet Mobile

**Local mobile evidence triage. One CLI. Android and iOS.**

Python standard library only. No daemon, database server, container, cloud service,
or required third-party runtime package. Runs with Python 3.11+ on macOS, Linux,
and Windows. Optional CLI tools extend collection and parsing.

This is an initial working release with a limited native support matrix. Physical
device collection is implemented but has not yet been validated on real devices.

## Apple Silicon setup

Use an Apple Silicon Mac running macOS 13 or newer. First install Apple's
command-line developer tools (`xcode-select --install`) and [Homebrew](https://brew.sh).
Accept your private GitHub collaborator invitation, then:

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

The patched Mulder integration requires the upstream source at revision
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
git clone https://github.com/enleak/lawliet-mobile.git
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
adapter has been exercised against the installed tool; LEAPP adapters have
protocol-fixture tests but await real LEAPP integration validation.

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

Android collection gathers `getprop`, package inventory, an existing logcat buffer,
and a bugreport. It does **not** acquire private app databases or a full filesystem;
the bugreport ZIP is retained, but deep bugreport parsing is not implemented.
iOS collection uses `idevicebackup2 backup --full`; "full" means a full **logical
backup**, not a full filesystem extraction. Encrypted backups can be collected
but must be decrypted separately for analysis.

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

Next priorities: real device acquisition validation; real LEAPP integration tests;
versioned schema fixtures from supported mobile OS/app versions; structured SAF /
UnifiedLogs and SQLite Dissect adapters; endpoint/mobile case correlation.
MVT/AndroidQF remain research candidates, not implemented dependencies: their
[license](https://license.mvt.re/1.1/) requires explicit data-owner consent.

No upstream tool is bundled. Before shipping optional binaries, review the exact
versions, dependency licenses, and distribution obligations. This private initial
repository does not grant a redistribution license for Lawliet's own code.
