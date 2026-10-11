# Ancalor Mobile

**Local mobile evidence triage. One CLI. Android and iOS.**

Python standard library only. No daemon, database server, container, cloud service,
or required third-party runtime package. Runs with Python 3.11+ on macOS, Linux,
and Windows. Optional CLI tools extend collection and parsing.

This is an initial working release with a limited native support matrix. Physical
device collection is implemented but has not yet been validated on real devices.

## Try it in a minute

```bash
git clone https://github.com/enleak/ancalor-mobile.git
cd ancalor-mobile
python3 -m ancalor_mobile demo
python3 -m ancalor_mobile timeline --case demo
python3 -m ancalor_mobile search parcel-review.example --case demo
python3 -m ancalor_mobile correlate --case demo
python3 -m ancalor_mobile verify --case demo
```

Open `ancalor-cases/demo/reports/investigation.html` in a browser. The report has
local search, category filters, expandable original fields, source references,
hashes, analysis coverage, and print styles. It makes no network requests.

The demo creates **15 fictional artifacts across an iPhone backup and an Android
filesystem extraction**. Reserved `.example` domains and 555 numbers are test data.
It does not connect to a phone or download anything. Use `demo --case demo2` for
another fresh run; existing cases are never replaced.

On macOS/Linux you can also run `./ancalor`. Optional installation:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/ancalor-mobile --help
```

Installation uses setuptools as a build dependency. Direct module/script use
requires no installation and no external packages. Windows: use `py -m
ancalor_mobile` and `.venv\Scripts\python.exe` as appropriate.

## A real investigation

```bash
./ancalor case create CASE-001 --name "Mobile investigation" --examiner "Analyst"
./ancalor import /path/to/iphone-backup --case CASE-001 --platform ios
./ancalor import /path/to/android-extraction.zip --case CASE-001 --platform android
./ancalor analyze --case CASE-001
./ancalor case show CASE-001
./ancalor timeline --case CASE-001 --category messages
./ancalor search "example.com" --case CASE-001
./ancalor correlate --case CASE-001 --kind url
./ancalor inspect RECORD_ID --case CASE-001
./ancalor timeline --case CASE-001 --since 2026-10-01 --until 2026-10-11 \
  --limit 100000 --format jsonl --out timeline.jsonl
./ancalor report --case CASE-001
./ancalor verify --case CASE-001
./ancalor audit --case CASE-001 --json
```

`--workspace /path/to/cases` and `--json` work before or after subcommands.
`ANCALOR_WORKSPACE` also sets the workspace. The default is `./ancalor-cases`.
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
./ancalor doctor
./ancalor tools configure ileapp /path/to/iLEAPP/ileapp.py
./ancalor tools configure aleapp /path/to/ALEAPP/aleapp.py
./ancalor analyze --case CASE-001 --evidence IOS_EVIDENCE_ID --engine ileapp
./ancalor analyze --case CASE-001 --evidence ANDROID_EVIDENCE_ID --engine aleapp
./ancalor analyze --case CASE-001 --engine exiftool
```

Installed executables on PATH are detected automatically. Configured Python entry
points run in the same Python interpreter as Ancalor: install their dependencies
there or configure a prebuilt executable instead. Tools are never auto-installed.

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
./ancalor devices
./ancalor collect android --case CASE-001 --serial ANDROID_SERIAL
./ancalor collect ios --case CASE-001 --serial IOS_UDID
./ancalor analyze --case CASE-001
```

Connect the device by USB. Android needs USB debugging and host authorization;
iOS generally needs an unlocked device and an approved trust pairing. Collection
is explicit and logged. Ancalor never initiates collection when importing or
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
repository does not grant a redistribution license for Ancalor's own code.
