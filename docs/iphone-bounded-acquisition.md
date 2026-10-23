# Bounded iPhone acquisition

LAWLIET can collect a small app inventory or retain selected message/contact
databases, then import, hash, parse and display the results in the existing case.
The default iPhone CLI/desktop profile is `ios-apps`. A full logical backup
requires an explicit `ios-backup` selection; smaller methods never fall back to it.

## Choose the evidence scope

| Profile | What is retained | What it does not establish |
| --- | --- | --- |
| `ios-apps` | Installation-service app metadata and device information; original stdout plus byte-identical validated plist copies | Private app data, message history, app usage, historical/deleted installations |
| `ios-selected` | `HomeDomain/Library/SMS/sms.db`, `HomeDomain/Library/AddressBook/AddressBook.sqlitedb`, returned `-wal`/`-shm` companions, backup metadata and omission receipts | Full filesystem access, complete phone coverage, attachment/media bytes, contact photos, a restorable backup |
| `ios-backup` | Existing `idevicebackup2 backup --full` logical backup, subject to the selected storage budget | A physical image, full filesystem extraction or inclusion of cloud-only/excluded app data |

`ios-selected` uses Apple's backup protocol with an exact database-path filter.
Excluded payload bytes can still travel over USB before the upstream tool
discards them. The phone can request whole-backup free space and on-device
passcode confirmation. This reduces retained storage; it does not promise a
short transfer or bypass the phone's capacity checks. The adapter does not use
the upstream `messages` preset, which also includes attachments.

## Optional tools and installation

Keep acquisition dependencies outside the source checkout and evidence folders.
LAWLIET resolves installed/configured executables; starting collection never
downloads tools, installs phone apps, roots/jailbreaks or changes encryption.

- `ios-apps`: `idevice_id`, `ideviceinfo` and `ideviceinstaller`. The inventory
  adapter accepts ideviceinstaller 1.2+ within major 1 and ideviceinfo major 1;
  it checks versions before issuing inventory commands.
- `ios-selected`: `idevice_id`, `ideviceinfo` and **pymobiledevice3 11.41.2**.
  The exact version and advertised CLI contract are checked before backup.
- `ios-backup`: `idevice_id` and `idevicebackup2`.

For the optional selected profile, create an independent Python environment and
configure its executable. Replace these example paths; use the same case
workspace in the desktop and CLI:

```sh
python3 -m venv /path/to/optional-pymobiledevice3
/path/to/optional-pymobiledevice3/bin/python -m pip install 'pymobiledevice3==11.41.2'
./lawliet --workspace /path/to/cases tools configure pymobiledevice3 \
  /path/to/optional-pymobiledevice3/bin/pymobiledevice3
./lawliet --workspace /path/to/cases doctor
```

On Windows, use the environment's `Scripts/python.exe` and
`Scripts/pymobiledevice3.exe`. Host USB drivers, pairing and external-tool behavior
need qualification on that host; shared desktop support alone does not qualify
physical acquisition. The new optional environment is not installed by the
existing setup profile. Pinning pymobiledevice3 does not pin every transitive
dependency; record the actual environment used for casework.

Upstream [pymobiledevice3 11.41.2 metadata](https://github.com/doronz88/pymobiledevice3/blob/v11.41.2/pyproject.toml)
declares GPL-3.0-or-later; [its license](https://github.com/doronz88/pymobiledevice3/blob/v11.41.2/LICENSE)
and dependency licenses remain separate from LAWLIET's. The external
[ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller/blob/master/src/ideviceinstaller.c) utility
uses GPL-2.0-or-later, and the libimobiledevice utilities use LGPL-2.1-or-later.
These tools are independently installed, not vendored into this implementation.
Redistribution needs its own license/dependency review.

## CLI workflow

Unlock the authorized iPhone, connect it by USB and approve Trust on the phone
when needed. Select its exact reported UDID. Enter a requested passcode on the
phone, not into the CLI, logs, chat or a report.

```sh
./lawliet --workspace /path/to/cases devices
./lawliet --workspace /path/to/cases case create CASE-001
./lawliet --workspace /path/to/cases preflight ios --profile ios-apps --max-gib 1
./lawliet --workspace /path/to/cases collect ios --case CASE-001 \
  --serial IOS_UDID --profile ios-apps

./lawliet --workspace /path/to/cases preflight ios --profile ios-selected --max-gib 1
./lawliet --workspace /path/to/cases collect ios --case CASE-001 \
  --serial IOS_UDID --profile ios-selected
```

The two small profiles enforce lower limits regardless of a larger `--max-gib`:
**16 MiB** for inventory and **256 MiB** for selected databases. Preflight reserves
two collection budgets plus 1 GiB headroom: approximately 1.03 GiB and 1.5 GiB,
respectively. Collection logs, metadata, omission lists and temporary validation
copies also consume storage. Periodic guards are stop thresholds and can overshoot
between checks; they are not hard filesystem quotas or phone-content estimates.

The selected profile checks `WillEncrypt` before starting backup and
`Manifest.plist` after collection. Anything other than a known unencrypted state
stops this route. It does not request a backup password, disable encryption or
silently broaden acquisition. An explicit `ios-backup` may preserve encrypted
bytes; native/iLEAPP analysis requires a separately decrypted supported input.

## Review in either desktop

In the native Swift app, open the case's acquisition dialog, choose the iPhone,
then select **Installed apps**, **Messages & contacts**, or **Logical backup**.
Use **Check storage & tools**, review the scope and start acquisition.

In the shared desktop, open the case, discover/select the device and choose the
matching iPhone profile. Review the storage result and authorize that collection.
Both interfaces call the existing backend; completed evidence is indexed without
a second manual import. Collection and parsing outcomes remain distinct.

Review Applications and Device for inventory, or Messages and Contacts for
selected databases. Use All artifacts for source records and the timeline for
dated observations. App/device inventories stay undated. Inspect original fields,
source file/hash and record locator; installed-app presence does not imply use.

Native iOS message parsing preserves plaintext and source timestamps, direction,
service and raw fields. Starting with `native/0.1.14`, when plaintext is absent,
a bounded decoder reads the text field from qualified Foundation typedstream or
binary NSKeyedArchiver attributed bodies. Plaintext takes precedence. The record
retains the BLOB hash, decoder version and text location; typedstream byte ranges
are within the BLOB, not offsets within the SQLite file. The inspector labels
decoded text and unsupported/malformed bodies. Original database bytes remain
unchanged. Search, timeline and JSONL export use the decoded text.

This is text-only decoding, not a general Apple archive interpreter. Typedstream
attribute graphs are not decoded or fully validated. Inputs are limited to 1 MiB
and decoded text to 256 KiB; binary plist graphs have additional object, reference
and depth limits. Unsupported layouts remain visible coverage limitations.
Reaction/reply/edit semantics, attachments and deleted content are not inferred
from decoded text. Independently Foundation-generated synthetic fixtures and
adversarial tests are retained under `tests/fixtures/ios_attributed_body`.

Native contact parsing now joins `ABMultiValue.record_id` to `ABPerson.ROWID`
within the same source database. Observed property codes 3 and 4 supply phone
numbers and emails, with optional labels from `ABMultiValueLabel`. Every value
retains its person, value and label row references and original fields. The
inspector and phone search use these typed values without merging people across
sources or assigning a contact identity to messages. Unsupported schema/value
types, orphan rows, unresolved labels and per-contact size limits are reported.
These are qualified schema conventions, not a claim to support every iOS contact
store. Collected database bytes and indexed artifact coverage remain separate claims.

## Receipts, omissions and failure handling

The selected profile preserves original `Manifest.db`, `Manifest.plist`,
`Info.plist` and `Status.plist` without patching out omitted rows. It retains
`selection.json`, `omissions.jsonl`, command logs and collection metadata.
Intentional exclusions and missing selected payloads have different reasons.
Zero-byte transport placeholders may be removed before evidence intake, with
their paths recorded; original acquired database bytes are not rewritten.

A successful selected collection means the requested databases and required
metadata passed the adapter's checks. Missing selected files, malformed SQLite,
transfer errors or unfinished snapshots remain partial/failed. Unexpected retained
nonselected payloads are refused. Failed attempts retain diagnostics and any
partial bytes; there is no automatic full-backup retry.

Generic backup validation still compares the **original full manifest** with
retained payloads, so this deliberately filtered acquisition reports incomplete
backup inventory. That warning is expected and must be read with the omission
receipt; it is not silently waived. Missing attachment bytes remain unavailable.
Supplying a WAL does not independently prove its provenance or pairing.

## Qualification as of 21 October 2026

The integrated live inventory route returned **352 application observations and
one device record**, with **8,521,670 bytes (about 8.1 MiB)** of preserved evidence.
Collection staging and indexes are additional. Independent raw-plist/index field
and hash comparisons passed. This covers the observed phone/configuration and
installation metadata, not private content or device-wide completeness.

The installed native macOS app also completed the same collection through its
acquisition dialog with `native/0.1.13`: 352 apps plus one device record. The
independent comparison passed again. Its Verify action checked all 22 preserved
files across the CLI and GUI inventory acquisitions. Separate acquisitions stay
separate; an all-source view therefore shows overlapping observations. Search,
pagination, source locators, scope selection and in-dialog readiness were checked
in the running app. The previous app was retained for rollback.

Local regression: 1,520 tests ran with 251 platform/opt-in skips and no failures.
After the final diagnostic changes, 72 iOS-focused tests passed with one
Windows-only skip. Native compilation and bundle signature verification passed.
These results do not qualify physical iPhone collection on Windows or Linux.

Synthetic tests cover selected payloads, original manifest preservation, omitted
attachments, WAL limits, encrypted-input refusal and GUI query presentation.
The first live selected-database attempt requested on-phone passcode
confirmation, then iOS ended it with `Device locked (MBErrorDomain/208)`.
LAWLIET retained the attempt logs, reported failure and imported no evidence.
Successful physical message/contact collection has **not** yet been established.
Unlock the phone and accept the next backup prompt on the phone before a new
attempt can qualify this route. Synthetic results do not replace that check.

### Software follow-up, 22 October 2026

Cross-platform checks found and corrected Windows path separators in selected
backup validation and an isolated-worker schema gate that had not been updated
for `native/0.1.13`. Exact parser identities remain checked; unknown versions are
still rejected. The Android qualification oracle was explicitly requalified for
the new parser label without changing its raw evidence or expected source fields.

The full Windows suite also exposed an omission-inventory publication conflict
with the collection's protected parent directory. Omission records now use the
existing anchored output writer, preserving directory protection and refusing
preexisting output files. Selected-backup tests run in the focused Windows
acquisition gate as well as the full suite.

The USB routes now refuse inherited usbmux/tunnel/device-fallback overrides
before collection. Errors identify environment variable names without exposing
their values. Remove the reported overrides from LAWLIET's launch environment and
restart; the application never changes the shared process environment itself.

Seven optional tests also exercise the actual pinned pymobiledevice3 CLI and
file-transfer implementation with synthetic binary streams. They passed locally
with socket connections forbidden, including selected WAL retention, discarded
payloads, temporary-path moves and protocol failures. To reproduce in the pinned
tool environment, run from the source checkout:

```sh
LAWLIET_PYMOBILEDEVICE3_CONTRACT=1 /path/to/pymobiledevice3-venv/bin/python \
  -m unittest tests.test_ios_upstream_contract -v
```

These checks do not replace the pending physical message/contact test. Excluded
payload bytes still cross the transport, temporary placeholders count toward the
100,000-file limit, and the original manifest itself can exceed the retention
budget. The disk guard is not a memory quota for the external tool's incoming
protocol frames. Unsupported or oversized collections must remain visible failures.

### Live follow-up, 23 October 2026

A trusted iPhone on iOS 26.6.1 passed the selected-profile host/tool preflight.
The attempted messages/contacts collection ended with Apple backup error
`MBErrorDomain/208` (device locked). LAWLIET retained diagnostics and imported no
evidence. A successful physical selected-database acquisition remains unqualified;
the parser improvements above do not change that result.

The `native/0.1.14` local regression run completed 1,587 tests with 261 explicit
platform/optional skips and no failures. Six additional compiled Swift phone-pivot
checks passed. The native app builds and passes bundle-signature verification.
A wholly synthetic case exercises plaintext precedence, two Foundation archive
formats, unavailable bodies, contact joins, search, provenance, export, reanalysis
and unchanged input hashes. Physical phone coverage is a separate qualification.
