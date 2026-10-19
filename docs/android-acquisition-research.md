# Android acquisition and analysis priorities

Reviewed 2026-10-15. This is a capability assessment, not a device examination
or proof of an installed integration. Upstream `main` documentation can describe
features newer than the pinned runtimes. Check installed source and CLI help
before constructing commands; never upgrade a runtime silently.

## Separate the four coverage questions

1. **Acquired:** Which files or provider records were actually returned, from
   which device/user, with which failures and collection limits?
2. **Parsed:** Which retained files and formats did each parser examine? Which
   modules failed, were unsupported, or returned no rows?
3. **Indexed:** Can every expected parsed record be found, exported and traced
   to its source and run, with original timestamp values preserved?
4. **Reviewed:** Which investigative questions do those records answer, and
   which remain unknown? A negative keyword/IOC result is scoped to examined
   material, not the entire phone.

LAWLIET already has case imports, hashes, run membership, coverage, native
parsing, external adapters and indexed review. Improve these boundaries before
adding duplicate parsers. Keep direct deterministic review available without an
agent. The current validated agent route uses Codex with Mulder MCP tools;
Mulder's separate autonomous `investigate` command is a different workflow.

## Select acquisition by the required evidence

| Need | Current route to assess | Boundary to display |
|---|---|---|
| Supplied contacts | Selected UTF-8 vCard 3/4 export -> import -> native -> contacts/search | Exported file coverage; not direct provider access or a complete address book |
| Ordinary SMS | Explicit supported provider collection or supported telephony backup | Device/version/permissions and selected Android user matter; RCS is separate |
| Photos/documents | Explicit authorized shared-storage paths | Live files can change; shared storage is not private app storage |
| WhatsApp/Signal/Discord | Supplied supported export or accessible extraction and required keys | Installed package/cache indicators do not establish acquired message history |
| Suspected compromise | Suitable acquired AndroidQF data or bugreport -> compatible MVT mode | IOC matches require examination; no match is not a clean-device certificate |

Android isolates app data through its application sandbox. Android 12 also
restricts `adb backup` app-data export for apps targeting API 31 or later, with
a debuggable-app exception. USB authorization alone does not establish access to
private chats. Do not change backup/security settings to make a failed route
appear supported. See [Android sandbox](https://source.android.com/docs/security/app-sandbox)
and [backup restrictions](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions).

## AndroidQF and MVT: useful, version-sensitive extensions

Current MVT documentation removes direct ADB analysis and recommends
`check-androidqf` for AndroidQF acquisitions and `check-bugreport` for standalone
bugreports. Local CLI help must confirm the selected mode. Do not route every
directory to `check-backup` or every file to `check-bugreport`: container type and
acquisition layout need explicit validation. See [MVT migration guidance](https://docs.mvt.re/en/latest/android/adb/).

Current AndroidQF upstream describes per-module acquisition status and hashes,
optional APK collection and collector deployment, and collection steps requiring
phone interaction. These are reasons for a preflight scope preview, not grounds
to run default collection automatically. Preserve partial-status metadata and
device-side effects alongside returned bytes. AndroidQF is an acquisition tool,
not universal private-app extraction. Its consent-based license also needs an
explicit workflow boundary. See [official AndroidQF documentation](https://github.com/mvt-project/androidqf/blob/main/README.md).

## Parser and index acceptance

ALEAPP parses existing extractions; it does not make unavailable files appear.
Keep the selected parser version, selected modules, source paths and original
outputs. Compare normalized fields and dates against source records, not only
the upstream HTML appearance. Treat dependency/module failures separately from
zero matching artifacts. See [ALEAPP usage and module documentation](https://github.com/abrignoni/ALEAPP/blob/main/README.md).

For contacts, check repeated numbers/emails, Unicode, folded values, exact record
references, source hashes, text search and formatted-number pivots. A vCard REV
is revision information about that card; it is not proof of contact creation or
communication. Missing timezone must not become assumed UTC. The current native
reader supports a conservative UTF-8 subset, not all vCard encodings/properties.
See [vCard REV definition](https://www.rfc-editor.org/rfc/rfc6350.html#section-6.7.4).

## Validation priorities

1. Qualify controlled phone collection and export/ingestion separately from
   synthetic tests. Record exact formats, expected fields, omissions and failures.
2. Fix gaps demonstrated through real index/query paths, preserving original
   artifacts and existing exact-number boundaries.
3. Qualify AndroidQF collection separately from the existing MVT output-analysis
   adapter. Verify each supported MVT mode against the installed version and
   retain provenance before advertising a complete compromise workflow.
4. Complete parser isolation qualification; an installed parser is not proof of
   filesystem/network containment. Do not trade away case isolation for speed.
5. Expand device/app coverage only with representative evidence and independently
   known expected records; broad lab completions are not substitutes for those
   contracts.

## Full acquisition: exact-device assessment

Record the device model, complete build, security patch, selected Android user,
authorization and access state before choosing a collection method. A successful
provider query does not establish access to private application files. A failed
read of one path does not establish the state of every private path. Record root
availability as unknown unless an explicitly authorized check establishes it.
A similar model or Android version is insufficient to qualify a method.

| Route | Implementation/access requirement | Current qualification |
|---|---|---|
| Accessible logical collection | Authorized ADB and individually supported providers, shared paths and diagnostics | Method-specific; record denied and omitted scopes |
| Existing private-app collector | Already authorized working root; three fixed app directories under user 0 | Selected app acquisition only: WhatsApp, WhatsApp Business and Signal; not FFS, not Discord or all users |
| Broader decrypted filesystem capture | Verified privileged reader, accessible storage classes/users and explicitly defined filesystem scope | Not implemented/qualified by the selected-app collector; requires a separately tested acquisition adapter |
| External specialist extraction | Exact device/build/security-patch and access-state support confirmed by the provider, then preserved extraction imported locally | Compatibility must be established for the examined device |
| Imported filesystem/image parsing | Already acquired supported evidence plus compatible parser | Analysis capability; does not establish device acquisition capability |

A logical collection and a decrypted filesystem acquisition should have separate
method names, coverage manifests and acceptance results. Neither automatically
establishes recoverable deleted data. A filesystem export is also distinct from
a raw partition image. A raw image can contain encrypted bytes rather than
readable app databases: Android's CE and DE storage classes have different key
availability, including per-user keys. See [AOSP file-based encryption](https://source.android.com/docs/security/features/encryption/file-based).

Do not unlock a bootloader as an evidence-preservation shortcut: the documented
unlock transition performs a factory reset. Device-specific availability differs.
Existing root must be observed and authorized, not installed by default. See [AOSP bootloader
state transitions](https://source.android.com/docs/core/architecture/bootloader/locking_unlocking).

LAWLIET does not provide a universal non-root full-filesystem acquisition route.
That limitation does not establish that no specialist method exists for a device.
Do not infer support from commercial marketing for other device generations or
from ALEAPP supporting an extraction format. Exact-build provider confirmation
and an actual acquisition test are needed before advertising compatibility.

### AndroidQF candidate pin and integration boundary

On this review date, the [latest release](https://github.com/mvt-project/androidqf/releases/tag/v1.8.3)
resolves to v1.8.3. Read-only remote tag resolution returned annotated tag
`5b707a6382847aeb1ddc4162ad6398bbbd45ca0e`, peeled commit
`472203c2395f7b07502d1f16b22a4d2900e35dda`. This pins a candidate for evaluation;
this source review does not qualify a downloaded executable or its binary digest.

Its [tagged README](https://github.com/mvt-project/androidqf/blob/472203c2395f7b07502d1f16b22a4d2900e35dda/README.md)
describes interactive choices and an acquisition folder beside the executable.
It documents a bundled on-device collector and optional backup/APK/intrusion-log
collection. This differs from newer `main` documentation describing streamed
archives, additional status metadata and unattended flags. Do not transplant
those newer interfaces into a v1.8.3 adapter without inspecting the exact source
and installed help.

For an eventual adapter: separate host installation approval from device-side
collector authorization; pin and verify host/collector artifacts; use an isolated
per-run staging location; retain choices, tool version and process logs; hash
returned evidence; record partial failures; then dispatch its recognized output
to the matching MVT mode. Preserve originals independently of derived output.
Use native macOS execution as the first candidate rather than assuming Linux
USB container instructions apply to macOS. This is logical/diagnostic acquisition
support, not a full-filesystem implementation.

### ALEX compared with AndroidQF

[ALEX](https://github.com/prosch88/ALEX) is an ADB-based logical acquisition
application with a CustomTkinter interface and GPL-3.0 licensing. Source review
at commit `4790ab34d66b68e6d78e48a7bc86f9d70e59bffd` also identifies conditional
root filesystem ZIP/TAR routes. These are candidate capabilities, not evidence
of non-root support for any particular build. Its relationship to UFADE does not
establish Android access or iOS capabilities in LAWLIET.

The pinned [entry source](https://github.com/prosch88/ALEX/blob/4790ab34d66b68e6d78e48a7bc86f9d70e59bffd/alex.py)
ties acquisition to GUI state. Its provider-text converter conflates printed
`NULL` and empty strings; use original responses rather than treating that JSON
as a lossless typed export. The [filesystem worker](https://github.com/prosch88/ALEX/blob/4790ab34d66b68e6d78e48a7bc86f9d70e59bffd/alex/devdump.py)
deploys a temporary device script and has root-dependent execution and exclusions.
Device modifications, explicit serial binding and failure propagation need
review before any adapter. Source inspection alone does not qualify execution.

Prefer AndroidQF as the first external diagnostic-acquisition candidate because
it has a documented MVT analysis path. Evaluate ALEX for complementary collection
after exact access and output contracts are established. Neither a tool registry
entry nor a root-only filesystem button resolves missing private-data access.
