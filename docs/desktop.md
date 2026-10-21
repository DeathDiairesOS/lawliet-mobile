# Shared LAWLIET desktop

The optional shared desktop opens a native application window on Windows, macOS
and Linux. It reuses the case database, collectors, parsers, evidence protection
and reporting APIs. There is no browser login, local HTTP listener, database
server or cloud requirement. The existing Swift app remains available on macOS.

This is a preview while operating-system qualification continues. The shared
interface is not yet feature-identical to Swift. Platform-specific tool support
is separate from desktop rendering support.

For the installed-app inventory and selected message/contact database profiles,
see [bounded iPhone acquisition](iphone-bounded-acquisition.md). Their storage,
pairing and device-specific qualification limits are separate from the synthetic
desktop workflow below.

## Validation status

At `59c4f35`, the installed native application passed the complete synthetic
Android **collection → automatic parsing → examination → reviewed report export
→ fresh-process restart** workflow on Windows, macOS and Linux. All three hosted
runs and their independent-field comparison passed in
[run 39475712473](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39475712473).
The [retained comparison](desktop-qualification-result.json) identifies exact
versions, source commit, field fingerprints and receipt hashes.

| Host | Native desktop workflow | Remaining scope |
| --- | --- | --- |
| macOS | macOS 15.7.9 Intel, Cocoa/WebKit; supplementary local Apple Silicon pass at `9a6c16e` | Restricted agent endpoint needs a qualified Mulder setup |
| Windows | Windows Server 2025, WebView2 | Physical USB/drivers and upstream-tool compatibility need device-specific qualification |
| Linux | Ubuntu 24.04 x86_64, Qt/Xvfb | Physical USB permissions and upstream tools need separate checks |

The five Android methods are SMS provider, contacts provider, explicit shared
files, diagnostics/package inventory and accessible Trash. Their fixed synthetic
subprocess responses produce ten expected observations. A separate frozen import
supplies eleven observations and a missing-WAL control. Original/collected hashes,
precise source citations and both report packages are checked. No customer data,
physical phone, external model or customer delivery is involved.

This establishes a working host software path; it does not establish complete
phone access, app-private data availability or identical tool coverage on every
OS. See the [qualification scope](desktop-qualification.md).

## Install from the reviewed repository

Use Python 3.11–3.13 for the desktop dependency environment. The backend separately
tests Python 3.11 and 3.14. Run these commands from the repository clone. The
virtual environment holds application dependencies, never case evidence.

Windows 10/11, PowerShell:

```powershell
py -3.11 -m venv .desktop-venv
.\.desktop-venv\Scripts\python.exe -m pip install ".[desktop]"
.\.desktop-venv\Scripts\lawliet-desktop.exe
```

Microsoft Edge WebView2 Runtime and .NET Framework 4.8 or newer must be available.
The app explicitly requests Edge Chromium; it does not fall back to Internet
Explorer. Obtain missing runtime prerequisites from Microsoft. The Python
installation and WebView2 architecture must be compatible.
Windows analysis staging requires a volume that supports the verified Windows
permissions and handle operations, such as NTFS; unsupported storage returns an
error instead of silently dropping those protections.

macOS:

```sh
python3 -m venv .desktop-venv
.desktop-venv/bin/python -m pip install '.[desktop]'
.desktop-venv/bin/lawliet-desktop
```

macOS uses the system WebKit renderer through PyObjC. This command does not replace
an existing `/Applications/LAWLIET.app`. The established Apple Silicon setup path
in the README still builds the native Swift application.

Linux with Qt (Ubuntu CI exercises this route):

```sh
python3 -m venv .desktop-venv
.desktop-venv/bin/python -m pip install '.[desktop-qt]'
.desktop-venv/bin/lawliet-desktop --renderer qt
```

Qt requires host display libraries in addition to its Python packages. For the
Ubuntu 24.04 X11 route used in CI, install the runtime dependencies below:

```sh
sudo apt-get install --no-install-recommends -y \
  libegl1 libopengl0 libx11-xcb1 libxcb-cursor0 libxkbcommon-x11-0 \
  libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 \
  libxcb-shape0 libxcb-randr0 libxcb-xfixes0 libxcb-sync1 libxcb-shm0 \
  libxi6 libxrender1 libfontconfig1 libsm6 libice6 libnss3 libasound2t64
```

The list follows [Qt's X11 requirements](https://doc.qt.io/qt-6/linux-requirements.html),
plus OpenGL and WebEngine runtime libraries. Package names vary by distribution.
CI adds `xvfb` and `xauth` to provide a virtual display; an ordinary desktop session
already provides its display. CI also checks the installed Qt plugin's linked
libraries before launch. An xcb loader error can indicate a missing dependency
other than the cursor library named in Qt's generic message.

Alternatively, use the smaller system GTK/WebKit renderer with the `desktop`
extra and your distribution's PyGObject, GTK 3 and WebKitGTK 4.1 packages; Python
must be able to import the system `gi` bindings. GTK is not the automated Linux
qualification route yet. See [pywebview prerequisites](https://pywebview.flowrl.com/guide/installation.html).

Cases default to `~/Documents/LAWLIET/cases`. Select another workspace inside the
app, or pass `--workspace /absolute/path/to/cases`. The selected workspace applies
to the running session; use a launcher argument to retain a custom choice. No
cases are copied, migrated or deleted automatically.

## Included workflow

1. Create a case, record the objective and scope, and assign examiner tasks.
2. Import authorized evidence using the native file/folder picker. Run compatible
   existing native, LEAPP or configured ExifTool analysis.
3. Search paginated artifacts, filter by source/category, inspect original values
   and hashes, use the timeline, and inspect retained files or SQLite records.
4. View verified raster media automatically on selection. Previews are cached
   within bounds and resized for display; originals remain preserved.
5. Save examiner findings. Prepare a source-bound report, inspect verified text,
   record explicit approval and export the approved bytes with a release receipt.

The acquisition view uses explicit device detection, preflight and authorization
before invoking the existing collectors. Forensic tools and device drivers must
be installed separately. The synthetic subprocess qualification exercises these
controls; actual USB collection and device permissions still require separate tests.

The agent screen prepares, authorizes and monitors existing scoped plans; it does
not create a new LLM agent or silently send evidence to a model. The restricted
Codex/Mulder collection endpoint still requires macOS. Windows/Linux desktop
availability does not make that endpoint portable. MVT imports require a supported
retained bundle and its validated provenance; raw arbitrary JSON is not accepted.

## Current limits

- The host collection workflow and broad backend suites pass on Windows, macOS
  and Linux; see the [qualification scope](desktop-qualification.md).
  These results do not qualify collection on customer phones. The restricted
  Mulder collection endpoint remains macOS-only because its process sandbox is
  platform-specific; direct collectors and the acquisition GUI work independently.
- No one-click signed Windows/Linux installer is included yet. The installed
  `lawliet-desktop` entry point launches the desktop application from its venv.
- Optional forensic tools, physical USB methods and remote providers need separate
  installation, authorization and method-specific testing on each host platform.
- Device mirroring, inline audio/video/HEIC playback, report-redaction editing and
  some native Swift specialized controls are not implemented in this interface.
- Inline media is limited to 16 MiB, verified report text to 2 MiB and backend
  replies to 32 MiB. Oversized results return a visible error; query smaller sets.
- Closing the window stops owned workers; interrupted evidence processing remains
  visible in case history. Do not assume an interrupted collection can resume.

## Validation and trust boundary

Run `python -m unittest tests.test_android_qualification tests.test_desktop_bridge tests.test_desktop_smoke_controller -v`
for synthetic parser, bridge and receipt checks without GUI dependencies. Run a
native-window qualification with an empty dedicated workspace and a new result
path:

```sh
python -m lawliet_mobile.desktop --workspace /tmp/lawliet-desktop-check \
  --smoke-test /tmp/lawliet-desktop-result.json \
  --smoke-collection /absolute/path/to/lawliet-mobile/tests/fixtures/collection_adb.py
```

Use unused local paths on Windows instead of `/tmp`. The test creates and imports
through the actual forms, compares parsed fields and provenance with the frozen
oracle, filters the timeline, inspects source bytes, queries SQLite including WAL
records, previews media and saves a finding. It checks visible missing-input errors
and a missing-WAL control. Instruction-like and HTML-looking messages must remain
literal evidence text.

The test prepares a report, verifies export is disabled before approval, records
an explicit **synthetic-only** examiner declaration and exports locally. It checks
the complete package and exact selected citation, then launches a fresh native
process to reopen the case and approved report. Source hashes must remain equal
to the frozen inventory. The explicit `--smoke-collection` option substitutes
both discovery tools, then runs all five collectors against the test subprocess
and exercises a second finding/report. No real phone is discovered or collected,
no model is called, and no report is delivered to a customer. Synthetic paths
replace only the OS file picker; the application's import, approval and export
handlers still run.

The receipt, restart log and synthetic fixture are retained beside the selected
output path for replay. A result of `ok: true` applies to this bounded corpus and
workflow. The [qualification guide](desktop-qualification.md) describes independent
answer checks and host comparison. `.github/workflows/desktop.yml` runs installed
native windows on all three hosts and uploads synthetic receipts and logs.

The application loads only packaged HTML/CSS/JavaScript; evidence is rendered as
text, never as an HTML report. CSP blocks network resources and unapproved scripts.
pywebview 6 requires `unsafe-eval` for its trusted generated API stubs; inline
scripts still need the packaged source hash. The bridge allowlists backend actions,
uses subprocess argument arrays, caps requests/results, binds actions to the chosen
workspace and requires native picker grants for import/export paths. Credentials
are not written by the bridge. This is a local application boundary, not a sandbox
for malicious native forensic parsers; use isolated examination hosts as required.

pywebview is optional and distributed separately under BSD-3-Clause. Its renderer
and transitive dependencies retain their own licenses; the Qt route adds Qt
licensing and a larger runtime. No third-party binary has been vendored here.
