# Shared LAWLIET desktop

The optional shared desktop opens a native application window on Windows, macOS
and Linux. It reuses the case database, collectors, parsers, evidence protection
and reporting APIs. There is no browser login, local HTTP listener, database
server or cloud requirement. The existing Swift app remains available on macOS.

This is a preview while operating-system qualification continues. The shared
interface is not yet feature-identical to Swift. Platform-specific tool support
is separate from desktop rendering support.

## Validation status

The installed native window passed the synthetic case-to-report flow on all three
hosts in [run 39189489660](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39189489660).
This establishes the desktop workflow; it does not establish identical forensic
tool coverage or physical phone acquisition on every OS.

| Host | Native desktop workflow | Backend qualification | Restricted agent collection endpoint |
| --- | --- | --- | --- |
| macOS | Passed, system WebKit | Required CLI checks and Apple Silicon installation pass | macOS only; separate qualified Mulder setup |
| Windows | Passed, WebView2 | Review preview; broader regression suite still fails | Unavailable on this host |
| Linux | Passed, Qt under Xvfb | Required CLI checks pass | Unavailable on this host |

The native smoke tests use the same Python backend as the CLI. Optional upstream
parsers, local device drivers, USB interactions and provider configuration still
need their own checks. No customer data is included in CI.

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
be installed separately. A rendered acquisition view does not prove successful
USB collection on that OS or complete access to a phone.

The agent screen prepares, authorizes and monitors existing scoped plans; it does
not create a new LLM agent or silently send evidence to a model. The restricted
Codex/Mulder collection endpoint still requires macOS. Windows/Linux desktop
availability does not make that endpoint portable. MVT imports require a supported
retained bundle and its validated provenance; raw arbitrary JSON is not accepted.

## Current limits

- Windows backend qualification remains incomplete. At `e928391`, the Python
  3.14 broad suite ran 1,392 tests and reported 36 failures and 151 errors (351
  skips). The targeted ownership tests and expanded native GUI passed separately.
  Remaining issues include POSIX-specific provider collection staging, container
  workflows and test fixtures. These are not all harmless test differences. Treat
  Windows as a review preview; do not use its collection routes on customer phones
  until method-specific qualification is complete. The restricted agent endpoint
  remains macOS-only. [Broad run](https://github.com/DeathDiairesOS/lawliet-mobile/actions/runs/39189489574).
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

Run `python -m unittest tests.test_desktop_bridge tests.test_case_catalog -v` for
real synthetic backend/bridge checks without GUI dependencies. Run a native-window
smoke with an empty dedicated workspace:

```sh
python -m lawliet_mobile.desktop --workspace /tmp/lawliet-desktop-check \
  --smoke-test /tmp/lawliet-desktop-result.json
```

Use unused local paths on Windows instead of `/tmp`. The smoke actually creates,
imports, parses, filters and searches artifacts, opens source details, submits a
read-only SQLite query through the actual dialog, verifies a media preview, saves
a finding, opens a report and rechecks evidence hashes. It also checks that an
HTML-looking source message remains literal text. It performs no USB discovery, collection,
model calls, report approval or customer release. A result of `ok: true` is scoped
to those synthetic checks. `.github/workflows/desktop.yml` runs the window check
on Windows, macOS and Linux and retains the result and logs.

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
