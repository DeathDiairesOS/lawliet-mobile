# Android screen mirroring and control (macOS)

Choose **Connected device** in Lawliet Mobile’s sidebar. No case selection is
required. When the sidebar is hidden, the same button appears in the bottom bar.
The existing **Process → Android screen & control** entry also remains available.
Opening this panel starts USB discovery only. Nothing starts viewing or control
when a phone connects. Discovery polls every three seconds while the panel is
open; brief connections between polls may be missed.

## Dependencies and launch

Python 3.11+, the existing SwiftUI macOS application (macOS 13+), Android SDK
Platform Tools (`adb`) and scrcpy are required. No Python packages were added.
Install optional tools deliberately, for example with Homebrew:

```sh
brew install scrcpy
brew install --cask android-platform-tools
```

The integration checks tool versions and required flags. Use a released scrcpy
3.x with `--display-orientation`, `--no-control`, `--no-audio`,
`--no-clipboard-autosync` and `--no-power-on`. Older incompatible versions fail
with an upgrade message. Capability checks do not establish device compatibility.
No tools are bundled or automatically installed. scrcpy is Apache-2.0; SDL,
FFmpeg and Android Platform Tools have their own license/distribution notices.

Executable discovery reuses Lawliet's PATH and tools.json configuration. Finder
may give an app a different PATH from Terminal. If needed, configure the tools
for the workspace used by the application (resolve the paths with `command -v`):

```sh
python3 -m lawliet_mobile --workspace /path/to/cases tools configure adb /path/to/adb
python3 -m lawliet_mobile --workspace /path/to/cases tools configure scrcpy /path/to/scrcpy
python3 desktop/build.py --workspace /path/to/cases
open 'dist/Lawliet Mobile.app'
```

Run these commands from the repository root. ADB must be a native executable for
scrcpy. This release enables the desktop adapter on macOS. Backend process
separation allows later Windows/Linux adapters; the current audit locking,
process groups and SwiftUI UI have not been ported to Windows.

## Connecting and viewing

On the Android device, enable Developer options (typically tap Build number
seven times) and USB debugging. Use a data-capable USB cable. Review and approve
the host authorization prompt on the unlocked device. This tool does not bypass
locks or authentication. Multiple USB devices are listed; select an explicit
serial. Unauthorized and offline devices remain visible but cannot start viewing.
Manufacturer/model/Android version are read only after ADB authorization.
Network transports and emulators are excluded from this panel.

Acknowledge the state-change notice and click **Start viewing**. The live display
opens in a separate, managed scrcpy window. Resize it normally; scrcpy preserves
the aspect ratio and follows the phone's orientation. **Rotate display** restarts
the session with the displayed image rotated 90 degrees; it does not change the
phone's orientation setting. Rotation and control changes create separate,
logged mirroring sessions.

Click **Enable device control** explicitly to restart scrcpy with input enabled.
Mouse clicks, drags, scrolling and keyboard input work in its window. Back, Home
and Recent apps buttons in Lawliet send individually audited ADB key events.
Scrcpy shortcuts (default MOD is left Alt or left Super/Command) also support
MOD+b, MOD+h and MOD+s for navigation. **Disable device control** restarts viewing
with `--no-control`. New sessions always start with control disabled.

**Stop mirroring**, **Disconnect session**, closing the panel, or quitting the
application stops its owned process. Disconnect session leaves the USB cable and
shared local ADB service connected. The local ADB daemon is not killed. Removing
the phone, losing authorization or discovery failure terminates mirroring. A
scrcpy window closed by the investigator is recognized during the next poll.

## Forensic limits and audit

USB debugging, ADB discovery and scrcpy are not forensically read-only or
non-invasive. Viewing uses scrcpy's `--no-control` input suppression. It still
copies and executes a temporary server on the device and can alter logs and
other state. Explicitly enabling control can change app/device state and evidence.
Audio capture, automatic clipboard synchronization and automatic screen power-on
are disabled. Manual scrcpy clipboard shortcuts remain possible in control mode.

A filtering ADB launcher records scrcpy's ADB command arguments and blocks APK
installation, arbitrary file pushes, network setup and unrecognized commands.
Only the temporary scrcpy server upload is permitted. APK/file drops therefore
fail instead of installing an app or copying investigator files. This is an
integration guard, not a sandbox for malicious substituted executables.

**Open audit log** displays the session's local UTC JSONL journal inside Lawliet.
Search events or command details, select an event to inspect its fields and original
JSONL, and use Refresh to load newly appended events. Back to device returns to
the controls without closing the device service. Show log in Finder reveals the
original file under the workspace's `.device-interaction/` directory. The viewer
reads at most the latest 2 MB and 1,000 complete events, marks unreadable lines,
and waits for incomplete writes; it never edits the journal. It records discovery observations, status changes,
Lawliet navigation, start/stop requests, control/rotation changes, session times,
Lawliet ADB command results and scrcpy ADB invocations/blocked requests. Each panel
instance has a unique log, outside imported evidence. The journal contains device
identifiers and command arguments; keep it with approved local investigation
records. It is not automatically attached to a case, immutable, or independently
signed. App crashes/power loss may leave no final stop event; an open session is
not proof that mirroring completed normally.

Standard scrcpy exposes no per-input audit API. Individual taps, swipes, typed
text, scrolling and shortcuts inside its window are **not individually logged**.
The UI discloses this limitation. Use Lawliet navigation buttons when an individual
navigation audit record is required. No screen video or screenshots are retained.
No device identifiers or journal contents are sent to external telemetry.

Embedding scrcpy's separate SDL process in SwiftUI/AppKit has no supported
cross-process view API. This implementation uses the user-authorized separate
window fallback, with native scrcpy video/input handling. It does not implement a
streaming protocol or repeated ADB screenshots. Protected/secure app screens may
be blank and OEM input restrictions may prevent control.

## Troubleshooting

- Missing tools: install them yourself and configure their native paths for the
  selected workspace; reopen the panel after configuration.
- Unauthorized: unlock and authorize on the phone. Offline: inspect cable/port,
  USB debugging state and competing tools; reconnect and refresh.
- Start failure: read the error text and audit journal, check the scrcpy version
  and OEM restrictions. Unknown scrcpy ADB commands fail closed; newer releases
  may require an adapter update.
- Input unavailable: explicitly enable control. Some OEMs require an additional
  USB debugging/security setting. Establish authorization through normal device
  settings; no bypass is offered.
- ADB service errors stop the session instead of implying a disconnected phone
  was successfully examined. Startup is marked `starting` until scrcpy reports a
  video texture; a running child alone does not prove frames were displayed.

Upstream references: [scrcpy](https://github.com/Genymobile/scrcpy),
[control](https://github.com/Genymobile/scrcpy/blob/master/doc/control.md),
[shortcuts](https://github.com/Genymobile/scrcpy/blob/master/doc/shortcuts.md),
[ADB](https://developer.android.com/tools/adb).
