# Automatic image review

The native artifact list displays thumbnails for acquired images automatically.
Selecting an image displays a larger preview inside Record details. **Open larger
preview** remains available for a separate window; it is no longer required for
routine image review. Video and audio still require explicit playback.

This uses the existing audited `preview` backend action. It verifies the source
and creates a derived copy in the case's `previews` directory. The native decoder
checks that copy's SHA-256 and its case-contained path before displaying it.
Original evidence is not edited. Automatic previews do append processing audit
records and create derived files, so they are not a read-only case operation.

Requests come from mounted list rows and the selected inspector. SwiftUI may
prefetch rows within the current paginated page. A single background worker
serializes preview requests; the selected inspector takes priority. Queued work
is dropped when its view disappears, and results from an old case cannot appear
in another case. Foreground processing pauses this queue and waits for its active
request to finish. This coordinates jobs within this app instance, not other
applications independently writing the same case.

List images are downsampled to 256 pixels and inspector images to 800 pixels,
with orientation applied. The queue holds at most 128 requests. The memory cache
targets 48 images / 32 MiB and retains mounted images even when that target is
exceeded. Cached images represent a previously verified byte snapshot; reopening
the larger preview runs verification again. They do not continuously verify the
original file in the background.

Automatic decoding accepts images up to 64 MiB, 100 megapixels and 20,000 pixels
on either axis. Animated images show their first frame. Missing attachment bytes,
unsupported codecs, integrity failures and unsafe paths remain explicit errors;
report references alone do not establish that original media was acquired.

## Validation on 2026-10-12

- Eleven focused native cache, subprocess and build-cache tests passed:
  `build/inline-media-tests.log`. These include queue serialization, case isolation,
  cancellation of queued work, cache reuse/eviction, tamper rejection, path
  containment and retry after correction.
- A synthetic case was created/imported/parsed with the installed backend. The
  native GUI automatically rendered its three PNG thumbnails and selected image;
  mouse and keyboard selection updated the inspector without a preview button.
  The backend integrity check passed for all three original files and the audit
  chain: `build/inline-media-ui-integrity.json`.
- A synthetic WebP passed the actual verified native decoder:
  `build/inline-webp-check.log`.
- The normal installed app was opened on `NATIVE-tc-333045cb`, the case in the
  user's screenshot. WebP/PNG/JPEG rows showed verified thumbnails and its selected
  WebP rendered automatically inside Record details. No manual preview was needed.
- The tested native executable was installed in the existing app. All 66 resource
  files, including its existing backend, were preserved. Signature verification
  passed; installation and reversible backup are recorded in
  `build/inline-media-installed.json`.

This validates the image review workflow, not acquisition completeness, every
media codec or other forensic engines. No physical-device collection, model call,
external evidence upload, customer report release or Linear operation was run.
