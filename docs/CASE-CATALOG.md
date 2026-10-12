# Local case catalog and draft history

The native Cases queue now discovers supported Lawliet databases across registered
folders and nested analysis outputs. Cases stay in their original locations.
`Case folders…` adds/removes references and separately selects where new cases are
created. Folder preferences survive restarts; removing a reference does not delete
files or allow a stale workspace preference to restore the removed reference.

Each queue row is identified by its canonical case-folder path. The backend still
receives that folder's parent workspace and actual case ID. Identical case IDs in
different locations remain separate. Search covers case ID, name, client, examiner
and location; status/priority/due filters retain their administrative meanings.
The table renders 50 cases per page. Selecting a case exposes its full path.

This is a catalog of existing Lawliet case databases. It does not automatically
merge replay/validation databases into one customer engagement or invent client
associations. Recovered technical runs therefore appear as separate rows, with
their containing folder shown. A future examiner-authored grouping can link them.

## Read-only discovery

`desktop/catalog_backend.py` is a small standard-library query helper bundled next
to the existing backend. The native background transport routes only `catalog`
and `report-history` to it. Existing acquisition, parser, search, metadata/task,
finding and draft-generation routes remain unchanged.

Discovery reads supported case metadata and open-task counts. It does not count or
read forensic artifacts, initialize schemas, migrate databases, parse evidence,
run Mulder or contact a device/provider. SQLite uses read-only immutable mode;
nonempty case WALs are explicitly refused so pending metadata is not represented
as current and no SHM/journal is created. Refresh after the writer checkpoints.
Unavailable/corrupt cases remain visible and cannot open; folder errors appear as
catalog notices. Unsupported case metadata schemas are not guessed.

Scanning stops at a case database. It skips symlinks, hidden folders and known
evidence/work/input/tool-output directories (see `SKIP` in the helper). Limits are
32 registered roots, 5,000 visited directories, 2,000 cases, 12 levels, 10,000 entries
per directory and 20 seconds. Omitted/inaccessible locations are disclosed. Add a
narrower case folder explicitly when a case lies in an intentionally skipped tree.
Metadata reads have a SQLite progress deadline and a 1 MiB value limit. Discovery
does not certify case integrity, original-device completeness or examiner review.

## Case report history

`Report history` lists existing `customer-drafts` bundles for the selected case,
50 per page. It shows draft ID, entry/source counts, investigation reference and
file-modified time. File time is not an investigative event or report creation
timestamp. The listing reads bounded manifests; it does not authenticate them.
Invalid/missing manifests are visible as unavailable, with their error.

`Review draft` opens the existing native integrity/citation reader. The reader
checks the bundle before displaying it and guards case path as well as case ID.
It keeps drafts unreviewed/unredacted and does not fetch URLs or attachments.
The reader can return to history. New drafts still use explicit selected findings
and the existing backend ledger/draft routes. Legacy arbitrary HTML/exports and
upstream Mulder reports are not newly indexed by this history; the existing agent
report viewer remains available for supported imported engine outputs.

## Validation

- `build/catalog-tests.log`: 41 focused checks passed (11 catalog plus 30 existing
  source/query/draft/transport/cache/coverage/report checks).
- `build/catalog-final-controls.log`: catalog checks repeated after the final
  persistence adjustment, including duplicate path identity and legacy-preference
  migration. `build/catalog-final-build.log`: native compilation and signature
  verification.
- Native queue found 61 local case databases in 237 visited directories; the
  measured helper discovery took approximately 0.05 seconds on this machine.
  Pages contained 50 and 11 rows. Searching opened the retained Android013 case.
- Its history listed one draft; double-click reopened ten interpretations and ten
  source snapshots without a file picker.
- Two synthetic `SAME` IDs in different folders opened distinct Alpha/Beta client
  metadata. The empty case showed no drafts rather than the preceding case's draft.
- GUI new-case rehearsal created `UX-CATALOG-NEW` in an explicitly selected isolated
  folder; `../invalid` disabled creation. Reference removal cleared active case
  context while leaving the case database present.
- Existing Android evidence/database hashes remained unchanged. Receipt:
  `build/ux-android13-readonly-check.json`. Synthetic fixtures are under
  `build/catalog-ux-fixture` and `build/catalog-ux-new-cases`.

The final packaging uses a frozen backend copied from the other session's verified
native015-context checkpoint, with all 57 Python source hashes compared before and
after copying. `build/catalog-backend-checkpoint.json` pins that copy. The optional
`desktop/build.py --backend-source` supports such a known checkpoint; default builds
still package repository source. No new forensic dependency is required.

Independent examiner approval/redaction/release, byte/SQLite inspection UI and
job-local navigation/cancellation remain separate work. No live collection,
remote model, customer release or Linear action was performed for this feature.
