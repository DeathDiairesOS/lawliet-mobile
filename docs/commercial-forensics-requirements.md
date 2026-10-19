# Commercial mobile forensics requirements

Research date: **2026-10-15**. This document translates primary guidance and
current repository evidence into engineering priorities. It is not certification,
an accreditation claim, or a guarantee of admissibility. “Implemented” means code
exists; “qualified” applies only to a recorded configuration and test scope.

## Current foundation and qualification boundary

Retain the Python standard-library backend, SQLite case index, native macOS GUI,
preserved imports, provenance, coverage ledger, search, timeline, findings and
report preparation. The [coverage ledger](../lawliet_mobile/coverage_ledger.py),
[native coverage view](../desktop/CoverageReviewView.swift) and
[coverage tests](../tests/test_coverage_ledger.py) distinguish collection, parsing,
search, review and verification.

The exercised agent route is **Codex -> patched Mulder MCP over stdio -> retained
tool outputs/indexed artifacts -> examiner review**. Mulder `investigate` is a
separate model orchestrator. Its legacy desktop launcher is not interchangeable
with the tested MCP route. The native screen now prepares a scoped, copyable
Codex request; it does not launch an agent or authorize data disclosure. An
in-app Codex launcher remains proposed. Native
review and deterministic parsing remain useful without either agent workflow.

Qualification must name the exact device, build, selected user, collection
method and independently known expected records. Synthetic tests and successful
processing of acquired evidence do not establish acquisition completeness,
atomic address-book capture or independent examiner signoff. Preserve command
errors even when the process exits zero; a rejected provider projection must
not become an empty-calendar conclusion. Device-specific collection records
belong in the retained case and its validation packet, not the source repository.

The practical service scope is acquired-evidence analysis plus explicitly
qualified logical collection. Accept a case only against its required evidence
and supported route. Escalate inaccessible private data or full-filesystem needs
for exact-device assessment and preserve/import the resulting supported evidence;
do not promise universal acquisition.

## Lessons from commercial workflows

These vendor examples inform workflow design, not LAWLIET device compatibility.

| Official workflow | Engineering lesson |
|---|---|
| [Oxygen Android Agent](https://www.oxygenforensics.com/technical-resources/android-agent/) | Logical collection and deeper internal-memory access have different methods and constraints. A review interface cannot supply missing acquisition access. Verify exact device/build support separately. |
| [Cellebrite Reader, part 3](https://cellebrite.com/en/ask-the-expert/cellebrite-reader-part-3-driving-your-investigation-with-reader/) | Connect search, tags, conversations, source files and review reports. Reader visibility depends on what the originating export included; omitted files and timeline content remain unavailable. |
| [Belkasoft Android WhatsApp analysis](https://belkasoft.com/android-whatsapp-forensics-analysis) | Let examiners pivot from conversations to the source SQLite record. Preserve database/backup provenance and distinguish attachment originals from thumbnails or missing files. |

Apply these lessons to existing artifact details, attachments and review exports
before expanding parser count.

## Prioritized requirements

### 1. P0 — Explain whether the case objective is answerable

**Scenario:** A customer requests a conversation timeline but only shared media
was collected. **Current:** coverage, run membership, exact expected-source
reconciliation and a read-only `case-assess` projection exist. Six scenario
summaries use inventory, coverage and processing state to show missing evidence,
failed processing and concrete next actions; the native case view exposes them.
**Next:** validate the complete installed workflow with representative customer
intake and an independent examiner.
Finding validity and report approval remain separate review workflows.
Never convert parsing success into collection completeness or review approval.
**Release evidence:** incomplete, zero-hit, unsupported and successful fixture
cases produce distinct assessments with traceable source/run references and no
case mutation. NIST tests declared supported functionality, not universal phone
coverage. [NIST mobile specification](https://www.nist.gov/document/mobile-device-forensic-tool-test-specification-v33).

### 2. P0 — Select acquisition using the actual device and required data

**Scenario:** “Can you retrieve WhatsApp, Signal or Discord messages?”
**Current:** ADB/provider/shared-storage routes and imported extractions exist;
private access and application formats constrain results. Existing selected
root-dependent app collection is not full filesystem. **Pending:** qualify each
method against device/build/profile/access state and define escalation/import
routes for unavailable data. AndroidQF is a candidate, not completed collection
support. **Release evidence:** expected versus returned records, denied paths,
operator interactions and device changes accompany every acquisition. SWGDE
emphasizes device-state-dependent acquisition and contemporaneous documentation.
[SWGDE acquisition guidance](https://www.swgde.org/documents/published-complete-listing/18-f-003-2/).

### 3. P0 — Preserve evidence and make provenance inspectable

**Scenario:** An examiner must explain a message in a dispute. **Current:** hashes,
audit records, source references, working copies and custody controls exist.
**Pending:** qualify the complete packaged workflow and every new adapter;
operator-entered identity is not authenticated identity. **Release evidence:**
the displayed value resolves to retained bytes, parser/run and source record;
changed inputs invalidate verification; interrupted work retains failure history.
Hash checks establish retained-byte integrity, not that a live phone collection
was exhaustive. Reuse the [custody implementation](../lawliet_mobile/custody.py)
and its [regression tests](../tests/test_custody.py).

### 4. P0 — Prove field fidelity with independently known content

**Scenario:** Incorrect sender, time or attachment changes the interpretation.
**Current:** synthetic controls, real extraction replays and scoped contact
comparisons exist. **Pending:** independent operator-created SMS/MMS/calls,
contacts and media acceptance across supported methods. **Release evidence:**
record exact expected fields, omissions, malformed input, permissions and
interruptions; compare raw output through index, GUI and export. Record test
version, procedure, tester and anomalies. SWGDE bases testing on function rather
than commercial/open-source origin; its mobile guidance requires known content.
[SWGDE tool testing](https://www.swgde.org/documents/published-complete-listing/18-q-001-minimum-requirements-for-testing-tools-used-in-digital-and-multimedia-forensics/).

### 5. P1 — Make search, time and database interpretation reproducible

**Scenario:** “What happened during these seven days?” **Current:** indexed search,
date filters, original fields and SQLite inspection/recovery paths exist.
**Pending:** qualify each supported format and timestamp meaning; preserve WAL
limitations and recovery uncertainty. **Release evidence:** Unicode, repeated
numbers, unknown timezone, daylight-saving boundaries, BLOBs and committed WAL
rows survive review/export. Keep undated records discoverable and record search
scope. A recovered candidate does not establish user deletion. Active SQLite
and deleted-data recovery require separate evaluation under the NIST specification.

### 6. P0 — Keep agent conclusions reviewable and operations bounded

**Scenario:** A customer suspects monitoring. **Current:** the collection endpoint
uses a saved, examiner-authorized plan and a restricted tool set; broader registry
presence does not qualify every operation. **Pending:** qualification of each
workflow's allowlist, evidence disclosure decisions and independent agent
evaluation. **Release evidence:**
source-backed observations remain distinct from hypotheses; unsupported claims
are rejected; prompt injection cannot authorize operations; failures and budget
stops remain visible. Negative IOC results describe examined evidence and rule
versions, never certify a clean phone. Record model/configuration, tool calls,
costs and reviewer corrections without exposing credentials.

MVT dispatch now distinguishes acquired AndroidQF, Android Backup and bugreport
inputs, retains partial failures, and rejects evidence outside the active case.
This is acquired-evidence analysis, not AndroidQF device collection or a validated
clean/compromised verdict. Qualify timestamp interpretation and case isolation
for each route; use LAWLIET's normalized timeline and one server per case.
See the [MVT dispatch tests](../tests/test_mulder_mvt_dispatch.py),
[temporal contract tests](../tests/test_mulder_temporal_contract.py) and
[case ownership boundary](MULDER-CASE-OWNERSHIP.md). Positive-finding finalization
gates must not cause fabricated findings in negative examinations.

### 7. P0 — Protect customer data throughout processing

**Scenario:** A case contains intimate media or unrelated third-party records.
**Current:** local storage, scoped exports, case boundaries and selected isolation
controls exist. **Pending:** complete parser isolation qualification; host LEAPP
execution still has unresolved filesystem/network containment. Local storage
alone does not establish local model processing. **Release evidence:** hostile
archives, paths, parser output and cross-case references cannot escape scope;
network policy is exercised; secrets stay outside routine logs/model context;
external evidence disclosure requires explicit authorization. Recovery backups
need verified restoration and an approved copy on separate storage.

### 8. P0 — Deliver an examiner-authorized, traceable report

**Scenario:** A client needs a defensible explanation and selected exhibits.
**Current:** source-linked drafts, integrity-bound local release and a limited
references-only redacted derivative exist. **Pending:** installed-GUI acceptance,
independent review and general binary/PDF/media redaction. **Release evidence:**
scope, authority, methods, limitations, evidence disposition and authorizer appear;
changed sources invalidate approval; amendments preserve prior reports.
Mulder output supports the examination report rather than approving itself.
[Report review implementation](../lawliet_mobile/report_review.py) and
[review-flow tests](../tests/test_report_review_flow.py);
[SWGDE report requirements](https://www.swgde.org/documents/published-complete-listing/18-q-002-swgde-requirements-for-report-writing-in-digital-and-multimedia-forensics/).

### 9. P1 — Make installation, licenses and maintenance supportable

**Scenario:** Another examiner clones the tool and repeats the case workflow.
**Current:** setup pins sources, patches and dependency versions; Python artifact
hash locking is incomplete, Homebrew packages roll, and optional tests may skip.
No LICENSE, NOTICE, SECURITY or CONTRIBUTING file was found in the non-ignored
publishing set; `pyproject.toml` has no project-license metadata. Choose and
document LAWLIET's license before describing a public release as open source;
this document does not select one. Dependency licenses remain separate.
**Pending:** dependency/license inventory, reproducible release qualification,
update regression policy and defect-to-affected-case tracking. **Release evidence:**
a fresh-machine receipt identifies versions, failures/skips and supported routes;
updates retain older case outputs and reversible runtime selection. Mulder's
[Apache 2.0 license](https://github.com/calebevans/mulder/blob/main/LICENSE) does
not cover other tools. [MVT](https://github.com/mvt-project/mvt/blob/main/LICENSE)
and [AndroidQF](https://github.com/mvt-project/androidqf/blob/main/LICENSE) impose
consensual-use conditions; evaluate the intended customer procedure and
redistribution obligations for each exact dependency before release.

## Delivery boundary

Prioritize a case assessment that exposes existing limitations, then close
scenario-specific acceptance gaps. Follow the [README](../README.md) fresh-machine
workflow and [Android research](android-acquisition-research.md). Record observed
test scope without turning regression counts into cases solved or overall
readiness percentages. These recommendations support a quality process;
[NIST CFTT](https://www.nist.gov/itl/csd/secure-systems-and-applications/computer-forensics-tool-testing-program-cftt)
provides testing methodology and reports, not a certification claim for LAWLIET.
