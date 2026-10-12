# Court-use engineering acceptance

Status: NOT QUALIFIED FOR COURT USE. This is a technical development assessment,
not a determination of admissibility. U.S. use is confirmed; state/federal forum and civil/criminal context
remain pending. Human examiner qualification, lawful authority and counsel review cannot
be established by a successful parser or generated report.

Guidance used: NIST SP 800-101 Rev.1 (2014),
https://csrc.nist.gov/pubs/sp/800/101/r1/final ; SWGDE 18-F-003-2.0
Best Practices for Mobile Device Evidence Collection & Preservation Handling and
Acquisition (2025),
https://www.swgde.org/documents/published-complete-listing/18-f-003-2/ .
These references are guidance, not product endorsements or certificates.

| Requirement | Current state | Required acceptance evidence |
|---|---|---|
| Authority, scope and device intake | Custody/device-state backend exists; UI and real operational intake incomplete | Actual operator entries, scope reference, device photographs, contemporaneous handling record |
| Preserve originals and transformations | Imported bytes, SHA-256 and run outputs retained; media grouping preserves raw observations | Repeated integrity and independently checked source-location rehearsal |
| Live device changes | ADB commands logged; live phone is not write-blocked | Record actual USB/debugging/network changes, device/host clock observations and collection limits |
| Chain of custody | Append-only API over locally editable hash chain | Identified handlers, real signatures, contemporaneous transfers; independently protected custody records and anchored receipts |
| Reproduce parser execution | Executable hashes, arguments, logs; external analyses now capture backend/Python fingerprints | Exact release build, tool versions/configuration/assets, dependency tree, repeatable representative fixtures |
| Time interpretation | Original EXIF fields preserved; explicit offset/subseconds normalized; unknown/conflicting offsets undated | Boundary/DST/precision fixtures and independent timeline comparison |
| Validate each offered method | Scoped Samsung SMS/contact/photo/Trash tests; acquired schemas and fixtures | Ground truth for each supported device/OS/app/schema; failures, false positives and unreturned artifacts documented |
| Explain recovery | Accessible Trash distinguished from carving; unstable copies fail hash agreement | Recovery-specific ground truth; no inferred deletion from missing rows or filename |
| AI findings | Source snapshots and interpretations separate; no automatic examiner approval | Exact prompt/model/tool trace where used; verify every factual claim and citation; record corrections and independent review |
| Court exhibits | Draft/approval/local-release integrity gates exist | Exact reproducible exhibits with provenance, source hashes, scope, limitations and report author/reviewer identities |
| Redaction | General redacted delivery unsupported; separate internal masking work in progress | Independent canary checks over attachments, metadata, indexes, previews and all released formats |
| Secure storage | Case is plaintext on local storage; hashes do not stop rewriting | Approved encrypted storage, access control, retention and independent backup/anchor procedure |

Release rule: preserve and report unknowns. Never substitute invented identities,
authority, signatures, custody history, validation outcomes or reviewer approval.
Do not label a tool or result court-ready solely because tests pass. ADB-read-only
commands do not establish an unchanged live device. Hash equality establishes
byte agreement under this collection method, not photographic truth or legal
admissibility. EXIF/GPS are editable metadata claims.

For this owned-phone test the declared capture time is
2026-10-12T01:10:56.343000Z (October 11, 2026 at 9:10:56.343 PM New York).
Trash copies matching the original photo SHA-256 demonstrate accessible Trash
collection only. Permanent-deletion recovery remains unqualified.

U.S. federal reference (December 1, 2025 rules):
https://www.uscourts.gov/sites/default/files/document/federal-rules-of-evidence.pdf
Rule 901 addresses authentication, including explaining a process/system and its
accuracy. Rule 702 addresses qualified expert testimony, sufficient facts and
reliable methods applied reliably. Rules 902(13)/(14) provide certification routes
for certain electronic records/copied data, with qualified-person certification
and notice requirements. Hashes alone are not those certifications. These are
engineering reference points; applicable state rules, legal authority, hearsay,
other objections and proceeding-specific requirements require legal review.
