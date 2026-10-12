# Media item view

The desktop Media view presents one item per acquired byte-identical file content, identified by the case file inventory SHA-256 and byte count. This is a content grouping, not proof of a single capture event or acquisition. Native media-index and ExifTool observations remain immutable individual artifacts with distinct evidence IDs, file IDs, parser identities, source locators and fields. Unknown/report-only media remains separate. Names alone never group files.

Grouping occurs after evidence/parser/run/search/date filters and before pagination. Observation details include only rows matching that scope, are bounded to 20 per item, and disclose truncation and total observation count. The preferred matching native artifact keeps its real artifact/file identity for preview and examiner findings. ExifTool supplies the display summary and readable metadata fields when present; conflicting/repeated observations remain in provenance. No timestamps are inferred or changed.

Desktop media-only exports use the same grouping and retain original observations in the derived `media_item` envelope. Raw core queries and other views remain parser-observation records. Sidebar media counts report grouped content items; `media_observation_count` and raw total retain their separate meaning. No source evidence, findings or original artifact rows are deleted or rewritten.

Tests cover preservation, distinct-byte files, scoped search/evidence/parser/run behavior, pagination before limits, media export consistency, report-only exclusions, and bounded provenance. The owned-phone test JPEG has original native, ExifTool and accessible Samsung Trash acquisition observations; these form one content item.

The Trash test read a still-existing file from Samsung Gallery shared-storage Trash and compared its SHA-256 with the pre-deletion baseline. It is not permanent-deletion, unallocated-space, encryption-bypass or general-device recovery validation.

## Trash photos UI

The Trash photos view selects only media file IDs with recorded `ancalor-android-trash-acquisition-v1` receipts. A receipt must belong to the same case, declare a supported Android shared-storage Trash path and read-only ADB method, and match the acquired file byte count and before/after/acquired SHA-256 values. Registration records an audit entry. It is a local acquisition record, not independent authentication of the phone state.

A missing file, a filename containing deleted, or zero search results cannot create a Trash classification. Evidence/parser/run filters continue to limit observations and origins. Existing cases without origin records show an empty Trash view; no source migration guesses are performed. The UI states that it is displaying recorded Trash acquisitions rather than scanning the phone or proving permanent-deletion recovery. ExifTool and native observations of the acquired Trash copy remain attached to one media item.
