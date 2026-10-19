# Mulder review case ownership

A retained review belongs to one Mulder parent case instance. Sharing the same
`db-dir/lawliet-review` directory does not authorize reading a sibling review.
Native, export and SQLite recovery creators bind their new reviews automatically.
Switching the active Mulder case changes which reviews its tools may access.

For an existing operator-created review, bind it explicitly before using the
restricted SMS or parser profile. Close competing work on that review first:

```sh
python3 lawliet --workspace /absolute/db-dir/lawliet-review --json tools bind-mulder-review \
  --case REVIEW-ID --parent-case-db /absolute/db-dir/PARENT-ID.db
```

Both databases must already exist. This appends a review audit event; it does not
create the parent or silently reassign an already bound review. Select the
corresponding parent when starting Mulder. A recreated parent with the same name
is a different instance and cannot inherit the old binding.

Historical unbound native, export and recovery reviews can be read without
rewriting their audit when the active parent index contains the exact retained
path in a reserved producer header. Unverified membership is refused; it is not
inferred from directory placement or ordinary evidence text.

The guard applies to retained review tool calls, including query, files,
inspection, SQL, findings, SMS collection and isolated ExifTool. It is a review
API boundary, not an operating-system access control or authentication of
privileged edits to databases and indexes. Current integration qualification uses
one Mulder worker; it does not establish concurrent case-switch isolation.
