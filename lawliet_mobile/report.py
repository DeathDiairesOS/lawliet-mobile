"""Portable exports; no web server, CDN, or third-party assets."""
import csv
import html
import json
from collections import Counter
from pathlib import Path

from .core import UserError, audit, now, select_artifacts, verify
from .correlate import shared_entities


def safe_output(root, db, destination, create_parent=True):
    path = Path(destination).expanduser().resolve()
    evidence_dir = root / "evidence"
    if path == root / "case.sqlite" or path == evidence_dir or evidence_dir in path.parents:
        raise UserError("Output must not overwrite case metadata or imported evidence.")
    for row in db.execute("SELECT input_path FROM evidence"):
        source = Path(row[0])
        if path == source or (source.is_dir() and source in path.parents):
            raise UserError("Output must not overwrite the original evidence input.")
    if create_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


def paired_output_paths(root, db, destination):
    """Validate output scope without creating through an untrusted path."""
    requested=Path(destination).expanduser()
    # macOS exposes its temporary-directory roots through system aliases.
    # Normalize only these fixed OS paths; arbitrary export links stay refused.
    import sys
    if sys.platform=='darwin' and requested.is_absolute() and len(requested.parts)>1 and requested.parts[1] in {'var','tmp','etc'}:
        requested=Path('/private').joinpath(*requested.parts[1:])
    if requested.is_symlink():raise UserError('Export destination must not be a symlink.')
    path=safe_output(root,db,requested,create_parent=False)
    # Do not let resolution authorize a different directory through a link.
    if requested.absolute() != path:
        raise UserError('Export destination must not contain a symlink or parent traversal.')
    raw_companion=Path(str(path)+'.coverage.json')
    if raw_companion.is_symlink():raise UserError('Coverage companion must not be a symlink.')
    companion=safe_output(root,db,raw_companion,create_parent=False)
    if path.exists() or companion.exists() or companion.is_symlink():
        raise FileExistsError('Choose a new export filename and coverage companion.')
    return path, companion


def write_jsonl_export(root, db, destination, records, scope_filters=None):
    """Stream JSONL with privacy-minimal coverage; clean both new files on failure."""
    from .anchored_output import OutputFiles
    from .coverage_ledger import _iter_entries, portable_summary
    from .acquisition import case_coverage
    from .portable_coverage import checked_scope, bounded_json
    context_scope=checked_scope(db,scope_filters)
    path, companion=paired_output_paths(root,db,destination)
    count=0;eids=set();pairs=set();scope_known=scope_filters is not None
    scope_filters={} if scope_filters is None else scope_filters
    outputs=OutputFiles([path,companion])
    db.execute('SAVEPOINT streaming_jsonl_export')
    try:
        with outputs:
            with outputs.open(path) as stream:
                for record in records:
                    stream.write(json.dumps(record,ensure_ascii=False)+'\n')
                    count+=1
                    if record.get('evidence_id'):eids.add(record['evidence_id'])
                    if record.get('evidence_id') and record.get('logical_path'):pairs.add((record['evidence_id'],record['logical_path']))
            acquisition=case_coverage(root,db,include_ledger=False)
            portable=portable_summary({'entries':_iter_entries(root,db,acquisition)},
                {'format':'jsonl','records':count,'evidence_ids':eids,'source_pairs':pairs,'truncated':False if scope_known else None,**context_scope})
            portable['export_scope'].update(selection=('filtered' if scope_filters else 'whole-case-indexed-records') if scope_known else 'provided-record-window',
                extent='unbounded-indexed-scope' if scope_known else 'unknown',
                empty_result=count==0,filter_fields=sorted(scope_filters))
            portable['export_sha256']=outputs.digest(path)
            encoded=bounded_json(portable)
            with outputs.open(companion) as stream:
                stream.write(encoded)
            result={'path':str(path),'records':count,'coverage_path':str(companion),
                    'sha256':portable['export_sha256'],'coverage_sha256':outputs.digest(companion)}
            outputs.publish()
            audit(db,'export.created',{**result,'format':'jsonl','scope_filter_fields':sorted(scope_filters),
                                      'independent_examiner_signoff':False})
            outputs.check_parent()
            if outputs.digest(path)!=result['sha256'] or outputs.digest(companion)!=result['coverage_sha256']:
                raise UserError('Export changed before audit completion.')
            db.execute('RELEASE SAVEPOINT streaming_jsonl_export')
            return result
    except BaseException:
        db.execute('ROLLBACK TO SAVEPOINT streaming_jsonl_export')
        db.execute('RELEASE SAVEPOINT streaming_jsonl_export')
        raise


def write_export(root, db, destination, format_name, records):
    if format_name == 'jsonl':
        return write_jsonl_export(root,db,destination,records)['path']
    from .coverage_ledger import portable_summary, source_pairs
    from .acquisition import case_coverage
    from .portable_coverage import bounded_json
    path, companion = paired_output_paths(root, db, destination)
    from .anchored_output import OutputFiles
    outputs = OutputFiles([path, companion])
    db.execute('SAVEPOINT paired_export')
    try:
        with outputs:
            with outputs.open(path) as handle:
                if format_name == "json":
                    handle.write(json.dumps(records, indent=2, ensure_ascii=False) + "\n")
                else:
                    fields = ["id", "evidence_id", "category", "timestamp", "timestamp_raw", "title", "body", "logical_path", "source_ref", "source_sha256", "parser"]
                    def cell(value):
                        value = str(value) if value is not None else ""
                        return "'" + value if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    for record in records:
                        writer.writerow({key: cell(record.get(key)) for key in fields})
            coverage = portable_summary(case_coverage(root, db)['ledger'], {
                'format': format_name, 'records': len(records), 'truncated': None,
                'evidence_ids': [r['evidence_id'] for r in records if r.get('evidence_id')],
                'source_pairs': source_pairs(records)})
            coverage['export_scope'].update(selection='provided-record-window',
                extent='unknown', truncated=None, empty_result=not records)
            coverage['export_sha256'] = outputs.digest(path)
            encoded = bounded_json(coverage)
            with outputs.open(companion) as handle:
                handle.write(encoded)
            companion_sha = outputs.digest(companion)
            outputs.publish()
            audit(db, "export.created", {"path": str(path), "format": format_name,
                "records": len(records), "coverage_path": str(companion),
                "sha256": coverage['export_sha256'], "coverage_sha256": companion_sha,
                "independent_examiner_signoff": False})
            outputs.check_parent()
            if outputs.digest(path) != coverage['export_sha256'] or outputs.digest(companion) != companion_sha:
                raise UserError('Export changed before audit completion.')
            db.execute('RELEASE SAVEPOINT paired_export')
            return str(path)
    except BaseException:
        db.execute('ROLLBACK TO SAVEPOINT paired_export')
        db.execute('RELEASE SAVEPOINT paired_export')
        raise


def write_report(root, db, destination, filters=None, preview_limit=None):
    filters = {} if filters is None else filters
    from .portable_coverage import checked_scope
    context_scope = checked_scope(db, filters)
    if preview_limit is not None and (type(preview_limit) is not int or not 1 <= preview_limit <= 10000):
        raise UserError('Preview limit must be an integer between 1 and 10,000.')
    path, companion = paired_output_paths(root, db, destination)
    records = select_artifacts(db, limit=preview_limit + 1 if preview_limit else 100_001, **filters)
    truncated = bool(preview_limit and len(records) > preview_limit)
    if preview_limit:
        records = records[:preview_limit]
    if len(records) > 100_000:
        raise UserError("HTML reports are limited to 100,000 records; use --category messages, --app, --evidence or date filters, or export JSONL.")
    meta = dict(db.execute("SELECT key,value FROM meta"))
    evidence = list(db.execute("SELECT * FROM evidence"))
    runs = list(db.execute("SELECT * FROM runs ORDER BY started_at"))
    integrity = verify(root, db)
    from .acquisition import case_coverage
    coverage = case_coverage(root, db)
    categories = Counter(r["category"] for r in records)
    escape = lambda value: html.escape(str(value if value is not None else ""), quote=True)
    card_values = [("Artifacts", len(records)), ("Evidence sources", len(evidence)), ("Files verified", integrity["files_checked"]), ("Analysis runs", len(runs))]
    if filters or preview_limit:
        card_values = [("Artifacts", len(records)), ("Evidence sources", len({r['evidence_id'] for r in records}))]
    cards = "".join(f'<div class="stat"><strong>{value}</strong><span>{escape(label)}</span></div>' for label, value in card_values)
    rows = []
    for record in records:
        date = record["timestamp"] or "Undated / timezone unknown"
        source = record["logical_path"] or record["source_ref"]
        rows.append(f'''<article class="record" data-category="{escape(record['category'])}">
          <div class="record-top"><span class="badge">{escape(record['category'])}</span><time>{escape(date)}</time><span class="device">{escape(record['evidence_id'])}</span></div>
          <h3>{escape(record['title'])}</h3><p class="body">{escape(record['body'])}</p>
          <details><summary>Evidence &amp; original fields</summary><dl>
          <dt>Source</dt><dd>{escape(source)}</dd><dt>Record reference</dt><dd>{escape(record['source_ref'])}</dd>
          <dt>SHA-256</dt><dd>{escape(record['source_sha256'] or 'Source-file mapping unavailable; original tool report retained')}</dd>
          <dt>Parser</dt><dd>{escape(record['parser'])}</dd><dt>Original timestamp</dt><dd>{escape(record['timestamp_raw'])}</dd>
          </dl><pre>{escape(json.dumps(record['data'], indent=2, ensure_ascii=False))}</pre></details></article>''')
    if filters or preview_limit:
        selected_eids={r.get('evidence_id') for r in records}
        evidence=[{**dict(r),'label':'Selected supplied evidence'} for r in evidence if r['id'] in selected_eids]
    evidence_rows = "".join(f"<tr><td>{escape(r['label'])}</td><td>{escape(r['platform'])}</td><td><code>{escape(r['id'])}</code></td><td>{escape(r['imported_at'])}</td></tr>" for r in evidence)
    run_rows = "".join(f"<tr><td>{escape(r['engine'])}</td><td>{escape(r['status'])}</td><td>{r['records']}</td><td><details><summary>Run details</summary><pre>{escape(r['detail'])}</pre></details></td></tr>" for r in runs)
    if filters or preview_limit:
        from .coverage_ledger import portable_summary, source_pairs
        portable=portable_summary(coverage['ledger'],{'format':'html','records':len(records),'truncated':truncated,'evidence_ids':[r.get('evidence_id') for r in records],'source_pairs':source_pairs(records),**context_scope})
        portable['report_filters'] = sorted(filters)
        run_rows = '<tr><td colspan="4"><pre>' + escape(json.dumps(portable,indent=2)) + '</pre></td></tr>'
    else:
        run_rows += '<tr><td colspan="4"><details><summary>Acquisition coverage and report scope</summary><pre>' + escape(json.dumps({'report_filters': filters, 'acquisitions': coverage['acquisitions'], 'collection_attempts': coverage['collection_attempts'], 'note': coverage['note'], 'ledger': coverage['ledger']}, indent=2)) + '</pre></details></td></tr>'
    options = "".join(f'<option value="{escape(k)}">{escape(k)} ({v})</option>' for k, v in sorted(categories.items()))
    shared_rows = "".join(f"<tr><td>{escape(r['kind'])}</td><td>{escape(r['value'])}</td><td>{r['evidence_sources']}</td><td>{r['records']}</td></tr>" for r in shared_entities(db))
    if filters or preview_limit:
        shared_rows = '<tr><td colspan=4>Whole-case entity pivots omitted from scoped export.</td></tr>'
    integrity_label = "VERIFIED" if integrity["ok"] else "INTEGRITY FAILURE"
    document = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Lawliet Mobile · __NAME__</title><style>
    :root{color-scheme:dark;--bg:#0c1118;--panel:#141d28;--line:#2a3747;--text:#e4eaf2;--muted:#9aaec4;--accent:#65e4bb}*{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 ui-sans-serif,system-ui,sans-serif}main{max-width:1120px;margin:auto;padding:40px 28px 80px}
    header{border-bottom:1px solid var(--line);padding-bottom:30px}.brand{font-size:12px;font-weight:750;letter-spacing:.2em;color:var(--accent)}h1{font-size:42px;line-height:1.15;margin:18px 0 12px;letter-spacing:-.04em}h2{font-size:21px;margin:38px 0 14px}h3{font-size:17px;margin:10px 0 4px}
    .muted,time,.device,dt{color:var(--muted)}.status{display:inline-block;padding:5px 12px;border:1px solid var(--line);border-radius:20px;font-size:12px;color:var(--accent)}
    .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:26px}.stat{padding:20px;background:var(--panel);border:1px solid var(--line);border-radius:12px}.stat strong{display:block;font-size:32px}.stat span{color:var(--muted);font-size:13px}
    .note{border-left:3px solid var(--accent);padding:10px 16px;background:var(--panel);color:var(--muted);margin:24px 0}.controls{display:flex;gap:12px;position:sticky;top:0;background:var(--bg);padding:14px 0;z-index:1}
    input,select{background:var(--panel);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:12px;font:inherit}input{flex:1;min-width:0}input:focus,select:focus{outline:2px solid var(--accent)}
    .record{padding:20px 22px;background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:12px 0}.record-top{display:flex;gap:14px;align-items:center;flex-wrap:wrap;font-size:12px}.badge{color:var(--accent);text-transform:uppercase;letter-spacing:.08em;font-weight:700}.device{margin-left:auto;font-family:monospace}.body{white-space:pre-wrap;overflow-wrap:anywhere;margin:0 0 12px}
    summary{cursor:pointer;color:var(--muted);font-size:13px}dl{display:grid;grid-template-columns:145px 1fr;gap:8px;font-size:12px}dd{margin:0;overflow-wrap:anywhere;font-family:monospace}pre{background:var(--bg);padding:14px;border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 ui-monospace,monospace}table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted)}td,th{padding:12px 10px;border-bottom:1px solid var(--line)}.table-wrap{overflow-x:auto}footer{margin-top:45px;border-top:1px solid var(--line);padding-top:20px;color:var(--muted);font-size:12px}code{font-family:ui-monospace,monospace}[hidden]{display:none!important}
    @media(max-width:650px){main{padding:24px 16px}.stats{grid-template-columns:repeat(2,1fr)}h1{font-size:32px}.controls{flex-direction:column}dl{grid-template-columns:1fr}.device{margin-left:0}}
    @media print{body{background:white;color:#111}.controls{display:none}main{padding:0}.record,.stat,.note{background:white;border-color:#ccc;break-inside:avoid}.muted,time,dt,summary,.device,.stat span{color:#444}.badge,.brand,.status{color:#167152}pre{background:#f5f5f5}}
    </style></head><body><main><header><div class="brand">LAWLIET / MOBILE FORENSICS</div><h1>__NAME__</h1><div class="muted">Case __CASE__ · Examiner: __EXAMINER__ · Generated __GENERATED__</div><p><span class="status">__INTEGRITY__</span> <span class="muted">Evidence hashes &amp; audit chain checked at report generation</span></p></header>
    <section class="stats">__CARDS__</section><div class="note">Local evidence triage report. Coverage depends on available evidence and parser support. No findings does not establish absence of activity or compromise. Undated records retain their original timestamp values. Recovery and malware verdicts are not provided by the native engine.</div>
    <div class="note"><strong>Report scope:</strong> __SCOPE__<br>Counts are artifact rows; multiple parsers, repeated runs and attachments can represent the same message. Shared entities below cover the whole case.</div>
    <h2>Evidence inventory</h2><div class="table-wrap"><table><thead><tr><th>Source</th><th>Platform</th><th>Evidence ID</th><th>Imported</th></tr></thead><tbody>__EVIDENCE__</tbody></table></div>
    <h2>Analysis coverage</h2><div class="table-wrap"><table><thead><tr><th>Engine</th><th>Status</th><th>New records</th><th>Details</th></tr></thead><tbody>__RUNS__</tbody></table></div>
    <h2>Shared entities across evidence sources</h2><p class="muted">Exact textual matches are investigation pivots; they do not establish attribution or maliciousness.</p><div class="table-wrap"><table><thead><tr><th>Type</th><th>Entity</th><th>Sources</th><th>Records</th></tr></thead><tbody>__SHARED__</tbody></table></div>
    <h2>Investigation timeline</h2><div class="controls"><input id="search" type="search" aria-label="Search timeline" placeholder="Search messages, numbers, URLs, or original fields…"><select id="category" aria-label="Artifact category"><option value="">All categories</option>__OPTIONS__</select></div><p class="muted" id="visible"></p><section id="timeline">__ROWS__</section>
    <footer>Lawliet Mobile 0.1.0 · No external assets or network requests · Audit head: <code>__HEAD__</code><p>This local hash chain detects inconsistent edits; it is not an independently signed custody record.</p></footer></main><script>
    const records=Array.from(document.querySelectorAll('.record'));const search=document.querySelector('#search');const category=document.querySelector('#category');function filter(){const q=search.value.toLowerCase();let n=0;for(const r of records){const match=(!category.value||r.dataset.category===category.value)&&r.textContent.toLowerCase().includes(q);r.hidden=!match;if(match)n++}document.querySelector('#visible').textContent=n+' of '+records.length+' records'}search.addEventListener('input',filter);category.addEventListener('change',filter);filter();
    </script></body></html>'''
    values = {"SCOPE": escape(json.dumps(filters, ensure_ascii=False) if filters else "All case artifacts"), "NAME": escape(meta["name"]), "CASE": escape(meta["case_id"]), "EXAMINER": escape(meta["examiner"] or "Unspecified"), "GENERATED": escape(now()), "INTEGRITY": integrity_label, "CARDS": cards, "EVIDENCE": evidence_rows, "RUNS": run_rows, "SHARED": shared_rows, "OPTIONS": options, "ROWS": "".join(rows), "HEAD": escape(integrity["audit_head"])}
    incomplete = [a.get("status", "unknown") for a in coverage["collection_attempts"] if a.get("status") != "complete"]
    if filters or preview_limit:
        incomplete = []  # Selected portable context below carries scoped limitations.
    if incomplete:
        values["SCOPE"] += escape(" — Case includes incomplete acquisition attempts: " + ", ".join(incomplete) + ". Review acquisition coverage below.")
    if preview_limit:
        values["SCOPE"] += escape(f" — Preview: first {len(records)} chronological rows; additional rows exist." if truncated else f" — Preview: all {len(records)} matching rows.")
    # Single substitution pass prevents placeholder-looking evidence from becoming markup.
    import re
    document = re.sub(r"__([A-Z]+)__", lambda match: values[match[1]], document)
    from .coverage_ledger import portable_summary, source_pairs
    from .portable_coverage import bounded_json
    portable = portable_summary(coverage['ledger'], {
        'format': 'html', 'filters': filters, 'preview_limit': preview_limit,
        'truncated': truncated, 'records': len(records),
        'evidence_ids': [r.get('evidence_id') for r in records],
        'source_pairs': source_pairs(records), **context_scope})
    from .anchored_output import OutputFiles
    outputs = OutputFiles([path, companion])
    db.execute('SAVEPOINT paired_html_report')
    try:
        with outputs:
            with outputs.open(path) as handle:
                handle.write(document)
            portable['export_sha256'] = outputs.digest(path)
            encoded = bounded_json(portable)
            with outputs.open(companion) as handle:
                handle.write(encoded)
            companion_sha = outputs.digest(companion)
            outputs.publish()
            audit(db, "report.created", {"path": str(path), "records": len(records),
                "integrity_ok": integrity["ok"], "filters": filters,
                "preview_limit": preview_limit, "truncated": truncated,
                "coverage_path": str(companion), "sha256": portable['export_sha256'],
                "coverage_sha256": companion_sha, "independent_examiner_signoff": False})
            outputs.check_parent()
            if outputs.digest(path) != portable['export_sha256'] or outputs.digest(companion) != companion_sha:
                raise UserError('Report changed before audit completion.')
            db.execute('RELEASE SAVEPOINT paired_html_report')
            return {"path": str(path), "records": len(records), "integrity_ok": integrity["ok"], "truncated": truncated}
    except BaseException:
        db.execute('ROLLBACK TO SAVEPOINT paired_html_report')
        db.execute('RELEASE SAVEPOINT paired_html_report')
        raise
