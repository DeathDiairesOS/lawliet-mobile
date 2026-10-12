"""Streaming local draft reports from checked investigation state and trace."""
import json

from .core import UserError, audit, digest, now
from .investigation import ENTRY_KINDS, get, verify_ledger
from .report import safe_output


def export(root, db, iid, destination):
    """Create a new JSON report and hash receipt; never release or upload it."""
    db.execute('SAVEPOINT investigation_export')
    created = []
    try:
        state = get(db, iid)
        checked = verify_ledger(db)
        path = safe_output(root, db, destination)
        receipt_path = safe_output(root, db, str(path) + '.receipt.json')
        if path.exists() or receipt_path.exists():
            raise UserError('Choose a new report filename; report or receipt already exists.')
        evidence_ids = state['scope']['evidence_ids']
        marks = ','.join('?' for _ in evidence_ids)
        meta = dict(db.execute('SELECT key,value FROM meta'))
        header = {'format': 'ancalor-investigation-report-v1', 'created_at': now(),
                  'review_status': 'draft_unreviewed', 'case_id': meta['case_id'],
                  'investigation': state, 'ledger_verification': checked,
                  'limitations': [
                      'This is an analyst-authored investigation ledger, not an autonomous investigation result.',
                      'All statements remain unreviewed. Citations do not prove the associated conclusions.',
                      'Source bytes were not rehashed for this export; hashes identify the recorded source inventory.',
                      'The local audit chain is not an independent signature or immutable storage.',
                      'Open questions and hypotheses have no resolution workflow yet.',
                      'Backend parser runs below are contextual case history, not actions performed by this controller.',
                      'Failed query attempts are not yet durably recorded; the trace is not a complete attempt history.',
                      'No model ran; model cost and analyst time saved were not measured.']}

        def events(kind=None):
            query = 'SELECT * FROM investigation_events WHERE investigation_id=?'
            params = [iid]
            if kind:
                query += ' AND kind=?'
                params.append(kind)
            for row in db.execute(query + ' ORDER BY sequence', params):
                value = dict(row)
                value['request'] = json.loads(value['request'])
                value['result'] = json.loads(value['result'])
                yield value

        with path.open('x', encoding='utf-8') as out:
            created.append(path)
            # Stream arrays; don't materialize an entire case or event history.
            out.write(json.dumps(header, ensure_ascii=True, indent=2)[:-1])

            def section(name, values):
                out.write(',\n' + json.dumps(name) + ': [\n')
                first = True
                for value in values:
                    if not first:
                        out.write(',\n')
                    out.write(json.dumps(value, ensure_ascii=True, sort_keys=True))
                    first = False
                out.write('\n]')

            section('evidence_inventory', (dict(r) for r in db.execute(
                f'''SELECT e.id,e.label,e.platform,e.imported_at,e.encrypted,
                    (SELECT count(*) FROM files f WHERE f.evidence_id=e.id) AS inventoried_files,
                    (SELECT count(*) FROM artifacts a WHERE a.evidence_id=e.id) AS indexed_artifacts
                    FROM evidence e WHERE e.id IN ({marks}) ORDER BY e.id''', evidence_ids)))
            section('backend_processing_history', (dict(r) for r in db.execute(
                f'''SELECT id,evidence_id,engine,started_at,finished_at,status,records
                    FROM runs WHERE evidence_id IN ({marks}) ORDER BY started_at,id''', evidence_ids)))
            for kind in ENTRY_KINDS:
                section(kind + '_entries', events('analyst.' + kind))
            section('execution_trace', events())
            out.write('\n}\n')
        receipt = {'format': 'ancalor-investigation-export-receipt-v1', 'filename': path.name,
                   'case_id': meta['case_id'], 'investigation_id': iid, 'created_at': now(),
                   'sha256': digest(path), 'bytes': path.stat().st_size,
                   'audit_head_before_export': checked['audit_head'], 'review_status': 'draft_unreviewed'}
        with receipt_path.open('x', encoding='utf-8') as out:
            created.append(receipt_path)
            json.dump(receipt, out, ensure_ascii=True, indent=2)
            out.write('\n')
        audit(db, 'investigation.exported', {'investigation_id': iid, 'path': str(path),
                                            'sha256': receipt['sha256'], 'receipt_sha256': digest(receipt_path)})
        db.execute('RELEASE SAVEPOINT investigation_export')
        return {**receipt, 'path': str(path), 'receipt_path': str(receipt_path)}
    except BaseException:
        db.execute('ROLLBACK TO SAVEPOINT investigation_export')
        db.execute('RELEASE SAVEPOINT investigation_export')
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise


def _fingerprint(db, iid):
    """Bind approval to scope and every retained investigation event."""
    from .investigation import checksum
    return checksum([get(db,iid),[dict(r) for r in db.execute('SELECT * FROM investigation_events WHERE investigation_id=? ORDER BY sequence',(iid,))]])


def build_customer_draft(root, db, iid, redactions=None):
    """Build an internal, source-linked draft; never approve, release or fetch media."""
    import shutil
    import uuid
    from pathlib import Path
    from .findings import readable
    from .coverage_ledger import portable_summary, source_pairs
    from .acquisition import case_coverage
    from .core import json_text
    if redactions is not None:
        raise UserError('Redacted customer packages are not implemented. No redaction or safe-release claim is available; supplied redaction requests are refused.')
    verify_ledger(db);state=get(db,iid)
    draft_id=uuid.uuid4().hex;folder=root/'customer-drafts'/draft_id
    if folder.parent.is_symlink():raise UserError('Unsafe customer draft directory.')
    folder.mkdir(parents=True,exist_ok=False)
    db.execute('SAVEPOINT customer_draft')
    try:
        machine=export(root,db,iid,folder/'investigation.json')
        if Path(machine['path']).stat().st_size>32*1024**2:raise UserError('Customer draft exceeds32MiB; narrow investigation scope.')
        data=json.loads(Path(machine['path']).read_text())
        entries=[];citations={}
        for kind in ENTRY_KINDS:
            for event in data[kind+'_entries']:
                refs=[]
                for citation in event['result']['citations']:
                    aid=citation['id'];refs.append(aid)
                    if aid in citations:continue
                    original=citation.get('data') or '{}'
                    original=json.loads(original) if isinstance(original,str) else original
                    parser=citation.get('parser') or 'unknown'
                    tier=('derived-tool-report' if any(parser==prefix or parser.startswith(prefix+'/') for prefix in ('aleapp','ileapp','leapp','import/leapp','import/tsv','import/jsonl')) or (isinstance(original,dict) and any(key in original for key in ('_ancalor_report','_import_report'))) else
                          'supplied-text-export' if parser.startswith('whatsapp-export/') else 'supplied-file; acquisition tier unverified')
                    runs=[dict(r) for r in db.execute('SELECT r.id,r.engine,r.status FROM runs r JOIN artifact_runs ar ON ar.run_id=r.id WHERE ar.artifact_id=? ORDER BY r.id',(aid,))] if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='artifact_runs'").fetchone() else []
                    attachment=original.get('attachment',{}) if isinstance(original,dict) else {}
                    message=original.get('message',{}) if isinstance(original,dict) else {}
                    citations[aid]={'artifact_id':aid,'snapshot':citation,'source_tier':tier,
                        'source_locator':{'retained_logical_path':citation.get('logical_path'),'record_table_key_or_offset':citation.get('source_ref'),'recorded_source_sha256':citation.get('source_sha256')},
                        'parser':parser,'parser_runs':runs,'parser_run_link_state':'linked' if runs else 'unavailable',
                        'attachment_state':attachment.get('status') or message.get('attachment_status') or 'not-assessed',
                        'exhibit_scope':'Indexed citation snapshot only. Raw files, attachments, thumbnails and external URLs are not included or fetched.',
                        'verification':'Source linkage only; assertion accuracy and source authenticity require examiner review.'}
                entries.append({'kind':kind,'entry_id':event['action_key'],'text':event['request']['text'],'artifact_ids':refs})
        chronology=sorted(citations.values(),key=lambda c:(c['snapshot'].get('timestamp') is None,c['snapshot'].get('timestamp') or '',c['artifact_id']))
        coverage=portable_summary(case_coverage(root,db)['ledger'],{'format':'customer-draft','records':len(citations),'evidence_ids':state['scope']['evidence_ids'],'source_pairs':source_pairs(c['snapshot'] for c in citations.values())})
        annex={'format':'ancalor-customer-annex-v1','review_status':'draft_unreviewed','investigation_id':iid,
               'objective':state['objective'],'scope':state['scope'],'source_inventory':data['evidence_inventory'],
               'methods_and_versions':data['backend_processing_history'],'entries':entries,'chronology_artifact_ids':[c['artifact_id'] for c in chronology],
               'citations':list(citations.values()),'coverage':coverage,'limitations':data['limitations']+[
                   'No independent reviewer or examiner approval has been supplied.',
                   'Conflicts are unresolved unless explicitly described by the analyst; no automated contradiction adjudication is performed.',
                   'Attachment states are parser observations, not verified file inclusion. All exhibits are indexed snapshots only.',
                   'This draft is unredacted. Redaction requests are refused; no sensitive-string removal is claimed.']}
        (folder/'technical-annex.json').write_text(json.dumps(annex,ensure_ascii=True,indent=2)+'\n')
        with (folder/'exhibits.jsonl').open('x',encoding='utf-8') as stream:
            for citation in citations.values():stream.write(json_text(citation)+'\n')
        lines=['LAWLIET — CUSTOMER REPORT DRAFT','DRAFT / UNREVIEWED / UNREDACTED',
               'Question: '+state['objective'],'Scope: selected investigation evidence only.',
               f"Material source-linked entries: {sum(x['kind'] in ('observation','interpretation') for x in entries)}; unique cited artifact snapshots: {len(citations)}.",
               'SOURCE INVENTORY']
        for source in data['evidence_inventory']:lines.append(f"{source['id']} · {source['label']} · {source['platform']} · supplied files {source['inventoried_files']}")
        lines.append('METHODS / VERSIONS')
        for run in data['backend_processing_history']:lines.append(f"{run['engine']} · run {run['id']} · status {run['status']}")
        for kind,title in [('observation','OBSERVATIONS'),('interpretation','INFERENCES / INTERPRETATIONS'),('hypothesis','ALTERNATIVE EXPLANATIONS / POTENTIAL CONFLICTS'),('question','OPEN QUESTIONS / MISSING INFORMATION'),('task','NEXT STEPS')]:
            lines.append(title)
            selected=[e for e in entries if e['kind']==kind]
            lines.extend(e['text']+' [source artifacts: '+', '.join(e['artifact_ids'])+']' for e in selected)
            if not selected:lines.append('Not recorded; do not infer none exist.')
        lines.append('CHRONOLOGY / SOURCE LOCATORS')
        for citation in chronology:
            snap=citation['snapshot'];locator=citation['source_locator']
            lines.extend([f"Artifact {citation['artifact_id']} · UTC {snap.get('timestamp') or 'unknown'} · raw time {snap.get('timestamp_raw')}",
                          str(snap.get('body') or ''),f"Tier: {citation['source_tier']} · parser: {citation['parser']} · runs: {json.dumps(citation['parser_runs'])}",
                          f"Source: {locator['retained_logical_path']} · locator: {locator['record_table_key_or_offset']} · recorded SHA256: {locator['recorded_source_sha256']}",
                          'Attachment: '+str(citation['attachment_state'])+'; indexed reference only, file not included.'])
        lines.extend(['LIMITATIONS']+annex['limitations'])
        (folder/'report.txt').write_text('\n\n'.join(readable(line) for line in lines)+'\n',encoding='utf-8')
        files=[{'path':p.name,'sha256':digest(p),'bytes':p.stat().st_size} for p in sorted(folder.iterdir()) if p.is_file()]
        manifest={'format':'ancalor-customer-bundle-v1','draft_id':draft_id,'investigation_id':iid,'review_status':'draft_unreviewed',
                  'redaction_status':'unredacted; no redaction implementation','investigation_fingerprint':_fingerprint(db,iid),'files':files,
                  'counts':{'unique_cited_artifacts':len(citations),'entries':len(entries)},'attachments':'references-only; no raw attachments or external assets copied'}
        (folder/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        manifest_sha=digest(folder/'manifest.json')
        audit(db,'customer_report.draft_created',{'draft_id':draft_id,'investigation_id':iid,'manifest_sha256':manifest_sha})
        db.execute('RELEASE SAVEPOINT customer_draft')
        return {'draft_id':draft_id,'path':str(folder),'manifest_sha256':manifest_sha,'review_status':'draft_unreviewed','counts':manifest['counts']}
    except BaseException:
        db.execute('ROLLBACK TO SAVEPOINT customer_draft');db.execute('RELEASE SAVEPOINT customer_draft')
        shutil.rmtree(folder)
        raise


def _safe_descendant(root,path):
    """Do not let symlinked case containers redefine source containment."""
    if root.is_symlink():raise UserError('Unsafe case directory.')
    try:relative=path.relative_to(root)
    except ValueError:raise UserError('Unsafe case source path.') from None
    if '..' in relative.parts:raise UserError('Unsafe case source path.')
    current=root
    for part in relative.parts:
        current=current/part
        if current.is_symlink():raise UserError('Unsafe symlink in case source path.')
    if not path.resolve().is_relative_to(root.resolve()):raise UserError('Unsafe case source path.')
    return path


def _checked_draft(root,db,draft_id):
    from pathlib import Path
    from .core import digest
    if not isinstance(draft_id,str) or len(draft_id)!=32 or any(c not in '0123456789abcdef' for c in draft_id):raise UserError('Invalid customer draft ID.')
    verify_ledger(db)
    folder=_safe_descendant(root,root/'customer-drafts'/draft_id)
    if folder.parent.is_symlink() or folder.is_symlink() or not folder.is_dir():raise UserError('Unknown safe customer draft.')
    manifest_path=folder/'manifest.json'
    if manifest_path.is_symlink() or not manifest_path.is_file():raise UserError('Missing safe draft manifest.')
    sha=digest(manifest_path);manifest=json.loads(manifest_path.read_text())
    receipts=[json.loads(r[0]) for r in db.execute("SELECT detail FROM audit WHERE action='customer_report.draft_created'")]
    if not any(r.get('draft_id')==draft_id and r.get('manifest_sha256')==sha for r in receipts):raise UserError('Draft manifest has no matching audit receipt.')
    expected={'manifest.json'}
    for entry in manifest['files']:
        relative=Path(entry['path'])
        if relative.name!=entry['path'] or relative.name in {'','.', '..'}:raise UserError('Unsafe draft manifest path.')
        path=folder/relative
        if path.is_symlink() or not path.is_file() or digest(path)!=entry['sha256'] or path.stat().st_size!=entry['bytes']:raise UserError('Draft output integrity mismatch.')
        expected.add(relative.name)
    if {p.name for p in folder.iterdir()}!=expected:raise UserError('Draft contains unmanifested content.')
    if _fingerprint(db,manifest['investigation_id'])!=manifest['investigation_fingerprint']:raise UserError('Investigation changed after draft; rebuild and re-review.')
    annex=json.loads((folder/'technical-annex.json').read_text())
    for citation in annex['citations']:
        locator=citation['source_locator'];snapshot=citation['snapshot']
        if not all(locator.get(key) for key in ('retained_logical_path','record_table_key_or_offset','recorded_source_sha256')):
            raise UserError('Material citation lacks a retained hash/path/record locator; release requires source reconciliation.')
        file=db.execute('SELECT * FROM files WHERE id=? AND evidence_id=?',(snapshot.get('file_id'),snapshot.get('evidence_id'))).fetchone()
        if not file:raise UserError('Material citation source mapping is unavailable; reconcile before approval.')
        evidence_root=root/'evidence'/file['evidence_id'];source=_safe_descendant(root,evidence_root/file['path'])
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(evidence_root.resolve()) or digest(source)!=locator['recorded_source_sha256']:
            raise UserError('Retained citation source integrity mismatch; approval/release blocked.')
    return folder,manifest,sha


def approve_customer_draft(root,db,draft_id,reviewer,declaration):
    """Record an explicit operator-supplied examiner declaration; no auto approval."""
    if not isinstance(reviewer,str) or not reviewer.strip() or len(reviewer)>200:raise UserError('Explicit examiner name required.')
    if not isinstance(declaration,str) or not declaration.strip() or len(declaration)>4000:raise UserError('Explicit examiner approval declaration required.')
    folder,manifest,sha=_checked_draft(root,db,draft_id)
    value={'draft_id':draft_id,'manifest_sha256':sha,'reviewer':reviewer,'declaration':declaration,'approved_at':now(),
           'scope':'Recorded operator declaration for exact unredacted draft bytes; identity/qualifications/independent acceptance not authenticated.'}
    audit(db,'customer_report.approved',value)
    return value


def release_customer_draft(root,db,draft_id,destination,redactions=None):
    """Copy approved bytes locally; no external delivery, upload or new approval."""
    import shutil
    if redactions is not None:raise UserError('Redacted release is unsupported; no package produced.')
    folder,manifest,sha=_checked_draft(root,db,draft_id)
    approvals=[json.loads(r[0]) for r in db.execute("SELECT detail FROM audit WHERE action='customer_report.approved' ORDER BY id")]
    approvals=[r for r in approvals if r.get('draft_id')==draft_id and r.get('manifest_sha256')==sha]
    if not approvals:raise UserError('Recorded examiner approval of these exact draft bytes is required before release.')
    target=safe_output(root,db,destination)
    if target.exists():raise FileExistsError('Choose a new release directory.')
    if target.is_relative_to(folder.resolve()):raise UserError('Release directory must be outside the source draft.')
    target.mkdir(parents=True,exist_ok=False)
    try:
        expected={'manifest.json'}|{entry['path'] for entry in manifest['files']}
        for name in expected:
            source=folder/name
            if source.is_symlink() or not source.is_file():raise UserError('Unsafe or changing draft output; release blocked.')
            shutil.copyfile(source,target/name)
        if {p.name for p in target.iterdir()}!=expected or any(p.is_symlink() or not p.is_file() for p in target.iterdir()):
            raise UserError('Unexpected content appeared in release package.')
        if digest(target/'manifest.json')!=sha or any(digest(target/f['path'])!=f['sha256'] or (target/f['path']).stat().st_size!=f['bytes'] for f in manifest['files']):
            raise UserError('Draft changed during release copy; no release produced.')
        receipt={'draft_id':draft_id,'manifest_sha256':sha,'approval':approvals[-1],'released_at':now(),'review_status':'recorded_examiner_approval','limitations':'Approval is an operator declaration, not independently authenticated signoff. Bundled content retains original draft labels because approved bytes are not rewritten.'}
        (target/'release-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        audit(db,'customer_report.released',{'draft_id':draft_id,'manifest_sha256':sha,'path':str(target),'release_receipt_sha256':digest(target/'release-receipt.json')})
        return {'path':str(target),**receipt}
    except BaseException:
        shutil.rmtree(target)
        raise

# Bounded, references-only literal-redacted derivatives. Original drafts stay intact.
_REDACT_FILES={'report.txt','technical-annex.json','investigation.json','exhibits.jsonl'}
_REDACT_BYTES=16*1024**2
_REDACT_MATCHES=10000
_REDACT_LIMITS=[
 'References-only package: no original evidence, media, attachments, thumbnails, PDFs, indexes or external assets are copied or fetched.',
 'Only operator-selected case-sensitive literals were removed; case, spelling and Unicode variants are not inferred. This is not automatic sensitive-data detection.',
 'JSON keys, decoded string values and recursively encoded JSON strings are transformed with encoding layers preserved. The manifest identifies derivative bytes, not original file bytes.',
 'Escape spellings in ordinary non-JSON plaintext are not automatically decoded or inferred; only literal text and valid decoded JSON representations are checked.',
 'Source hashes and citation identifiers remain unchanged. A masked source path or locator is a restricted reference, not an exact original locator; original evidence must be consulted in authorized storage.',
 'No binary or media redaction is implemented. Missing/external attachments remain references only.',
 'Original draft labels and historical statements may remain quoted in transformed source documents. This derivative manifest governs the package status.',
 'This derivative requires its own explicit exact-byte approval. Operator identity, qualifications and independent acceptance are not authenticated.'
]


def _redaction_json(text):
    def pairs(items):
        value={}
        for key,item in items:
            if key in value:raise UserError('Duplicate JSON key is unsupported for redaction.')
            value[key]=item
        return value
    def constant(value):raise UserError('Nonfinite JSON value is unsupported for redaction.')
    return json.loads(text,object_pairs_hook=pairs,parse_constant=constant)


def _redaction_transform(payloads,literals):
    """Worker-only bounded transformation; structured values never replaced as raw JSON."""
    import re,time
    from .masking_preview import _literals
    literals=_literals(literals)
    if set(payloads)!=_REDACT_FILES:raise UserError('Unsupported redaction surfaces.')
    if sum(len(x.encode('utf-8')) for x in payloads.values())>_REDACT_BYTES:raise UserError('Redaction input byte budget exceeded.')
    pattern=re.compile('|'.join(re.escape(v) for v in sorted(literals,key=lambda x:(-len(x),x))))
    token='[REDACTED]';counts=[0]*len(literals);indices={v:i for i,v in enumerate(literals)};deadline=time.monotonic()+5;nodes=0
    def text(value):
        def match(m):
            if sum(counts)>=_REDACT_MATCHES:raise UserError('Redaction match budget exceeded.')
            counts[indices[m.group()]]+=1
            return token
        return pattern.sub(match,value)
    def walk(value,depth=0):
        nonlocal nodes
        nodes+=1
        if nodes>200000 or depth>32 or time.monotonic()>deadline:raise UserError('Redaction structure/time budget exceeded.')
        if isinstance(value,str):
            stripped=value.lstrip()
            if stripped.startswith(('{','[','"')):
                try:decoded=_redaction_json(value)
                except json.JSONDecodeError:decoded=None
                if isinstance(decoded,(dict,list,str)):
                    return json.dumps(walk(decoded,depth+1),ensure_ascii=False,separators=(',',':'),allow_nan=False)
            return text(value)
        if isinstance(value,list):return [walk(x,depth+1) for x in value]
        if isinstance(value,dict):
            output={}
            for key,item in value.items():
                new=walk(key,depth+1)
                if new in output:raise UserError('Redacted JSON keys collide; narrow selections.')
                output[new]=walk(item,depth+1)
            return output
        return value
    output={}
    for name,raw in payloads.items():
        if name.endswith('.txt'):output[name]=text(raw)
        elif name.endswith('.jsonl'):
            lines=raw.splitlines()
            if len(lines)>1000:raise UserError('Exhibit line budget exceeded.')
            output[name]=''.join(json.dumps(walk(_redaction_json(line)),ensure_ascii=False,allow_nan=False)+'\n' for line in lines if line.strip())
        else:output[name]=json.dumps(walk(_redaction_json(raw)),ensure_ascii=False,indent=2,allow_nan=False)+'\n'
    if not sum(counts):raise UserError('No selected literal matched; no derivative produced.')
    if sum(len(x.encode('utf-8')) for x in output.values())>_REDACT_BYTES:raise UserError('Redaction output byte budget exceeded.')
    _redaction_scan(output,literals)
    return {'payloads':output,'selection_counts':counts,'consumed_matches':sum(counts)}


def _redaction_scan(payloads,literals):
    """Check full bytes and recursively decoded surfaces, including nested JSON strings."""
    nodes=0
    def scan(value,depth=0):
        nonlocal nodes
        nodes+=1
        if nodes>200000 or depth>32:raise UserError('Redaction scan structure budget exceeded.')
        if isinstance(value,str):
            if any(v in value for v in literals):raise UserError('Selected literal remains in package; no package produced.')
            if value.lstrip().startswith(('{','[','"')):
                try:decoded=_redaction_json(value)
                except json.JSONDecodeError:return
                if isinstance(decoded,(dict,list,str)):scan(decoded,depth+1)
        elif isinstance(value,dict):
            for k,v in value.items():scan(k,depth+1);scan(v,depth+1)
        elif isinstance(value,list):
            for v in value:scan(v,depth+1)
    for name,text in payloads.items():
        scan(name);scan(text)
        if name.endswith('.json'):scan(_redaction_json(text))
        elif name.endswith('.jsonl'):
            for line in text.splitlines():
                if line.strip():scan(_redaction_json(line))


def _redaction_worker(payloads,literals):
    import subprocess,sys,tempfile
    from pathlib import Path
    program="import importlib.util,sys,json; p=importlib.util.spec_from_file_location('lawliet_mobile._redaction_stage',sys.argv[1]); m=importlib.util.module_from_spec(p); p.loader.exec_module(m); d=json.load(open(sys.argv[2])); r=m._redaction_transform(d['payloads'],d['literals']); open(sys.argv[3],'x').write(json.dumps(r,ensure_ascii=False))"
    encoded=json.dumps({'payloads':payloads,'literals':literals},ensure_ascii=False)
    if len(encoded.encode('utf-8'))>2*_REDACT_BYTES:raise UserError('Redaction worker input budget exceeded.')
    with tempfile.TemporaryDirectory(prefix='lawliet-redacted-') as td:
        folder=Path(td);request=folder/'input.json';output=folder/'output.json';request.write_text(encoded,encoding='utf-8')
        try:result=subprocess.run([sys.executable,'-c',program,__file__,str(request),str(output)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=6)
        except subprocess.TimeoutExpired:raise UserError('Redaction worker exceeded its time limit.') from None
        if result.returncode or not output.is_file() or output.stat().st_size>2*_REDACT_BYTES:raise UserError('Bounded redaction worker refused this request.')
        return _redaction_json(output.read_text(encoding='utf-8'))


def create_redacted_customer_draft(root,db,draft_id,literals):
    """Create new exact-byte-reviewable derivative; never reuse original approval."""
    import hashlib,shutil,uuid
    from .masking_preview import _preflight,_literals
    literals=_literals(literals);created=None
    if not db.in_transaction:db.execute('BEGIN IMMEDIATE')
    else:db.execute('UPDATE audit SET id=id WHERE 0')
    db.execute('SAVEPOINT redacted_draft')
    try:
        source,manifest,source_sha=_preflight(root,db,draft_id)
        payloads={}
        for name in sorted(_REDACT_FILES):
            raw=(source/name).read_bytes()
            if len(raw)>_REDACT_BYTES:raise UserError('Redaction input budget exceeded.')
            entry=next(x for x in manifest['files'] if x['path']==name)
            if hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise UserError('Draft changed before redaction.')
            try:payloads[name]=raw.decode('utf-8')
            except UnicodeError:raise UserError('Only UTF-8 text/JSON/JSONL can be redacted.') from None
        if sum(len(x.encode('utf-8')) for x in payloads.values())>_REDACT_BYTES:raise UserError('Redaction input budget exceeded.')
        annex=_redaction_json(payloads['technical-annex.json'])
        # Stable IDs/hashes are needed for cross-file citation consistency; refuse selections altering them.
        protected=[draft_id,source_sha]
        for c in annex['citations']:
            protected.extend(str(v) for v in [c['artifact_id'],c['snapshot']['evidence_id'],c['snapshot']['file_id'],c['source_locator']['recorded_source_sha256']])
        if any(literal in value for literal in literals for value in protected):raise UserError('Selection overlaps citation identity/hash; narrower literal selection required.')
        result=_redaction_worker(payloads,literals);redacted=result['payloads']
        transformed=_redaction_json(redacted['technical-annex.json'])
        exhibits=[_redaction_json(line) for line in redacted['exhibits.jsonl'].splitlines() if line.strip()]
        if transformed['citations']!=exhibits:raise UserError('Redacted annex/exhibit citations diverged.')
        if len(transformed['entries'])!=manifest['counts']['entries'] or len(exhibits)!=manifest['counts']['unique_cited_artifacts']:raise UserError('Redaction changed counts.')
        ids=[c['artifact_id'] for c in exhibits]
        if len(set(ids))!=len(ids) or set(transformed['chronology_artifact_ids'])!=set(ids):raise UserError('Redaction changed citation identities.')
        if any(aid not in ids for e in transformed['entries'] for aid in e['artifact_ids']):raise UserError('Redacted entry has unresolved citation.')
        _,_,after_sha=_preflight(root,db,draft_id)
        if after_sha!=source_sha:raise UserError('Source draft changed during redaction.')
        derivative_id=uuid.uuid4().hex;parent=_safe_descendant(root,root/'customer-redacted-drafts');parent.mkdir(mode=0o700,exist_ok=True)
        target=parent/derivative_id;target.mkdir(mode=0o700,exist_ok=False);created=target
        files=[{'path':name,'bytes':len(text.encode('utf-8')),'sha256':hashlib.sha256(text.encode('utf-8')).hexdigest()} for name,text in sorted(redacted.items())]
        value={'format':'ancalor-customer-redacted-bundle-v1','derivative_id':derivative_id,'review_status':'unreviewed_redacted_derivative','source_manifest_sha256':source_sha,
            'files':files,'counts':manifest['counts'],'attachments':'references-only; no binary assets copied','redaction':{'method':'case-sensitive leftmost-longest literal, nonrecursive replacement','selection_count':len(literals),'consumed_matches':result['consumed_matches'],'selected_literals_absent_from_bytes_and_decoded_surfaces':True},'limitations':_REDACT_LIMITS}
        redacted['manifest.json']=json.dumps(value,ensure_ascii=False,indent=2)+'\n';_redaction_scan(redacted,literals)
        if sum(len(v.encode('utf-8')) for v in redacted.values())>_REDACT_BYTES:raise UserError('Final package byte budget exceeded.')
        for name,text in redacted.items():
            with (target/name).open('x',encoding='utf-8') as stream:stream.write(text)
        _,_,final_sha=_preflight(root,db,draft_id)
        if final_sha!=source_sha:raise UserError('Source draft changed while publishing derivative.')
        receipt={'derivative_id':derivative_id,'manifest_sha256':digest(target/'manifest.json'),'source_draft_id':draft_id,'source_manifest_sha256':source_sha,'selection_count':len(literals),'consumed_matches':result['consumed_matches']}
        audit(db,'customer_report.redacted_created',receipt);db.execute('RELEASE SAVEPOINT redacted_draft')
        return {**receipt,'path':str(target),'review_status':'unreviewed_redacted_derivative','counts':value['counts'],'release_allowed':False}
    except BaseException:
        try:db.execute('ROLLBACK TO SAVEPOINT redacted_draft');db.execute('RELEASE SAVEPOINT redacted_draft')
        finally:
            if created is not None:shutil.rmtree(created)
        raise


def _checked_redacted_customer_draft(root,db,derivative_id):
    from .masking_preview import _preflight
    if not isinstance(derivative_id,str) or len(derivative_id)!=32 or any(c not in '0123456789abcdef' for c in derivative_id):raise UserError('Invalid derivative ID.')
    verify_ledger(db);folder=_safe_descendant(root,root/'customer-redacted-drafts'/derivative_id)
    expected=_REDACT_FILES|{'manifest.json'}
    if not folder.is_dir() or {p.name for p in folder.iterdir()}!=expected:raise UserError('Derivative file inventory differs.')
    if any(p.is_symlink() or not p.is_file() for p in folder.iterdir()):raise UserError('Unsafe derivative file.')
    if sum(p.stat().st_size for p in folder.iterdir())>_REDACT_BYTES:raise UserError('Derivative exceeds byte budget.')
    sha=digest(folder/'manifest.json');manifest=_redaction_json((folder/'manifest.json').read_text())
    receipt=next((json.loads(r[0]) for r in db.execute("SELECT detail FROM audit WHERE action='customer_report.redacted_created' ORDER BY id DESC") if json.loads(r[0]).get('derivative_id')==derivative_id and json.loads(r[0]).get('manifest_sha256')==sha),None)
    if receipt is None:raise UserError('No audited derivative matches these bytes.')
    if {e['path'] for e in manifest['files']}!=_REDACT_FILES or len(manifest['files'])!=len(_REDACT_FILES):raise UserError('Unsupported derivative manifest.')
    for item in manifest['files']:
        path=folder/item['path']
        if digest(path)!=item['sha256'] or path.stat().st_size!=item['bytes']:raise UserError('Derivative integrity changed; approval invalid.')
    _,_,source_sha=_preflight(root,db,receipt['source_draft_id'])
    if source_sha!=receipt['source_manifest_sha256']:raise UserError('Original source draft changed.')
    return folder,manifest,sha


def approve_redacted_customer_draft(root,db,derivative_id,reviewer,declaration):
    if not isinstance(reviewer,str) or not reviewer.strip() or len(reviewer)>200:raise UserError('Explicit reviewer required.')
    if not isinstance(declaration,str) or not declaration.strip() or len(declaration)>4000:raise UserError('Explicit derivative approval declaration required.')
    _,_,sha=_checked_redacted_customer_draft(root,db,derivative_id)
    receipt={'derivative_id':derivative_id,'manifest_sha256':sha,'reviewer':reviewer,'declaration':declaration,'approved_at':now(),'scope':'Exact derivative bytes only; operator declaration, not authenticated identity or independent qualification.'}
    audit(db,'customer_report.redacted_approved',receipt);return receipt


def release_redacted_customer_draft(root,db,derivative_id,destination):
    """Copy approved derivative bytes locally, never original attachments or approval prose."""
    import shutil
    from pathlib import Path
    folder,manifest,sha=_checked_redacted_customer_draft(root,db,derivative_id)
    approved=any(json.loads(r[0]).get('derivative_id')==derivative_id and json.loads(r[0]).get('manifest_sha256')==sha for r in db.execute("SELECT detail FROM audit WHERE action='customer_report.redacted_approved'"))
    if not approved:raise UserError('Fresh recorded approval of exact derivative bytes required.')
    raw=Path(destination).absolute()
    if any(p.is_symlink() for p in [raw,*raw.parents]):raise UserError('Unsafe release path.')
    target=safe_output(root,db,raw)
    if target.exists() or target.is_relative_to(root.resolve()):raise UserError('Choose a new external local directory for this derivative.')
    created=False;db.execute('SAVEPOINT redacted_release')
    try:
        target.mkdir(mode=0o700,parents=True,exist_ok=False);created=True
        expected=_REDACT_FILES|{'manifest.json'}
        for name in sorted(expected):
            with (folder/name).open('rb') as source,(target/name).open('xb') as dest:shutil.copyfileobj(source,dest,1024*1024)
        _,_,after_sha=_checked_redacted_customer_draft(root,db,derivative_id)
        if after_sha!=sha or {p.name for p in target.iterdir()}!=expected or any(p.is_symlink() or not p.is_file() for p in target.iterdir()):raise UserError('Release source or inventory changed.')
        if digest(target/'manifest.json')!=sha or any(digest(target/e['path'])!=e['sha256'] for e in manifest['files']):raise UserError('Release copy integrity mismatch.')
        # No newly supplied reviewer/declaration/path text enters the scanned package.
        receipt={'derivative_id':derivative_id,'manifest_sha256':sha,'path':str(target),'released_at':now(),'recorded_exact_byte_approval':True}
        audit(db,'customer_report.redacted_released',receipt);db.execute('RELEASE SAVEPOINT redacted_release');return receipt
    except BaseException:
        try:db.execute('ROLLBACK TO SAVEPOINT redacted_release');db.execute('RELEASE SAVEPOINT redacted_release')
        finally:
            if created:shutil.rmtree(target)
        raise
