"""Examiner-selected literal masking of internal TXT previews, never release."""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from .core import UserError, audit, digest, now
from .investigation_report import _checked_draft, _safe_descendant

VERSION='literal-masking-preview/1'
TOKEN='[MASKED]'
BANNER='INTERNAL MASKED TEXT PREVIEW — NOT APPROVED FOR RELEASE\n\n'
MAX_TEXT=2*1024**2
MAX_SELECTION_BYTES=16*1024
MAX_MATCHES=10000
MAX_WORKER_BYTES=16*1024**2
MAX_DRAFT_BYTES=64*1024**2
MAX_PREVIEW_BYTES=4*1024**2
TIMEOUT=5
FILES={'report.txt','technical-annex.json','investigation.json','investigation.json.receipt.json','exhibits.jsonl'}
LIMITATIONS=[
    'Only this plaintext report preview was transformed; original evidence and draft files remain unchanged.',
    'Case-sensitive literal matching uses leftmost, longest non-overlapping matches. Replacements are never matched again.',
    'Spelling, formatting, case and Unicode variants are not automatically recognized.',
    'Selection counts describe consumed matches; overlapping selections may be present in the source but consumed by a longer match.',
    'The included files are checked for the selected literal strings only. This is not general sensitive-data detection or package sanitization.',
    'Attachments, images, PDFs, thumbnails, original JSON/JSONL exhibits and indexes are not copied into this preview.',
    'The original draft approval does not authorize this derivative. Customer redaction/release requests remain unsupported.',
    'Paths, request values, original drafts, evidence and internal case records are not anonymized by this operation.'
]


def _literals(values):
    if not isinstance(values,list) or not 1<=len(values)<=128:
        raise UserError('Select 1–128 distinct literal strings for an internal preview.')
    if any(not isinstance(v,str) or not 1<=len(v)<=512 for v in values) or len(set(values))!=len(values):
        raise UserError('Preview selections require distinct nonempty strings of at most 512 characters.')
    try:used=sum(len(v.encode('utf-8')) for v in values)
    except UnicodeError:raise UserError('Preview selections require valid UTF-8 text.') from None
    if used>MAX_SELECTION_BYTES:raise UserError('Preview selection byte budget exceeded.')
    return values


def _render(text, literals):
    literals=_literals(literals)
    if not isinstance(text,str) or len(text.encode('utf-8'))>MAX_TEXT:
        raise UserError('Plaintext preview exceeds 2 MiB; narrow the source draft.')
    pattern=re.compile('|'.join(re.escape(v) for v in sorted(literals,key=lambda v:(-len(v),v))))
    indices={v:i for i,v in enumerate(literals)};counts=[0]*len(literals)
    chunks=[BANNER];spans=[];cursor=0;used=len(BANNER.encode('utf-8'))
    for match in pattern.finditer(text):
        if len(spans)>=MAX_MATCHES:raise UserError('Preview match budget exceeded.')
        piece=text[cursor:match.start()];used+=len(piece.encode('utf-8'))+len(TOKEN)
        if used>MAX_TEXT:raise UserError('Masked plaintext exceeds preview byte budget.')
        chunks.extend([piece,TOKEN]);index=indices[match.group()];counts[index]+=1
        spans.append({'selection_index':index,'start_character':match.start(),'end_character':match.end()});cursor=match.end()
    tail=text[cursor:];used+=len(tail.encode('utf-8'))
    if used>MAX_TEXT:raise UserError('Masked plaintext exceeds preview byte budget.')
    if not spans:raise UserError('No selected literal matched the source report; no preview produced.')
    chunks.append(tail);output=''.join(chunks)
    if any(v in output for v in literals):
        raise UserError('Selected literals overlap preview labels or replacement text; no preview produced.')
    return {'text':output,'spans':spans,'selections':[{'index':i,'consumed_matches':counts[i],
            'present_in_source':v in text} for i,v in enumerate(literals)]}


def _run_worker(text,literals):
    with tempfile.TemporaryDirectory(prefix='lawliet-masking-') as td:
        folder=Path(td);request=folder/'request.json';output=folder/'output.json'
        encoded=json.dumps({'text':text,'literals':literals},ensure_ascii=False)
        if len(encoded.encode('utf-8'))>MAX_WORKER_BYTES:raise UserError('Preview worker input budget exceeded.')
        request.write_text(encoded,encoding='utf-8')
        try:
            result=subprocess.run([sys.executable,'-m','lawliet_mobile.masking_preview','--worker',str(request),str(output)],
                capture_output=True,timeout=TIMEOUT)
        except subprocess.TimeoutExpired:raise UserError('Preview matching exceeded its process time limit; narrow selections.') from None
        if result.returncode or not output.is_file() or output.stat().st_size>MAX_WORKER_BYTES:
            raise UserError('Bounded literal masking refused this request; no preview produced.')
        return json.loads(output.read_text(encoding='utf-8'))


def _preflight(root,db,draft_id):
    if not isinstance(draft_id,str) or len(draft_id)!=32 or any(c not in '0123456789abcdef' for c in draft_id):
        raise UserError('Invalid source draft ID.')
    folder=_safe_descendant(root,root/'customer-drafts'/draft_id)
    if folder.parent.is_symlink() or folder.is_symlink() or not folder.is_dir():raise UserError('Unknown safe source draft.')
    manifest=folder/'manifest.json'
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size>128*1024:
        raise UserError('Source draft manifest missing or exceeds preview budget.')
    value=json.loads(manifest.read_text())
    names=[entry.get('path') for entry in value.get('files',[]) if isinstance(entry,dict)]
    if len(names)!=len(FILES) or set(names)!=FILES:raise UserError('Source draft contains unsupported preview surfaces.')
    sizes={}
    for name in FILES:
        path=folder/name
        if path.is_symlink() or not path.is_file():raise UserError('Source draft file unavailable or unsafe.')
        sizes[name]=path.stat().st_size
    if sum(sizes.values())>MAX_DRAFT_BYTES or sizes['report.txt']>MAX_TEXT or sizes['technical-annex.json']>8*1024**2:
        raise UserError('Source draft exceeds internal preview byte budget.')
    annex=json.loads((folder/'technical-annex.json').read_text());citations=annex.get('citations')
    if not isinstance(citations,list) or len(citations)>1000:raise UserError('Source citation budget exceeded.')
    # Bound the repeated source hashing performed by _checked_draft, including duplicates.
    source_bytes=0
    for citation in citations:
        snapshot=citation.get('snapshot',{})
        row=db.execute('SELECT * FROM files WHERE id=? AND evidence_id=?',(snapshot.get('file_id'),snapshot.get('evidence_id'))).fetchone()
        if not row:raise UserError('Source citation mapping unavailable.')
        source=_safe_descendant(root,root/'evidence'/row['evidence_id']/row['path'])
        if source.is_symlink() or not source.is_file():raise UserError('Source citation file unavailable or unsafe.')
        source_bytes+=source.stat().st_size
        if source_bytes>MAX_DRAFT_BYTES:raise UserError('Source verification exceeds internal preview byte budget.')
    return _checked_draft(root,db,draft_id)


def create(root,db,draft_id,literals):
    """New private preview only; never alter source draft or reuse approval."""
    literals=_literals(literals);created=None
    if not db.in_transaction:db.execute('BEGIN IMMEDIATE')
    else:db.execute('UPDATE audit SET id=id WHERE 0')
    db.execute('SAVEPOINT masking_preview')
    try:
        source,source_manifest,source_manifest_sha=_preflight(root,db,draft_id)
        source_report=source/'report.txt';source_report_sha=digest(source_report)
        raw=source_report.read_bytes()
        if len(raw)>MAX_TEXT or hashlib.sha256(raw).hexdigest()!=source_report_sha:
            raise UserError('Source report changed or exceeds preview byte budget.')
        try:text=raw.decode('utf-8')
        except UnicodeError:raise UserError('Source report is not supported UTF-8 plaintext.') from None
        rendered=_run_worker(text,literals)
        _preflight(root,db,draft_id)
        if digest(source_report)!=source_report_sha:raise UserError('Source report changed during preview creation.')
        preview_id=uuid.uuid4().hex;parent=root/'report-previews'
        if parent.is_symlink():raise UserError('Unsafe report preview directory.')
        parent.mkdir(mode=0o700,exist_ok=True)
        target=parent/preview_id;target.mkdir(mode=0o700,exist_ok=False);created=target
        text=rendered['text'];mapping={'format':'ancalor-mask-spans-v1','source_report_sha256':source_report_sha,
            'offset_unit':'Unicode code-point indices in the original report.txt, not file bytes',
            'selections':rendered['selections'],'spans':rendered['spans']}
        payloads={'preview.txt':text,'selection-spans.json':json.dumps(mapping,ensure_ascii=False,indent=2)+'\n'}
        files=[{'path':name,'bytes':len(data.encode('utf-8')),'sha256':hashlib.sha256(data.encode('utf-8')).hexdigest()} for name,data in payloads.items()]
        manifest={'format':'ancalor-internal-masking-preview-v1','preview_id':preview_id,'created_at':now(),
            'source_draft_id':draft_id,'source_manifest_sha256':source_manifest_sha,'source_report_sha256':source_report_sha,
            'review_status':'internal_masked_text_preview','release_allowed':False,'parser':VERSION,
            'selection_count':len(literals),'consumed_matches':len(rendered['spans']),'files':files,
            'literal_check_scope':'Generated preview files only; not original case/draft/request/response/audit or arbitrary sensitive strings.',
            'limitations':LIMITATIONS}
        payloads['manifest.json']=json.dumps(manifest,ensure_ascii=False,indent=2)+'\n'
        if sum(len(data.encode('utf-8')) for data in payloads.values())>MAX_PREVIEW_BYTES:
            raise UserError('Internal preview output byte budget exceeded.')
        if any(v in name or v in data for v in literals for name,data in payloads.items()):
            raise UserError('Selected literals overlap retained preview metadata; no preview produced.')
        for name,data in payloads.items():
            with (created/name).open('x',encoding='utf-8') as stream:stream.write(data)
        _,_,after_manifest_sha=_preflight(root,db,draft_id)
        if after_manifest_sha!=source_manifest_sha or digest(source_report)!=source_report_sha:
            raise UserError('Source draft changed during preview creation.')
        result={'preview_id':preview_id,'path':str(created),'source_draft_id':draft_id,
            'source_manifest_sha256':source_manifest_sha,'manifest_sha256':digest(created/'manifest.json'),
            'selection_count':len(literals),'consumed_matches':len(rendered['spans']),
            'selections':rendered['selections'],'review_status':'internal_masked_text_preview','release_allowed':False}
        audit(db,'customer_report.masking_preview_created',{k:v for k,v in result.items() if k not in {'path','selections'}})
        db.execute('RELEASE SAVEPOINT masking_preview')
        return result
    except BaseException:
        try:
            db.execute('ROLLBACK TO SAVEPOINT masking_preview');db.execute('RELEASE SAVEPOINT masking_preview')
        finally:
            if created is not None:shutil.rmtree(created)
        raise


if __name__=='__main__':
    if len(sys.argv)!=4 or sys.argv[1]!='--worker':raise SystemExit(2)
    try:
        request=Path(sys.argv[2]);output=Path(sys.argv[3])
        if request.stat().st_size>MAX_WORKER_BYTES:raise UserError('Input limit.')
        data=json.loads(request.read_text(encoding='utf-8'));result=_render(data['text'],data['literals'])
        encoded=json.dumps(result,ensure_ascii=False)
        if len(encoded.encode('utf-8'))>MAX_WORKER_BYTES:raise UserError('Output limit.')
        with output.open('x',encoding='utf-8') as stream:stream.write(encoded)
    except Exception:raise SystemExit(2) from None
