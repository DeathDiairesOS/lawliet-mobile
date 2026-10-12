"""Bounded, read-only file inspection and analysis previews. Never executes tools."""
from collections import Counter
from pathlib import Path

from .adapters import catalog, get_adapter
from .core import UserError

PROFILES=('standard','application','threat-hunting','sqlite-recovery','custom')


def classify(path, header):
    """Return evidence of format, not proof that a whole file is valid."""
    if header.startswith(b'SQLite format 3\x00'):return 'sqlite_header'
    if header[:4] in (b'\x37\x7f\x06\x82',b'\x37\x7f\x06\x83'):return 'sqlite_wal_header'
    if header.startswith(b'\xd9\xd5\x05\xf9\x20\xa1\x63\xd7'):return 'sqlite_journal_header'
    if header.startswith((b'PK\x03\x04',b'PK\x05\x06')):
        return 'apk_candidate' if path.suffix.lower()=='.apk' else 'zip_header'
    if header.startswith((b'\xff\xd8\xff',b'\x89PNG\r\n\x1a\n',b'GIF87a',b'GIF89a')):return 'image_header'
    if header.startswith(b'RIFF') and header[8:12]==b'WEBP':return 'image_header'
    if header[4:8]==b'ftyp':return 'iso_media_header'
    if header.lstrip(b'\xef\xbb\xbf \t\r\n').startswith(b'BEGIN:VCARD'):return 'vcard_header'
    if path.suffix.lower()=='.xml':return 'xml_name_hint'
    if path.name.endswith(('-wal','-journal','-shm')):return 'sqlite_sidecar_name_hint'
    if path.suffix.lower()=='.backup':return 'backup_name_hint'
    return 'unclassified'


def preview(root,db,workspace,evidence_id,profile='standard',selected=(),max_files=100000,max_jobs=200):
    if profile not in PROFILES:raise UserError('Unknown analysis profile.')
    if selected and profile!='custom':raise UserError('Explicit tools require the custom profile.')
    if profile=='custom' and not selected:raise UserError('Select at least one implemented adapter for custom analysis.')
    for name in selected:get_adapter(name)
    if not 1<=max_files<=100000 or not 1<=max_jobs<=1000:raise UserError('Invalid discovery limits.')
    evidence=db.execute('SELECT * FROM evidence WHERE id=?',(evidence_id,)).fetchone()
    if not evidence:raise UserError('Unknown evidence.')
    inventory=db.execute('SELECT COUNT(*) FROM files WHERE evidence_id=?',(evidence_id,)).fetchone()[0]
    base=Path(root)/'evidence'/evidence_id
    counts=Counter();examples={};sqlite_files=[];problems=[];inspected=0;problem_count=0
    # DB inventory drives reads; no recursive expansion or writable SQLite open.
    for row in db.execute('SELECT * FROM files WHERE evidence_id=? ORDER BY id LIMIT ?',(evidence_id,max_files)):
        inspected+=1
        try:
            path=base/row['path']
            if not path.resolve().is_relative_to(base.resolve()) or path.is_symlink() or not path.is_file():
                raise UserError('Missing or unsafe evidence path.')
            with path.open('rb') as stream:header=stream.read(64)
            kind=classify(Path(row['logical_path']),header)
        except (OSError,UserError) as exc:
            kind='unreadable';problem_count+=1
            if len(problems)<20:problems.append({'file_id':row['id'],'path':row['logical_path'],'error':str(exc)})
        counts[kind]+=1
        if len(examples.setdefault(kind,[]))<5:
            examples[kind].append({'file_id':row['id'],'path':row['logical_path'],'stored_sha256':row['sha256']})
        if kind=='sqlite_header' and len(sqlite_files)<max_jobs:
            sqlite_files.append({'file_id':row['id'],'path':row['logical_path'],'stored_sha256':row['sha256']})
    adapters={r['name']:r for r in catalog(workspace)['adapters']}
    warnings=[];jobs=[]
    if profile=='custom':names=list(dict.fromkeys(selected))
    elif profile=='sqlite-recovery':names=['sqlite-dissect']
    elif profile in ('application','threat-hunting'):
        names=[]
        warnings.append('This profile has no implemented execution adapter yet. '+
                        ('JADX/MobSF integration is pending.' if profile=='application' else 'AndroidQF/MVT integration is pending; no collection or IOC lookup was performed.'))
    else:
        names=[]
        if (counts['vcard_header'] and not counts['sqlite_header'] and not counts['apk_candidate']) or (counts['xml_name_hint']==inspected and inspected):names.append('native')
        elif evidence['platform'] in ('android','ios'):names.append('aleapp' if evidence['platform']=='android' else 'ileapp')
        else:warnings.append('Platform is unknown. Choose a compatible adapter explicitly; no platform parser selected.')
        if counts['image_header'] or counts['iso_media_header']:names.append('exiftool')
    complete=inspected==inventory and not problem_count
    if not complete:warnings.append('Inspection is incomplete; resolve unreadable files or the inspection limit before analysis.')
    if counts['backup_name_hint']:warnings.append('Backup filenames do not establish Signal format. Use the explicit known-passphrase workflow for supported legacy backups.')
    if counts['sqlite_sidecar_name_hint'] or counts['sqlite_wal_header'] or counts['sqlite_journal_header']:
        warnings.append('Sidecar indicators do not establish association with a database. Recovery uses captured exact-name companions; unrelated sidecars are not automatically paired.')
    for name in names:
        spec=adapters[name]
        inputs=sqlite_files if spec['input_scope']=='file' else [None]
        if not inputs:warnings.append(name+': no plaintext SQLite header found; no recovery task proposed.')
        for file in inputs:
            if len(jobs)>=max_jobs:break
            state='available_unvalidated_version' if spec['available'] else 'missing_tool'
            if name=='native':state='available'
            if not complete:state='blocked_incomplete_inspection'
            elif evidence['encrypted']:state='blocked_encrypted_evidence'
            elif evidence['platform'] not in spec['platforms']:state='incompatible_platform'
            jobs.append({'tool':name,'state':state,'evidence_id':evidence_id,
                         'input_scope':spec['input_scope'],'file':file,
                         'scope_note':'Selected database and captured exact-name sidecars on working copies.' if file else
                                      'Entire evidence source; native readers inspect supported files and use database working copies.' if name=='native' else
                                      'Entire evidence source on working copies; format indicators do not restrict this adapter to individual matching files.',
                         'tool_version':spec['tool_version'],'version_status':spec['version_status'],
                         'availability_error':spec['availability_error']})
    proposed=sum(len(sqlite_files) if adapters[n]['input_scope']=='file' else 1 for n in names)
    truncated=proposed>max_jobs or (any(adapters[n]['input_scope']=='file' for n in names) and counts['sqlite_header']>len(sqlite_files))
    if truncated:warnings.append('Task preview limit reached; this is not the complete task list.')
    return {'preview_version':1,'evidence_id':evidence_id,'platform':evidence['platform'],'profile':profile,
            'inventory_files':inventory,'inspected_files':inspected,'inspection_complete':complete,
            'format_indicators':dict(counts),'examples':examples,'problems':problems,'problem_count':problem_count,
            'tasks':jobs,'tasks_truncated':truncated,'warnings':warnings,
            'limitations':['Preview only: no tools executed, jobs queued, device queried or evidence modified.',
                           'Headers and names are indicators, not full validation or proof of readable app records. APK candidates have ZIP headers; Android package contents were not validated.',
                           'Stored hashes are inventory values, not fresh verification. Execution must recheck evidence and tool compatibility.',
                           'Unclassified files remain retained; archives are not expanded during preview. No absence or completeness conclusion follows from discovery.']}
