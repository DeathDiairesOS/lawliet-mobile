"""Exact-path media indexing and verified local preview copies."""
import json
import shutil
import sqlite3
from urllib.parse import urlsplit
from pathlib import Path, PurePosixPath

from .core import UserError, add_artifact, audit, digest


def media_type(path):
    with Path(path).open('rb') as f:
        head=f.read(32)
    if head.startswith(b'\x89PNG\r\n\x1a\n'): return 'image/png', '.png'
    if head.startswith(b'\xff\xd8\xff'): return 'image/jpeg', '.jpg'
    if head.startswith((b'GIF87a',b'GIF89a')): return 'image/gif', '.gif'
    if head[:4]==b'RIFF' and head[8:12]==b'WEBP': return 'image/webp', '.webp'
    if head[:4]==b'RIFF' and head[8:12]==b'WAVE': return 'audio/wav', '.wav'
    if head.startswith(b'caff'): return 'audio/x-caf', '.caf'
    if len(head)>12 and head[4:8]==b'ftyp':
        if head[8:12] in {b'heic',b'heix',b'hevc',b'hevx',b'mif1',b'msf1'}: return 'image/heic', '.heic'
        if head[8:12] in {b'M4A ',b'M4B '}: return 'audio/mp4', '.m4a'
        if head[8:12]==b'qt  ': return 'video/quicktime', '.mov'
        if head[8:12] in {b'mp41',b'mp42',b'isom',b'iso2',b'avc1',b'M4V '}: return 'video/mp4', '.mp4'
    return None


def attachment_rows(source_db):
    names={r[0] for r in source_db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {'attachment','message_attachment_join'} <= names: return
    cols={r[1] for r in source_db.execute('PRAGMA table_info(attachment)')}
    join_cols={r[1] for r in source_db.execute('PRAGMA table_info(message_attachment_join)')}
    if not {'filename','total_bytes'} <= cols or not {'message_id','attachment_id'} <= join_cols: return
    links={}
    for mid,aid in source_db.execute('SELECT message_id,attachment_id FROM message_attachment_join'):
        links.setdefault(aid,[]).append(str(mid))
    # SQLite projects BLOB lengths without returning payload bytes. Preserve
    # storage classes separately so an INTEGER length cannot masquerade as data.
    names = [row[1] for row in source_db.execute('PRAGMA table_info(attachment)')]
    quoted = ['"' + name.replace('"', '""') + '"' for name in names]
    expressions = [expression for col in quoted for expression in
                   (f'typeof({col})', f"CASE WHEN typeof({col}) = 'blob' THEN length({col}) ELSE {col} END")]
    previous = source_db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
    source_db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, min(previous, 8 * 1024**2))
    try:
        cursor = source_db.execute('SELECT ROWID, ' + ','.join(expressions) + ' FROM attachment')
        for record in cursor:
            aid = record[0]
            raw = {name: ({'blob_bytes': record[2 + i * 2]} if record[1 + i * 2] == 'blob'
                          else record[2 + i * 2]) for i, name in enumerate(names)}
            yield {'attachment_row_id': aid, 'filename': raw['filename'],
                   'expected_bytes': raw['total_bytes'], 'message_row_ids': links.get(aid, []),
                   'raw_attachment': raw,
                   **{name: raw[name] for name in ('created_date', 'transfer_name') if name in raw}}
    except sqlite3.DataError as exc:
        raise sqlite3.DataError('Attachment metadata exceeds the bounded SQLite value/row limit; source coverage incomplete.') from exc
    finally:
        source_db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, previous)



def resolve_attachment(row, file_rows):
    name=row['filename']
    data={**row,'status':'not_acquired','file_id':None}
    if not isinstance(name, str) or not name or any(ord(c)<32 or ord(c)==127 for c in name) or '\\' in name:
        return {**data, 'status':'unsupported_reference'}
    if name.lower().startswith(('http:', 'https:')):
        try:
            url = urlsplit(name)
            safe_url = (url.scheme.lower() in ('http', 'https') and bool(url.hostname)
                        and not url.username and not url.password and not any(c.isspace() for c in name))
            url.port  # Validate malformed/out-of-range ports without resolving the host.
        except ValueError:
            safe_url = False
        return {**data, 'status':'external_reference' if safe_url else 'unsupported_reference'}
    if ':' in name or '..' in name.split('/') or '.' in name.split('/') or '//' in name or name.endswith('/'):
        return {**data, 'status':'unsupported_reference'}
    candidates=[]
    # Match complete known paths only, never a basename or an arbitrary suffix.
    if name.startswith('~/'): candidates=[name[2:], 'HomeDomain/'+name[2:], 'MediaDomain/'+name[2:]]
    elif name.startswith('/var/mobile/') or name.startswith('/private/var/mobile/'):
        relative=name.split('/var/mobile/',1)[1]
        candidates=[name.lstrip('/'),relative,'HomeDomain/'+relative,'MediaDomain/'+relative]
    elif name and not name.startswith('/') and '..' not in PurePosixPath(name).parts:
        candidates=[name]
    matches=[r for r in file_rows if r['logical_path'] in candidates]
    if not candidates: return {**data, 'status':'unsupported_reference'}
    if len(matches)>1: data['status']='ambiguous_path'
    elif matches:
        match=matches[0]
        data.update(file_id=match['id'],logical_path=match['logical_path'],sha256=match['sha256'],bytes=match['size'])
        data['status']='available' if row['expected_bytes'] is not None and row['expected_bytes']==match['size'] else 'size_mismatch'
    return data


def index_media(root, db, evidence_id, files, parser, *, run_id=None):
    count=0
    for source in files:
        path=root/'evidence'/evidence_id/source['path']
        kind=media_type(path)
        if kind:
            data={'media':{'file_id':source['id'],'mime':kind[0],'bytes':source['size'],'status':'available'},
                  'note':'Type identified by file signature. No capture timestamp inferred from host filesystem times.'}
            count+=add_artifact(db,evidence_id,source['id'],'media',None,None,Path(source['logical_path']).name,
                                kind[0], 'file:'+source['logical_path'],parser,data,run_id=run_id)
    return count


def snapshot_source(root, db, artifact, data):
    if artifact['parser'] == 'import/leapp':
        from .imported_snapshot import imported_snapshot_source
        return imported_snapshot_source(root, db, artifact, data)
    fields=data.get('_leapp_fields',{})
    if artifact['parser']!='aleapp' or data.get('_leapp_report_name')!='Recent Activity':
        raise UserError('Preview requires locally acquired media or a supported ALEAPP task snapshot.')
    if not isinstance(fields,dict):
        raise UserError('Invalid snapshot fields.')
    profile,task=fields.get('CE Profile',''),fields.get('Task ID','')
    if not isinstance(profile,str) or not isinstance(task,str) or not profile.isascii() or not profile.isdigit() or not task.isascii() or not task.isdigit():
        raise UserError('Snapshot profile/task identifiers are missing or invalid.')
    logical=f'data/system_ce/{profile}/snapshots/{task}.jpg'
    sources=list(db.execute('SELECT * FROM files WHERE evidence_id=? AND logical_path=?',(artifact['evidence_id'],logical)))
    if len(sources)!=1:
        raise UserError('No unique acquired snapshot at the recorded profile/task path.')
    reference=artifact['source_ref'].rsplit(':line=',1)[0]
    relative=PurePosixPath(reference)
    if relative.is_absolute() or '..' in relative.parts or not reference.startswith('runs/'):
        raise UserError('Invalid retained report reference.')
    report=root/reference
    if not report.resolve().is_relative_to((root/'runs').resolve()) or report.is_symlink() or not report.is_file():
        raise UserError('Retained report is unavailable.')
    if digest(report)!=data.get('_ancalor_report',{}).get('sha256'):
        raise UserError('Retained report integrity check failed.')
    image=PurePosixPath(fields.get('Snapshot Image',''))
    if len(image.parts)!=2 or image.parts[0]!='media' or image.suffix.lower() not in {'.jpg','.jpeg','.png'}:
        raise UserError('Unsupported task snapshot reference.')
    output_image=report.parent.parent/image
    if output_image.is_symlink() or not output_image.is_file() or not output_image.resolve().is_relative_to(report.parent.parent.resolve()):
        raise UserError('Retained snapshot is unavailable.')
    if digest(output_image)!=sources[0]['sha256']:
        raise UserError('Report snapshot does not match the acquired image hash.')
    return sources[0]


def preview(root,db,artifact_id):
    artifact=db.execute('SELECT * FROM artifacts WHERE id=?',(artifact_id,)).fetchone()
    if not artifact:
        raise UserError('Unknown artifact.')
    data=json.loads(artifact['data'])
    if artifact['parser'].startswith('native/'):
        item=data.get('media') or data.get('attachment')
        if not isinstance(item,dict) or item.get('status')!='available':
            raise UserError('Attachment is missing, ambiguous, or has a size mismatch. Preview unavailable.')
        source=db.execute('SELECT * FROM files WHERE id=? AND evidence_id=?',(item.get('file_id'),artifact['evidence_id'])).fetchone()
    elif artifact['parser']=='exiftool' and artifact['category']=='media' and artifact['file_id'] is not None:
        source=db.execute('SELECT * FROM files WHERE id=? AND evidence_id=?',(artifact['file_id'],artifact['evidence_id'])).fetchone()
        if not source or data.get('SourceFile')!=source['path']:
            raise UserError('ExifTool preview requires an exact acquired-file mapping.')
    else:
        source=snapshot_source(root,db,artifact,data)
    if not source: raise UserError('No matching evidence file.')
    path=root/'evidence'/artifact['evidence_id']/source['path']
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to((root/'evidence'/artifact['evidence_id']).resolve()) or digest(path)!=source['sha256']:
        raise UserError('Media integrity check failed.')
    kind=media_type(path)
    if not kind or source['size']>512*1024**2:
        raise UserError('Preview supports recognized images/audio/video up to 512 MiB.')
    destination=root/'previews'/(source['sha256']+kind[1]);destination.parent.mkdir(exist_ok=True)
    shutil.copyfile(path,destination)
    if digest(destination)!=source['sha256']: raise UserError('Preview copy integrity failed.')
    audit(db,'media.previewed',{'artifact_id':artifact_id,'sha256':source['sha256'],'mime':kind[0]})
    return {'path':str(destination),'mime':kind[0],'sha256':source['sha256'],'bytes':source['size']}
