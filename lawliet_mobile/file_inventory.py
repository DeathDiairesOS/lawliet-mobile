"""Bounded retained-file browsing, separate from parsed artifact queries."""
import shutil
from .core import UserError, audit, digest
from .media import media_type


def inventory(db, query='', evidence=None, offset=0, limit=100):
    if not isinstance(query,str) or len(query)>4096 or type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=100:
        raise UserError('Use a bounded literal file query and pages of 1–100 files.')
    db.create_function('file_contains',2,lambda path,value:value.casefold() in path.casefold())
    clause='file_contains(logical_path,?)';args=[query]
    if evidence:clause+=' AND evidence_id=?';args.append(evidence)
    total=db.execute('SELECT COUNT(*) FROM files WHERE '+clause,args).fetchone()[0]
    rows=db.execute('SELECT id,evidence_id,logical_path,sha256,size FROM files WHERE '+clause+' ORDER BY evidence_id,logical_path,id LIMIT ? OFFSET ?',args+[limit,offset]).fetchall()
    return {'files':[dict(r) for r in rows],'total':total,'offset':offset,'has_more':offset+len(rows)<total}


def preview_file(root,db,file_id):
    if type(file_id) is not int:raise UserError('Select a retained file ID.')
    source=db.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone()
    if not source:raise UserError('Unknown retained file.')
    if source['size']>64*1024**2:raise UserError('File previews are limited to recognized images up to64MiB.')
    base=root/'evidence'/source['evidence_id'];path=base/source['path']
    if (any(p.is_symlink() for p in (path,*path.parents)) or not path.is_file() or
            not path.resolve().is_relative_to(base.resolve()) or path.stat().st_size!=source['size'] or digest(path)!=source['sha256']):
        raise UserError('Retained file integrity check failed.')
    kind=media_type(path)
    if not kind or not kind[0].startswith('image/'):raise UserError('Use byte inspection for this file; image preview is unsupported.')
    destination=root/'previews'/(source['sha256']+kind[1]);destination.parent.mkdir(exist_ok=True)
    shutil.copyfile(path,destination)
    if digest(destination)!=source['sha256']:raise UserError('Preview integrity check failed.')
    audit(db,'file.previewed',{'file_id':file_id,'sha256':source['sha256']})
    return {'path':str(destination),'mime':kind[0],'sha256':source['sha256'],'bytes':source['size']}
