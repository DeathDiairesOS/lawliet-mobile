"""Resolve images from complete retained LEAPP output, without executing HTML."""
from pathlib import PurePosixPath
from .core import UserError, digest
from .tsv import report_reader


def imported_snapshot_source(root, db, artifact, data):
    if artifact['parser'] != 'import/leapp' or data.get('_leapp_report_name') != 'Recent Activity':
        raise UserError('Select a supported snapshot from a complete imported ALEAPP output folder.')
    fields = data.get('_leapp_fields', {})
    image = fields.get('Snapshot Image', '') if isinstance(fields, dict) else ''
    if not isinstance(image, str):
        raise UserError('Unsupported imported snapshot reference.')
    relative = PurePosixPath(image)
    if ('\\' in image or len(relative.parts) != 2 or
            relative.parts[0] != 'media' or relative.suffix.lower() not in {'.jpg', '.jpeg', '.png'}):
        raise UserError('Unsupported imported snapshot reference.')
    report = db.execute('SELECT * FROM files WHERE id=? AND evidence_id=?',
                        (artifact['file_id'], artifact['evidence_id'])).fetchone()
    metadata = data.get('_import_report', {})
    if not report or metadata.get('filename') != report['path'] or metadata.get('sha256') != report['sha256']:
        raise UserError('Imported snapshot report binding failed.')
    base = root / 'evidence' / artifact['evidence_id']
    path = base / report['path']
    if (any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file() or
            not path.resolve().is_relative_to(base.resolve()) or digest(path) != report['sha256']):
        raise UserError('Imported snapshot report integrity check failed.')
    number = metadata.get('record')
    if type(number) is not int or not 2 <= number <= 1000000:
        raise UserError('Invalid imported snapshot record reference.')
    with path.open(encoding='utf-8-sig', newline='') as stream:
        supplied = next((row for index,row in enumerate(report_reader(stream),2) if index == number),None)
    if supplied != fields:
        raise UserError('Snapshot fields do not match the retained report record.')
    # LEAPP TSV output and media are siblings under one retained output root.
    logical = str(PurePosixPath(report['path']).parent.parent / relative)
    sources = list(db.execute('SELECT * FROM files WHERE evidence_id=? AND path=?',
                             (artifact['evidence_id'], logical)))
    if len(sources) != 1:
        raise UserError('Referenced snapshot was not retained with this report.')
    image_path = base / sources[0]['path']
    if any(p.is_symlink() for p in (image_path, *image_path.parents)):
        raise UserError('Snapshot symlinks are refused.')
    return sources[0]
