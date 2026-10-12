#!/usr/bin/env python3
"""Create and restore-check a local source/validation snapshot, without uploading."""
import argparse
import hashlib
import json
import os
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

EXCLUDED={'.git','__pycache__','.session-watch','.venv','venv','node_modules','build','dist','.cache','cache'}
VALIDATION_DATA_DIRS={'inputs','input','originals','evidence','datasets','downloads','cases','retained-tools','02-originals','03-working','04-mulder-runs'}
VALIDATION_SUFFIXES={'.py','.json','.jsonl','.txt','.log','.md','.csv','.sh','.toml','.patch','.yaml','.yml'}
MAX_SNAPSHOT_BYTES=256*1024**2

def snapshot_files(base,label,excluded):
    # Prune excluded trees before walking: active acquisitions and venvs can contain thousands of files.
    for current,dirs,files in os.walk(base,followlinks=False):
        directory=Path(current)
        for name in list(dirs):
            child=directory/name
            omit=(child.is_symlink() or name in EXCLUDED or name.endswith(('.quarantine','-venv')) or (child/'pyvenv.cfg').exists())
            if label=='validation':
                omit=omit or name in VALIDATION_DATA_DIRS or name.startswith(('hickman-','mvs2026-'))
            if omit:
                dirs.remove(name);excluded.append({'path':str(Path(label)/child.relative_to(base)),'reason':'excluded directory'})
        for name in sorted(files):
            path=directory/name
            if path.is_symlink() or not path.is_file():continue
            if name.endswith(('.lock','.tmp','.pyc','.partial')):continue
            if label=='validation' and (path.suffix not in VALIDATION_SUFFIXES or 'image-creation' in name.casefold()):
                excluded.append({'path':str(Path(label)/path.relative_to(base)),'reason':'not a report or script'});continue
            yield path


def create_snapshot(workspace, validation, destination):
    workspace,validation,destination=map(lambda p:Path(p).resolve(),(workspace,validation,destination))
    for base in (workspace,validation):
        if not base.is_dir():raise ValueError(f'Missing source directory: {base}')
        if destination==base or destination.is_relative_to(base):
            raise ValueError('Snapshot destination must be outside source and validation directories')
    destination.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    archive=destination/f'lawliet-source-validation-{stamp}.tar.gz'
    rows=[];excluded=[];total_bytes=0
    with tempfile.TemporaryDirectory(prefix='lawliet-snapshot-') as tmp:
        stage=Path(tmp)/'stage';stage.mkdir()
        for label,base in [('source',workspace),('validation',validation)]:
            for path in snapshot_files(base,label,excluded):
                rel=path.relative_to(base)
                if any(part in EXCLUDED for part in rel.parts) or path.is_symlink() or not path.is_file():continue
                if path.name.endswith(('.lock','.tmp','.pyc')):continue
                if path.stat().st_size>32*1024**2:
                    excluded.append({'path':str(Path(label)/rel),'reason':'over32MiB'});continue
                before=path.stat();data=path.read_bytes();after=path.stat()
                if (before.st_mtime_ns,before.st_size)!=(after.st_mtime_ns,after.st_size):
                    raise RuntimeError(f'File changed while snapshotting: {path}')
                total_bytes+=len(data)
                if total_bytes>MAX_SNAPSHOT_BYTES:raise RuntimeError('Source/report snapshot exceeds256MiB budget')
                name=Path(label)/rel;target=stage/name;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(data);target.chmod(before.st_mode & 0o777)
                rows.append({'path':name.as_posix(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        manifest={'created_at':stamp,'scope':'Source and validation scripts/reports only. Excludes Git metadata, virtual environments, acquisition/evidence directories, non-report validation files, files >32MiB, symlinks and caches;256MiB total budget. Same-disk staging is not a separate backup.','files':rows,'excluded':excluded,'uncompressed_bytes':total_bytes}
        (stage/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        partial=archive.with_suffix('.partial')
        with tarfile.open(partial,'w:gz') as tar:
            for path in sorted(stage.rglob('*')):
                if path.is_file():tar.add(path,arcname=path.relative_to(stage),recursive=False)
        restored=Path(tmp)/'restored';restored.mkdir()
        with tarfile.open(partial,'r:gz') as tar:tar.extractall(restored,filter='data')
        restored_manifest=json.loads((restored/'manifest.json').read_text())
        for row in restored_manifest['files']:
            data=(restored/row['path']).read_bytes()
            if len(data)!=row['bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:
                raise RuntimeError('Restore mismatch: '+row['path'])
        os.replace(partial,archive)
    receipt={'archive':str(archive),'files':len(rows),'bytes':archive.stat().st_size,'restore_verified':True,'separate_destination':False,'scope':manifest['scope']}
    archive.with_suffix('.receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--workspace',type=Path,required=True);parser.add_argument('--validation',type=Path,required=True);parser.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(create_snapshot(args.workspace.resolve(),args.validation.resolve(),args.destination.resolve()),indent=2))
