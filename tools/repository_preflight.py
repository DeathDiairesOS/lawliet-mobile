#!/usr/bin/env python3
"""Inspect the Git publishing set without staging, deleting or uploading files."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCAL_PATH = re.compile(r'/Users/[^/\s]+/|/Volumes/|[A-Za-z]:\\Users\\')
TOKEN = re.compile(r'(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)')
# Existing failed-volume guards and their synthetic fixtures are deliberate.
REVIEWED_PATH_LITERALS = {'desktop/LawlietMobile.swift','desktop/CaseCatalog.swift','desktop/catalog_backend.py','tests/CaseCatalogCheck.swift','tests/test_case_catalog.py','tools/repository_preflight.py'}
FORBIDDEN = {'build','dist','work','cases','evidence','runtime','validation','outputs','logs','intake','originals','snapshots','backups','.session-watch','.device-interaction','.venv'}


def inspect(root):
    output = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root)
    names = sorted(set(p for p in output.decode().split('\0') if p))
    issues,files=[],[]
    for name in names:
        path=root/name
        if not path.exists():
            issues.append({'path':name,'reason':'Tracked path missing from working tree'});continue
        if path.is_symlink():
            issues.append({'path':name,'reason':'Symlink needs explicit publication review'});continue
        if not path.is_file():continue
        data=path.read_bytes()
        files.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        parts=Path(name).parts
        if any(part in FORBIDDEN or part.endswith('.app') for part in parts):
            issues.append({'path':name,'reason':'Generated/runtime path is in the publishing set'})
        if len(data)>10*1024**2:issues.append({'path':name,'reason':'Large file needs explicit publication review'})
        try:text=data.decode('utf-8')
        except UnicodeError:continue
        if LOCAL_PATH.search(text) and name not in REVIEWED_PATH_LITERALS:issues.append({'path':name,'reason':'Machine-specific absolute path needs review'})
        if TOKEN.search(text):issues.append({'path':name,'reason':'Credential-shaped content needs review; value not displayed'})
    for args in (['git','diff','--check'], ['git','diff','--cached','--check']):
        check=subprocess.run(args,cwd=root,capture_output=True,text=True)
        if check.returncode:issues.append({'path':'tracked diff','reason':' '.join(args)+' failed','details':check.stdout})
    return {'scope':'Tracked and non-ignored working-tree candidates; not a commit or exhaustive secret audit',
            'reviewed_path_literal_exceptions':sorted(REVIEWED_PATH_LITERALS),
            'candidate_files':len(files),'candidate_bytes':sum(f['bytes'] for f in files),
            'issues':issues,'files':files,'ready_for_commit_review':not issues}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=inspect(ROOT)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='files'},indent=2))
    raise SystemExit(1 if result['issues'] else 0)
