"""Verify retained engine outputs against case-audited manifests."""
import json
from .core import UserError, digest
from .mulder_engine import job_path, read_json


def captured_manifest(root, db, jid):
    receipts = [json.loads(row['detail']) for row in db.execute(
        "SELECT detail FROM audit WHERE action='engine.finished' AND json_extract(detail,'$.run_id')=?", (jid,))]
    manifest = job_path(root, jid) / 'output-manifest.json'
    expected = receipts[0].get('results', {}).get('manifest_sha256') if len(receipts)==1 else None
    if not expected or not manifest.is_file() or manifest.is_symlink() or digest(manifest) != expected:
        raise UserError('Engine output manifest integrity does not match its case audit receipt.')
    return read_json(manifest, 64*1024**2)


def verify_outputs(root, db):
    checked = 0
    for row in db.execute("SELECT detail FROM audit WHERE action='engine.finished'"):
        detail = json.loads(row['detail'])
        expected = detail.get('results', {}).get('manifest_sha256')
        if not expected:
            continue
        path = job_path(root, detail['run_id'])
        manifest = path / 'output-manifest.json'
        if not manifest.is_file() or manifest.is_symlink() or digest(manifest) != expected:
            raise UserError('Engine output manifest integrity mismatch: ' + detail['run_id'])
        inventory = read_json(manifest, 64*1024**2)
        listed = set()
        for item in inventory:
            output = path / item['path']
            if not output.resolve().is_relative_to((path / 'outputs').resolve()) or output.is_symlink():
                raise UserError('Unsafe engine output manifest path.')
            if not output.is_file() or digest(output) != item['sha256']:
                raise UserError('Engine output integrity mismatch: ' + item['path'])
            listed.add(output);checked += 1
        for output in (path / 'outputs').rglob('*'):
            if output.is_symlink() or (output.is_file() and output not in listed):
                raise UserError('Untracked engine output: ' + str(output.relative_to(path)))
    return checked
