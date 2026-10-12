"""Local intake of completed upstream outputs, without executing an agent or parser."""
import shutil
import os
import uuid
from pathlib import Path

from .core import UserError, audit, connect, digest, import_evidence, now
from .mulder_engine import VERSION, atomic_json, job_path
from .mulder_results import ingest, output_case_id


def import_outputs(workspace, case, source, upstream_case_id, version):
    upstream_case_id = output_case_id(upstream_case_id)
    if version != VERSION:
        raise UserError('Only reviewed Mulder 1.5.2 outputs are supported. The version must be supplied explicitly.')
    source = Path(source).expanduser()
    if source.is_symlink() or not source.is_dir():
        raise UserError('Select a regular Mulder output directory, not a link or individual file.')
    if not (source / (upstream_case_id+'.db')).is_file():
        raise UserError('The selected folder does not contain the named Mulder case database.')
    jid = uuid.uuid4().hex
    with connect(workspace, case) as (root, db):
        # Reuse ordinary bounded, hashed case intake. These are derivative reports,
        # not an assertion that the underlying device evidence has been acquired.
        eid, count, size = import_evidence(root, db, source, 'unknown',
                                         label='Mulder output · '+upstream_case_id,
                                         max_bytes=5*1024**3, expand_archives=False)
        path = job_path(root, jid)
        path.mkdir(parents=True, mode=0o700)
        state = {'id': jid, 'engine': 'mulder', 'status': 'importing', 'created_at': now(), 'worker_pid': os.getpid(),
                 'evidence_id': eid, 'upstream_case_id': upstream_case_id,
                 'engine_version': version, 'version_source': 'examiner_declared',
                 'execution_mode': 'output_import', 'upstream_execution_status': 'unknown',
                 'objective': 'Review imported Mulder output · '+upstream_case_id}
        atomic_json(path / 'status.json', state)
        audit(db, 'engine.output_import_requested', {**state, 'source': str(source.resolve()),
                                                   'files': count, 'bytes': size})
        db.commit()
        try:
            if shutil.disk_usage(root).free < size + 256*1024**2:
                raise UserError('Insufficient free space for a controlled output copy; imported originals are preserved.')
            outputs = path / 'outputs'
            outputs.mkdir()
            for row in db.execute('SELECT path,sha256 FROM files WHERE evidence_id=?', (eid,)):
                original = root / 'evidence' / eid / row['path']
                destination = outputs / row['path']
                if original.is_symlink() or not original.resolve().is_relative_to((root/'evidence'/eid).resolve()):
                    raise UserError('Unsafe preserved output path.')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, destination)
                if digest(original) != row['sha256'] or digest(destination) != row['sha256']:
                    raise UserError('Imported output changed while preparing analysis.')
            result = ingest(root, db, jid, eid, version, upstream_case_id)
            state.update(status='partial' if result['warnings'] else 'completed', results=result)
            audit(db, 'engine.finished', {'run_id': jid, 'status': state['status'],
                                         'execution_mode': 'output_import', 'results': result,
                                         'originals_unchanged': True})
            (path/'process.log').write_text('Imported existing Mulder outputs locally. No engine, model or forensic parser was executed.\nUpstream execution status and model configuration have not been independently verified.\n')
        except Exception as exc:
            state.update(status='failed', error=str(exc) if isinstance(exc, UserError) else
                         'Output ingestion failed: '+type(exc).__name__+'. Original files are retained.')
            audit(db, 'engine.failed', {'run_id': jid, 'error': state['error'], 'execution_mode': 'output_import'})
        state['finished_at'] = now()
        atomic_json(path/'status.json', state)
        return state
