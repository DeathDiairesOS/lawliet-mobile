"""Retain an encrypted-input refusal without pretending a parser executed."""
import uuid
from .core import UserError, audit, begin_run_index, json_text, now

ENCRYPTED_INPUT = 'encrypted_input_requires_decryption'


def refuse_encrypted(db, evidence_id, engine, reason):
    run_id = uuid.uuid4().hex[:12]
    when = now()
    detail = {'error': reason, 'execution_started': False,
              'preflight_refusal': ENCRYPTED_INPUT,
              'coverage': 'Encrypted supplied input was refused before tool execution. '
                          'No decryption, parsing or zero-match examination occurred.'}
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,finished_at,status,records,detail) '
               'VALUES(?,?,?,?,?,?,?,?)',
               (run_id, evidence_id, engine, when, when, 'failed', 0, json_text(detail)))
    begin_run_index(db, run_id)
    audit(db, 'analysis.refused', {'run_id': run_id, 'evidence_id': evidence_id,
                                'engine': engine, **detail})
    db.commit()
    raise UserError(reason)
