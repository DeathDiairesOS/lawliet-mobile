"""Local case administration. Never changes evidence, findings or release approval."""
import json
import re
import uuid
from datetime import date

from .core import UserError, audit, json_text, now

STATUSES = ('Untriaged', 'Intake', 'In progress', 'Awaiting input', 'Review', 'Closed')
PRIORITIES = ('Normal', 'High', 'Urgent', 'Low')
FIELDS = {'client': 200, 'owner': 200, 'objective': 4000, 'scope': 8000,
          'notes': 12000, 'due_date': 10, 'status': 30, 'priority': 20}


def profile(db):
    meta = dict(db.execute('SELECT key,value FROM meta'))
    value = json.loads(meta.get('case_management', '{}'))
    return {'schema_version': 1, 'revision': 0, 'status': 'Untriaged',
            'priority': 'Normal', 'client': '', 'owner': meta.get('examiner', ''),
            'objective': '', 'scope': '', 'notes': '', 'due_date': '', **value}


def _tasks_exist(db):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='case_tasks'").fetchone() is not None


def summary(db):
    p = profile(db)
    pending = db.execute('SELECT COUNT(*) FROM case_tasks WHERE completed=0').fetchone()[0] if _tasks_exist(db) else 0
    return {key: p[key] for key in ('status', 'priority', 'client', 'owner', 'due_date')} | {'open_tasks': pending}


def details(db, offset=0):
    try:
        offset = int(offset)
    except (ValueError, TypeError) as exc:
        raise UserError('Invalid task page.') from exc
    if offset < 0:
        raise UserError('Invalid task page.')
    tasks = [dict(r) for r in db.execute('SELECT * FROM case_tasks ORDER BY completed,created_at,id LIMIT 101 OFFSET ?', (offset,))] if _tasks_exist(db) else []
    events = [dict(r) for r in db.execute('SELECT id,at,action FROM audit ORDER BY id DESC LIMIT 30')]
    return {'profile': profile(db), 'tasks': tasks[:100], 'has_more': len(tasks) > 100,
            'activity': events, 'summary': summary(db)}


def update(db, values, expected_revision):
    if not isinstance(values, dict) or set(values) - FIELDS.keys():
        raise UserError('Unsupported case management fields.')
    for key, limit in FIELDS.items():
        if key in values and (not isinstance(values[key], str) or len(values[key]) > limit or '\x00' in values[key]):
            raise UserError(f'Invalid {key}; maximum {limit} characters.')
    if 'status' in values and values['status'] not in STATUSES:
        raise UserError('Unsupported case status.')
    if 'priority' in values and values['priority'] not in PRIORITIES:
        raise UserError('Unsupported case priority.')
    due = values.get('due_date', '')
    if due:
        try:
            if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', due):
                raise ValueError()
            date.fromisoformat(due)
        except ValueError as exc:
            raise UserError('Due date must be a valid YYYY-MM-DD date or blank.') from exc
    if type(expected_revision) is not int:
        raise UserError('A case revision is required.')
    db.execute('BEGIN IMMEDIATE')
    old = profile(db)
    if old['revision'] != expected_revision:
        raise UserError('Case details changed in another window. Reload before saving.')
    changed = {key: value for key, value in values.items() if old[key] != value}
    if changed:
        value = {**old, **changed, 'revision': old['revision'] + 1, 'updated_at': now()}
        db.execute('INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)', ('case_management', json_text(value)))
        audit(db, 'case.details_updated', {'revision': value['revision'],
              'before': {k: old[k] for k in changed}, 'after': changed})
    return details(db)


def add_task(db, text):
    if not isinstance(text, str) or not text.strip() or len(text) > 2000 or '\x00' in text:
        raise UserError('Enter a task of 1–2,000 characters.')
    db.execute('BEGIN IMMEDIATE')
    db.execute('''CREATE TABLE IF NOT EXISTS case_tasks(
        id TEXT PRIMARY KEY, text TEXT NOT NULL, completed INTEGER NOT NULL DEFAULT 0,
        revision INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)''')
    identifier, at = uuid.uuid4().hex, now()
    db.execute('INSERT INTO case_tasks(id,text,created_at,updated_at) VALUES(?,?,?,?)', (identifier, text.strip(), at, at))
    audit(db, 'case.task_added', {'task_id': identifier, 'text': text.strip()})
    return details(db)


def set_task(db, identifier, completed, expected_revision):
    if type(completed) is not bool or type(expected_revision) is not int:
        raise UserError('Task state and revision are required.')
    db.execute('BEGIN IMMEDIATE')
    row = db.execute('SELECT * FROM case_tasks WHERE id=?', (identifier,)).fetchone() if _tasks_exist(db) else None
    if row is None:
        raise UserError('Unknown task in this case.')
    if row['revision'] != expected_revision:
        raise UserError('Task changed in another window. Reload before saving.')
    if bool(row['completed']) != completed:
        db.execute('UPDATE case_tasks SET completed=?,revision=revision+1,updated_at=? WHERE id=?', (int(completed), now(), identifier))
        audit(db, 'case.task_updated', {'task_id': identifier, 'completed': completed, 'revision': row['revision'] + 1})
    return details(db)
