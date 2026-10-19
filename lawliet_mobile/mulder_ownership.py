"""Bind retained review work to one active Mulder case instance.

This is a review-API scope boundary, not an OS filesystem authorization layer.
Legacy cases need an exact retained-path claim in the active parent's index;
operator-created cases require an explicit binding before restricted MCP use.
"""
from contextlib import closing
import hashlib
import json
import sqlite3
from pathlib import Path
from .core import UserError, audit, connect, json_text

KEY = '_lawliet_mulder_case_binding'
FORMAT = 'lawliet-mulder-review-binding-v1'
ACTION = 'mulder.review_case_bound'


def _scope(case_path, parent_database):
    root = Path(case_path).absolute()
    parent = Path(parent_database).absolute()
    if parent.is_symlink() or not parent.is_file():
        raise UserError('Regular active Mulder case database required.')
    parent = parent.resolve()
    allowed = {(parent.parent / n).resolve() for n in ('lawliet-review', 'ancalor-review')}
    if (any(p.is_symlink() for p in (root, *root.parents)) or root.resolve().parent not in allowed
            or (root/'case.sqlite').is_symlink() or not (root/'case.sqlite').is_file()):
        raise UserError('Select a direct retained review child in the active Mulder case store; links are refused.')
    return root, parent


def _parent_identity(parent):
    try:
        with closing(sqlite3.connect(parent.as_uri()+'?mode=ro', uri=True, timeout=.1)) as db:
            db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF')
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 524288)
            rows = db.execute('SELECT case_id,ingested_at FROM case_metadata LIMIT 2').fetchall()
        if (len(rows)!=1 or not all(isinstance(x,str) and 0<len(x)<=256 for x in rows[0])
                or rows[0][0]!=parent.stem):
            raise UserError('Active Mulder case identity is invalid or ambiguous.')
        info=parent.stat()
        return {'format':FORMAT, 'case_id':rows[0][0], 'case_ingested_at':rows[0][1],
                'database_device':info.st_dev,'database_inode':info.st_ino}
    except sqlite3.Error as exc:
        raise UserError('Active Mulder case identity cannot be established.') from exc


def _audited_binding(db):
    row = db.execute('SELECT value FROM meta WHERE key=?',(KEY,)).fetchone()
    value = json.loads(row['value']) if row else None
    previous, claims = '0'*64, []
    for event in db.execute('SELECT * FROM audit ORDER BY id'):
        expected = hashlib.sha256(json_text([event['at'],event['action'],event['detail'],previous]).encode()).hexdigest()
        if event['previous_hash']!=previous or event['hash']!=expected:
            raise UserError('Review case audit integrity mismatch.')
        previous = event['hash']
        if event['action']==ACTION:claims.append(json.loads(event['detail']))
    if value is None:
        if claims:raise UserError('Review binding metadata missing; scope refused.')
        return None
    if not isinstance(value,dict) or len(claims)!=1 or claims[0]!=value:
        raise UserError('Review binding lacks its unique matching audit.')
    return value


def bind_review_case(case_path, parent_database, creation_tool_call_id=None):
    """Explicit operator/creator binding. Never silently retarget another owner."""
    if creation_tool_call_id is not None and (not isinstance(creation_tool_call_id,str) or not 1<=len(creation_tool_call_id)<=128):
        raise UserError('Invalid review creator identifier.')
    root,parent = _scope(case_path,parent_database);identity = _parent_identity(parent)
    with connect(root.parent,root.name) as (_,db):
        existing = _audited_binding(db)
        if existing is not None:
            if existing.get('owner')!=identity or existing.get('review_case_id')!=root.name:
                raise UserError('Review case already belongs to another Mulder case instance.')
            return existing
        value = {'owner':identity,'review_case_id':root.name,
                 'parent_database_at_binding':str(parent),
                 'basis':'creator' if creation_tool_call_id else 'explicit_operator',
                 'creation_tool_call_id':creation_tool_call_id}
        db.execute('INSERT INTO meta(key,value) VALUES(?,?)',(KEY,json_text(value)))
        audit(db,ACTION,value)
    return value


def _legacy_index_claim(root,parent,identity):
    """Read-only compatibility proof; never alter historical review audits."""
    sources = ('phone.ancalor_native','phone.lawliet_native','phone.ancalor_export','phone.lawliet_export',
               'phone.ancalor_recovery','phone.lawliet_recovery')
    try:
        with closing(sqlite3.connect(parent.as_uri()+'?mode=ro',uri=True,timeout=.1)) as db:
            db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF')
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 524288)
            rows = db.execute('SELECT substr(w.raw_text,1,262145) FROM windows w JOIN sources s ON s.source_id=w.source_id WHERE w.line_start=1 AND s.case_id=? AND s.source_name IN ('+','.join('?' for _ in sources)+') LIMIT 10001',(identity['case_id'],*sources))
            for number,(raw,) in enumerate(rows):
                if number>=10000:raise UserError('Legacy ownership index exceeds its verification bound; explicit binding required.')
                if not isinstance(raw,str):continue
                first = raw.split('\n',1)[0]
                if len(first.encode('utf-8'))>262144:continue
                try:header=json.loads(first)
                except (ValueError,RecursionError):continue
                retained = header.get('retained') if isinstance(header,dict) else None
                claimed = retained.get('case_path') if isinstance(retained,dict) else None
                if isinstance(claimed,str) and Path(claimed).resolve()==root.resolve():return True
    except sqlite3.Error as exc:
        raise UserError('Legacy review ownership cannot be verified; explicit binding required.') from exc
    return False


def require_review_case(case_path,parent_database):
    root,parent = _scope(case_path,parent_database);identity = _parent_identity(parent)
    try:
        with connect(root.parent,root.name) as (_,db):binding = _audited_binding(db)
    except (ValueError,TypeError,sqlite3.Error) as exc:
        raise UserError('Review case ownership cannot be verified.') from exc
    if binding is not None:
        if binding.get('owner')!=identity or binding.get('review_case_id')!=root.name:
            raise UserError('Review case belongs to another active Mulder case instance.')
    elif not _legacy_index_claim(root,parent,identity):
        raise UserError('Review case is not bound to this active Mulder case; explicit operator binding required.')
    return root
