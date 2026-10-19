"""Bounded SMS observations through an authorized Android content provider.

No collector installation, permissions, root, clock changes or RCS/MMS claim.
Typed hexadecimal projections avoid content-query's NULL and delimiter ambiguity.
"""
import json
import math
import os
import re
import shlex
import stat
import time
import uuid
from pathlib import Path

from .core import UserError, add_artifact, audit, begin_run_index, digest, import_evidence, json_text, now
from .messages import metadata, scope_message
from .parsers import timestamp
from .provider_contacts import ids_from_output
from .tools import command, execute, storage_guard

VERSION = 'adb-sms-provider/0.1'
URI = 'content://sms'
FIELDS = ('thread_id', 'address', 'date', 'date_sent', 'type', 'body', 'read', 'status')
PROJECTION = ':'.join(['_id'] + [term for field in FIELDS for term in ('typeof('+field+')', 'hex('+field+')')])


class _ProviderBudgetExceeded(UserError):
    pass


def decode_row(raw, expected_id):
    """Strict format; no replacement decoding, delimiter guessing or NULL coercion."""
    if not raw.endswith('\n') or '\n' in raw[:-1]:
        raise UserError('Unrecognized typed SMS response; raw response retained.')
    values = raw[:-1].split(', ')
    if len(values) != 1 + 2 * len(FIELDS) or values[0] != f'Row: 0 _id={expected_id}':
        raise UserError('SMS record identifier or projection shape differs; raw response retained.')
    result = {'_id': expected_id}
    for index, field in enumerate(FIELDS):
        typed, encoded = values[1 + index*2:3 + index*2]
        prefix = 'typeof('+field+')='
        hex_prefix = 'hex('+field+')='
        if not typed.startswith(prefix) or not encoded.startswith(hex_prefix):
            raise UserError('SMS projection labels differ; raw response retained.')
        kind, value = typed[len(prefix):], encoded[len(hex_prefix):]
        if len(value) > 2*1024**2 or not re.fullmatch(r'(?:[0-9A-F]{2})*', value):
            raise UserError('SMS hexadecimal field invalid or above 1 MiB; raw response retained.')
        if kind == 'null':
            if value: raise UserError('Inconsistent provider NULL observation.')
            result[field] = None
        elif kind in {'text', 'integer'}:
            try: decoded = bytes.fromhex(value).decode('utf-8')
            except (ValueError, UnicodeError): raise UserError('SMS field is not valid UTF-8; raw response retained.') from None
            if kind == 'integer':
                if len(decoded)>20 or not re.fullmatch(r'-?\d+', decoded): raise UserError('Invalid provider integer observation.')
                result[field] = int(decoded)
                if not -(2**63)<=result[field]<2**63:raise UserError('Provider integer exceeds signed SQLite range.')
            else: result[field] = decoded
        else:
            raise UserError('Unsupported SMS storage type '+kind+'; raw response retained.')
    return result


def normalized(fields, user, observed_at):
    if not isinstance(fields['body'], (str, type(None))) or not isinstance(fields['address'], (str, type(None))):
        raise UserError('SMS body/address storage is not qualified text or NULL.')
    if fields['date'] is not None and type(fields['date']) is not int:
        raise UserError('SMS date storage is not qualified integer milliseconds; raw response retained.')
    direction = {1:'incoming', 2:'outgoing'}.get(fields['type'], 'unknown') if type(fields['type']) is int else 'unknown'
    address = fields['address'] or ''
    thread = fields['thread_id']
    conversation = f'android-user:{user}/thread:{thread}' if type(thread) is int else f"android-user:{user}/unlinked-record:{fields['_id']}"
    message = metadata('sms', conversation,
                       address if direction=='incoming' else '', address if direction=='outgoing' else '', direction,
                       body_status='plaintext' if fields['body'] is not None else 'no_plaintext_body',
                       attachment_status='not_assessed',
                       timestamp_field='date',
                       conversation_kind='stored_provider_thread' if type(thread) is int else 'source_record_fallback_not_a_confirmed_conversation',
                       schema_note='Android SMS provider observation; not an original SQLite database extraction.')
    return {'category':'messages', 'timestamp':timestamp(fields['date'], unit='milliseconds'),
            'timestamp_raw':None if fields['date'] is None else str(fields['date']),
            'title':'SMS provider · '+direction, 'body':fields['body'] or '',
            'data':{'raw_fields':fields, 'message':message,
                    'timestamp_semantics':'UTC conversion of the supplied SMS provider date column; date_sent is retained separately. No delivery or human-reading time is inferred.',
                    'timestamp_precision':'millisecond source encoding',
                    'field_contract_reference':'https://developer.android.com/reference/android/provider/Telephony.TextBasedSmsColumns',
                    'provider':{'uri':URI, 'record_id':fields['_id'], 'android_user':user,
                                'observed_host_utc':observed_at, 'source_tool':VERSION,
                                'limitation':'Per-record provider observation, not a transaction-wide snapshot, full filesystem, MMS or RCS acquisition.'}}}


def collect_sms(root, db, workspace, serial, timeout=900, max_bytes=64*1024**2,
                max_messages=1000, user=None, prefix=None):
    from .runner_lease import lease
    with lease(root,db):
        _reconcile_collection_manifests(root, db)
        return _collect_sms_owned(root,db,workspace,serial,timeout,max_bytes,max_messages,user,prefix)


def _write_manifest(path, value):
    """Publish generated metadata without following parent/destination links."""
    path = Path(path).absolute()
    if '..' in path.parts:
        raise UserError('Manifest parent traversal refused.')
    if os.name == 'nt':
        from .windows_files import WindowsDirectory
        with WindowsDirectory(path.parent) as parent:
            try:
                existing = parent.open_file(path.name)
            except FileNotFoundError:
                pass
            else:
                os.close(existing)
            _, fd = parent.new_file()
            published = False
            try:
                remaining = memoryview((json_text(value)+'\n').encode('utf-8'))
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise OSError('Manifest write made no progress.')
                    remaining = remaining[written:]
                os.fsync(fd)
                parent.rename(fd, path.name, replace=True)
                published = True
            finally:
                try:
                    if not published:
                        parent.delete(fd)
                finally:
                    os.close(fd)
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(path.anchor, flags)
    temporary = None
    try:
        # Anchor every path component to its opened directory; a later rename
        # cannot redirect this operation into another directory via a symlink.
        for component in path.parts[1:-1]:
            child = os.open(component, flags, dir_fd=parent)
            os.close(parent); parent = child
        try:
            existing = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1):
            raise UserError('Manifest destination is not a single-link regular file; write refused.')
        candidate = '.manifest-' + uuid.uuid4().hex
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        temporary = candidate  # Cleanup ownership starts only after exclusive creation.
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(json_text(value)+'\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
    finally:
        if temporary is not None:
            try: os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError: pass
        os.close(parent)


def _reconcile_collection_manifests(root, db):
    """Only reconcile jobs already proven abandoned by the case ownership lease."""
    for run in db.execute("SELECT id,detail FROM runs WHERE status='interrupted' AND engine=?", (VERSION,)):
        detail = json.loads(run['detail'])
        if detail.get('recovery', {}).get('state') != 'abandoned_owner_reconciled':
            continue
        cid = detail.get('collection_id')
        if not isinstance(cid, str) or not re.fullmatch(r'[0-9a-f]{12}', cid):
            continue
        path = root/'collections'/cid/'collection.json'
        if (path.parent.is_symlink() or path.parent.parent.is_symlink()
                or not path.is_file() or path.is_symlink()):
            continue
        manifest = json.loads(path.read_text())
        if (not (manifest.get('status') == 'running' or manifest.get('processing_state') == 'pending')
                or manifest.get('run_id') != run['id']
                or manifest.get('runner_ownership') != detail.get('runner_ownership')):
            continue
        manifest.update(status='interrupted', processing_state='interrupted', recovery=detail['recovery'],
                        limitations=['Owner stopped before finalization. Raw logs and checkpointed observations retained; not imported, indexed or complete.'])
        _write_manifest(path, manifest)
        audit(db, 'collection.abandoned', {'collection_id':cid, 'run_id':run['id'], 'status':'interrupted'})
    db.commit()


def _create_collection_staging(root, cid):
    """Create initial derived files through opened directories, never links."""
    root = Path(root).absolute()
    if '..' in root.parts or not re.fullmatch(r'[0-9a-f]{12}', cid):
        raise UserError('Invalid SMS staging path or collection identifier.')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(root.anchor, flags)
    try:
        for component in root.parts[1:]:
            child = os.open(component, flags, dir_fd=parent)
            os.close(parent); parent = child
        try:
            os.mkdir('collections', mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
        child = os.open('collections', flags, dir_fd=parent)
        os.close(parent); parent = child
        os.mkdir(cid, mode=0o700, dir_fd=parent)
        child = os.open(cid, flags, dir_fd=parent)
        os.close(parent); parent = child
        os.mkdir('payload', mode=0o700, dir_fd=parent)
        child = os.open('payload', flags, dir_fd=parent)
        os.close(parent); parent = child
        fd = os.open('sms-provider.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        os.close(fd)
    except OSError as exc:
        raise UserError('SMS collection staging cannot be created safely; no device command was run.') from exc
    finally:
        os.close(parent)
    folder = root/'collections'/cid
    return folder, folder/'payload', folder/'payload/sms-provider.jsonl'


def _collect_sms_owned(root, db, workspace, serial, timeout, max_bytes,
                       max_messages, user, prefix):
    if not isinstance(serial,str) or serial.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.:-]+',serial):
        raise UserError('Use an explicit valid device serial.')
    if type(max_messages) is not int or not 1 <= max_messages <= 20000:
        raise UserError('SMS collection limit must be 1–20000 records.')
    if user is not None and (type(user) is not int or not 0 <= user <= 2147483647):
        raise UserError('Android user must be a nonnegative integer.')
    if prefix is not None and (not isinstance(prefix,str) or not prefix or len(prefix)>128 or any(ord(c)<32 for c in prefix)):
        raise UserError('SMS prefix must be 1–128 characters without control characters.')
    if (type(timeout) not in (int,float) or not math.isfinite(timeout) or timeout<=0
            or type(max_bytes) is not int or not 0 < max_bytes <= 64*1024**2):
        raise UserError('Invalid SMS collection budget.')
    tool = command(workspace,'adb')
    tool_pins = [{'path':str(Path(path).resolve()),'sha256':digest(Path(path))} for path in tool]
    from .runtime_context import snapshot
    runtime=snapshot()
    adb = tool + ['-s',serial]
    cid = uuid.uuid4().hex[:12]
    folder, payload, output = _create_collection_staging(root, cid)
    deadline = time.monotonic()+timeout; commands=[]; errors=[]; rows=[]; observed=[]; status='failed'; interrupted=None; device={}; clock={}
    audit(db,'collection.started',{'collection_id':cid,'profile':'sms-provider','serial':serial,
                                  'user':user,'prefix_selected':prefix is not None,'max_messages':max_messages,
                                  'device_changes':'Read-only provider queries; device services may log reads. No installation, permission, root or clock changes.'});db.commit()
    from .runner_lease import ownership
    owner = ownership(); rid = uuid.uuid4().hex[:12]
    detail = {'runner_ownership':owner, 'collection_id':cid, 'checkpointed_records':0}
    db.execute('INSERT INTO runs(id,engine,started_at,status,detail) VALUES(?,?,?,?,?)',
               (rid,VERSION,now(),'running',json_text(detail)))
    audit(db,'analysis.started',{'run_id':rid,'engine':VERSION,'runner_ownership':owner,'collection_id':cid})
    db.commit()
    progress={'collection_id':cid,'run_id':rid,'runner_ownership':owner,'platform':'android','profile':'sms-provider',
        'status':'running','processing_state':'pending','serial':serial,'checkpointed_records':0,'coverage':[{'source':URI,'state':'requested',
        'detail':'SMS provider collection started; no finalized source or completeness claim.'}],
        'limitations':['An unfinished attempt is not a clean zero result. Raw response files may be partial.']}
    _write_manifest(folder/'collection.json',progress)
    def run(args, name):
        remaining = deadline-time.monotonic()
        if remaining<=0: raise UserError('SMS collection deadline exceeded.')
        try:
            result=execute(adb+args,folder/name,min(30,remaining),guard=storage_guard(folder,max_bytes))
        except BaseException as exc:
            if hasattr(exc,'tool_result'):commands.append(exc.tool_result)
            raise
        commands.append(result)
        raw=(folder/name).read_bytes().decode('utf-8')
        if result['returncode'] or Path(result['stderr']).read_text().strip(): raise UserError('Provider query failed; raw diagnostics retained.')
        if re.search(r'permission denial|permission denied|securityexception',raw,re.I): raise UserError('SMS provider access denied; no permission change attempted.')
        return raw
    def query(projection, selection, name):
        args=['content','query','--user',str(user),'--uri',URI,'--projection',projection]
        if selection: args += ['--where',selection]
        return run(['shell',shlex.join(args)],name)
    try:
        if run(['get-state'],'state.txt').strip()!='device': raise UserError('Device unavailable or unauthorized.')
        run(['version'],'adb-version.txt')
        for key in ('ro.product.manufacturer','ro.product.model','ro.build.version.release','ro.build.fingerprint'):
            device[key]=run(['shell','getprop',key],key+'.txt').strip()
        before=now();remote=run(['shell','date','+%Y-%m-%dT%H:%M:%S%z'],'device-clock.txt')
        clock={'device_output':remote.strip(),'host_before_utc':before,'host_after_utc':now(),'correction_applied':False}
        if user is None:
            raw=run(['shell','am','get-current-user'],'user.txt').strip()
            if not re.fullmatch(r'\d+',raw): raise UserError('Current Android user could not be established.')
            user=int(raw)
            if user>2147483647:raise UserError('Current Android user exceeds supported range.')
        selection=None if prefix is None else "substr(body,1,"+str(len(prefix))+")='"+prefix.replace("'","''")+"'"
        if query(PROJECTION,'0=1','projection-check.txt').strip()!='No result found.':
            raise UserError('Provider projection preflight returned an unexpected row; collection refused.')
        observed=ids_from_output(query('_id',selection,'ids-before.txt'))
        if len(observed)>max_messages: raise UserError('SMS identifiers exceed declared record limit; no message fields requested.')
        for identifier in observed:
            try:
                raw=query(PROJECTION,f'_id={identifier}',f'sms-{identifier}.txt')
                row=normalized(decode_row(raw,identifier),user,now())
                row['data']['provider'].update(raw_response_log=f'sms-{identifier}.txt',raw_response_sha256=digest(folder/f'sms-{identifier}.txt'))
                row_bytes=len((json.dumps(row,ensure_ascii=False)+'\n').encode('utf-8'))
                retained_bytes=sum(p.stat().st_size for p in folder.rglob('*') if p.is_file())
                receipt_bytes=sum(len(json_text(item).encode('utf-8')) for item in commands)+16*1024
                if retained_bytes+row_bytes+receipt_bytes>max_bytes:
                    raise _ProviderBudgetExceeded('Generated SMS observations and retained logs exceed the collection byte budget; partial source retained.')
                with output.open('a') as journal:
                    journal.write(json.dumps(row,ensure_ascii=False)+'\n')
                    journal.flush(); os.fsync(journal.fileno())
                rows.append(row)
                detail['checkpointed_records']=len(rows)
                db.execute('UPDATE runs SET detail=? WHERE id=?',(json_text(detail),rid));db.commit()
                progress['checkpointed_records']=len(rows)
                _write_manifest(folder/'collection.json',progress)
            except (UserError,UnicodeError) as exc:
                errors.append({'source':f'{URI}/{identifier}','error':str(exc)})
                if isinstance(exc,_ProviderBudgetExceeded):break
        after=ids_from_output(query('_id',selection,'ids-after.txt'))
        if set(after)!=set(observed): errors.append({'source':URI,'error':'Selected provider identifiers changed during collection; snapshot completeness is not established.'})
        status='partial' if errors else 'complete'
    except BaseException as exc:
        errors.append({'source':URI,'error':str(exc) or type(exc).__name__})
        status='partial' if rows else 'failed'
        if isinstance(exc,(KeyboardInterrupt,SystemExit)):
            status='interrupted';interrupted=exc
    tool_integrity=[]
    for pin in tool_pins:
        try: actual=digest(Path(pin['path']))
        except OSError: actual=None
        match=actual==pin['sha256']
        tool_integrity.append({**pin,'sha256_after':actual,'unchanged':match})
        if not match:
            errors.append({'source':'collection_tool','error':'Pinned collection tool changed or became unavailable during collection; results require review.'})
    if errors and status=='complete':status='partial' if rows else 'failed'
    coverage=[{'source':'payload/sms-provider.jsonl','state':'collected' if rows else 'collected_empty' if status=='complete' else 'failed',
               'detail':'Selected SMS provider observations only. No MMS/RCS, private-app or device completeness claim.'}]
    manifest={'collection_id':cid,'run_id':rid,'runner_ownership':owner,'platform':'android','profile':'sms-provider','serial':serial,'android_user':user,
              'selector_prefix':prefix,'status':status,'collection_status':status,'processing_state':'pending',
              'records':len(rows),'ids_observed':len(observed),
              'errors':errors,'commands':commands,'coverage':coverage,'tool_pins':tool_pins,'tool_integrity':tool_integrity,'runtime_context':runtime,'device':device,'clock_observation':clock,
              'limitations':['Per-record reads are not a transaction-wide snapshot; unchanged identifier sets do not prove unchanged content.',
                             'Live-command storage guards are periodic stop conditions and can overshoot between checks; generated rows are budgeted before retention.',
                             'SMS access does not establish MMS/RCS coverage, app-private access or complete acquisition.',
                             'Prefix selection is a provider-side SQL selector; this is distinct from a full phone backup.']}
    _write_manifest(folder/'collection.json',manifest)
    eid=import_evidence(root,db,folder,'android',label=f'Android user {user} · SMS provider')[0]
    file=db.execute('SELECT * FROM files WHERE evidence_id=? AND path=?',(eid,'payload/sms-provider.jsonl')).fetchone()
    db.execute('UPDATE runs SET evidence_id=? WHERE id=?',(eid,rid));begin_run_index(db,rid)
    count=0
    for number,row in enumerate(rows,1):
        data=row['data'];scope_message(data,eid,file['logical_path'])
        count+=add_artifact(db,eid,file['id'],'messages',row['timestamp'],row['timestamp_raw'],row['title'],row['body'],f'payload/sms-provider.jsonl:line={number}',VERSION,data,run_id=rid)
    detail={'runner_ownership':owner,'checkpointed_records':len(rows),'errors':errors,'collection_id':cid,'coverage':'Provider SMS observations only; no full-device claim.',
            'unparsed_candidates':[] if rows or status!='complete' else [{'source':file['logical_path'],'state':'parsed-empty','category':'messages','records':0,'rows_observed':0,'reason':'No SMS identifiers matched this explicitly selected provider scope. No device-wide absence conclusion.'}]}
    db.execute('UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?',(now(),status,count,json_text(detail),rid))
    audit(db,'analysis.finished',{'run_id':rid,'status':status,'new_records':count})
    result={**manifest,'processing_state':'finalized','evidence_id':eid,'run_id':rid,'path':str(folder)}
    audit(db,'collection.finished',{'collection_id':cid,'status':status,'evidence_id':eid,'run_id':rid,'errors':errors});db.commit()
    _write_manifest(root/'collections'/(cid+'-receipt.json'),result)
    # This is generated collection staging metadata. The imported evidence copy
    # preserves its earlier pending snapshot and is never rewritten.
    _write_manifest(folder/'collection.json',result)
    if interrupted is not None:raise interrupted
    return result
