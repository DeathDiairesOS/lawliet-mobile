"""Bounded, read-only ADB contacts export with retained per-field responses."""
import re
import shlex
import time
import uuid
from pathlib import Path
from .core import UserError, audit, import_evidence, json_text, now, digest
from .tools import command, execute, storage_guard

CONTACTS='content://com.android.contacts/contacts'
DATA='content://com.android.contacts/data'


def ids_from_output(raw):
    if raw.strip()=='No result found.':return []
    result=[]
    for line in raw.splitlines():
        match=re.fullmatch(r'Row: (\d+) _id=(\d+)',line)
        if not match or int(match[1])!=len(result):raise UserError('Unrecognized provider ID response; raw output retained.')
        result.append(int(match[2]))
    if not raw or len(result)!=len(set(result)):raise UserError('Empty or duplicate provider ID response.')
    return result


def field_from_output(raw,field):
    prefix='Row: 0 '+field+'='
    if not raw.startswith(prefix) or not raw.endswith('\n'):
        raise UserError('Provider field response missing or unrecognized; raw output retained.')
    # One ID and one column per query: embedded commas/newlines are field content.
    value=raw[len(prefix):-1]
    if value=='NULL':raise UserError('Provider NULL/literal-NULL ambiguity; field not converted.')
    return value


def escape_vcard(value):
    if '\x00' in value or '\r' in value:raise UserError('Unsupported control character in contact field.')
    return value.replace('\\','\\\\').replace('\n','\\n').replace(';','\\;').replace(',','\\,')


def collect_contacts(root,db,workspace,serial,timeout=900,max_bytes=64*1024**2,max_contacts=1000):
    if not serial or not re.fullmatch(r'[A-Za-z0-9_.:-]+',serial) or serial.startswith('-'):raise UserError('Use an explicit valid device serial.')
    if timeout<=0 or max_bytes<=0 or not 1<=max_contacts<=10000:raise UserError('Invalid contacts collection limits.')
    adb=command(workspace,'adb')+['-s',serial]
    identifier=uuid.uuid4().hex[:12];folder=root/'collections'/identifier;folder.mkdir(parents=True)
    deadline=time.monotonic()+timeout;commands=[];errors=[];cards=[];observed=[]
    evidence_id=None;status='failed';started=now()
    audit(db,'collection.started',{'collection_id':identifier,'profile':'contacts-provider','serial':serial,'max_contacts':max_contacts,'device_changes':'Read-only provider queries. No app installation, permission grants or root. Queries may be logged by the device.'});db.commit()
    def run(args,name):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise UserError('Contacts collection deadline exceeded.')
        try:
            value=execute(adb+args,folder/name,min(30,remaining),guard=storage_guard(folder,max_bytes))
        except Exception as exc:
            if hasattr(exc,'tool_result'):commands.append(exc.tool_result)
            raise
        commands.append(value)
        if value['returncode']!=0:raise UserError('ADB query failed; inspect retained logs.')
        raw=(folder/name).read_bytes().decode('utf-8')
        stderr=Path(value['stderr']).read_text(errors='replace')
        if stderr.strip():raise UserError('ADB query emitted diagnostics; inspect retained logs.')
        return raw
    def query(uri,column,where,name):
        args=['content','query','--uri',uri,'--projection',column]
        if where:args+=['--where',where]
        return run(['shell',shlex.join(args)],name)
    try:
        if run(['get-state'],'device-state.txt').strip()!='device':raise UserError('Device unavailable or unauthorized.')
        observed=ids_from_output(query(CONTACTS,'_id',None,'contact-ids-before.txt'))
        if len(observed)>max_contacts:raise UserError(f'Provider returned {len(observed)} contacts, exceeding limit {max_contacts}; no contact fields requested.')
        total_data=0
        for cid in observed:
            name=field_from_output(query(CONTACTS,'display_name',f'_id={cid}',f'contact-{cid}-name.txt'),'display_name')
            fields=[('FN',name),('UID',f'android-provider-contact-{cid}')]
            for kind,mime in [('TEL','vnd.android.cursor.item/phone_v2'),('EMAIL','vnd.android.cursor.item/email_v2')]:
                row_ids=ids_from_output(query(DATA,'_id',f"contact_id={cid} AND mimetype='{mime}'",f'contact-{cid}-{kind}-ids.txt'))
                total_data+=len(row_ids)
                if total_data>max_contacts*20:raise UserError('Contact data-row limit exceeded.')
                for rid in row_ids:
                    value=field_from_output(query(DATA,'data1',f'_id={rid}',f'contact-{cid}-{kind}-{rid}.txt'),'data1')
                    fields.append((kind,value))
            card='BEGIN:VCARD\nVERSION:3.0\n'+'\n'.join(k+':'+escape_vcard(v) for k,v in fields)+'\nEND:VCARD\n'
            cards.append(card)
        after=ids_from_output(query(CONTACTS,'_id',None,'contact-ids-after.txt'))
        if sorted(after)!=sorted(observed):errors.append('Contact IDs changed during acquisition; snapshot is inconsistent.')
        status='partial' if errors else 'complete'
    except Exception as exc:
        errors.append(str(exc));status='partial' if cards else 'failed'
    finally:
        if cards:(folder/'contacts.vcf').write_text(''.join(cards),encoding='utf-8',newline='')
        manifest={'collection_id':identifier,'platform':'android','serial':serial,'profile':'contacts-provider','started_at':started,'finished_at':now(),'status':status,
                  'observed_contacts':len(observed),'exported_contacts':len(cards),'commands':commands,'errors':errors,
                  'coverage':[{'source':'Android contacts provider','state':status,'detail':'Display names, phone numbers and email addresses for readable contacts. Live queries are not an atomic snapshot; matching before/after IDs does not prove fields unchanged. No deleted contacts, photos, notes, groups, other profiles, or phone-wide completeness claim.'}],
                  'derivation':'contacts.vcf is generated from the retained single-field responses, not a device-created backup or original database. UID is the observed provider contact ID, not a globally stable identity.',
                  'log_hashes':{p.name:digest(p) for p in folder.iterdir() if p.is_file()}}
        report=folder/'collection.json';report.write_text(json_text(manifest)+'\n')
        # Even denied/empty attempts preserve the complete bounded response set.
        try:evidence_id=import_evidence(root,db,folder,'android','Android contacts provider export',max_bytes=max_bytes)[0]
        except Exception as exc:
            status='failed';errors.append('Evidence import failed: '+str(exc))
            manifest.update(status=status,errors=errors);report.write_text(json_text(manifest)+'\n')
        audit(db,'collection.finished',{'collection_id':identifier,'status':status,'evidence_id':evidence_id,'manifest_sha256':digest(report),'errors':errors});db.commit()
    return {'collection_id':identifier,'status':status,'evidence_id':evidence_id,'path':str(folder),'observed_contacts':len(observed),'exported_contacts':len(cards),'errors':errors}
