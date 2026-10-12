"""Logged Android access observations without installing apps or changing permissions."""
import re
import uuid
from pathlib import Path
from .core import UserError, audit, digest, json_text, now
from .tools import command, execute


def provider_state(output):
    lowered=output.lower()
    if any(s in lowered for s in ['permission denial','permission denied','securityexception','not allowed']):return 'access_denied'
    if 'no result found' in lowered:return 'readable_empty'
    if re.search(r'Row:\s*\d+\s+_id=',output):return 'readable_ids_only'
    return 'unresolved'


def assess_android(root,db,workspace,serial):
    if not serial or serial.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.:-]+',serial):raise UserError('Use an explicit valid device serial.')
    cmd=command(workspace,'adb')+['-s',serial]
    folder=root/'assessments'/uuid.uuid4().hex[:12];folder.mkdir(parents=True)
    result={'platform':'android','serial':serial,'started_at':now(),'commands':[],'providers':{},'status':'running',
            'device_changes':'Read-only ADB queries only; no root, bootloader, package, permission or clock changes. Device services may log these queries.'}
    audit(db,'assessment.started',{'serial':serial,'path':str(folder.relative_to(root))});db.commit()
    def run(args,name):
        value=execute(cmd+args,folder/name,30)
        result['commands'].append(value)
        return (folder/name).read_text(errors='replace'),value
    try:
        state,status=run(['get-state'],'state.txt')
        if status['returncode']!=0 or state.strip()!='device':raise UserError('Device unavailable or host not authorized.')
        props,status=run(['shell','getprop'],'properties.txt')
        pairs=dict(re.findall(r'^\[(.*?)\]: \[(.*?)\]$',props,re.M))
        result['device']={key:pairs.get(key) for key in ['ro.product.manufacturer','ro.product.model','ro.build.version.release','ro.build.version.sdk','ro.build.version.security_patch','ro.build.fingerprint']}
        clock,_=run(['shell','date','+%Y-%m-%dT%H:%M:%S%z'],'clock.txt')
        result['clock']={'device':clock.strip(),'observed_host_utc':now(),'note':'Observation only; no offset correction applied.'}
        su,status=run(['shell','command','-v','su'],'su-path.txt')
        result['root_command']='present_unverified' if status['returncode']==0 and su.strip() else 'not_observed'
        for name,uri in [('contacts','content://com.android.contacts/contacts'),('calls','content://call_log/calls'),('sms','content://sms')]:
            output,status=run(['shell','content','query','--uri',uri,'--projection','_id'],name+'-access.txt')
            stderr=Path(status['stderr']).read_text(errors='replace') if status.get('stderr') else ''
            result['providers'][name]={'state':provider_state(output+'\n'+stderr),'returncode':status['returncode'],
                'scope':'ID-only shell permission probe. No contact names, message bodies or call numbers requested.'}
        result['routes']=[
            {'artifact':'SMS/MMS','route':'telephony USB backup','state':'requires_attempt','limit':'Device and app backup policy can omit records; this probe does not test backup success.'},
            {'artifact':'SMS/MMS/calls','route':'SMS Backup & Restore XML export','state':'supported_import','limit':'Requires a supplied export. Installing or granting a helper app changes the device and must be documented.'},
            {'artifact':'contacts','route':'UTF-8 vCard 3/4 export','state':'supported_import','limit':'Requires a supplied export; contact labels are not authenticated identities.'},
            {'artifact':'shared files/media','route':'explicit shared-folder USB pull','state':'requires_path_access','limit':'Does not reach private app sandboxes.'},
            {'artifact':'WhatsApp/Signal','route':'app export, known-passphrase legacy backup, or existing-root extraction','state':'source_dependent','limit':'No bootloader unlock, root installation or private-key bypass.'}]
        result['status']='assessed'
    except Exception as exc:
        result['status']='failed';result['error']=str(exc)
        if hasattr(exc,'tool_result'):result['commands'].append(exc.tool_result)
    result['finished_at']=now()
    result['log_hashes']={p.name:digest(p) for p in folder.iterdir() if p.is_file()}
    report=folder/'assessment.json';report.write_text(json_text(result)+'\n')
    audit(db,'assessment.finished',{'serial':serial,'status':result['status'],'report':str(report.relative_to(root)),'sha256':digest(report)});db.commit()
    return {**result,'path':str(report)}
