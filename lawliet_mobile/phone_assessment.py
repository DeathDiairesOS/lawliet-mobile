"""Logged Android access observations without installs or permission changes.

The case lease serializes cooperating app writers. Creation, retained reads and
report publication reject static links; the shared runner anchors command logs
to opened descriptors and refuses changed destinations. This protects log
identity, not all child filesystem access or an OS-enforced resource boundary.
"""
import re
import os
import hashlib
import shlex
import time
import uuid
from pathlib import Path
from .core import UserError, audit, json_text, now
from .tools import command, execute, storage_guard
from .child_output import ChildOutputs
from .provider_contacts import ids_from_output
from .anchored_output import OutputFiles

MAX_ASSESSMENT_BYTES=8*1024**2


def provider_state(output, returncode=0, stderr=''):
    lowered=(output+'\n'+stderr).lower()
    if any(s in lowered for s in ['permission denial','permission denied','securityexception','not allowed']):return 'access_denied'
    if type(returncode) is not int or returncode!=0 or stderr.strip():return 'unresolved'
    try:
        identifiers=ids_from_output(output)
    except UserError:
        return 'unresolved'
    return 'readable_ids_only' if identifiers else 'readable_empty'


def assess_android(root,db,workspace,serial,*,android_user=None):
    if not isinstance(serial,str) or not serial or serial.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.:-]+',serial):raise UserError('Use an explicit valid device serial.')
    if android_user is not None and (type(android_user) is not int or not 0<=android_user<=2147483647):raise UserError('Android user must be a nonnegative integer.')
    from .runner_lease import lease
    with lease(root,db):
        return _assess_android_owned(root,db,workspace,serial,android_user)


def _assess_android_owned(root,db,workspace,serial,android_user):
    folder=root/'assessments'/uuid.uuid4().hex[:12]
    report=folder/'assessment.json'
    with OutputFiles([report]) as destination:
        return _assess_in_folder(root,db,workspace,serial,android_user,folder,report,destination)


def _assess_in_folder(root,db,workspace,serial,android_user,folder,report,destination):
    cmd=command(workspace,'adb')+['-s',serial]
    deadline=time.monotonic()+120
    observe_current=android_user is None
    result={'platform':'android','serial':serial,'started_at':now(),'commands':[],'providers':{},'status':'running','android_user':android_user,
            'scope':'Access observations only; no provider fields collected or parsed. Empty IDs do not establish phone-wide absence.',
            'collection_performed':False,'full_filesystem_qualified':False,
            'device_changes':'Read-only ADB queries only; no root, bootloader, package, permission or clock changes. Device services may log these queries.'}
    audit(db,'assessment.started',{'serial':serial,'path':str(folder.relative_to(root))});db.commit()
    def run(args,name):
        destination.check_parent()
        remaining=deadline-time.monotonic()
        if remaining<=0:raise UserError('Android assessment deadline exceeded.')
        value=execute(cmd+args,folder/name,min(30,remaining),guard=storage_guard(folder,MAX_ASSESSMENT_BYTES))
        result['commands'].append(value)
        destination.check_parent()
        storage_guard(folder,MAX_ASSESSMENT_BYTES)()
        with ChildOutputs(folder) as outputs:
            text=outputs.read(name,MAX_ASSESSMENT_BYTES).decode('utf-8')
            stderr=outputs.read(Path(value['stderr']).name,MAX_ASSESSMENT_BYTES).decode('utf-8')
        return text,value,stderr
    try:
        state,status,stderr=run(['get-state'],'state.txt')
        if status['returncode']!=0 or stderr.strip() or state.strip()!='device':raise UserError('Device unavailable or host not authorized.')
        props,status,stderr=run(['shell','getprop'],'properties.txt')
        if status['returncode']!=0 or stderr.strip():raise UserError('Device metadata query failed; source diagnostics retained.')
        pairs=dict(re.findall(r'^\[(.*?)\]: \[(.*?)\]$',props,re.M))
        result['device']={key:pairs.get(key) for key in ['ro.product.manufacturer','ro.product.model','ro.build.version.release','ro.build.version.sdk','ro.build.version.security_patch','ro.build.fingerprint','ro.board.platform','ro.soc.model','ro.hardware','ro.build.type','ro.debuggable','ro.boot.flash.locked']}
        clock,clock_status,clock_stderr=run(['shell','date','+%Y-%m-%dT%H:%M:%S%z'],'clock.txt')
        result['clock']={'device':clock.strip(),'observed_host_utc':now(),'note':'Observation only; no offset correction applied.'}
        result['clock']['query_succeeded']=clock_status['returncode']==0 and not clock_stderr.strip()
        su,status,stderr=run(['shell','command','-v','su'],'su-path.txt')
        result['root_command']='present_unverified' if status['returncode']==0 and not stderr.strip() and re.fullmatch(r'/[^\s]+',su.strip()) else 'not_observed'
        if observe_current:
            current,status,stderr=run(['shell','am','get-current-user'],'user-before.txt')
            if status['returncode']!=0 or stderr.strip() or not re.fullmatch(r'[0-9]+',current.strip()) or int(current.strip())>2147483647:raise UserError('Current Android user could not be established; no provider queries performed.')
            android_user=int(current.strip())
        result['android_user']=android_user
        result['user_binding']='observed-current-user' if observe_current else 'explicit-user'
        for name,uri in [('contacts','content://com.android.contacts/contacts'),('calls','content://call_log/calls'),('sms','content://sms'),('calendars','content://com.android.calendar/calendars')]:
            args=['content','query','--user',str(android_user),'--uri',uri,'--projection','_id']
            output,status,stderr=run(['shell',shlex.join(args)],name+'-access.txt')
            result['providers'][name]={'state':provider_state(output,status['returncode'],stderr),'returncode':status['returncode'],'android_user':android_user,
                'scope':'ID-only shell access probe, not acquisition. Calendar IDs do not establish readable events. No contact names, message bodies or call numbers requested.'}
        result['routes']=[
            {'artifact':'SMS/MMS','route':'telephony USB backup','state':'requires_attempt','limit':'Device and app backup policy can omit records; this probe does not test backup success.'},
            {'artifact':'SMS/MMS/calls','route':'SMS Backup & Restore XML export','state':'supported_import','limit':'Requires a supplied export. Installing or granting a helper app changes the device and must be documented.'},
            {'artifact':'contacts','route':'UTF-8 vCard 3/4 export','state':'supported_import','limit':'Requires a supplied export; contact labels are not authenticated identities.'},
            {'artifact':'shared files/media','route':'explicit shared-folder USB pull','state':'requires_path_access','limit':'Does not reach private app sandboxes.'},
            {'artifact':'WhatsApp/Signal','route':'app export, known-passphrase legacy backup, or existing-root extraction','state':'source_dependent','limit':'No bootloader unlock, root installation or private-key bypass.'},
            {'artifact':'full filesystem','route':'device/build-specific privileged acquisition','state':'not_established','limit':'Neither an su pathname nor logical/provider access proves privileged access, decrypted filesystem coverage or a supported exact-build acquisition method.'}]
        result['status']='assessed'
        if observe_current:
            current,status,stderr=run(['shell','am','get-current-user'],'user-after.txt')
            if status['returncode']!=0 or stderr.strip() or current.strip()!=str(android_user):
                result['status']='partial'
                result['error']='Current Android user changed or became unavailable; provider probes remained bound to the originally observed user.'
    except Exception as exc:
        result['status']='failed';result['error']=str(exc)
        if hasattr(exc,'tool_result'):result['commands'].append(exc.tool_result)
    result['finished_at']=now()
    result['log_hashes']={}
    remaining=MAX_ASSESSMENT_BYTES
    try:
        destination.check_parent()
        with ChildOutputs(folder) as logs:
            if logs.windows is not None:
                with logs.windows.listing() as entries:
                    names = sorted(entry.name for entry in entries)
            else:
                names = sorted(os.listdir(logs.fd))
            for name in names:
                try:
                    data=logs.read(name,remaining)
                    remaining-=len(data)
                    result['log_hashes'][name]=hashlib.sha256(data).hexdigest()
                except (OSError,UserError) as exc:
                    result['status']='failed'
                    result.setdefault('unverified_logs',[]).append({'name':name,'error':str(exc)})
    except (OSError,UserError) as exc:
        result['status']='failed';result['error']='Log verification failed: '+str(exc)
    report_hash=None;report_path=None
    try:
        with destination.open(report) as output:output.write(json_text(result)+'\n')
        report_hash=destination.digest(report)
        destination.publish()
        report_path=str(report)
    except (OSError,UserError) as exc:
        result['status']='failed';result['error']='Assessment publication failed: '+str(exc)
        report_hash=None
    audit(db,'assessment.finished',{'serial':serial,'status':result['status'],'report':str(report.relative_to(root)) if report_path else None,'sha256':report_hash});db.commit()
    return {**result,'path':report_path}
