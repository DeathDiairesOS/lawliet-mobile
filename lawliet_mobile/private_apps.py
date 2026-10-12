"""Read private Android app folders using an already available root shell."""
import json
import shlex
import uuid
from pathlib import Path
from .core import UserError, audit, extract_archive, import_evidence, json_text
from .tools import command, execute, storage_guard

PACKAGES=('com.whatsapp','com.whatsapp.w4b','org.thoughtcrime.securesms')


def collect_private_apps(root,db,workspace,serial,timeout=900,max_bytes=20*1024**3):
    if not serial or serial.startswith('-') or any(c.isspace() or c in '/\\' for c in serial):
        raise UserError('Select a valid Android serial.')
    rid=uuid.uuid4().hex[:12];folder=root/'collections'/rid;folder.mkdir(parents=True)
    commands=[];sources=[];eid=None;status='failed'
    audit(db,'collection.started',{'collection_id':rid,'platform':'android','serial':serial,'method':'existing-root private app archive','note':'Reads live app data; not an atomic snapshot. Does not install root or stop applications.'});db.commit()
    try:
        adb=command(workspace,'adb')+['-s',serial]
        probe=execute(adb+['shell','command','-v','su'],folder/'root-presence.log',20);commands.append(probe)
        if probe['returncode'] or not (folder/'root-presence.log').read_text().strip():
            raise UserError('No existing root shell is available. Private app collection requires an authorized rooted extraction, app export, or supported backup; no rooting is performed.')
        identity=execute(adb+['shell','su','-c','id'],folder/'root-access.log',30);commands.append(identity)
        if identity['returncode'] or 'uid=0' not in (folder/'root-access.log').read_text():
            raise UserError('Existing root access was not granted on the device.')
        for package in PACKAGES:
            archive=folder/(package+'.tar')
            # Fixed allowlist and quoted remote shell command; no user-supplied paths.
            remote=f'tar -cf - -C /data/user/0 {package}'
            r=execute(adb+['exec-out','su','-c',shlex.quote(remote)],archive,timeout,guard=storage_guard(folder,max_bytes));commands.append(r)
            if r['returncode']:
                sources.append({'package':package,'state':'not_returned','reason':'Package unavailable or root archive command failed.'});continue
            destination=folder/'extracted'/package;destination.mkdir(parents=True)
            try:
                extract_archive(archive,destination,max_bytes,100000)
                storage_guard(folder,max_bytes)()
                sources.append({'package':package,'state':'collected','note':'Live read; encrypted databases may still require supplied keys.'})
            except UserError as exc:
                sources.append({'package':package,'state':'failed','reason':str(exc)})
                raise
        status='complete' if all(s['state']=='collected' for s in sources) else 'partial'
        (folder/'collection.json').write_text(json_text({'collection_id':rid,'platform':'android','serial':serial,'status':status,'sources':sources,'commands':commands})+'\n')
        eid,_,_=import_evidence(root,db,folder,'android','Existing-root private app collection',max_bytes=max_bytes)
        return {'collection_id':rid,'status':status,'evidence_id':eid,'sources':sources}
    except BaseException as exc:
        status='failed';sources.append({'state':'failed','reason':str(exc)});raise
    finally:
        (folder/'collection.json').write_text(json_text({'collection_id':rid,'platform':'android','serial':serial,'status':status,'sources':sources,'commands':commands,'evidence_id':eid})+'\n')
        audit(db,'collection.finished',{'collection_id':rid,'status':status,'evidence_id':eid,'sources':sources});db.commit()
