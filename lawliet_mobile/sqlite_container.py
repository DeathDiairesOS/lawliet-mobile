"""Opt-in Python SQLite container; daemon identity is the recovery authority.

The trusted host controller holds the case lease. The parser receives no lease,
control descriptor, socket, host environment, CaseDB or writable host mount.
"""
from __future__ import annotations
import hashlib,json,os,re,selectors,stat,subprocess,time
from pathlib import Path
from .core import UserError,digest
from .container_runner import docker,owned_state,publish,remove_stopped,confirmed_absent
from .sqlite_container_codec import decode,MAX_FRAME
PROTOCOL='lawliet-sqlite-container-job-v1'
IMAGE='sha256:4701f9885ba369bf50a80ae4b5e1f637be3aa961dbb9b676d295e98fb2c01075'
WORKER=Path(__file__).with_name('sqlite_container_worker.py')
MAX_INPUT=64*1024**2

def execution_profile():
 return {'profile':'lawliet-python-sqlite-isolation/1','protocol':PROTOCOL,'host_adapter_sha256':digest(Path(__file__)),'host_codec_sha256':digest(Path(__file__).with_name('sqlite_container_codec.py')),'bootstrap_sha256':digest(WORKER)}

def validate_config(value,*,recovery=False):
 if not isinstance(value,dict) or set(value)!={'image','socket','docker','bootstrap_sha256'} or value['image']!=IMAGE or not isinstance(value['bootstrap_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['bootstrap_sha256']) or not recovery and value['bootstrap_sha256']!=digest(WORKER):raise UserError('SQLite container profile/source pin mismatch.')
 cfg=dict(value)
 for key in ('socket','docker'):
  if not isinstance(cfg[key],str):raise UserError('Explicit local SQLite container components required.')
  cfg[key]=str(Path(cfg[key]).expanduser().resolve())
  if any(c in cfg[key] for c in (',','\n','\r')):raise UserError('Unsupported container component path.')
 if not Path(cfg['docker']).is_file() or not os.access(cfg['docker'],os.X_OK):raise UserError('Docker CLI unavailable; no host fallback.')
 try:s=Path(cfg['socket']).stat()
 except OSError as exc:raise UserError('Existing Docker Unix socket required; no startup or host fallback.') from exc
 if not stat.S_ISSOCK(s.st_mode):raise UserError('Existing Docker Unix socket required.')
 pinned=os.environ.get('LAWLIET_CONTAINER_SOCKET')
 if pinned and str(Path(pinned).expanduser().resolve())!=cfg['socket']:raise UserError('SQLite socket differs from explicit endpoint.')
 return cfg

def configured(root):
 from .tools import configuration
 settings=configuration(Path(root).parent)
 if 'sqlite_workspace_container' not in settings:return None
 cfg=validate_config(settings['sqlite_workspace_container'])
 return available(cfg)

def available(cfg):
 p=docker(cfg,['image','inspect',IMAGE])
 if p.returncode:raise UserError('Pinned SQLite container image unavailable; no image pull or host fallback.')
 try:
  image=json.loads(p.stdout)[0]
  if image['Id']!=IMAGE or image['Os']!='linux' or image['Architecture']!='arm64':raise ValueError('image identity/platform')
 except (ValueError,TypeError,KeyError,IndexError) as exc:raise UserError('SQLite container image identity/platform mismatch.') from exc
 return cfg

def configure(workspace,image,socket,docker_path):
 """Record an explicit existing runtime; never pull/start daemon or fallback."""
 from .tools import config_path
 from .child_output import ChildOutputs
 from .sqlite_workspace import _worker_json
 cfg=available(validate_config({'image':image,'socket':socket,'docker':docker_path,'bootstrap_sha256':digest(WORKER)}))
 path=config_path(workspace);path.parent.mkdir(parents=True,exist_ok=True)
 with ChildOutputs(path.parent) as outputs:
  try:settings=_worker_json(outputs.read(path.name,1024**2))
  except FileNotFoundError:settings={}
 if not isinstance(settings,dict):raise UserError('Tool settings must be an object.')
 settings['sqlite_workspace_container']=cfg;publish(path,settings)
 return {'tool':'sqlite_workspace','container':cfg,'execution_profile':execution_profile(),'scope':'Opt-in64MiB selected SQLite view, bounded Linux worker; existing local image only, no host fallback or image pull.'}

def labels(root,rid,owner):
 return {'lawliet.protocol':PROTOCOL,'lawliet.case':hashlib.sha256(str(Path(root)).encode()).hexdigest(),'lawliet.run':rid,'lawliet.owner':owner['nonce']}

def inventory(cfg,expected):
 p=docker(cfg,['ps','-a','--no-trunc',*[s for k,v in expected.items() for s in ('--filter','label='+k+'='+v)],'--format','{{.ID}}'])
 if p.returncode:raise UserError('SQLite daemon unavailable; retry refused.')
 ids=p.stdout.splitlines()
 if len(ids)>1 or any(not re.fullmatch('[0-9a-f]{64}',v) for v in ids):raise UserError('Ambiguous SQLite daemon ownership; retry refused.')
 return ids

def stopped(v):
 s=v['State']
 if any(s.get(k) for k in ('Running','Paused','Restarting')) or s.get('Status') not in ('created','exited'):raise UserError('SQLite daemon worker active or uncertain; retry refused.')
 return v

def settled_receipt(value,cfg,expected,profile):
 return (isinstance(value,dict) and set(value)=={'protocol','container_id','cfg','labels','state','exit_code','OOMKilled','execution_profile'} and value['protocol']==PROTOCOL and isinstance(value['container_id'],str) and re.fullmatch('[0-9a-f]{64}',value['container_id']) is not None and value['cfg']==cfg and value['labels']==expected and value['execution_profile']==profile and value['state']=='removed_after_verified_stop' and type(value['exit_code']) is int and 0<=value['exit_code']<=255 and type(value['OOMKilled']) is bool)

def _audited_labels(value,rid,owner):
 return (isinstance(value,dict) and set(value)=={'lawliet.protocol','lawliet.case','lawliet.run','lawliet.owner'} and value['lawliet.protocol']==PROTOCOL and value['lawliet.run']==rid and value['lawliet.owner']==owner['nonce'] and isinstance(value['lawliet.case'],str) and re.fullmatch('[0-9a-f]{64}',value['lawliet.case']) is not None)

def _registration_shape(cfg,profile,owner):
 # Historical settled jobs must not depend on fresh socket/CLI/source probes.
 hashes=('host_adapter_sha256','host_codec_sha256','bootstrap_sha256')
 return (isinstance(cfg,dict) and set(cfg)=={'image','socket','docker','bootstrap_sha256'} and cfg['image']==IMAGE and all(isinstance(cfg[k],str) and Path(cfg[k]).is_absolute() and not any(c in cfg[k] for c in (',','\n','\r')) for k in ('socket','docker')) and isinstance(cfg['bootstrap_sha256'],str) and re.fullmatch('[0-9a-f]{64}',cfg['bootstrap_sha256']) is not None and isinstance(profile,dict) and set(profile)=={'profile','protocol',*hashes} and profile['profile']=='lawliet-python-sqlite-isolation/1' and profile['protocol']==PROTOCOL and all(isinstance(profile[k],str) and re.fullmatch('[0-9a-f]{64}',profile[k]) is not None for k in hashes) and profile['bootstrap_sha256']==cfg['bootstrap_sha256'] and isinstance(owner,dict) and set(owner)=={'protocol','device','inode','nonce'} and owner['protocol']=='ancalor-runner-lease-v1' and type(owner['device']) is int and owner['device']>=0 and type(owner['inode']) is int and owner['inode']>0 and isinstance(owner['nonce'],str) and re.fullmatch('[0-9a-f]{32}',owner['nonce']) is not None)

def recover_before_retry(root,db):
 """Resolve audited daemon registrations; missing mutable metadata never hides one."""
 claims={}
 for entry in db.execute("SELECT detail FROM audit WHERE action='sqlite_query.started'"):
  try:claim=json.loads(entry['detail'])
  except (ValueError,TypeError):continue
  if not isinstance(claim,dict) or 'sqlite_container_config' not in claim:continue
  rid=claim.get('run_id')
  if not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{12}',rid):raise UserError('SQLite container audited run identity malformed.')
  claims.setdefault(rid,[]).append(claim)
 rows={row['id']:row for row in db.execute('SELECT id,evidence_id,engine,detail FROM runs')}
 for rid,row in rows.items():
  try:detail=json.loads(row['detail'] or '{}')
  except (ValueError,TypeError):detail=None
  if isinstance(detail,dict) and 'sqlite_container_config' in detail and rid not in claims:raise UserError('SQLite container claim lacks unique audited start.')
 for rid,entries in claims.items():
  if len(entries)!=1:raise UserError('SQLite container claim lacks unique audited start.')
  row=rows.get(rid)
  if row is None:raise UserError('SQLite container audited run is missing.')
  try:d=json.loads(row['detail'] or '{}')
  except (ValueError,TypeError) as exc:raise UserError('SQLite container run detail malformed.') from exc
  claim=entries[0]
  if (not isinstance(d,dict) or 'sqlite_container_config' not in d or claim['sqlite_container_config']!=d['sqlite_container_config'] or claim.get('runner_ownership')!=d.get('runner_ownership') or claim.get('container_execution_profile')!=d.get('container_execution_profile') or claim.get('evidence_id')!=row['evidence_id'] or row['engine']!='sqlite-workspace/1'):raise UserError('SQLite container run differs from audited registration.')
  cfg=d['sqlite_container_config'];owner=d.get('runner_ownership');profile=d.get('container_execution_profile')
  if not _registration_shape(cfg,profile,owner):raise UserError('SQLite container audited registration malformed.')
  completed=[]
  for entry in db.execute("SELECT detail FROM audit WHERE action IN ('sqlite_query.finished','sqlite_query.container_reconciled')"):
   try:end=json.loads(entry['detail'])
   except (ValueError,TypeError):continue
   if isinstance(end,dict) and end.get('run_id')==rid and isinstance(end.get('container'),dict) and end['container'].get('state')=='removed_after_verified_stop':completed.append(end)
  if len(completed)>1:raise UserError('SQLite container terminal settlement is ambiguous; manual reconciliation required.')
  has_labels='sqlite_container_labels' in claim
  if has_labels!=('sqlite_container_labels' in d) or has_labels and claim['sqlite_container_labels']!=d['sqlite_container_labels']:raise UserError('SQLite container run labels differ from audited registration.')
  if has_labels:
   expected=claim['sqlite_container_labels']
   if not _audited_labels(expected,rid,owner):raise UserError('SQLite container audited labels malformed.')
  else:
   # Legacy compatibility is only for exact full settled receipts already
   # bound to the unique audited start and terminal. Never guess current paths.
   receipt=d.get('container');expected=receipt.get('labels') if isinstance(receipt,dict) else None
   if not _audited_labels(expected,rid,owner):raise UserError('Unresolved legacy SQLite container labels; manual reconciliation required.')
  if (len(completed)==1 and completed[0]['container']==d.get('container') and settled_receipt(d.get('container'),cfg,expected,profile)):continue
  if not has_labels:raise UserError('Unresolved legacy SQLite container registration; manual reconciliation required.')
  cfg=validate_config(cfg,recovery=True);ids=inventory(cfg,expected)
  if not ids:raise UserError('SQLite create outcome uncertain; empty inventory cannot establish verified stop; manual reconciliation required.')
  for cid in ids:
   v=stopped(owned_state(cfg,cid,expected));remove_stopped(cfg,cid,expected)
   receipt={'protocol':PROTOCOL,'container_id':cid,'cfg':cfg,'labels':expected,'state':'removed_after_verified_stop','exit_code':v['State']['ExitCode'],'OOMKilled':v['State']['OOMKilled'],'execution_profile':profile}
   publish(Path(root)/'runs'/rid/'sqlite-container-recovered.json',receipt)
   from .core import audit,json_text
   d['container']=receipt;db.execute('UPDATE runs SET detail=? WHERE id=?',(json_text(d),rid));audit(db,'sqlite_query.container_reconciled',{'run_id':rid,'container':receipt});db.commit()

def _mount(source,target):
 source=str(source)
 if any(c in source for c in (',','\n','\r')):raise UserError('Unsupported SQLite mount path.')
 return ['--mount','type=bind,src='+source+',dst='+target+',readonly']

class _Staging:
 """Hold run/destination directory identities; every write uses nofollow dirfds."""
 def __init__(self,folder):self.folder=Path(folder).absolute();self.fd=None;self.dirs={}
 @staticmethod
 def _open(path):
  path=Path(path).absolute()
  if '..' in path.parts:raise UserError('SQLite staging traversal refused.')
  fd=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   for part in path.parts[1:]:
    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
   return fd
  except BaseException:os.close(fd);raise
 def __enter__(self):self.fd=self._open(self.folder);return self
 def __exit__(self,*args):
  for fd in self.dirs.values():os.close(fd)
  self.dirs.clear()
  if self.fd is not None:os.close(self.fd);self.fd=None
 @staticmethod
 def _parts(relative):
  from pathlib import PurePosixPath
  value=PurePosixPath(relative)
  if not isinstance(relative,str) or not value.parts or value.is_absolute() or '..' in value.parts or value.as_posix()!=relative or '\\' in relative:raise UserError('SQLite staging path refused.')
  return value.parts
 def _parent(self,relative,create=False):
  parts=self._parts(relative);fd=os.dup(self.fd)
  try:
   for part in parts[:-1]:
    if create:
     try:os.mkdir(part,0o755,dir_fd=fd)
     except FileExistsError:pass
    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
   return fd,parts[-1]
  except BaseException:os.close(fd);raise
 def check(self):
  fd=self._open(self.folder)
  try:
   if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)!=(os.fstat(self.fd).st_dev,os.fstat(self.fd).st_ino):raise UserError('SQLite staging directory changed.')
  finally:os.close(fd)
  for name,original in self.dirs.items():
   parent,leaf=self._parent(name)
   try:
    current=os.stat(leaf,dir_fd=parent,follow_symlinks=False);held=os.fstat(original)
    if not stat.S_ISDIR(current.st_mode) or (current.st_dev,current.st_ino)!=(held.st_dev,held.st_ino):raise UserError('SQLite staging child directory changed.')
   finally:os.close(parent)
 def mkdir(self,name):
  self.check();parent,leaf=self._parent(name)
  try:
   os.mkdir(leaf,0o755,dir_fd=parent)
   self.dirs[name]=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   os.fsync(parent)
  finally:os.close(parent)
  self.check()
 def write(self,name,data):
  self.check();parent,leaf=self._parent(name,create=True);fd=None
  try:
   fd=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
   view=memoryview(data)
   while view:
    count=os.write(fd,view)
    if count<=0:raise OSError('SQLite staged write made no progress.')
    view=view[count:]
   os.fchmod(fd,0o444);os.fsync(fd);os.fsync(parent)
  finally:
   if fd is not None:os.close(fd)
   os.close(parent)
  self.check()
 def read(self,name,limit):
  self.check();parent,leaf=self._parent(name);fd=None
  try:
   fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>limit:raise UserError('SQLite staged file unsafe or oversized.')
   data=bytearray()
   while len(data)<=limit:
    block=os.read(fd,min(65536,limit+1-len(data)))
    if not block:break
    data.extend(block)
   signature=lambda v:(v.st_dev,v.st_ino,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
   if len(data)!=before.st_size or signature(before)!=signature(os.fstat(fd)) or signature(before)!=signature(os.stat(leaf,dir_fd=parent,follow_symlinks=False)):raise UserError('SQLite staged file changed.')
  finally:
   if fd is not None:os.close(fd)
   os.close(parent)
  self.check();return bytes(data)


def run(root,rid,owner,cfg,selected,query_request,folder):
 """Run one audited caller-owned job. No automatic image pull or fallback."""
 from .runner_lease import CURRENT
 context=CURRENT.get()
 if context is None or context['root']!=str(root) or context['identity']!=owner:raise UserError('SQLite container requires current case ownership.')
 cfg=validate_config(cfg)
 profile=query_request['container_execution_profile']
 if execution_profile()!=profile:raise UserError('SQLite execution profile changed before launch.')
 selected=[(suffix,item) for suffix,item in selected if suffix!='-shm']
 if sum(item['size'] for _,item in selected)>MAX_INPUT:raise UserError('SQLite container input bundle exceeds64MiB.')
 expected=labels(root,rid,owner);marker=folder/'sqlite-container.json'
 with _Staging(folder) as staged:
  stage=folder/'container-input';control=folder/'container-control';code=folder/'container-code'
  staged.mkdir('container-input');staged.mkdir('container-control');staged.mkdir('container-code')
  from .child_output import ChildOutputs
  for suffix,item in selected:
   source=Path(item['retained_path'])
   with ChildOutputs(source.parent) as inputs:data=inputs.read(source.name,MAX_INPUT)
   if len(data)!=item['size'] or hashlib.sha256(data).hexdigest()!=item['sha256']:raise UserError('SQLite container input copy mismatch.')
   staged.write('container-input/database.sqlite'+suffix,data)
  worker=code/'sqlite_workspace.py';bootstrap=control/'bootstrap.py'
  with ChildOutputs(Path(__file__).parent) as inputs:
   data=inputs.read('sqlite_workspace.py',2*1024**2)
   if hashlib.sha256(data).hexdigest()!=query_request['worker_source_sha256']:raise UserError('SQLite container worker source changed.')
   staged.write('container-code/sqlite_workspace.py',data)
  with ChildOutputs(WORKER.parent) as inputs:
   data=inputs.read(WORKER.name,2*1024**2)
   if hashlib.sha256(data).hexdigest()!=cfg['bootstrap_sha256']:raise UserError('SQLite bootstrap changed.')
   staged.write('container-control/bootstrap.py',data)
  request={k:query_request[k] for k in ('query','parameters','row_limit','max_output_bytes','timeout_seconds','worker_source_sha256')};request.update(protocol='lawliet-python-sqlite-input/1',inputs=[{'name':'database.sqlite'+suffix,'bytes':item['size'],'sha256':item['sha256']} for suffix,item in selected])
  req=control/'request.json';request_raw=json.dumps(request,ensure_ascii=True).encode('utf-8');staged.write('container-control/request.json',request_raw);request_hash=hashlib.sha256(request_raw).hexdigest()
  args=['create','--pull','never','--restart','no','--log-driver','none','--network','none','--ipc','none','--read-only','--memory','256m','--memory-swap','256m','--pids-limit','16','--cpus','1','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65534:65534','--tmpfs','/scratch:rw,noexec,nosuid,nodev,size=128m,mode=1777']
  for k,v in expected.items():args+=['--label',k+'='+v]
  for source,target in ((stage,'/input'),(control,'/control'),(code,'/code')):args+=_mount(source,target)
  args+=['--entrypoint','/usr/local/bin/python',cfg['image'],'-I','-S','-B','/control/bootstrap.py']
  cid=None;client=None;receipt=None;failure=None;payload=None;buffers={'out':bytearray(),'err':bytearray()}
  try:
   publish(marker,{'protocol':PROTOCOL,'cfg':cfg,'labels':expected,'state':'create_requested'})
   staged.check();p=docker(cfg,args)
   if p.returncode:raise UserError('SQLite container creation refused; no host fallback.')
   cid=p.stdout.strip();v=owned_state(cfg,cid,expected);stopped(v)
   h=v['HostConfig']
   if (v['Config']['User']!='65534:65534' or not h['ReadonlyRootfs'] or h['NetworkMode']!='none' or h['IpcMode']!='none' or h['PidMode']!='' or h['Memory']!=268435456 or h['MemorySwap']!=268435456 or h['PidsLimit']!=16 or h['NanoCpus']!=1000000000 or h['CapDrop']!=['ALL'] or 'no-new-privileges' not in h['SecurityOpt'] or len(v['Mounts'])!=3 or any(m['RW'] for m in v['Mounts'])):raise UserError('SQLite container security profile mismatch; launch refused.')
   exact_mounts={(str(stage),'/input'),(str(control),'/control'),(str(code),'/code')}
   actual_mounts={(m.get('Source'),m.get('Destination')) for m in v['Mounts']}
   if (h['Privileged'] or h.get('Devices') or h.get('DeviceRequests') or h.get('CapAdd') or h['LogConfig']!={'Type':'none','Config':{}} or h['RestartPolicy']!={'Name':'no','MaximumRetryCount':0} or h['Tmpfs']!={'/scratch':'rw,noexec,nosuid,nodev,size=128m,mode=1777'} or h['SecurityOpt']!=['no-new-privileges'] or actual_mounts!=exact_mounts or any(m.get('Type')!='bind' or m.get('Propagation')!='rprivate' for m in v['Mounts'])):raise UserError('SQLite container mount/security configuration mismatch.')
   publish(marker,{'protocol':PROTOCOL,'container_id':cid,'cfg':cfg,'labels':expected,'state':'registered_before_start'})
   staged.check()
   client=subprocess.Popen([cfg['docker'],'--host','unix://'+cfg['socket'],'start','-a',cid],stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,env={'PATH':os.defpath,'LANG':'C'},close_fds=True,start_new_session=True)
   sel=selectors.DefaultSelector();sel.register(client.stdout,selectors.EVENT_READ,'out');sel.register(client.stderr,selectors.EVENT_READ,'err');buffers={'out':bytearray(),'err':bytearray()};deadline=time.monotonic()+query_request['timeout_seconds']+5
   try:
    while sel.get_map():
     if time.monotonic()>deadline:raise subprocess.TimeoutExpired('SQLite container',query_request['timeout_seconds']+5)
     for key,_ in sel.select(.1):
      data=os.read(key.fileobj.fileno(),65536)
      if not data:sel.unregister(key.fileobj);continue
      if len(buffers[key.data])+len(data)>(MAX_FRAME if key.data=='out' else 65536):raise UserError('SQLite container stream exceeds bound.')
      buffers[key.data].extend(data)
    client.wait(timeout=3)
   finally:sel.close()
   v=stopped(owned_state(cfg,cid,expected))
   if client.returncode or v['State']['ExitCode'] or v['State']['OOMKilled']:raise UserError('SQLite container failed or reached a resource limit; no result promoted.')
   payload=decode(bytes(buffers['out']),request,request_sha256=request_hash)
   if execution_profile()!=profile or hashlib.sha256(staged.read('container-code/sqlite_workspace.py',2*1024**2)).hexdigest()!=query_request['worker_source_sha256'] or hashlib.sha256(staged.read('container-control/bootstrap.py',2*1024**2)).hexdigest()!=cfg['bootstrap_sha256'] or hashlib.sha256(staged.read('container-control/request.json',2*1024**2)).hexdigest()!=request_hash:raise UserError('SQLite container control/code changed; no result promoted.')
   for suffix,item in selected:
    if hashlib.sha256(staged.read('container-input/database.sqlite'+suffix,MAX_INPUT)).hexdigest()!=item['sha256']:raise UserError('SQLite container original copy changed.')
  except BaseException as exc:
   failure=exc
  finally:
   try:
    from .anchored_output import OutputFiles
    try:
     paths=[folder/'container.stdout.json',folder/'container.stderr']
     with OutputFiles(paths) as publication:
      for target,data in zip(paths,[bytes(buffers['out']),bytes(buffers['err'])]):
       with publication.open(target) as stream:stream.buffer.write(data)
      publication.publish()
    except BaseException as exc:
     if failure is None:failure=exc
    # Enumerate labels even after a lost create response, before allowing retry.
    ids=[cid] if cid and re.fullmatch('[0-9a-f]{64}',cid) else inventory(cfg,expected)
    for owned in ids:
     v=owned_state(cfg,owned,expected)
     if any(v['State'].get(k) for k in ('Running','Paused','Restarting')):
      p=docker(cfg,['kill',owned])
      if p.returncode:raise UserError('SQLite container stop uncertain; daemon recovery required.')
     v=stopped(owned_state(cfg,owned,expected));remove_stopped(cfg,owned,expected)
     receipt={'protocol':PROTOCOL,'container_id':owned,'cfg':cfg,'labels':expected,'state':'removed_after_verified_stop','exit_code':v['State']['ExitCode'],'OOMKilled':v['State']['OOMKilled'],'execution_profile':profile};publish(marker,receipt)
   finally:
    if client is not None:
     if client.poll() is None:client.kill()
     client.wait();client.stdout.close();client.stderr.close()
  if failure is not None:
   failure.tool_result={'container':receipt};raise failure
  if receipt is None:raise UserError('SQLite container completion receipt missing.')
  return payload,receipt
