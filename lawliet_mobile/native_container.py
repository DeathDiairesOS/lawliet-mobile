"""Opt-in Python Native container; daemon identity is the recovery authority.

The trusted host controller holds the case lease. The parser receives no lease,
control descriptor, socket, host environment, CaseDB or writable host mount.
"""
from __future__ import annotations
import hashlib,json,os,re,selectors,shutil,stat,subprocess,time
from pathlib import Path
from .core import UserError,digest
from .container_runner import docker,owned_state,publish,remove_stopped,confirmed_absent
from .native_container_codec import validate,MAX_STDOUT
PROTOCOL='lawliet-native-container-job-v1'
IMAGE='sha256:4701f9885ba369bf50a80ae4b5e1f637be3aa961dbb9b676d295e98fb2c01075'
WORKER=Path(__file__).with_name('native_container_worker.py')
MAX_INPUT=32*1024**2
MAX_FILES=1000
MAX_MANIFEST=2*1024**2
MAX_WALL=90

def canonical(value):
 return json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()

def package_manifest():
 return {p.name:digest(p) for p in sorted(Path(__file__).parent.glob('*.py'))}

def execution_profile(package=None):
 package=package if package is not None else package_manifest()
 return {'profile':'lawliet-native-isolation/1','protocol':PROTOCOL,'host_adapter_sha256':digest(Path(__file__)),'host_codec_sha256':digest(Path(__file__).with_name('native_container_codec.py')),'bootstrap_sha256':digest(WORKER),'package_manifest_sha256':hashlib.sha256(canonical(package)).hexdigest()}

def validate_config(value,*,recovery=False):
 if not isinstance(value,dict) or set(value)!={'image','socket','docker','bootstrap_sha256'} or value['image']!=IMAGE or (not isinstance(value['bootstrap_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['bootstrap_sha256']) or not recovery and value['bootstrap_sha256']!=digest(WORKER)):raise UserError('Native container profile/source pin mismatch.')
 cfg=dict(value)
 for key in ('socket','docker'):
  if not isinstance(cfg[key],str):raise UserError('Explicit local Native container components required.')
  cfg[key]=str(Path(cfg[key]).expanduser().resolve())
  if any(c in cfg[key] for c in (',','\n','\r')):raise UserError('Unsupported container component path.')
 if not Path(cfg['docker']).is_file() or not os.access(cfg['docker'],os.X_OK):raise UserError('Docker CLI unavailable; no host fallback.')
 try:s=Path(cfg['socket']).stat()
 except OSError as exc:raise UserError('Existing Docker Unix socket required; no startup or host fallback.') from exc
 if not stat.S_ISSOCK(s.st_mode):raise UserError('Existing Docker Unix socket required.')
 pinned=os.environ.get('LAWLIET_CONTAINER_SOCKET')
 if pinned and str(Path(pinned).expanduser().resolve())!=cfg['socket']:raise UserError('Native socket differs from explicit endpoint.')
 return cfg

def configured(root):
 from .tools import configuration
 settings=configuration(Path(root).parent)
 if 'native_workspace_container' not in settings:return None
 cfg=validate_config(settings['native_workspace_container'])
 return available(cfg)

def available(cfg):
 p=docker(cfg,['image','inspect',IMAGE])
 if p.returncode:raise UserError('Pinned Native container image unavailable; no image pull or host fallback.')
 try:
  image=json.loads(p.stdout)[0]
  if image['Id']!=IMAGE or image['Os']!='linux' or image['Architecture']!='arm64':raise ValueError('image identity/platform')
 except (ValueError,TypeError,KeyError,IndexError) as exc:raise UserError('Native container image identity/platform mismatch.') from exc
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
 settings['native_workspace_container']=cfg;publish(path,settings)
 return {'tool':'native','container':cfg,'execution_profile':execution_profile(),'scope':'Opt-in32MiB whole retained evidence inventory, bounded Linux worker; existing local image only, no host fallback or image pull.'}

def labels(root,rid,owner):
 return {'lawliet.protocol':PROTOCOL,'lawliet.case':hashlib.sha256(str(Path(root)).encode()).hexdigest(),'lawliet.run':rid,'lawliet.owner':owner['nonce']}

def inventory(cfg,expected):
 p=docker(cfg,['ps','-a','--no-trunc',*[s for k,v in expected.items() for s in ('--filter','label='+k+'='+v)],'--format','{{.ID}}'])
 if p.returncode:raise UserError('Native daemon unavailable; retry refused.')
 ids=p.stdout.splitlines()
 if len(ids)>1 or any(not re.fullmatch('[0-9a-f]{64}',v) for v in ids):raise UserError('Ambiguous Native daemon ownership; retry refused.')
 return ids

def stopped(v):
 s=v['State']
 if any(s.get(k) for k in ('Running','Paused','Restarting')) or s.get('Status') not in ('created','exited'):raise UserError('Native daemon worker active or uncertain; retry refused.')
 return v

def settled_receipt(value,cfg,expected,profile):
 return (isinstance(value,dict) and set(value)=={'protocol','container_id','cfg','labels','state','exit_code','OOMKilled','execution_profile'} and value['protocol']==PROTOCOL and isinstance(value['container_id'],str) and re.fullmatch('[0-9a-f]{64}',value['container_id']) is not None and value['cfg']==cfg and value['labels']==expected and value['execution_profile']==profile and value['state']=='removed_after_verified_stop' and type(value['exit_code']) is int and 0<=value['exit_code']<=255 and type(value['OOMKilled']) is bool)

def recover_before_retry(root,db):
 # The audit is durable registration authority; mutable run details cannot hide
 # a native worker by dropping its config or changing its terminal status.
 claims={}
 for entry in db.execute("SELECT detail FROM audit WHERE action='analysis.started'"):
  try:claim=json.loads(entry['detail'])
  except (ValueError,TypeError):continue
  if not isinstance(claim,dict) or 'native_container_config' not in claim:continue
  rid=claim.get('run_id')
  if not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{12}',rid):raise UserError('Native container audited run identity malformed.')
  claims.setdefault(rid,[]).append(claim)
 rows={row['id']:row for row in db.execute('SELECT id,evidence_id,engine,detail FROM runs')}
 for rid,row in rows.items():
  try:detail=json.loads(row['detail'] or '{}')
  except (ValueError,TypeError):detail=None
  if isinstance(detail,dict) and 'native_container_config' in detail and rid not in claims:raise UserError('Native container claim lacks unique audited start.')
 for rid,entries in claims.items():
  if len(entries)!=1:raise UserError('Native container claim lacks unique audited start.')
  row=rows.get(rid)
  if row is None:raise UserError('Native container audited run is missing.')
  try:d=json.loads(row['detail'] or '{}')
  except (ValueError,TypeError) as exc:raise UserError('Native container run detail malformed.') from exc
  claim=entries[0]
  if (not isinstance(d,dict) or 'native_container_config' not in d or claim.get('native_container_config')!=d['native_container_config'] or claim.get('runner_ownership')!=d.get('runner_ownership') or claim.get('container_execution_profile')!=d.get('container_execution_profile') or claim.get('evidence_id')!=row['evidence_id'] or claim.get('engine')!=row['engine'] or 'native_container_labels' not in claim or claim['native_container_labels']!=d.get('native_container_labels')):raise UserError('Native container run differs from audited registration.')
  cfg=d['native_container_config'];owner=d.get('runner_ownership')
  if not isinstance(owner,dict) or not isinstance(owner.get('nonce'),str) or not re.fullmatch('[0-9a-f]{32}',owner['nonce']):raise UserError('Native container owner malformed.')
  expected=claim['native_container_labels']
  if (not isinstance(expected,dict) or set(expected)!={'lawliet.protocol','lawliet.case','lawliet.run','lawliet.owner'} or expected['lawliet.protocol']!=PROTOCOL or expected['lawliet.run']!=rid or expected['lawliet.owner']!=owner['nonce'] or not isinstance(expected['lawliet.case'],str) or not re.fullmatch('[0-9a-f]{64}',expected['lawliet.case'])):raise UserError('Native container audited labels malformed.')
  completed=[]
  for a in db.execute("SELECT detail FROM audit WHERE action IN ('analysis.finished','analysis.container_reconciled')"):
   c=json.loads(a['detail'])
   if c.get('run_id')==row['id'] and isinstance(c.get('container'),dict) and c['container'].get('state')=='removed_after_verified_stop':completed.append(c)
  if len(completed)>1:raise UserError('Native container terminal settlement is ambiguous; manual reconciliation required.')
  if len(completed)==1 and completed[0]['container']==d.get('container') and settled_receipt(d.get('container'),cfg,expected,d.get('container_execution_profile')):continue
  cfg=validate_config(cfg,recovery=True);ids=inventory(cfg,expected)
  if not ids:
   from .child_output import ChildOutputs
   with ChildOutputs(Path(root)/'runs'/row['id']) as outputs:
    try:marker=json.loads(outputs.read('native-container.json',16384))
    except FileNotFoundError:marker=None
   if marker is not None:
    if not isinstance(marker,dict) or marker.get('protocol')!=PROTOCOL or marker.get('cfg')!=cfg or marker.get('labels')!=expected:raise UserError('Native recovery marker differs from audited registration.')
   # A missing marker or labelled worker does not establish that a registered
   # daemon worker stopped. Even a pre-create failure requires reconciliation.
   raise UserError('Native create/start outcome uncertain; empty inventory alone cannot settle it.')
  for cid in ids:
   v=stopped(owned_state(cfg,cid,expected));remove_stopped(cfg,cid,expected)
   receipt={'protocol':PROTOCOL,'container_id':cid,'cfg':cfg,'labels':expected,'state':'removed_after_verified_stop','exit_code':v['State']['ExitCode'],'OOMKilled':v['State']['OOMKilled'],'execution_profile':d.get('container_execution_profile')}
   publish(Path(root)/'runs'/row['id']/'native-container-recovered.json',receipt)
   from .core import audit,json_text
   d['container']=receipt;db.execute('UPDATE runs SET detail=? WHERE id=?',(json_text(d),row['id']));audit(db,'analysis.container_reconciled',{'run_id':row['id'],'container':receipt});db.commit()

def _mount(source,target):
 source=str(source)
 if any(c in source for c in (',','\n','\r')):raise UserError('Unsupported Native mount path.')
 return ['--mount','type=bind,src='+source+',dst='+target+',readonly']

def request_for(cfg,evidence,manifest):
 package=package_manifest();profile=execution_profile(package)
 request={'protocol':'lawliet-native-artifacts/1','bootstrap_sha256':cfg['bootstrap_sha256'],'package_sha256':package,'evidence':{'id':evidence['id'],'platform':evidence['platform'],'label':evidence['label'],'input_name':Path(evidence['input_path'] or '').name,'encrypted':bool(evidence['encrypted'])},'inputs':manifest}
 raw=canonical(request)
 if len(raw)>MAX_MANIFEST:raise UserError('Native container control manifest exceeds2MiB; no host fallback.')
 return request,raw,profile

class _Staging:
 """Hold run/destination directory identities; every write uses nofollow dirfds."""
 def __init__(self,folder):self.folder=Path(folder).absolute();self.fd=None;self.dirs={};self.windows=None
 @staticmethod
 def _open(path):
  path=Path(path).absolute()
  if '..' in path.parts:raise UserError('Native staging traversal refused.')
  fd=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   for part in path.parts[1:]:
    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
   return fd
  except BaseException:os.close(fd);raise
 def __enter__(self):
  if os.name=='nt':
   from .container_staging import WindowsStaging
   self.windows=WindowsStaging(self.folder).__enter__()
  else:self.fd=self._open(self.folder)
  return self
 def __exit__(self,*args):
  if self.windows is not None:self.windows.__exit__(*args);self.windows=None;return
  for fd in self.dirs.values():os.close(fd)
  self.dirs.clear()
  if self.fd is not None:os.close(self.fd);self.fd=None
 @staticmethod
 def _parts(relative):
  from pathlib import PurePosixPath
  value=PurePosixPath(relative)
  if not isinstance(relative,str) or not value.parts or value.is_absolute() or '..' in value.parts or value.as_posix()!=relative or '\\' in relative:raise UserError('Native staging path refused.')
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
  if self.windows is not None:return self.windows.check()
  fd=self._open(self.folder)
  try:
   if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)!=(os.fstat(self.fd).st_dev,os.fstat(self.fd).st_ino):raise UserError('Native staging directory changed.')
  finally:os.close(fd)
  for name,original in self.dirs.items():
   parent,leaf=self._parent(name)
   try:
    current=os.stat(leaf,dir_fd=parent,follow_symlinks=False);held=os.fstat(original)
    if not stat.S_ISDIR(current.st_mode) or (current.st_dev,current.st_ino)!=(held.st_dev,held.st_ino):raise UserError('Native staging child directory changed.')
   finally:os.close(parent)
 def mkdir(self,name):
  if self.windows is not None:return self.windows.mkdir(name)
  self.check();parent,leaf=self._parent(name)
  try:
   os.mkdir(leaf,0o755,dir_fd=parent)
   self.dirs[name]=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   os.fsync(parent)
  finally:os.close(parent)
  self.check()
 def write(self,name,data):
  if self.windows is not None:return self.windows.write(name,data)
  self.check();parent,leaf=self._parent(name,create=True);fd=None
  try:
   fd=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
   view=memoryview(data)
   while view:
    count=os.write(fd,view)
    if count<=0:raise OSError('Native staged write made no progress.')
    view=view[count:]
   os.fchmod(fd,0o444);os.fsync(fd);os.fsync(parent)
  finally:
   if fd is not None:os.close(fd)
   os.close(parent)
  self.check()
 def read(self,name,limit):
  if self.windows is not None:return self.windows.read(name,limit)
  self.check();parent,leaf=self._parent(name);fd=None
  try:
   fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>limit:raise UserError('Native staged file unsafe or oversized.')
   data=bytearray()
   while len(data)<=limit:
    block=os.read(fd,min(65536,limit+1-len(data)))
    if not block:break
    data.extend(block)
   signature=lambda v:(v.st_dev,v.st_ino,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
   if len(data)!=before.st_size or signature(before)!=signature(os.fstat(fd)) or signature(before)!=signature(os.stat(leaf,dir_fd=parent,follow_symlinks=False)):raise UserError('Native staged file changed.')
  finally:
   if fd is not None:os.close(fd)
   os.close(parent)
  self.check();return bytes(data)

def run(root,rid,owner,cfg,manifest,request,raw,profile,folder):
 from .runner_lease import CURRENT
 from .child_output import ChildOutputs
 context=CURRENT.get()
 if context is None or context['root']!=str(root) or context['identity']!=owner:raise UserError('Native container requires current case ownership.')
 cfg=validate_config(cfg)
 if execution_profile()!=profile:raise UserError('Native execution profile changed before launch.')
 eid=request['evidence']['id'];expected=labels(root,rid,owner);marker=folder/'native-container.json'
 with _Staging(folder) as staged:
  stage=folder/'container-evidence';control=folder/'container-control';code=folder/'container-code'
  staged.mkdir('container-evidence');staged.mkdir('container-control');staged.mkdir('container-code');staged.mkdir('container-code/lawliet_mobile')
  for f in manifest:
   source=root/'evidence'/eid/f['path']
   with ChildOutputs(source.parent) as inputs:data=inputs.read(source.name,MAX_INPUT)
   if len(data)!=f['bytes'] or hashlib.sha256(data).hexdigest()!=f['sha256']:raise UserError('Native container source copy mismatch.')
   staged.write('container-evidence/'+f['path'],data)
  actual={}
  with ChildOutputs(Path(__file__).parent) as package_inputs:
   for name in sorted(request['package_sha256']):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.py',name):raise UserError('Native package entry malformed.')
    data=package_inputs.read(name,2*1024**2);actual[name]=hashlib.sha256(data).hexdigest();staged.write('container-code/lawliet_mobile/'+name,data)
  if actual!=request['package_sha256']:raise UserError('Native package changed during staging.')
  req=control/'request.json';staged.write('container-control/request.json',raw);request_hash=hashlib.sha256(raw).hexdigest()
  target='/scratch/evidence/'+eid
  args=['create','--pull','never','--restart','no','--log-driver','none','--network','none','--ipc','none','--read-only','--memory','256m','--memory-swap','256m','--pids-limit','16','--cpus','1','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65534:65534','--tmpfs','/scratch:rw,noexec,nosuid,nodev,size=128m,mode=1777']
  for k,v in expected.items():args+=['--label',k+'='+v]
  mounts=((stage,target),(control,'/control'),(code,'/code'))
  for source,destination in mounts:args+=_mount(source,destination)
  args+=['--entrypoint','/usr/local/bin/python',cfg['image'],'-I','-S','-B','/code/lawliet_mobile/native_container_worker.py']
  cid=None;client=None;receipt=None;failure=None;payload=None;buffers={'out':bytearray(),'err':bytearray()}
  try:
   publish(marker,{'protocol':PROTOCOL,'cfg':cfg,'labels':expected,'state':'create_requested'})
   staged.check();p=docker(cfg,args)
   if p.returncode:raise UserError('Native container creation refused; no host fallback.')
   cid=p.stdout.strip();v=stopped(owned_state(cfg,cid,expected));publish(folder/'native-inspect-created.json',v);h=v['HostConfig']
   actual_mounts={(m.get('Source'),m.get('Destination')) for m in v['Mounts']}
   if (v['Config']['User']!='65534:65534' or not h['ReadonlyRootfs'] or h['NetworkMode']!='none' or h['IpcMode']!='none' or h['PidMode']!='' or h['Memory']!=268435456 or h['MemorySwap']!=268435456 or h['PidsLimit']!=16 or h['NanoCpus']!=1000000000 or h['CapDrop']!=['ALL'] or h['SecurityOpt']!=['no-new-privileges'] or h['Privileged'] or h.get('Devices') or h.get('DeviceRequests') or h.get('CapAdd') or h['LogConfig']!={'Type':'none','Config':{}} or h['RestartPolicy']!={'Name':'no','MaximumRetryCount':0} or h['Tmpfs']!={'/scratch':'rw,noexec,nosuid,nodev,size=128m,mode=1777'} or len(v['Mounts'])!=3 or actual_mounts!={(str(s),d) for s,d in mounts} or any(m.get('RW') or m.get('Type')!='bind' or m.get('Propagation')!='rprivate' for m in v['Mounts'])):raise UserError('Native container security/mount profile mismatch; launch refused.')
   publish(marker,{'protocol':PROTOCOL,'container_id':cid,'cfg':cfg,'labels':expected,'state':'registered_before_start'})
   staged.check()
   client=subprocess.Popen([cfg['docker'],'--host','unix://'+cfg['socket'],'start','-a',cid],stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,env={'PATH':os.defpath,'LANG':'C'},close_fds=True,start_new_session=True)
   sel=selectors.DefaultSelector();sel.register(client.stdout,selectors.EVENT_READ,'out');sel.register(client.stderr,selectors.EVENT_READ,'err');deadline=time.monotonic()+MAX_WALL
   try:
    while sel.get_map():
     if time.monotonic()>deadline:raise subprocess.TimeoutExpired('Native container',MAX_WALL)
     for key,_ in sel.select(.1):
      data=os.read(key.fileobj.fileno(),65536)
      if not data:sel.unregister(key.fileobj);continue
      if len(buffers[key.data])+len(data)>(MAX_STDOUT if key.data=='out' else 65536):raise UserError('Native container stream exceeds bound.')
      buffers[key.data].extend(data)
    client.wait(timeout=3)
   finally:sel.close()
   v=stopped(owned_state(cfg,cid,expected));publish(folder/'native-inspect-exited.json',v)
   if client.returncode or v['State']['ExitCode'] or v['State']['OOMKilled']:raise UserError('Native container failed or reached a resource limit; no records promoted.')
   trusted={'protocol':'lawliet-native-artifacts/1','request_sha256':request_hash,'source_manifest_sha256':hashlib.sha256(canonical(manifest)).hexdigest(),'evidence_id':eid,'native_parser_version':__import__('lawliet_mobile.parsers',fromlist=['VERSION']).VERSION,'package_manifest_sha256':profile['package_manifest_sha256'],'bootstrap_sha256':cfg['bootstrap_sha256']}
   payload=validate(bytes(buffers['out']),trusted,manifest)
   if execution_profile()!=profile or hashlib.sha256(staged.read('container-control/request.json',MAX_MANIFEST)).hexdigest()!=request_hash or request['package_sha256']!={name:hashlib.sha256(staged.read('container-code/lawliet_mobile/'+name,2*1024**2)).hexdigest() for name in request['package_sha256']}:raise UserError('Native container control/package changed; no records promoted.')
   for f in manifest:
    if hashlib.sha256(staged.read('container-evidence/'+f['path'],MAX_INPUT)).hexdigest()!=f['sha256']:raise UserError('Native container immutable input copy changed.')
  except BaseException as exc:failure=exc
  finally:
   try:
    from .anchored_output import OutputFiles
    try:
     paths=[folder/'native.stdout.jsonl',folder/'native.stderr']
     with OutputFiles(paths) as publication:
      for path,data in zip(paths,[bytes(buffers['out']),bytes(buffers['err'])]):
       with publication.open(path) as stream:stream.buffer.write(data)
      publication.publish()
    except BaseException as exc:
     if failure is None:failure=exc
    ids=[cid] if cid and re.fullmatch('[0-9a-f]{64}',cid) else inventory(cfg,expected)
    for owned in ids:
     v=owned_state(cfg,owned,expected)
     if any(v['State'].get(k) for k in ('Running','Paused','Restarting')):
      p=docker(cfg,['kill',owned])
      if p.returncode:raise UserError('Native container stop uncertain; recovery required.')
     v=stopped(owned_state(cfg,owned,expected));publish(folder/'native-inspect-stopped.json',v);remove_stopped(cfg,owned,expected)
     receipt={'protocol':PROTOCOL,'container_id':owned,'cfg':cfg,'labels':expected,'state':'removed_after_verified_stop','exit_code':v['State']['ExitCode'],'OOMKilled':v['State']['OOMKilled'],'execution_profile':profile};publish(marker,receipt)
   finally:
    if client is not None:
     if client.poll() is None:client.kill()
     client.wait();client.stdout.close();client.stderr.close()
  if failure is not None:
   failure.tool_result={'container':receipt};raise failure
  if receipt is None:raise UserError('Native container completion receipt missing.')
  return payload,receipt


def source_manifest(db,evidence_id):
 from .core import _safe_name
 rows=list(db.execute('SELECT id,path,logical_path,sha256,size FROM files WHERE evidence_id=? ORDER BY id LIMIT ?',(evidence_id,MAX_FILES+1)))
 if len(rows)>MAX_FILES:raise UserError('Native container whole evidence inventory exceeds1000files; no subset or host fallback.')
 manifest=[]
 for f in rows:
  if (type(f['id']) is not int or f['id']<1 or type(f['size']) is not int or f['size']<0 or not re.fullmatch('[0-9a-f]{64}',f['sha256']) or str(_safe_name(f['path']))!=f['path'] or not f['path'] or not isinstance(f['logical_path'],str) or len(f['logical_path'].encode())>4096):raise UserError('Native source inventory identity is malformed.')
  manifest.append({'id':f['id'],'path':f['path'],'logical_path':f['logical_path'],'sha256':f['sha256'],'bytes':f['size']})
 if sum(f['bytes'] for f in manifest)>MAX_INPUT:raise UserError('Native container whole evidence inventory exceeds32MiB; no subset or host fallback.')
 return manifest

def analyze(root,db,evidence_id,cfg):
 from .parsers import _native_preflight,VERSION
 from .core import begin_run_index,add_artifact,audit,json_text,now
 from .runner_lease import ownership
 from .container_runner import create_run_directory
 import uuid
 if not isinstance(evidence_id,str) or not re.fullmatch('[0-9a-f]{12}',evidence_id):raise UserError('Native container evidence identity malformed.')
 manifest=source_manifest(db,evidence_id)
 evidence=dict(_native_preflight(root,db,evidence_id))
 request,raw,profile=request_for(cfg,evidence,manifest)
 if shutil.disk_usage(root).free<sum(f['bytes'] for f in manifest)+MAX_STDOUT+64*1024**2:raise UserError('Insufficient space for native container copies, bounded output and reserve.')
 owner=ownership();rid=uuid.uuid4().hex[:12];folder=create_run_directory(root,rid);source_hash=hashlib.sha256(canonical(manifest)).hexdigest();request_hash=hashlib.sha256(raw).hexdigest()
 initial={'runner_ownership':owner,'native_container_config':cfg,'native_container_labels':labels(root,rid,owner),'container_execution_profile':profile,'source_manifest_sha256':source_hash,'request_sha256':request_hash,'source_inventory':manifest,'scope':'Entire supplied retained evidence inventory within32MiB; native baseline capability limits remain.'}
 try:
  db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)',(rid,evidence_id,VERSION,now(),'running',json_text(initial)));begin_run_index(db,rid);audit(db,'analysis.started',{'run_id':rid,'evidence_id':evidence_id,'engine':VERSION,**initial});db.commit()
 except BaseException:db.rollback();raise
 container=None;count=0;detail=dict(initial)
 try:
  try:decoded,container=run(root,rid,owner,cfg,manifest,request,raw,profile,folder)
  except BaseException as exc:
   container=getattr(exc,'tool_result',{}).get('container');raise
  _native_preflight(root,db,evidence_id)
  if manifest!=source_manifest(db,evidence_id):raise UserError('Native source inventory changed; no records promoted.')
  from .child_output import ChildOutputs
  with ChildOutputs(folder) as outputs:
   retained=outputs.read('native.stdout.jsonl',MAX_STDOUT);stderr=outputs.read('native.stderr',65536)
  if retained!=decoded.raw:raise UserError('Retained native output changed; no records promoted.')
  status=decoded.footer['native_status']
  projection={k:decoded.detail[k] for k in ('sqlite_files_examined','databases_with_records','errors','sqlite_resource_policy','unparsed_candidates','coverage')}
  detail.update(projection,stdout_sha256=hashlib.sha256(retained).hexdigest(),stderr_sha256=hashlib.sha256(stderr).hexdigest(),artifact_frames_sha256=decoded.footer['artifacts_sha256'],artifact_frames_bytes=decoded.artifact_bytes,container=container,worker_runtime=decoded.runtime,emitted_artifacts=decoded.artifact_count,run_memberships=None,originals_unchanged=True,unverified_stdout_path=str(folder/'native.stdout.jsonl'),stderr_path=str(folder/'native.stderr'))
  from .anchored_output import OutputFiles
  candidate=folder/'validated-native-output.json'
  with OutputFiles([candidate]) as publication:
   with publication.open(candidate) as stream:stream.write(json_text({'run_id':rid,'native_status':status,'detail':detail,'publication_authority':'Rows/count/status become authoritative only with the matching committed CaseDB analysis.finished audit.'})+'\n')
   candidate_sha=publication.digest(candidate);publication.publish()
  detail.update(receipt_path=str(candidate),receipt_sha256=candidate_sha)
  db.execute('BEGIN IMMEDIATE')
  if manifest!=source_manifest(db,evidence_id):raise UserError('Native source inventory changed before publication.')
  for frame in decoded.iter_artifacts():
   count+=add_artifact(db,evidence_id,frame['file_id'],frame['category'],frame['timestamp'],frame['timestamp_raw'],frame['title'],frame['body'],frame['source_ref'],VERSION,frame['data'],run_id=rid)
  memberships=db.execute('SELECT count(*) FROM artifact_runs WHERE run_id=?',(rid,)).fetchone()[0]
  if memberships!=decoded.artifact_count:raise UserError('Native artifact stream repeats identities; no records promoted.')
  detail['run_memberships']=memberships
  detail['new_records']=count
  db.execute('UPDATE runs SET finished_at=?,status=?,records=?,detail=? WHERE id=?',(now(),status,count,json_text(detail),rid));audit(db,'analysis.finished',{'run_id':rid,'status':status,'new_records':count,'emitted_artifacts':decoded.artifact_count,'container':container,'receipt_sha256':candidate_sha,'stdout_sha256':detail['stdout_sha256'],'artifact_frames_sha256':detail['artifact_frames_sha256']});db.commit()
 except BaseException as exc:
  db.rollback()
  # A commit may have succeeded before interruption was delivered. Do not
  # overwrite its authoritative terminal state or discard already-committed rows.
  durable=db.execute('SELECT status FROM runs WHERE id=?',(rid,)).fetchone()
  if durable is not None and durable['status'] in ('complete','partial'):raise
  status='interrupted' if isinstance(exc,KeyboardInterrupt) else 'failed';detail={**initial,'error':str(exc),'unverified_stdout_path':str(folder/'native.stdout.jsonl'),'stderr_path':str(folder/'native.stderr')}
  if container is not None:detail['container']=container
  try:
   from .anchored_output import OutputFiles
   failure=folder/'failed-native-output.json'
   with OutputFiles([failure]) as publication:
    with publication.open(failure) as stream:stream.write(json_text({'run_id':rid,'status':status,**detail})+'\n')
    failure_sha=publication.digest(failure);publication.publish()
   db.execute('UPDATE runs SET finished_at=?,status=?,records=0,detail=? WHERE id=?',(now(),status,json_text(detail),rid));audit(db,'analysis.finished',{'run_id':rid,'status':status,'new_records':0,**({'container':container} if container is not None else {}),'receipt_sha256':failure_sha});db.commit()
  except BaseException:db.rollback();raise
  raise
 return {'run_id':rid,'engine':VERSION,'status':status,'new_records':count,**detail}
