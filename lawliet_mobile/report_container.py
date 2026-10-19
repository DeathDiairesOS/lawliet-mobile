"""Opt-in single-report decode containment; host retains report/CaseDB authority."""
from __future__ import annotations
import hashlib,json,os,re,selectors,shutil,stat,subprocess,time,uuid
from pathlib import Path
from .core import UserError,digest
from .container_runner import docker,owned_state,publish,remove_stopped
from .native_container import _Staging,_mount
from .report_container_codec import validate,MAX_STDOUT,PROTOCOL as STREAM_PROTOCOL
PROTOCOL='lawliet-report-container-job-v1'
IMAGE='sha256:4701f9885ba369bf50a80ae4b5e1f637be3aa961dbb9b676d295e98fb2c01075'
WORKER=Path(__file__).with_name('report_container_worker.py')
MAX_INPUT=32*1024**2
MAX_MANIFEST=2*1024**2
MAX_WALL=90

def canonical(value):
 return json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()

def _same_origin(left,right):
 """Typed host-origin identity; absent historical origin remains None."""
 def valid(value):
  if value is None:return True
  if type(value) is not dict or set(value)!={'file_id','evidence_id','path','logical_path','sha256','size'}:return False
  return (type(value['file_id']) is int and 0<value['file_id']<2**63 and type(value['size']) is int and 0<=value['size']<=MAX_INPUT and type(value['evidence_id']) is str and re.fullmatch('[0-9a-f]{12}',value['evidence_id']) is not None and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']) is not None and type(value['path']) is str and bool(value['path']) and (value['logical_path'] is None or type(value['logical_path']) is str))
 try:return valid(left) and valid(right) and canonical(left)==canonical(right)
 except (TypeError,ValueError,OverflowError,RecursionError):return False

def package_manifest():
 return {p.name:digest(p) for p in sorted(Path(__file__).parent.glob('*.py'))}

def execution_profile(package=None):
 package=package if package is not None else package_manifest()
 return {'profile':'lawliet-report-isolation/1','protocol':PROTOCOL,'host_adapter_sha256':digest(Path(__file__)),'host_codec_sha256':digest(Path(__file__).with_name('report_container_codec.py')),'bootstrap_sha256':digest(WORKER),'package_manifest_sha256':hashlib.sha256(canonical(package)).hexdigest()}

def validate_config(value,*,recovery=False):
 if not isinstance(value,dict) or set(value)!={'image','socket','docker','bootstrap_sha256'} or value['image']!=IMAGE or (not isinstance(value['bootstrap_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['bootstrap_sha256']) or not recovery and value['bootstrap_sha256']!=digest(WORKER)):raise UserError('Report container profile/source pin mismatch.')
 cfg=dict(value)
 for key in ('socket','docker'):
  if not isinstance(cfg[key],str):raise UserError('Explicit local Report container components required.')
  cfg[key]=str(Path(cfg[key]).expanduser().resolve())
  if any(c in cfg[key] for c in (',','\n','\r')):raise UserError('Unsupported container component path.')
 if not Path(cfg['docker']).is_file() or not os.access(cfg['docker'],os.X_OK):raise UserError('Docker CLI unavailable; no host fallback.')
 try:s=Path(cfg['socket']).stat()
 except OSError as exc:raise UserError('Existing Docker Unix socket required; no startup or host fallback.') from exc
 if not stat.S_ISSOCK(s.st_mode):raise UserError('Existing Docker Unix socket required.')
 pinned=os.environ.get('LAWLIET_CONTAINER_SOCKET')
 if pinned and str(Path(pinned).expanduser().resolve())!=cfg['socket']:raise UserError('Report socket differs from explicit endpoint.')
 return cfg

def configured(root):
 from .tools import configuration
 settings=configuration(Path(root).parent)
 if 'parsed_report_container' not in settings:return None
 cfg=validate_config(settings['parsed_report_container'])
 return available(cfg)

def available(cfg):
 p=docker(cfg,['image','inspect',IMAGE])
 if p.returncode:raise UserError('Pinned Report container image unavailable; no image pull or host fallback.')
 try:
  image=json.loads(p.stdout)[0]
  if image['Id']!=IMAGE or image['Os']!='linux' or image['Architecture']!='arm64':raise ValueError('image identity/platform')
 except (ValueError,TypeError,KeyError,IndexError) as exc:raise UserError('Report container image identity/platform mismatch.') from exc
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
 settings['parsed_report_container']=cfg;publish(path,settings)
 return {'tool':'report','container':cfg,'execution_profile':execution_profile(),'scope':'Explicit contained32MiB single JSONL/TSV import;16MiB normalized output, existing local image only; no pulls or fallback.'}

def labels(root,rid,owner):
 return {'lawliet.protocol':PROTOCOL,'lawliet.case':hashlib.sha256(str(Path(root)).encode()).hexdigest(),'lawliet.run':rid,'lawliet.owner':owner['nonce']}

def inventory(cfg,expected):
 p=docker(cfg,['ps','-a','--no-trunc',*[s for k,v in expected.items() for s in ('--filter','label='+k+'='+v)],'--format','{{.ID}}'])
 if p.returncode:raise UserError('Report daemon unavailable; retry refused.')
 ids=p.stdout.splitlines()
 if len(ids)>1 or any(not re.fullmatch('[0-9a-f]{64}',v) for v in ids):raise UserError('Ambiguous Report daemon ownership; retry refused.')
 return ids

def stopped(v):
 s=v['State']
 if any(s.get(k) for k in ('Running','Paused','Restarting')) or s.get('Status') not in ('created','exited'):raise UserError('Report daemon worker active or uncertain; retry refused.')
 return v

def settled_receipt(value,cfg,expected,profile):
 return (isinstance(value,dict) and set(value)=={'protocol','container_id','cfg','labels','state','exit_code','OOMKilled','execution_profile'} and value['protocol']==PROTOCOL and isinstance(value['container_id'],str) and re.fullmatch('[0-9a-f]{64}',value['container_id']) is not None and value['cfg']==cfg and value['labels']==expected and value['execution_profile']==profile and value['state']=='removed_after_verified_stop' and type(value['exit_code']) is int and 0<=value['exit_code']<=255 and type(value['OOMKilled']) is bool)

def recover_before_retry(root,db):
 # The audit is durable registration authority; mutable run details cannot hide
 # a report worker by dropping its config or changing its terminal status.
 claims={}
 for entry in db.execute("SELECT detail FROM audit WHERE action='parsed_import.started'"):
  try:claim=json.loads(entry['detail'])
  except (ValueError,TypeError):continue
  if not isinstance(claim,dict) or 'report_container_config' not in claim:continue
  rid=claim.get('run_id')
  if not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{12}',rid):raise UserError('Report container audited run identity malformed.')
  claims.setdefault(rid,[]).append(claim)
 rows={row['id']:row for row in db.execute('SELECT id,evidence_id,engine,detail FROM runs')}
 for rid,row in rows.items():
  try:detail=json.loads(row['detail'] or '{}')
  except (ValueError,TypeError):detail=None
  if isinstance(detail,dict) and 'report_container_config' in detail and rid not in claims:raise UserError('Report container claim lacks unique audited start.')
 for rid,entries in claims.items():
  if len(entries)!=1:raise UserError('Report container claim lacks unique audited start.')
  row=rows.get(rid)
  if row is None:raise UserError('Report container audited run is missing.')
  try:d=json.loads(row['detail'] or '{}')
  except (ValueError,TypeError) as exc:raise UserError('Report container run detail malformed.') from exc
  claim=entries[0]
  if (not isinstance(d,dict) or 'report_container_config' not in d or claim.get('report_container_config')!=d['report_container_config'] or claim.get('runner_ownership')!=d.get('runner_ownership') or claim.get('report_execution_profile')!=d.get('report_execution_profile') or claim.get('evidence_id')!=row['evidence_id'] or claim.get('engine')!=row['engine'] or row['engine'] not in ('import/jsonl','import/tsv') or claim.get('report_source')!=d.get('report_source') or not _same_origin(claim.get('report_origin'),d.get('report_origin')) or 'report_container_labels' not in claim or claim['report_container_labels']!=d.get('report_container_labels')):raise UserError('Report container run differs from audited registration.')
  cfg=d['report_container_config'];owner=d.get('runner_ownership')
  if not isinstance(owner,dict) or not isinstance(owner.get('nonce'),str) or not re.fullmatch('[0-9a-f]{32}',owner['nonce']):raise UserError('Report container owner malformed.')
  expected=claim['report_container_labels']
  if (not isinstance(expected,dict) or set(expected)!={'lawliet.protocol','lawliet.case','lawliet.run','lawliet.owner'} or expected['lawliet.protocol']!=PROTOCOL or expected['lawliet.run']!=rid or expected['lawliet.owner']!=owner['nonce'] or not isinstance(expected['lawliet.case'],str) or not re.fullmatch('[0-9a-f]{64}',expected['lawliet.case'])):raise UserError('Report container audited labels malformed.')
  completed=[]
  for a in db.execute("SELECT detail FROM audit WHERE action IN ('parsed_import.complete','parsed_import.failed','parsed_import.container_reconciled')"):
   c=json.loads(a['detail'])
   if c.get('run_id')==row['id'] and isinstance(c.get('container'),dict) and c['container'].get('state')=='removed_after_verified_stop':completed.append(c)
  if len(completed)>1:raise UserError('Report container terminal settlement is ambiguous; manual reconciliation required.')
  if any(not _same_origin(c.get('report_origin'),d.get('report_origin')) for c in completed):raise UserError('Report container terminal origin differs from audited registration.')
  if len(completed)==1 and completed[0]['container']==d.get('container') and settled_receipt(d.get('container'),cfg,expected,d.get('report_execution_profile')):continue
  cfg=validate_config(cfg,recovery=True);ids=inventory(cfg,expected)
  if not ids:
   from .child_output import ChildOutputs
   with ChildOutputs(Path(root)/'runs'/row['id']) as outputs:
    try:marker=json.loads(outputs.read('report-container.json',16384))
    except FileNotFoundError:marker=None
   if marker is not None:
    if not isinstance(marker,dict) or marker.get('protocol')!=PROTOCOL or marker.get('cfg')!=cfg or marker.get('labels')!=expected:raise UserError('Report recovery marker differs from audited registration.')
   # A missing marker or labelled worker does not establish that a registered
   # daemon worker stopped. Even a pre-create failure requires reconciliation.
   raise UserError('Report create/start outcome uncertain; empty inventory alone cannot settle it.')
  for cid in ids:
   v=stopped(owned_state(cfg,cid,expected));remove_stopped(cfg,cid,expected)
   receipt={'protocol':PROTOCOL,'container_id':cid,'cfg':cfg,'labels':expected,'state':'removed_after_verified_stop','exit_code':v['State']['ExitCode'],'OOMKilled':v['State']['OOMKilled'],'execution_profile':d.get('report_execution_profile')}
   publish(Path(root)/'runs'/row['id']/'report-container-recovered.json',receipt)
   from .core import audit,json_text
   d['container']=receipt;db.execute('UPDATE runs SET detail=? WHERE id=?',(json_text(d),row['id']));audit(db,'parsed_import.container_reconciled',{'run_id':row['id'],'container':receipt,'report_origin':d.get('report_origin')});db.commit()

def run(root,rid,owner,cfg,manifest,request,raw,profile,folder):
 from .runner_lease import CURRENT
 from .child_output import ChildOutputs
 started=time.monotonic()
 context=CURRENT.get()
 if context is None or context['root']!=str(root) or context['identity']!=owner:raise UserError('Report container requires current case ownership.')
 cfg=validate_config(cfg)
 if execution_profile()!=profile:raise UserError('Report execution profile changed before launch.')
 eid=request['source']['evidence_id'];expected=labels(root,rid,owner);marker=folder/'report-container.json'
 with _Staging(folder) as staged:
  stage=folder/'container-evidence';control=folder/'container-control';code=folder/'container-code'
  staged.mkdir('container-evidence');staged.mkdir('container-control');staged.mkdir('container-code');staged.mkdir('container-code/lawliet_mobile')
  for f in manifest:
   source=root/'evidence'/eid/f['path']
   with ChildOutputs(source.parent) as inputs:data=inputs.read(source.name,MAX_INPUT)
   if len(data)!=f['bytes'] or hashlib.sha256(data).hexdigest()!=f['sha256']:raise UserError('Report container source copy mismatch.')
   staged.write('container-evidence/report',data)
  actual={}
  with ChildOutputs(Path(__file__).parent) as package_inputs:
   for name in sorted(request['package_sha256']):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.py',name):raise UserError('Report package entry malformed.')
    data=package_inputs.read(name,2*1024**2);actual[name]=hashlib.sha256(data).hexdigest();staged.write('container-code/lawliet_mobile/'+name,data)
  if actual!=request['package_sha256']:raise UserError('Report package changed during staging.')
  req=control/'request.json';staged.write('container-control/request.json',raw);request_hash=hashlib.sha256(raw).hexdigest()
  target='/input'
  args=['create','--pull','never','--restart','no','--log-driver','none','--network','none','--ipc','none','--read-only','--memory','256m','--memory-swap','256m','--pids-limit','16','--cpus','1','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65534:65534','--tmpfs','/scratch:rw,noexec,nosuid,nodev,size=128m,mode=1777']
  for k,v in expected.items():args+=['--label',k+'='+v]
  mounts=((stage,target),(control,'/control'),(code,'/code'))
  for source,destination in mounts:args+=_mount(source,destination)
  args+=['--entrypoint','/usr/local/bin/python',cfg['image'],'-I','-S','-B','/code/lawliet_mobile/report_container_worker.py']
  cid=None;client=None;receipt=None;failure=None;payload=None;buffers={'out':bytearray(),'err':bytearray()}
  try:
   publish(marker,{'protocol':PROTOCOL,'cfg':cfg,'labels':expected,'state':'create_requested'})
   staged.check()
   if time.monotonic()-started>MAX_WALL:raise subprocess.TimeoutExpired('Report container',MAX_WALL)
   p=docker(cfg,args)
   if p.returncode:raise UserError('Report container creation refused; no host fallback.')
   cid=p.stdout.strip();v=stopped(owned_state(cfg,cid,expected));publish(folder/'report-inspect-created.json',v);h=v['HostConfig']
   actual_mounts={(m.get('Source'),m.get('Destination')) for m in v['Mounts']}
   if (v['Config']['User']!='65534:65534' or not h['ReadonlyRootfs'] or h['NetworkMode']!='none' or h['IpcMode']!='none' or h['PidMode']!='' or h['Memory']!=268435456 or h['MemorySwap']!=268435456 or h['PidsLimit']!=16 or h['NanoCpus']!=1000000000 or h['CapDrop']!=['ALL'] or h['SecurityOpt']!=['no-new-privileges'] or h['Privileged'] or h.get('Devices') or h.get('DeviceRequests') or h.get('CapAdd') or h['LogConfig']!={'Type':'none','Config':{}} or h['RestartPolicy']!={'Name':'no','MaximumRetryCount':0} or h['Tmpfs']!={'/scratch':'rw,noexec,nosuid,nodev,size=128m,mode=1777'} or len(v['Mounts'])!=3 or actual_mounts!={(str(s),d) for s,d in mounts} or any(m.get('RW') or m.get('Type')!='bind' or m.get('Propagation')!='rprivate' for m in v['Mounts'])):raise UserError('Report container security/mount profile mismatch; launch refused.')
   publish(marker,{'protocol':PROTOCOL,'container_id':cid,'cfg':cfg,'labels':expected,'state':'registered_before_start'})
   staged.check()
   if time.monotonic()-started>MAX_WALL:raise subprocess.TimeoutExpired('Report container',MAX_WALL)
   client=subprocess.Popen([cfg['docker'],'--host','unix://'+cfg['socket'],'start','-a',cid],stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,env={'PATH':os.defpath,'LANG':'C'},close_fds=True,start_new_session=True)
   sel=selectors.DefaultSelector();sel.register(client.stdout,selectors.EVENT_READ,'out');sel.register(client.stderr,selectors.EVENT_READ,'err');deadline=started+MAX_WALL
   try:
    while sel.get_map():
     if time.monotonic()>deadline:raise subprocess.TimeoutExpired('Report container',MAX_WALL)
     for key,_ in sel.select(.1):
      data=os.read(key.fileobj.fileno(),65536)
      if not data:sel.unregister(key.fileobj);continue
      if len(buffers[key.data])+len(data)>(MAX_STDOUT if key.data=='out' else 65536):raise UserError('Report container stream exceeds bound.')
      buffers[key.data].extend(data)
    client.wait(timeout=3)
   finally:sel.close()
   v=stopped(owned_state(cfg,cid,expected));publish(folder/'report-inspect-exited.json',v)
   if client.returncode or v['State']['ExitCode'] or v['State']['OOMKilled']:raise UserError('Report container failed or reached a resource limit; no records promoted.')
   trusted=bindings_for(raw,request,profile)
   payload=validate(bytes(buffers['out']),trusted)
   if execution_profile()!=profile or hashlib.sha256(staged.read('container-control/request.json',MAX_MANIFEST)).hexdigest()!=request_hash or request['package_sha256']!={name:hashlib.sha256(staged.read('container-code/lawliet_mobile/'+name,2*1024**2)).hexdigest() for name in request['package_sha256']}:raise UserError('Report container control/package changed; no records promoted.')
   for f in manifest:
    if hashlib.sha256(staged.read('container-evidence/report',MAX_INPUT)).hexdigest()!=f['sha256']:raise UserError('Report container immutable input copy changed.')
  except BaseException as exc:failure=exc
  finally:
   try:
    from .anchored_output import OutputFiles
    try:
     paths=[folder/'report.stdout.jsonl',folder/'report.stderr']
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
      if p.returncode:raise UserError('Report container stop uncertain; recovery required.')
     v=stopped(owned_state(cfg,owned,expected));publish(folder/'report-inspect-stopped.json',v);remove_stopped(cfg,owned,expected)
     receipt={'protocol':PROTOCOL,'container_id':owned,'cfg':cfg,'labels':expected,'state':'removed_after_verified_stop','exit_code':v['State']['ExitCode'],'OOMKilled':v['State']['OOMKilled'],'execution_profile':profile};publish(marker,receipt)
   finally:
    if client is not None:
     if client.poll() is None:client.kill()
     client.wait();client.stdout.close();client.stderr.close()
  if failure is not None:
   failure.tool_result={'container':receipt};raise failure
  if receipt is None:raise UserError('Report container completion receipt missing.')
  return payload,receipt

def bindings_for(raw,request,profile):
 source=request['source']
 return {'protocol':STREAM_PROTOCOL,'request_sha256':hashlib.sha256(raw).hexdigest(),'source_manifest_sha256':hashlib.sha256(canonical(source)).hexdigest(),'evidence_id':source['evidence_id'],'file_id':source['file_id'],'filename':source['filename'],'format_name':source['format_name'],'parser':'import/'+source['format_name'],'report_sha256':source['sha256'],'package_manifest_sha256':profile['package_manifest_sha256'],'bootstrap_sha256':request['bootstrap_sha256']}

def _source_read(root,source):
 from .child_output import ChildOutputs
 path=Path(root)/'evidence'/source['evidence_id']/source['path']
 with ChildOutputs(path.parent) as outputs:raw=outputs.read(path.name,MAX_INPUT)
 if len(raw)!=source['bytes'] or hashlib.sha256(raw).hexdigest()!=source['sha256']:raise UserError('Retained report changed; no contained output promoted.')
 return raw

def _report_origin(root,db,file_id,hashed,filename):
 """Resolve a selected retained file in this case; never trust caller metadata."""
 if file_id is None:return None
 if type(file_id) is not int or not 0<file_id<2**63:raise UserError('origin_file_id must be a positive integer file ID.')
 row=db.execute('SELECT f.* FROM files f JOIN evidence e ON e.id=f.evidence_id WHERE f.id=?',(file_id,)).fetchone()
 if row is None:raise UserError('Report origin file is not retained in this case.')
 path=row['path'];eid=row['evidence_id']
 if (not isinstance(eid,str) or not re.fullmatch('[0-9a-f]{12}',eid) or not isinstance(path,str) or not path or Path(path).is_absolute() or any(p in ('.','..') for p in path.split('/')) or '\\' in path or '\x00' in path or Path(path).name!=filename or row['sha256']!=hashed or type(row['size']) is not int or not 0<=row['size']<=MAX_INPUT):raise UserError('Report origin metadata/hash/schema name differs from selected snapshot.')
 from .child_output import ChildOutputs
 retained=Path(root)/'evidence'/eid/path
 with ChildOutputs(retained.parent) as outputs:data=outputs.read(retained.name,MAX_INPUT)
 if len(data)!=row['size'] or hashlib.sha256(data).hexdigest()!=hashed:raise UserError('Report origin retained bytes changed.')
 return {'file_id':file_id,'evidence_id':eid,'path':path,'logical_path':row['logical_path'],'sha256':row['sha256'],'size':row['size']}

def _previous(root,db,hashed,format_name,filename,profile,origin):
 """Reuse only uniquely audited, settled, current-profile contained results."""
 from .core import json_text
 for row in db.execute('SELECT * FROM runs WHERE engine=? AND status=? ORDER BY rowid DESC',('import/'+format_name,'complete')):
  try:d=json.loads(row['detail'])
  except (ValueError,TypeError):continue
  if isinstance(d,dict) and not _same_origin(d.get('report_origin'),d.get('report_origin')):raise UserError('Contained import stored origin is malformed.')
  source=d.get('report_source') if isinstance(d,dict) else None
  if (not isinstance(source,dict) or source.get('sha256')!=hashed or source.get('filename')!=filename or source.get('format_name')!=format_name or d.get('report_execution_profile')!=profile or not _same_origin(d.get('report_origin'),origin)):continue
  starts=[];ends=[];previous='0'*64
  for event in db.execute('SELECT * FROM audit ORDER BY id'):
   expected=hashlib.sha256(json_text([event['at'],event['action'],event['detail'],previous]).encode()).hexdigest()
   if event['previous_hash']!=previous or event['hash']!=expected:raise UserError('Contained import audit integrity mismatch.')
   previous=event['hash']
   if event['action'] not in ('parsed_import.started','parsed_import.complete','parsed_import.failed','parsed_import.container_reconciled'):continue
   claim=json.loads(event['detail'])
   if claim.get('run_id')!=row['id']:continue
   if event['action']=='parsed_import.started':starts.append(claim)
   elif isinstance(claim.get('container'),dict) and claim['container'].get('state')=='removed_after_verified_stop':ends.append(claim)
  if len(starts)!=1 or len(ends)!=1:raise UserError('Contained import reuse lacks unique audited registration/settlement.')
  start=starts[0]
  if not _same_origin(start.get('report_origin'),d.get('report_origin')) or any(start.get(key)!=d.get(key) for key in ('report_source','report_container_config','report_container_labels','report_execution_profile','runner_ownership')) or start.get('engine')!=row['engine'] or start.get('evidence_id')!=row['evidence_id']:raise UserError('Contained import reuse differs from audited registration.')
  if not settled_receipt(d.get('container'),d.get('report_container_config'),d.get('report_container_labels'),profile) or ends[0]['container']!=d['container'] or ends[0].get('status')!='complete' or not _same_origin(ends[0].get('report_origin'),origin):raise UserError('Contained import reuse is not a completed audited publication.')
  file=db.execute('SELECT * FROM files WHERE id=? AND evidence_id=?',(source.get('file_id'),row['evidence_id'])).fetchone()
  if not file or source.get('evidence_id')!=row['evidence_id'] or file['path']!=source.get('path') or file['sha256']!=hashed or file['size']!=source.get('bytes'):raise UserError('Contained import reuse report identity changed.')
  if d.get('report_sha256')!=hashed or ends[0].get('report_sha256')!=hashed or ends[0].get('evidence_id')!=row['evidence_id'] or type(row['records']) is not int or row['records']!=d.get('emitted_records') or ends[0].get('records')!=row['records']:raise UserError('Contained import reuse count/source audit changed.')
  _source_read(root,source)
  from .core import has_run_index
  if not has_run_index(db,row['id']) or db.execute('SELECT count(*) FROM artifact_runs WHERE run_id=?',(row['id'],)).fetchone()[0]!=d.get('emitted_records'):raise UserError('Contained import membership changed.')
  from .child_output import ChildOutputs
  with ChildOutputs(Path(root)/'runs'/row['id']) as outputs:retained=outputs.read('report.stdout.jsonl',MAX_STDOUT)
  output_hash=hashlib.sha256(retained).hexdigest()
  if output_hash!=d.get('stdout_sha256') or output_hash!=ends[0].get('stdout_sha256'):raise UserError('Contained import retained output integrity mismatch.')
  request={'protocol':STREAM_PROTOCOL,'bootstrap_sha256':d['report_container_config']['bootstrap_sha256'],'package_sha256':package_manifest(),'source':{k:v for k,v in source.items() if k!='path'}}
  decoded=validate(retained,bindings_for(canonical(request),request,profile))
  if decoded.count!=row['records'] or decoded.artifact_bytes!=d.get('normalized_output_bytes') or decoded.footer['artifacts_sha256']!=d.get('artifact_frames_sha256') or decoded.footer['runtime']!=d.get('runtime'):raise UserError('Contained import retained output metadata changed.')
  expected_ids=set()
  for frame in decoded.iter_artifacts():
   values=(row['evidence_id'],source['file_id'],frame['category'],frame['timestamp'],frame['timestamp_raw'],frame['title'],frame['body'],frame['source_ref'],frame['parser'],frame['data_json'])
   identifier=hashlib.sha256(json_text(values).encode()).hexdigest()[:24];expected_ids.add(identifier)
   stored=db.execute('SELECT * FROM artifacts WHERE id=?',(identifier,)).fetchone()
   if stored is None or tuple(stored)!=(identifier,*values):raise UserError('Contained import artifact integrity mismatch.')
  actual_ids={entry[0] for entry in db.execute('SELECT artifact_id FROM artifact_runs WHERE run_id=?',(row['id'],))}
  if actual_ids!=expected_ids or len(expected_ids)!=decoded.count:raise UserError('Contained import membership identity changed.')
  return {'status':'already_imported','evidence_id':row['evidence_id'],'run_id':row['id'],'records':0,'reused':True,'report_origin':origin,'execution':'Reused an audited completed contained import; no decoder execution.'}
 return None

def import_report(root,db,source,format_name,label=None,*,origin_file_id=None):
 from .core import import_evidence,begin_run_index,add_artifact,audit,json_text,now
 from .runner_lease import ownership
 from .container_runner import create_run_directory
 from .child_output import ChildOutputs
 if origin_file_id is not None and (type(origin_file_id) is not int or not 0<origin_file_id<2**63):raise UserError('origin_file_id must be a positive integer file ID.')
 source=Path(source)
 if format_name not in ('jsonl','tsv') or source.is_symlink() or not source.is_file():raise UserError('Contained import requires one regular JSONL/TSV file; no host fallback.')
 source=source.resolve()
 # Bound bytes before any hashing or parser allocations, including sparse files.
 if source.stat().st_size>MAX_INPUT:raise UserError('Contained report exceeds32MiB input cap; no host fallback.')
 cfg=configured(root)
 if cfg is None:raise UserError('Explicit report container configuration required; no host fallback.')
 with ChildOutputs(source.parent) as inputs:source_bytes=inputs.read(source.name,MAX_INPUT)
 hashed=hashlib.sha256(source_bytes).hexdigest();del source_bytes
 package=package_manifest();profile=execution_profile(package)
 origin=_report_origin(root,db,origin_file_id,hashed,source.name)
 previous=_previous(root,db,hashed,format_name,source.name,profile,origin) if origin is not None else None
 if previous:return previous
 if shutil.disk_usage(root).free < source.stat().st_size+MAX_STDOUT+64*1024**2:raise UserError('Insufficient free space for bounded contained report staging.')
 eid,_,_=import_evidence(root,db,source,'auto',label or source.name,max_bytes=MAX_INPUT,expand_archives=False)
 file=db.execute('SELECT * FROM files WHERE evidence_id=?',(eid,)).fetchone()
 report_source={'evidence_id':eid,'file_id':file['id'],'filename':source.name,'format_name':format_name,'sha256':file['sha256'],'bytes':file['size'],'path':file['path']}
 worker_source={k:v for k,v in report_source.items() if k!='path'}
 request={'protocol':STREAM_PROTOCOL,'bootstrap_sha256':cfg['bootstrap_sha256'],'package_sha256':package,'source':worker_source};raw=canonical(request)
 if len(raw)>MAX_MANIFEST:raise UserError('Contained report manifest exceeds2MiB.')
 owner=ownership();rid=uuid.uuid4().hex[:12];folder=create_run_directory(root,rid)
 initial={'runner_ownership':owner,'report_container_config':cfg,'report_container_labels':labels(root,rid,owner),'report_execution_profile':profile,'report_source':report_source,'report_origin':origin,'format':format_name,'report_sha256':hashed,'source_tier':'Derived report import; supplied source claims are not independently verified device records.'}
 try:
  db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,?,?,?)',(rid,eid,'import/'+format_name,now(),'running',json_text(initial)));begin_run_index(db,rid);audit(db,'parsed_import.started',{'run_id':rid,'evidence_id':eid,'engine':'import/'+format_name,**initial});db.commit()
 except BaseException:db.rollback();raise
 container=None;count=0
 try:
  if hashed!=file['sha256']:raise UserError('Source report changed between identity check and intake; no records imported.')
  manifest=[{'id':file['id'],'path':file['path'],'sha256':file['sha256'],'bytes':file['size']}]
  try:decoded,container=run(root,rid,owner,cfg,manifest,request,raw,profile,folder)
  except BaseException as exc:container=getattr(exc,'tool_result',{}).get('container');raise
  _source_read(root,report_source)
  if not _same_origin(_report_origin(root,db,origin_file_id,hashed,source.name),origin):raise UserError('Report origin changed before publication.')
  with ChildOutputs(folder) as outputs:
   retained=outputs.read('report.stdout.jsonl',MAX_STDOUT)
   if retained!=decoded.raw:raise UserError('Retained contained report output changed.')
  if execution_profile()!=profile:raise UserError('Contained report implementation changed before publication.')
  db.execute('BEGIN IMMEDIATE')
  for frame in decoded.iter_artifacts():
   count+=add_artifact(db,eid,file['id'],frame['category'],frame['timestamp'],frame['timestamp_raw'],frame['title'],frame['body'],frame['source_ref'],'import/'+format_name,frame['data'],run_id=rid)
  memberships=db.execute('SELECT count(*) FROM artifact_runs WHERE run_id=?',(rid,)).fetchone()[0]
  if memberships!=decoded.count:raise UserError('Contained report output repeats identities.')
  detail={**initial,'container':container,'emitted_records':decoded.count,'runtime':decoded.footer['runtime'],'stdout_sha256':hashlib.sha256(retained).hexdigest(),'artifact_frames_sha256':decoded.footer['artifacts_sha256'],'normalized_output_bytes':decoded.artifact_bytes}
  if format_name=='tsv':detail['reports']=[{'name':source.stem,'path':file['path'],'records':count,'sha256':hashed}]
  db.execute('UPDATE runs SET status=?,finished_at=?,records=?,detail=? WHERE id=?',('complete',now(),count,json_text(detail),rid));audit(db,'parsed_import.complete',{'run_id':rid,'evidence_id':eid,'status':'complete','records':count,'report_sha256':hashed,'report_origin':origin,'container':container,'stdout_sha256':detail['stdout_sha256']});db.commit()
 except BaseException as exc:
  db.rollback();durable=db.execute('SELECT status FROM runs WHERE id=?',(rid,)).fetchone()
  if durable is not None and durable['status']=='complete':raise
  status='interrupted' if isinstance(exc,KeyboardInterrupt) else 'failed'
  detail={**initial,'error':str(exc),'records':0,'unverified_stdout_path':str(folder/'report.stdout.jsonl')}
  if container is not None:detail['container']=container
  try:
   db.execute('UPDATE runs SET status=?,finished_at=?,records=0,detail=? WHERE id=?',(status,now(),json_text(detail),rid));audit(db,'parsed_import.failed',{'run_id':rid,'evidence_id':eid,'status':status,'records':0,'original_retained':True,'report_origin':origin,**({'container':container} if container is not None else {})});db.commit()
  except BaseException:db.rollback();raise
  if isinstance(exc,KeyboardInterrupt):raise
  raise UserError(f'Contained import failed; original report retained as {eid}; zero records promoted. {exc}') from exc
 return {'status':'complete','evidence_id':eid,'run_id':rid,'records':count,'contained':True,'report_origin':origin,'normalized_output_bytes':decoded.artifact_bytes,'reuse_available':origin is not None,**({'reuse_unavailable_reason':'No retained origin file ID supplied; unbound contained imports always create a new occurrence.'} if origin is None else {})}
