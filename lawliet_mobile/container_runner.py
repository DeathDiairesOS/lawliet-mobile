"""Opt-in trusted ExifTool containers; daemon ownership outlives its client."""
from __future__ import annotations
import hashlib,json,os,re,selectors,stat,subprocess,sys,time
from pathlib import Path,PurePosixPath
if __package__ is None:
 sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
 __package__='lawliet_mobile'
from .core import UserError
PROTOCOL='ancalor-container-job-v1'
IMAGE='sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5'
MAX_OUTPUT=128*1024**2


def create_run_directory(root, rid):
 """Create a private run without following any existing path component."""
 if not re.fullmatch('[0-9a-f]{12}',rid):raise UserError('Run identity malformed.')
 root=Path(root).absolute();fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in root.parts[1:]:
   next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   os.close(fd);fd=next_fd
  try:os.mkdir('runs',0o700,dir_fd=fd)
  except FileExistsError:pass
  next_fd=os.open('runs',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
  os.close(fd);fd=next_fd
  os.mkdir(rid,0o700,dir_fd=fd)
  os.fsync(fd)
 except OSError as exc:raise UserError('Run directory cannot be created safely.') from exc
 finally:os.close(fd)
 return root/'runs'/rid


def remove_stopped(cfg,cid,expected):
 """Reconcile lost removal responses only after exact ownership and stop."""
 state=owned_state(cfg,cid,expected)
 if any(state['State'].get(k) for k in ('Running','Paused','Restarting')):
  raise UserError('Owned container is not stopped; removal refused.')
 if state['State']['Status'] not in ('created','exited'):
  raise UserError('Owned container completion uncertain; removal refused.')
 try:
  result=docker(cfg,['rm',cid])
  if result.returncode==0:return state
 except subprocess.TimeoutExpired:pass
 if not confirmed_absent(cfg,cid):raise UserError('Owned stopped container still exists.')
 return state


def confirmed_absent(cfg,cid):
 # Call only after this controller proved the exact identity and stopped state.
 inventory=docker(cfg,['ps','-a','--no-trunc','--format','{{.ID}}'])
 if inventory.returncode:raise UserError('Container removal uncertain; daemon unavailable.')
 ids=inventory.stdout.splitlines()
 if any(not re.fullmatch('[0-9a-f]{64}',item) for item in ids):
  raise UserError('Container removal inventory malformed.')
 return cid not in ids


def validate_config(value,require_tool=True):
 if not isinstance(value,dict) or set(value)!={'image','tool_root','socket','docker'} or value['image']!=IMAGE:
  raise UserError('Container profile requires the qualified existing image and explicit local components.')
 result={'image':IMAGE}
 for key in ('tool_root','socket','docker'):
  p=Path(value[key]).expanduser().resolve()
  if ',' in str(p) or '\n' in str(p):raise UserError('Container component path contains unsupported characters.')
  result[key]=str(p)
 if not Path(result['docker']).is_file() or not os.access(result['docker'],os.X_OK):raise UserError('Configured Docker CLI unavailable.')
 if not stat.S_ISSOCK(Path(result['socket']).stat().st_mode):raise UserError('Existing local Docker socket required; no daemon startup attempted.')
 root=Path(result['tool_root'])
 if require_tool and (not (root/'bin/exiftool').is_file() or not (root/'libexec/lib/perl5/Image/ExifTool.pm').is_file()):raise UserError('Qualified ExifTool Perl tree required.')
 pinned=os.environ.get('LAWLIET_CONTAINER_SOCKET')
 if pinned and str(Path(pinned).resolve())!=result['socket']:raise UserError('Configured Docker socket differs from the explicit endpoint.')
 return result


def docker(cfg,args,timeout=10):
 env=dict(os.environ)
 for k in ('DOCKER_CONTEXT','DOCKER_HOST','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):env.pop(k,None)
 return subprocess.run([cfg['docker'],'--host','unix://'+cfg['socket'],*args],env=env,capture_output=True,text=True,timeout=timeout)


def labels(root,rid,owner):
 return {'lawliet.protocol':PROTOCOL,'lawliet.case':hashlib.sha256(str(Path(root)).encode()).hexdigest(),
         'lawliet.run':rid,'lawliet.owner':owner['nonce']}


def owned_state(cfg,cid,expected):
 if not isinstance(cid,str) or not re.fullmatch('[0-9a-f]{64}',cid):raise UserError('Container identity malformed; recovery refused.')
 p=docker(cfg,['inspect',cid])
 if p.returncode:raise UserError('Daemon ownership cannot be established; retry refused.')
 v=json.loads(p.stdout)[0]
 if v['Id']!=cid or v['Image']!=cfg['image'] or any(v['Config']['Labels'].get(k)!=x for k,x in expected.items()):raise UserError('Container identity mismatch; recovery refused.')
 return v


def publish(path,value):
 from .provider_sms import _write_manifest
 _write_manifest(path,value)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)


def _valid_labels(value,rid,owner):
 return (isinstance(value,dict) and set(value)=={'lawliet.protocol','lawliet.case','lawliet.run','lawliet.owner'}
         and value['lawliet.protocol']==PROTOCOL and value['lawliet.run']==rid and value['lawliet.owner']==owner['nonce']
         and isinstance(value['lawliet.case'],str) and re.fullmatch('[0-9a-f]{64}',value['lawliet.case']) is not None)


def settled_receipt(value,cfg,expected):
 """Full original v1 receipt only; a state label alone proves no settlement."""
 return (isinstance(cfg,dict) and set(cfg)=={'image','socket','docker','tool_root'} and cfg['image']==IMAGE and all(isinstance(v,str) for v in cfg.values())
         and isinstance(expected,dict) and set(expected)=={'lawliet.protocol','lawliet.case','lawliet.run','lawliet.owner'}
         and isinstance(expected['lawliet.run'],str) and re.fullmatch('[0-9a-f]{12}',expected['lawliet.run']) is not None
         and isinstance(expected['lawliet.owner'],str) and re.fullmatch('[0-9a-f]{32}',expected['lawliet.owner']) is not None
         and _valid_labels(expected,expected['lawliet.run'],{'nonce':expected['lawliet.owner']})
         and isinstance(value,dict) and set(value)=={'protocol','controller_pid','container_id','labels','cfg','state','exit_code','OOMKilled','error'}
         and value['protocol']==PROTOCOL and type(value['controller_pid']) is int and value['controller_pid']>0
         and isinstance(value['container_id'],str) and re.fullmatch('[0-9a-f]{64}',value['container_id']) is not None
         and value['labels']==expected and value['cfg']==cfg and value['state']=='removed_after_verified_stop'
         and type(value['exit_code']) is int and 0<=value['exit_code']<=255 and type(value['OOMKilled']) is bool
         and (value['error'] is None or isinstance(value['error'],str)))


def recover_before_retry(root,db):
 """Recover from audited registration, never mutable run details or new paths."""
 claims={}
 for entry in db.execute("SELECT detail FROM audit WHERE action='analysis.started'"):
  try:claim=json.loads(entry['detail'])
  except (ValueError,TypeError):continue
  if not isinstance(claim,dict) or 'container_config' not in claim:continue
  rid=claim.get('run_id')
  if not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{12}',rid):raise UserError('Container audited identity malformed; recovery refused.')
  claims.setdefault(rid,[]).append(claim)
 rows={row['id']:row for row in db.execute('SELECT id,evidence_id,engine,detail FROM runs')}
 for rid,row in rows.items():
  try:detail=json.loads(row['detail'] or '{}')
  except (ValueError,TypeError):detail=None
  if isinstance(detail,dict) and 'container_config' in detail and rid not in claims:raise UserError('Container claim lacks unique audited start; recovery refused.')
 for rid,entries in claims.items():
  if len(entries)!=1:raise UserError('Container claim lacks unique audited start; recovery refused.')
  row=rows.get(rid)
  if row is None:raise UserError('Container audited run is missing; recovery refused.')
  try:detail=json.loads(row['detail'] or '{}')
  except (ValueError,TypeError) as exc:raise UserError('Container run detail malformed; recovery refused.') from exc
  claim=entries[0]
  if (not isinstance(detail,dict) or 'container_config' not in detail or claim.get('container_config')!=detail['container_config']
      or claim.get('runner_ownership')!=detail.get('runner_ownership') or claim.get('engine')!=row['engine']
      or row['engine']!='exiftool' or claim.get('evidence_id')!=row['evidence_id']):raise UserError('Container run differs from audited registration; recovery refused.')
  cfg=detail['container_config'];owner=detail.get('runner_ownership')
  if not isinstance(owner,dict) or not isinstance(owner.get('nonce'),str) or not re.fullmatch('[0-9a-f]{32}',owner['nonce']):raise UserError('Container audited owner malformed.')
  expected=claim.get('container_labels')
  if expected is not None:
   if expected!=detail.get('container_labels') or not _valid_labels(expected,rid,owner):raise UserError('Container labels differ from audited registration.')
  elif 'container_labels' in detail:raise UserError('Container labels lack audited registration.')
  terminal=[]
  for entry in db.execute("SELECT detail FROM audit WHERE action IN ('analysis.finished','analysis.container_reconciled')"):
   try:end=json.loads(entry['detail'])
   except (ValueError,TypeError):continue
   if isinstance(end,dict) and end.get('run_id')==rid and isinstance(end.get('container'),dict) and end['container'].get('state')=='removed_after_verified_stop':terminal.append(end)
  # Legacy finished runs can carry their original path-derived labels in their
  # full, unique audited terminal receipt. Never derive labels from a moved root.
  if expected is None:
   if len(terminal)!=1:raise UserError('Legacy container job lacks unique audited settlement; manual reconciliation required.')
   receipt=terminal[0]['container'];expected=receipt.get('labels')
   if receipt!=detail.get('container') or not _valid_labels(expected,rid,owner) or not settled_receipt(receipt,cfg,expected):raise UserError('Legacy container settlement incomplete; manual reconciliation required.')
   continue
  if len(terminal)>1:raise UserError('Container terminal settlement is ambiguous; recovery refused.')
  if len(terminal)==1:
   if terminal[0]['container']==detail.get('container') and settled_receipt(terminal[0]['container'],cfg,expected):continue
   raise UserError('Container terminal settlement differs or is incomplete; recovery refused.')
  cfg=validate_config(cfg,require_tool=False)
  # The trusted supervisor survives ordinary parent death and holds the lease
  # until exact-owned stop/removal. Its private full receipt is distinct from a
  # missing marker or an empty label query. Confirm exact CID absence as well.
  from .child_output import ChildOutputs
  with ChildOutputs(Path(root)/'runs'/rid) as outputs:
   try:marker=json.loads(outputs.read('container.json',16384))
   except FileNotFoundError:marker=None
  if isinstance(marker,dict) and marker.get('state')=='removed_after_verified_stop':
   if not settled_receipt(marker,cfg,expected):raise UserError('Container controller settlement mismatch; recovery refused.')
   if not confirmed_absent(cfg,marker['container_id']):raise UserError('Container controller reports removal but exact worker still present; recovery refused.')
   from .core import audit,json_text
   detail['container']=marker
   db.execute('UPDATE runs SET detail=? WHERE id=?',(json_text(detail),rid))
   audit(db,'analysis.container_reconciled',{'run_id':rid,'container':marker,'authority':'Trusted controller full stop receipt and daemon-confirmed exact CID absence; no parser output promoted.'});db.commit()
   continue
  response=docker(cfg,['ps','-a',*[x for k,v in expected.items() for x in ('--filter','label='+k+'='+v)],'--format','{{.ID}}','--no-trunc'])
  if response.returncode:raise UserError('Container daemon unavailable; retry refused.')
  ids=response.stdout.splitlines()
  if len(ids)>1 or any(not re.fullmatch('[0-9a-f]{64}',cid) for cid in ids):raise UserError('Ambiguous daemon job ownership; recovery refused.')
  if not ids:raise UserError('Container create/start outcome uncertain; manual reconciliation required.')
  for cid in ids:
   state=owned_state(cfg,cid,expected)
   if any(state['State'].get(k) for k in ('Running','Paused','Restarting')):raise UserError('A daemon-owned parser still runs; retry refused.')
   if state['State'].get('Status') not in ('created','exited'):raise UserError('Daemon completion uncertain; retry refused.')
   remove_stopped(cfg,cid,expected)
   receipt={'protocol':PROTOCOL,'controller_pid':os.getpid(),'container_id':cid,'labels':expected,'cfg':cfg,'state':'removed_after_verified_stop',
            'exit_code':state['State']['ExitCode'],'OOMKilled':state['State']['OOMKilled'],'error':'Recovered verified stopped worker; no parser output promoted.'}
   if not settled_receipt(receipt,cfg,expected):raise UserError('Recovered container state malformed.')
   publish(Path(root)/'runs'/rid/'container-recovered.json',receipt)
   from .core import audit,json_text
   detail['container']=receipt
   db.execute('UPDATE runs SET detail=? WHERE id=?',(json_text(detail),rid))
   audit(db,'analysis.container_reconciled',{'run_id':rid,'container':receipt});db.commit()


def read_receipt(root,rid,owner,cfg):
 marker=Path(root)/'runs'/rid/'container.json'
 from .child_output import ChildOutputs
 with ChildOutputs(marker.parent) as outputs:
  receipt=json.loads(outputs.read(marker.name,16384))
 if not settled_receipt(receipt,cfg,labels(root,rid,owner)):
  raise UserError('Container completion receipt mismatch; output not promoted.')
 return receipt


def run_exiftool(root,rid,owner,cfg,input_path,output,timeout,guard):
 from .runner_lease import CURRENT
 context=CURRENT.get()
 if context is None:raise UserError('Container runner requires the existing case ownership lease.')
 cfg=validate_config(cfg);read,write=os.pipe();cr,cw=os.pipe();child=None
 config={'root':str(root),'run_id':rid,'owner':owner,'cfg':cfg,'input':str(input_path),'timeout':timeout,'stdout_limit':MAX_OUTPUT}
 raw=json.dumps(config).encode()
 if len(raw)>16384:raise UserError('Container launch configuration exceeds bound.')
 error_path=output.with_name(output.name+'.stderr');started=time.monotonic()
 try:
  with output.open('wb') as out,error_path.open('wb') as err:
   child=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--supervise',str(context['fd']),str(read),str(cr)],pass_fds=(context['fd'],read,cr),stdout=out,stderr=err,start_new_session=True)
   os.close(read);read=None;os.close(cr);cr=None
   pending=memoryview(raw)
   while pending:
    n=os.write(cw,pending)
    if n<=0:raise BrokenPipeError('Container config write stalled')
    pending=pending[n:]
   os.close(cw);cw=None
   try:
    while child.poll() is None:
     if guard:guard()
     if time.monotonic()-started>timeout:raise subprocess.TimeoutExpired('container ExifTool',timeout)
     time.sleep(.1)
   except BaseException as exc:
    os.close(write);write=None
    try:child.wait(timeout=12)
    except subprocess.TimeoutExpired:pass  # Helper retains lease until daemon state is known.
    if child.poll() is not None:
     try:exc.tool_result={'container':read_receipt(root,rid,owner,cfg)}
     except (OSError,ValueError,UserError):pass
    raise
  marker=root/'runs'/rid/'container.json'
  if not marker.is_file() or marker.is_symlink():raise UserError('Container job receipt missing; output not promoted.')
  receipt=read_receipt(root,rid,owner,cfg)
  result={'argv':['container-exiftool',cfg['image']], 'returncode':child.returncode,'stdout':str(output),'stderr':str(error_path),'elapsed_seconds':round(time.monotonic()-started,3),'container':receipt,'process_status_kind':'bounded container controller exit'}
  if child.returncode==0:
   rows=json.loads(output.read_text())
   for row in rows:
    p=PurePosixPath(row.get('SourceFile',''))
    if not p.is_relative_to('/input') or '..' in p.parts:raise UserError('Container output refers outside selected input.')
    row['SourceFile']=str(input_path.joinpath(*p.relative_to('/input').parts))
   output.write_text(json.dumps(rows,ensure_ascii=False)+'\n')
  return result
 finally:
  for fd in (read,write,cr,cw):
   if fd is not None:os.close(fd)


def supervise(lease_fd,alive_fd,config_fd):
 # Script invocation imports the canonical package via its parent directory.
 with os.fdopen(config_fd,'rb') as stream:raw=stream.read(16385)
 if len(raw)>16384:raise ValueError('Container config bound')
 c=json.loads(raw)
 if type(c.get('stdout_limit')) is not int or not 1<=c['stdout_limit']<=MAX_OUTPUT:raise UserError('Invalid container stdout bound')
 cfg=validate_config(c['cfg']);root=Path(c['root']);rid=c['run_id'];expected=labels(root,rid,c['owner']);marker=root/'runs'/rid/'container.json';cid=None;client=None;error=None;rc=125;removed=False;removal_pending=False;stopped_state=None
 try:
  argv=['create','--pull','never','--restart','no','--log-driver','none','--network','none','--read-only','--memory','64m','--memory-swap','64m','--pids-limit','16','--cpus','0.25','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65534:65534','--tmpfs','/tmp:rw,noexec,nosuid,size=8m,mode=1777']
  for k,v in expected.items():argv+=['--label',k+'='+v]
  for source,target in ((c['input'],'/input'),(cfg['tool_root'],'/tools')):
   if ',' in source or '\n' in source:raise UserError('Unsupported mount path')
   argv+=['--mount','type=bind,src='+source+',dst='+target+',readonly']
  argv+=['--entrypoint','/usr/bin/perl',cfg['image'],'-I/tools/libexec/lib/perl5','/tools/bin/exiftool','-config','','-json','-r','-n','/input']
  created=docker(cfg,argv)
  if created.returncode:raise UserError('Container creation refused: '+created.stderr[:1024])
  cid=created.stdout.strip();owned_state(cfg,cid,expected)
  publish(marker,{'protocol':PROTOCOL,'controller_pid':os.getpid(),'container_id':cid,'labels':expected,'cfg':cfg,'state':'registered_before_start'})
  probe=selectors.DefaultSelector();probe.register(alive_fd,selectors.EVENT_READ)
  if probe.select(0) and os.read(alive_fd,1)==b'':raise UserError('Parser owner ended before daemon launch')
  probe.close()
  env=dict(os.environ)
  for k in ('DOCKER_CONTEXT','DOCKER_HOST','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):env.pop(k,None)
  client=subprocess.Popen([cfg['docker'],'--host','unix://'+cfg['socket'],'start','-a',cid],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  sel=selectors.DefaultSelector();sel.register(alive_fd,selectors.EVENT_READ,'owner');sel.register(client.stdout,selectors.EVENT_READ,'out');sel.register(client.stderr,selectors.EVENT_READ,'err');totals={'out':0,'err':0};deadline=time.monotonic()+c['timeout']
  while True:
   if time.monotonic()>deadline:raise UserError('Container parser deadline exceeded')
   for key,_ in sel.select(.1):
    if key.data=='owner':
     if os.read(alive_fd,1)==b'':raise UserError('Parser owner ended before finalization')
    else:
     data=os.read(key.fileobj.fileno(),65536)
     if not data:sel.unregister(key.fileobj);continue
     cap=c['stdout_limit'] if key.data=='out' else 1024**2
     if totals[key.data]+len(data)>cap:raise UserError('Container output byte ceiling exceeded')
     target=sys.stdout.buffer if key.data=='out' else sys.stderr.buffer;target.write(data);target.flush();totals[key.data]+=len(data)
   if client.poll() is not None and len(sel.get_map())==1:break
  rc=client.returncode
  if owned_state(cfg,cid,expected)['State']['Running']:raise UserError('Attached client ended while daemon parser remains alive')
 except Exception as exc:error=str(exc);rc=125
 finally:
  if cid is not None:
   while True:
    try:
     if removal_pending and confirmed_absent(cfg,cid):
      removed=True
      publish(marker,stopped_state)
      break
     v=owned_state(cfg,cid,expected)
     if v['State']['Running']:
      p=docker(cfg,['stop','--time','1',cid])
      if p.returncode:raise UserError('Owned container stop failed')
     if removal_pending and confirmed_absent(cfg,cid):
      removed=True
      publish(marker,stopped_state)
      break
     v=owned_state(cfg,cid,expected)
     if v['State']['Running']:raise UserError('Owned worker remains active')
     publish(marker,{'protocol':PROTOCOL,'controller_pid':os.getpid(),'container_id':cid,'labels':expected,'cfg':cfg,'state':'stopped','exit_code':v['State']['ExitCode'],'OOMKilled':v['State']['OOMKilled'],'error':error})
     # Remove only after exact ownership and stopped-state verification.
     stopped_state={'protocol':PROTOCOL,'controller_pid':os.getpid(),'container_id':cid,'labels':expected,'cfg':cfg,'state':'removed_after_verified_stop','exit_code':v['State']['ExitCode'],'OOMKilled':v['State']['OOMKilled'],'error':error}
     removal_pending=True
     remove_stopped(cfg,cid,expected)
     removed=True
     publish(marker,{'protocol':PROTOCOL,'controller_pid':os.getpid(),'container_id':cid,'labels':expected,'cfg':cfg,'state':'removed_after_verified_stop','exit_code':v['State']['ExitCode'],'OOMKilled':v['State']['OOMKilled'],'error':error})
     break
    except Exception:
     if removed:
      rc=125;error='Owned worker removed but final receipt publication failed';break
     time.sleep(.2)  # Retain inherited case lease on uncertain cleanup.
  if client is not None:
   if client.poll() is None:client.kill()
   client.wait()
  if error:sys.stderr.write(error+'\n')
  os.close(alive_fd);os.close(lease_fd)
 return rc

if __name__=='__main__':
 if __package__ is None:
  sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
  from lawliet_mobile.container_runner import supervise as invoke
 else:invoke=supervise
 sys.exit(invoke(*(int(x) for x in sys.argv[2:])))
