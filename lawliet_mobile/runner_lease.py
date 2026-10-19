"""Single-case advisory ownership for trusted configured parser subprocesses."""
from __future__ import annotations
import contextlib,contextvars,json,os,signal,stat,subprocess,sys,time,uuid
from pathlib import Path
PROTOCOL='ancalor-runner-lease-v1'
CURRENT=contextvars.ContextVar('runner_lease',default=None)
@contextlib.contextmanager
def lease(root,db):
 from .core import UserError,audit,json_text,now,verify
 if os.name not in ('posix','nt'):raise UserError('External runner ownership is unsupported on this platform.')
 root=Path(root)
 if any(p.is_symlink() or (os.name=='nt' and getattr(p.lstat(),'st_file_attributes',0)&0x400) for p in (root,*root.parents)):raise UserError('Runner case path symlink or reparse point refused.')
 path=root/'.external-runner.lease'
 flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
 try:
  if os.name=='nt':
   from .runner_windows import open_lease
   fd=open_lease(path)
  else:fd=os.open(path,flags,0o600)
 except BlockingIOError as exc:raise UserError('A runner or its child still owns this case; retry refused.') from exc
 except OSError as exc:raise UserError('Runner lease cannot be opened safely.') from exc
 token=None
 try:
  value=os.fstat(fd)
  if not stat.S_ISREG(value.st_mode) or value.st_nlink!=1 or getattr(value,'st_file_attributes',0)&0x400 or (value.st_dev,value.st_ino)!=(path.stat().st_dev,path.stat().st_ino):raise UserError('Runner lease inode is unsafe.')
  if os.name=='posix':
   import fcntl
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError as exc:raise UserError('A runner or its child still owns this case; retry refused.') from exc
  raw=os.read(fd,4097)
  if not raw:
   os.write(fd,(PROTOCOL+'\n').encode());os.fsync(fd)
  elif raw!=(PROTOCOL+'\n').encode():raise UserError('Runner lease protocol is malformed; recovery refused.')
  if not verify(root,db)['ok']:raise UserError('Integrity check failed before runner recovery.')
  from .report_container import recover_before_retry as recover_reports
  recover_reports(root,db)
  from .native_container import recover_before_retry as recover_native
  recover_native(root,db)
  from .sqlite_container import recover_before_retry as recover_sqlite
  recover_sqlite(root,db)
  from .container_runner import recover_before_retry
  recover_before_retry(root,db)
  identity={'protocol':PROTOCOL,'device':value.st_dev,'inode':value.st_ino}
  abandoned=list(db.execute("SELECT id,engine,detail FROM runs WHERE status='running'"))
  checked=[]
  for row in abandoned:
   try:detail=json.loads(row['detail']);owner=detail['runner_ownership']
   except (TypeError,ValueError,KeyError):raise UserError('Legacy or unknown running job; automatic recovery refused.')
   if not isinstance(owner,dict) or any(owner.get(k)!=v for k,v in identity.items()) or not isinstance(owner.get('nonce'),str) or len(owner['nonce'])!=32:raise UserError('Running job ownership is uncertain; recovery refused.')
   recorded=False
   is_import=row['engine'] in {'import/jsonl','import/tsv','import/leapp'}
   started_action='parsed_import.started' if is_import else 'sqlite_query.started' if row['engine']=='sqlite-workspace/1' else 'analysis.started'
   for entry in db.execute('SELECT detail FROM audit WHERE action=?',(started_action,)):
    try:claim=json.loads(entry['detail'])
    except (ValueError,TypeError):continue
    if claim.get('run_id')==row['id'] and claim.get('runner_ownership')==owner and (row['engine']=='sqlite-workspace/1' or claim.get('engine')==row['engine']):recorded=True
   if not recorded:raise UserError('Running ownership lacks matching audited start; recovery refused.')
   checked.append((row,detail))
  if checked:
   db.execute('SAVEPOINT abandoned_runner_recovery')
   try:
    for row,detail in checked:
     if row['engine']=='sqlite-workspace/1':detail['state']='interrupted'
     detail['recovery']={'state':'abandoned_owner_reconciled','basis':'Exclusive same-inode protocol lease acquired; prior parent/guardian/child no longer hold it. Partial output retained, never promoted.','partial_output_retained':True}
     db.execute("UPDATE runs SET status='interrupted',finished_at=?,detail=? WHERE id=?",(now(),json_text(detail),row['id']))
     audit(db,'parsed_import.abandoned' if row['engine'] in {'import/jsonl','import/tsv','import/leapp'} else 'sqlite_query.abandoned' if row['engine']=='sqlite-workspace/1' else 'analysis.abandoned',{'run_id':row['id'],'protocol':PROTOCOL,'partial_output_retained':True})
    db.execute('RELEASE abandoned_runner_recovery');db.commit()
   except BaseException:db.execute('ROLLBACK TO abandoned_runner_recovery');db.execute('RELEASE abandoned_runner_recovery');raise
  token=CURRENT.set({'fd':fd,'root':str(root),'identity':{**identity,'nonce':uuid.uuid4().hex}})
  yield
 finally:
  if token is not None:CURRENT.reset(token)
  # Never LOCK_UN: inherited copies share this open-file description.
  os.close(fd)
def ownership():
 context=CURRENT.get()
 if context is None:raise RuntimeError('External runner requires ownership lease.')
 return dict(context['identity'])
def spawn(argv,*,cwd,stdout,stderr,stdin_fd=None):
 # Only an explicitly supplied descriptor is inherited; credentials themselves
 # never enter the launch configuration or process arguments.
 if stdin_fd is not None:
  if type(stdin_fd) is not int or stdin_fd<0:raise ValueError('stdin_fd must be an open descriptor.')
  os.fstat(stdin_fd)
 context=CURRENT.get()
 if os.name=='nt':
  from .runner_windows import spawn as windows_spawn
  return windows_spawn(argv,cwd=cwd,stdout=stdout,stderr=stderr,lease_fd=context['fd'] if context else None,stdin_fd=stdin_fd)
 if context is None:return subprocess.Popen(argv,cwd=cwd,stdout=stdout,stderr=stderr,stdin=stdin_fd if stdin_fd is not None else subprocess.DEVNULL,start_new_session=(os.name!='nt')),None
 if os.name!='posix':raise RuntimeError('Runner guardian requires POSIX; unsupported platform refused.')
 config=json.dumps({'argv':argv,'cwd':str(cwd) if cwd else None,**({'stdin_fd':stdin_fd} if stdin_fd is not None else {})}).encode()
 if len(config)>16384:raise ValueError('Guardian launch configuration exceeds bound.')
 read,write=os.pipe();config_read,config_write=os.pipe();child=None
 try:
  child=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--guardian',str(context['fd']),str(read),str(config_read)],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True,pass_fds=(context['fd'],read,config_read)+((stdin_fd,) if stdin_fd is not None else ()))
  os.close(read);read=None;os.close(config_read);config_read=None
  remaining=memoryview(config)
  while remaining:
   try:written=os.write(config_write,remaining)
   except InterruptedError:continue
   if written<=0:raise BrokenPipeError('Guardian configuration pipe made no progress.')
   remaining=remaining[written:]
  os.close(config_write);config_write=None
  return child,write
 except BaseException:
  # First release the configuration reader from EOF wait, then signal owner
  # death and reap only the guardian created by this launch.
  if config_write is not None:
   os.close(config_write);config_write=None
  if child is None:os.close(write)
  else:stop(child,write)
  raise
 finally:
  for fd in (read,config_read,config_write):
   if fd is not None:os.close(fd)
def stop(child,alive):
 if alive is None:
  if os.name!='nt':
   try:os.killpg(child.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  else:child.kill()
 else:
  os.close(alive)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:child.kill()
 child.wait()
def guardian(lease_fd,alive_fd,config_fd):
 import select
 with os.fdopen(config_fd,'rb') as stream:raw=stream.read(16385)
 if len(raw)>16384:raise ValueError('Guardian configuration bound')
 config=json.loads(raw)
 stdin_fd=config.get('stdin_fd')
 child=None
 try:
  child=subprocess.Popen(config['argv'],cwd=config['cwd'],stdin=stdin_fd if stdin_fd is not None else subprocess.DEVNULL,start_new_session=True,pass_fds=(lease_fd,))
  if stdin_fd is not None:os.close(stdin_fd);stdin_fd=None
  while child.poll() is None:
   readable,_,_=select.select([alive_fd],[],[],.1)
   if readable and os.read(alive_fd,1)==b'':
    return 125
  return child.returncode if child.returncode>=0 else 128-child.returncode
 finally:
  if child is not None:
   if child.poll() is None:
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
   child.wait()
  if stdin_fd is not None:os.close(stdin_fd)
  os.close(alive_fd)
if __name__=='__main__':sys.exit(guardian(*(int(x) for x in sys.argv[2:])))
