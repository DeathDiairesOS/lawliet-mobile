"""Known-passphrase legacy Signal backup adapter; secrets never enter argv/logs."""
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from .core import UserError, audit, digest, import_evidence, json_text, now
from .tools import command, storage_guard


def decrypt_signal(root,db,workspace,source,passphrase,timeout=900,max_bytes=20*1024**3):
    secret=re.sub(r'[\s-]','',passphrase)
    if not re.fullmatch(r'\d{30}',secret): raise UserError('Legacy Signal backups require the known 30-digit passphrase. New backup formats are not supported by this adapter.')
    if os.name!='posix': raise UserError('Secure passphrase transport currently requires macOS/Linux.')
    cmd=command(workspace,'signalbackup-tools')
    original_eid,_,_=import_evidence(root,db,source,'android','Original encrypted Signal backup',max_bytes=max_bytes,expand_archives=False)
    original=db.execute('SELECT * FROM files WHERE evidence_id=?',(original_eid,)).fetchone()
    run=uuid.uuid4().hex[:12];folder=root/'runs'/run;folder.mkdir(parents=True)
    output=folder/'decrypted';output.mkdir()
    work=folder/'input.backup';shutil.copyfile(root/'evidence'/original_eid/original['path'],work)
    argv=cmd+[str(work),'--output',str(output)]
    detail={'argv':argv,'original_evidence_id':original_eid,'executable_sha256':digest(cmd[-1]),
            'note':'Upstream stdout/stderr suppressed because it may print derived encryption keys. Passphrase sent through a non-echoing private terminal; never recorded.'}
    db.execute('INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES(?,?,?,?,?)',(run,original_eid,'signalbackup-tools',now(),'running'))
    audit(db,'signal.decrypt.started',{'run_id':run,'original_evidence_id':original_eid});db.commit()
    status='failed';child=None;master=slave=None
    try:
        import pty,termios
        master,slave=pty.openpty();attrs=termios.tcgetattr(slave);attrs[3]&=~termios.ECHO;termios.tcsetattr(slave,termios.TCSANOW,attrs)
        child=subprocess.Popen(argv,stdin=slave,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        os.write(master,(secret+'\n').encode());deadline=time.monotonic()+timeout;guard=storage_guard(folder,max_bytes)
        while child.poll() is None:
            guard()
            if time.monotonic()>deadline: raise UserError('Signal decryption timed out; partial output retained.')
            time.sleep(0.2)
        detail['returncode']=child.returncode
        if child.returncode: raise UserError('Signal decryption failed. Check backup format, tool compatibility and the supplied passphrase.')
        database=output/'database.sqlite'
        if not database.is_file(): raise UserError('Decoder returned no database.sqlite.')
        with database.open('rb') as f:
            if f.read(16)!=b'SQLite format 3\x00': raise UserError('Decoder output is not a plaintext SQLite database.')
        derived_eid,files,size=import_evidence(root,db,output,'android','Decrypted Signal backup · '+original_eid,max_bytes=max_bytes)
        detail.update(derived_evidence_id=derived_eid,files=files,bytes=size);status='complete'
        return {'status':status,'run_id':run,'original_evidence_id':original_eid,'evidence_id':derived_eid,'files':files}
    except BaseException as exc:
        detail['error']=str(exc);raise
    finally:
        if child and child.poll() is None:
            import signal
            os.killpg(child.pid,signal.SIGKILL);child.wait()
        for fd in (master,slave):
            if fd is not None: os.close(fd)
        db.execute('UPDATE runs SET status=?,finished_at=?,detail=? WHERE id=?',(status,now(),json_text(detail),run))
        audit(db,'signal.decrypt.finished',{'run_id':run,'status':status,'original_evidence_id':original_eid,'derived_evidence_id':detail.get('derived_evidence_id')});db.commit()
