"""Launch the opt-in three-tool Mulder parser endpoint; no daemon/image startup."""
import argparse
import os
import re
import stat
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tools.mulder_endpoint_runtime import endpoint_command,endpoint_runtime,RuntimeQualificationError
RUNTIME=Path(os.environ.get('LAWLIET_RUNTIME',str(Path.home()/'Library/Application Support/LAWLIET/runtime')))

def launch(runtime,db_dir,case_id,socket):
 runtime=Path(runtime).expanduser().resolve();db_dir=Path(db_dir).expanduser().resolve()
 if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,79}',case_id):raise ValueError('Explicit valid case ID required.')
 case_db=db_dir/(case_id+'.db')
 if case_db.is_symlink() or not case_db.is_file():raise ValueError('Regular pre-existing Mulder case database required.')
 socket=Path(socket).expanduser().resolve()
 if not stat.S_ISSOCK(socket.stat().st_mode):raise ValueError('Existing explicit local daemon socket required.')
 policy=ROOT/'integrations/mulder/policies/parser-container-local.sb'
 if not policy.is_file() or not Path('/usr/bin/sandbox-exec').is_file():raise ValueError('Local restricted endpoint components unavailable.')
 selected=endpoint_runtime(runtime,'parser-container',environment={'LAWLIET_CONTAINER_SOCKET':str(socket)})
 app=selected['app']
 if not app.is_file() or '_LAWLIET_CONTAINER_TOOLS' not in app.read_text():raise ValueError('Runtime lacks restricted container profile.')
 env=selected['environment']
 argv=['/usr/bin/sandbox-exec','-D','DOCKER_SOCKET='+str(socket),'-f',str(policy),*endpoint_command(selected),'serve','--case-id',case_id,'--db-dir',str(db_dir),'--transport','stdio','--workers','1']
 return argv,env

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime',default=str(RUNTIME));p.add_argument('--db-dir',required=True);p.add_argument('--case-id',required=True);p.add_argument('--socket',required=True);a=p.parse_args()
 try:argv,env=launch(a.runtime,a.db_dir,a.case_id,a.socket)
 except (ValueError,OSError,RuntimeQualificationError) as exc:p.error(str(exc))
 os.execve(argv[0],argv,env)
if __name__=='__main__':main()
