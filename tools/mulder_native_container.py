"""Opt-in three-tool native-container MCP endpoint; no image pull or daemon startup."""
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

def launch(runtime,db_dir,case_id,socket,*,mulder_source=None,lawliet_source=None,policy=None):
    runtime=Path(runtime).expanduser().resolve();db_dir=Path(db_dir).expanduser().resolve()
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,79}',case_id):raise ValueError('Explicit valid case ID required.')
    case_db=db_dir/(case_id+'.db')
    if case_db.is_symlink() or not case_db.is_file():raise ValueError('Regular pre-existing Mulder case database required.')
    socket=Path(socket).expanduser().resolve()
    if not stat.S_ISSOCK(socket.stat().st_mode):raise ValueError('Existing explicit local daemon socket required.')
    profile=Path(policy or ROOT/'integrations/mulder/policies/parser-container-local.sb').expanduser().resolve()
    if not profile.is_file() or not Path('/usr/bin/sandbox-exec').is_file():raise ValueError('Local restricted endpoint components unavailable.')
    selected=endpoint_runtime(runtime,'native-container',mulder_source=mulder_source,
                              lawliet_source=lawliet_source,environment={'LAWLIET_CONTAINER_SOCKET':str(socket)})
    source,backend=selected['source'],selected['backend']
    app=source/'mulder/server/app.py'
    tool=source/'mulder/server/tools/phone.py'
    if (not app.is_file() or '_LAWLIET_NATIVE_CONTAINER_TOOLS' not in app.read_text()
            or not tool.is_file() or "os.environ.get('LAWLIET_MCP_PROFILE') == 'native-container'" not in tool.read_text()
            or not (backend/'lawliet_mobile/native_container.py').is_file()):
        raise ValueError('Staged runtime lacks explicit Native-container registration/host-fallback guard.')
    env=selected['environment']
    argv=['/usr/bin/sandbox-exec','-D','DOCKER_SOCKET='+str(socket),'-f',str(profile),*endpoint_command(selected),'serve','--case-id',case_id,'--db-dir',str(db_dir),'--transport','stdio','--workers','1']
    return argv,env

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime',default=str(RUNTIME));p.add_argument('--db-dir',required=True);p.add_argument('--case-id',required=True);p.add_argument('--socket',required=True);p.add_argument('--mulder-source');p.add_argument('--lawliet-source');a=p.parse_args()
    try:argv,env=launch(a.runtime,a.db_dir,a.case_id,a.socket,mulder_source=a.mulder_source,lawliet_source=a.lawliet_source)
    except (ValueError,OSError,RuntimeQualificationError) as exc:p.error(str(exc))
    os.execve(argv[0],argv,env)
if __name__=='__main__':main()
