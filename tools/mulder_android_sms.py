"""Start a separate SMS-only MCP endpoint with local ADB transport.

No installation, default case/device selection, network daemon start or policy
change to the general offline server. Physical seed acceptance is separate.
"""
import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.mulder_endpoint_runtime import endpoint_command, endpoint_runtime, RuntimeQualificationError
RUNTIME = Path(os.environ.get('LAWLIET_RUNTIME', str(Path.home()/'Library/Application Support/LAWLIET/runtime')))


def launch(runtime, db_dir, case_id):
    runtime, db_dir = Path(runtime).expanduser().resolve(), Path(db_dir).expanduser().resolve()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', case_id):
        raise ValueError('Supply an explicit case ID with letters, digits, underscores or hyphens.')
    case_db = db_dir/(case_id+'.db')
    if case_db.is_symlink() or not case_db.is_file():
        raise ValueError('A regular pre-existing Mulder case database is required.')
    policy = ROOT/'integrations/mulder/policies/android-sms-local.sb'
    if (not policy.is_file() or not Path('/usr/bin/sandbox-exec').is_file()):
        raise ValueError('Local SMS endpoint requires the saved policy and macOS sandbox-exec.')
    selected = endpoint_runtime(runtime, 'android-sms',
                                environment={'ADB_SERVER_SOCKET': 'tcp:127.0.0.1:5037'})
    app = selected['app']
    # Avoid exposing the broad tool surface with a runtime predating this gate.
    if not app.is_file() or '_LAWLIET_TOOL_PROFILE' not in app.read_text():
        raise ValueError('Runtime lacks the restricted SMS tool profile; update the pinned integration first.')
    env = selected['environment']
    argv = ['/usr/bin/sandbox-exec', '-f', str(policy), *endpoint_command(selected),
            'serve', '--case-id', case_id, '--db-dir', str(db_dir),
            '--transport', 'stdio', '--workers', '1']
    return argv, env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', default=str(RUNTIME))
    parser.add_argument('--db-dir', required=True)
    parser.add_argument('--case-id', required=True)
    args = parser.parse_args()
    try:
        argv, env = launch(args.runtime, args.db_dir, args.case_id)
    except (OSError, ValueError, RuntimeQualificationError) as exc:
        parser.error(str(exc))
    os.execve(argv[0], argv, env)


if __name__ == '__main__':
    main()
