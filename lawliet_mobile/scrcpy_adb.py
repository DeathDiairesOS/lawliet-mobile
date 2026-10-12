"""Executed by scrcpy as ADB. No application package imports (copied launcher)."""
import json
import os
import re
import sys
from datetime import datetime, timezone


def permitted(args, serial):
    if args in (['start-server'], ['devices', '-l']):
        return True
    if args[:2] != ['-s', serial]:
        return False
    cmd = args[2:]
    if cmd[:1] == ['push']:
        return len(cmd) == 3 and os.path.basename(cmd[1]) in ('scrcpy-server', 'scrcpy-server.jar') and cmd[2] == '/data/local/tmp/scrcpy-server.jar'
    if cmd[:1] in (['forward'], ['reverse']):
        return len(cmd) == 3 and all(re.fullmatch(r'(tcp:[0-9]{1,5}|localabstract:scrcpy_[0-9a-f]+|--remove)', x) for x in cmd[1:])
    if cmd[:2] == ['shell', 'getprop']:
        return len(cmd) == 3 and cmd[2] in ('ro.product.model', 'ro.build.version.sdk')
    if cmd[:5] == ['shell', 'CLASSPATH=/data/local/tmp/scrcpy-server.jar', 'app_process', '/', 'com.genymobile.scrcpy.Server']:
        return len(cmd) >= 6 and all(re.fullmatch(r'[A-Za-z0-9_.=,:/+@-]+', x) for x in cmd[5:])
    return False


def main():
    import fcntl
    args = sys.argv[1:]
    allowed = permitted(args, (os.environ.get('LAWLIET_DEVICE_SERIAL') or os.environ['ANCALOR_DEVICE_SERIAL']))
    fd = os.open((os.environ.get('LAWLIET_DEVICE_AUDIT') or os.environ['ANCALOR_DEVICE_AUDIT']), os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        data = json.dumps({'at': datetime.now(timezone.utc).isoformat(), 'event': 'scrcpy.adb.command' if allowed else 'scrcpy.adb.blocked', 'argv': args}) + '\n'
        os.write(fd, data.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    if not allowed:
        print('Lawliet blocked ADB command: file drops, APK installs and network commands are disabled.', file=sys.stderr)
        return 1
    os.execv((os.environ.get('LAWLIET_REAL_ADB') or os.environ['ANCALOR_REAL_ADB']), [(os.environ.get('LAWLIET_REAL_ADB') or os.environ['ANCALOR_REAL_ADB'])] + args)


if __name__ == '__main__':
    sys.exit(main())
