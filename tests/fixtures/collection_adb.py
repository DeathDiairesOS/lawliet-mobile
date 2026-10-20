"""Synthetic ADB subprocess for workflow validation. Never accesses USB/network.

Only accepts fixed synthetic serials and the fixed commands
used by the scoped collectors. Fixture reads are logged beside this copied file.
"""
import base64
import hashlib
import json
from pathlib import Path
import shlex
import sys
import zipfile


PHOTO = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aWQAAAABJRU5ErkJggg==')
# Different acquired bytes keep the shared image and the Trash source distinct.
TRASH_PHOTO = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADUlEQVQIHWP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC')
TRASH_PATH = '/sdcard/Android/.Trash/com.sec.android.gallery3d/trashed-fixture.png'


def main():
    args = sys.argv[1:]
    with Path(__file__).with_suffix('.calls.jsonl').open('a') as log:
        log.write(json.dumps(args) + '\n')
    if args == ['devices', '-l']:
        return 'List of devices attached\nLAWLIET-SYNTHETIC device product:fixture model:Synthetic_validation_fixture\n'
    if len(args) < 3 or args[0] != '-s' or args[1] not in {'LAWLIET-SYNTHETIC', 'LAWLIET-DENIED', 'LAWLIET-PARTIAL'}:
        raise ValueError('Only explicit synthetic device serials are accepted')
    serial, args = args[1], args[2:]
    if args == ['get-state']:
        return 'device\n'
    if args == ['version']:
        return 'LAWLIET synthetic ADB fixture 1; not an Android device\n'
    if args == ['shell', 'am', 'get-current-user']:
        return '0\n'
    if args[:2] == ['shell', 'getprop']:
        return '[ro.product.model]: [Synthetic validation fixture]\n[ro.build.version.release]: [13]\n'
    if args[:2] == ['shell', 'date'] or args == ['shell', 'date +%Y-%m-%dT%H:%M:%S%z']:
        return '2026-10-17T12:00:00+0000\n'
    if args == ['shell', 'pm', 'list', 'packages', '-f']:
        return 'package:/data/app/example/base.apk=com.example.fixture\n'
    if args == ['logcat', '-d', '-v', 'epoch']:
        return ('--------- beginning of main\n'
                '1792238401.250 100 101 I ActivityManager: Synthetic activity resumed\n'
                'undated fixture text must not become an event\n')
    if len(args) == 2 and args[0] == 'bugreport':
        if serial == 'LAWLIET-PARTIAL':
            sys.stderr.buffer.write(b'Synthetic bugreport collection failure\n')
            raise SystemExit(9)
        with zipfile.ZipFile(args[1], 'w') as archive:
            archive.writestr('main_entry.txt', 'bugreport-fixture.txt')
            archive.writestr('bugreport-fixture.txt', 'Synthetic diagnostic report; not private application data.\n')
        return 'Synthetic bugreport ZIP retained\n'
    if args[:2] == ['backup', '-f']:
        if args[3:] != ['-noapk', '-nocompress', 'com.android.providers.telephony']:
            raise ValueError('Unexpected legacy backup scope')
        sys.stderr.buffer.write(b'Synthetic legacy backup unavailable on this device\n')
        raise SystemExit(1)
    if args == ['shell', 'find /sdcard/Android/.Trash -type f -print0']:
        return TRASH_PATH + '\0'
    if args == ['shell', 'sha256sum ' + TRASH_PATH]:
        return hashlib.sha256(TRASH_PHOTO).hexdigest() + '  ' + TRASH_PATH + '\n'
    if len(args) == 4 and args[:3] == ['pull', '-a', TRASH_PATH]:
        Path(args[3]).write_bytes(TRASH_PHOTO)
        return 'Synthetic Trash fixture copied\n'
    if args[:3] == ['shell', 'du', '-sk']:
        if args[3] != '/sdcard/Download/lawliet-seed': raise ValueError('Unexpected path')
        return '4\t/sdcard/Download/lawliet-seed\n'
    if args[:3] == ['pull', '-a', '/sdcard/Download/lawliet-seed']:
        destination = Path(args[3])/'lab-photo.png'
        destination.write_bytes(PHOTO)
        return 'Synthetic shared-storage fixture copied\n'
    if len(args) != 2 or args[0] != 'shell': raise ValueError('Unexpected command')
    query = shlex.split(args[1])
    if query[:2] != ['content', 'query']: raise ValueError('Unexpected shell operation')
    if serial == 'LAWLIET-DENIED': return 'Error while accessing provider: SecurityException: Permission Denial\n'
    uri = query[query.index('--uri')+1]
    projection = query[query.index('--projection')+1]
    where = query[query.index('--where')+1] if '--where' in query else None
    if uri == 'content://sms':
        if where == '0=1': return 'No result found.\n'
        if projection == '_id': return 'Row: 0 _id=41\nRow: 1 _id=42\n'
        identifier = int(where.removeprefix('_id='))
        if identifier not in (41, 42): raise ValueError('Unexpected SMS record')
        values = [('thread_id',7), ('address','+12025550123'), ('date',1792238400123 + (identifier-41)*60000),
                  ('date_sent',0), ('type',1 if identifier==41 else 2),
                  ('body','Meet at the blue station at noon — café.' if identifier==41 else 'Confirmed. Bring the receipt.'),
                  ('read',1), ('status',-1)]
        cells = [f'Row: 0 _id={identifier}']
        for field, value in values:
            cells += [f'typeof({field})=' + ('integer' if isinstance(value,int) else 'text'),
                      f'hex({field})=' + str(value).encode().hex().upper()]
        return ', '.join(cells)+'\n'
    if uri == 'content://com.android.contacts/contacts':
        if projection == '_id': return 'Row: 0 _id=7\n'
        if projection == 'display_name': return 'Row: 0 display_name=Alex Fixture\n'
    if uri == 'content://com.android.contacts/data':
        if projection == '_id': return 'Row: 0 _id=11\n' if 'phone_v2' in where else 'No result found.\n'
        if projection == 'data1': return 'Row: 0 data1=+12025550123\n'
    raise ValueError('Unexpected provider request')


if __name__ == '__main__':
    sys.stdout.buffer.write(main().encode('utf-8'))
