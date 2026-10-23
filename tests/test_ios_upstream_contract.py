"""Opt-in pinned upstream protocol tests using synthetic bytes, never USB.

Run with pymobiledevice3 11.41.2 already installed in the interpreter:
LAWLIET_PYMOBILEDEVICE3_CONTRACT=1 python -m unittest tests.test_ios_upstream_contract
No dependency download, device discovery or network access is performed.
"""
import asyncio
from contextlib import closing
from importlib.metadata import version
import os
from pathlib import Path
import socket
import sqlite3
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
import warnings

from lawliet_mobile.core import UserError, digest
from lawliet_mobile.ios_backup import BASE_PATHS, DATABASE_REGEX, VERSION, _inspect_backup
from tests.test_ios_selective_backup import SERIAL, fixture_backup

ENABLED = os.environ.get('LAWLIET_PYMOBILEDEVICE3_CONTRACT') == '1'
if ENABLED:
    from typer.main import get_command
    from pymobiledevice3.cli.backup import cli
    from pymobiledevice3.exceptions import LockdownError, NotEnoughDiskSpaceError, PyMobileDevice3Exception
    from pymobiledevice3.services.device_link import DeviceLink
    from pymobiledevice3.services.mobilebackup2 import BackupFile, Mobilebackup2Service


def prefixed(text):
    data = text.encode('utf-8')
    return struct.pack('>I', len(data)) + data


def transfer(device_name, file_name, data, error=False):
    end = (b'\x0b' + b'Synthetic interrupted file') if error else b'\x00'
    return (prefixed(device_name) + prefixed(file_name) + struct.pack('>IB', len(data) + 1, 12)
            + data + struct.pack('>I', len(end)) + end)


class SyntheticService:
    def __init__(self, payload=b'', response=None):
        self.payload = payload
        self.offset = 0
        self.responses = []
        self.response = response

    async def recvall(self, size):
        data = self.payload[self.offset:self.offset + size]
        if len(data) != size:
            raise EOFError('Synthetic stream exhausted')
        self.offset += size
        return data

    async def send_plist(self, value):
        self.responses.append(value)

    async def recv_plist(self):
        return self.response


@unittest.skipUnless(ENABLED, 'Set LAWLIET_PYMOBILEDEVICE3_CONTRACT=1 in the pinned tool environment')
class UpstreamSelectedIPhoneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if version('pymobiledevice3') != VERSION:
            raise AssertionError('This contract requires the exact qualified pymobiledevice3 version')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lawliet-upstream-ios-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        # Accidental real provider resolution must fail, including local usbmux.
        blocked = patch.object(socket.socket, 'connect', side_effect=AssertionError('No device/network I/O in synthetic tests'))
        blocked.start()
        self.addCleanup(blocked.stop)

    def test_exact_cli_arguments_parse_without_invoking_device_provider(self):
        command = get_command(cli).commands['backup']
        with command.make_context('backup', ['--udid', SERIAL, '--only-regex', DATABASE_REGEX,
                                            '--no-patch-manifest', str(self.base)]) as context:
            self.assertEqual(context.params['udid'], SERIAL)
            self.assertEqual(context.params['only_regex'], [DATABASE_REGEX])
            self.assertFalse(context.params['patch_manifest'])
            self.assertFalse(context.params['unback'])
            self.assertFalse(context.params['full'])
        self.assertTrue(Mobilebackup2Service._should_do_full_backup(False, self.base))

    def test_actual_filter_accepts_first_backup_logical_paths_and_sidecars_only(self):
        selection = Mobilebackup2Service.regex_filter_callback([DATABASE_REGEX])
        for path in BASE_PATHS:
            for suffix in ('', '-wal', '-shm'):
                for prefix in ('', 'HomeDomain/', 'HomeDomain-', '/var/mobile/'):
                    with self.subTest(path=path, suffix=suffix, prefix=prefix):
                        self.assertTrue(selection(BackupFile(device_name=prefix + path + suffix)))
        for path in ('Library/SMS/Attachments/photo.jpg', 'Library/AddressBook/AddressBookImages.sqlitedb',
                     'Library/SMS/sms.db-journal', 'Library/SMS/sms.db.bak', 'unrecognized-hashed-name'):
            self.assertFalse(selection(BackupFile(device_name=path)))

    def stream_collection(self, *, remote_error=False, unknown_device_names=False):
        source = fixture_backup(self.base / 'source', wal=True)
        metadata_hashes = {path.name: digest(path) for path in source.iterdir() if path.is_file()}
        with closing(sqlite3.connect(source / 'Manifest.db')) as database:
            logical = dict(database.execute('SELECT fileID, relativePath FROM Files'))
        collection = self.base / 'collection'
        backup = collection / 'backup'
        backup.mkdir(parents=True)
        selection = Mobilebackup2Service.regex_filter_callback([DATABASE_REGEX])
        service = SyntheticService()
        link = DeviceLink(service, backup, preserve_file=lambda name, device: Mobilebackup2Service.should_preserve_backup_file(name, device, selection))
        moves, packet, discarded = {}, bytearray(), []
        # Payloads arrive before Manifest.db, proving retention does not depend on
        # a previous backup's manifest or its availability during the first run.
        paths = sorted(source.rglob('*'), key=lambda path: path.name not in logical)
        for path in paths:
            if not path.is_file():
                continue
            name = f'{SERIAL}/Snapshot/{path.name}'
            destination = f'{SERIAL}/{path.relative_to(source).as_posix()}'
            asyncio.run(link.create_directory(['DLMessageCreateDirectory', str(Path(name).parent)]))
            data = path.read_bytes()
            if path.name in logical:
                device_name = '/var/mobile/' + logical[path.name]
                if unknown_device_names:
                    device_name = path.name
                if not data:
                    data = b'SYNTHETIC EXCLUDED ATTACHMENT' * 8192
                    discarded.append(name)
            else:
                device_name = path.name
            failed = remote_error and logical.get(path.name) == BASE_PATHS[0]
            if failed:
                data = data[:96]  # Header survives; SQLite content is incomplete.
            packet.extend(transfer(device_name, name, data, failed))
            moves[name] = destination
        packet.extend(b'\x00\x00\x00\x00')
        service.payload = bytes(packet)
        with warnings.catch_warnings(record=True) as emitted:
            warnings.simplefilter('always')
            asyncio.run(link.upload_files(['DLMessageUploadFiles', '', 0]))
        self.assertEqual(service.offset, len(packet))  # Excluded bytes were drained too.
        self.assertTrue(all((backup / name).stat().st_size == 0 for name in discarded))
        asyncio.run(link.move_items(['DLMessageMoveItems', moves, 0, 100]))
        link.cleanup_discarded_files()
        self.assertTrue(all(not (backup / moves[name]).exists() for name in discarded))
        self.assertTrue(all(response[1] == 0 for response in service.responses))
        result = _inspect_backup(collection, SERIAL, 256 * 1024**2)
        for name, expected in metadata_hashes.items():
            self.assertEqual(digest(backup / SERIAL / name), expected)
        return result, [str(item.message) for item in emitted]

    def test_actual_upload_move_cleanup_then_lawliet_inspection_with_wal(self):
        result, emitted = self.stream_collection()
        self.assertEqual(emitted, [])
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['selected_manifest_files'], 3)
        self.assertEqual(result['received_sidecars'], [BASE_PATHS[0] + '-wal'])
        self.assertEqual(result['excluded_manifest_entries'], 2)
        self.assertEqual(result['removed_zero_byte_placeholders'], [])

    def test_actual_remote_file_failure_warns_and_lawliet_detects_incomplete_database(self):
        result, emitted = self.stream_collection(remote_error=True)
        self.assertTrue(any('Failed to fully upload:' in item for item in emitted))
        self.assertTrue(any('database validation failed' in item for item in result['errors']))

    def test_unrecognized_first_transfer_names_do_not_become_successful_empty_collection(self):
        result, _ = self.stream_collection(unknown_device_names=True)
        self.assertEqual(result['selected_payloads'], [])
        self.assertTrue(any(BASE_PATHS[0] in error for error in result['errors']))
        self.assertTrue(any(BASE_PATHS[1] in error for error in result['errors']))

    def test_upstream_unknown_encryption_is_false_so_independent_preflight_remains_required(self):
        service = object.__new__(Mobilebackup2Service)
        service.lockdown = SimpleNamespace(get_value=AsyncMock(side_effect=LockdownError('Synthetic unreadable state', SERIAL, 'synthetic')))
        self.assertFalse(asyncio.run(service.get_will_encrypt()))

    def test_device_link_protocol_completion_is_not_status_plist_finished(self):
        for code, expected in ((208, PyMobileDevice3Exception), (105, NotEnoughDiskSpaceError)):
            with self.subTest(code=code):
                service = SyntheticService(response=['DLMessageProcessMessage', {'ErrorCode': code, 'ErrorDescription': 'Synthetic refusal'}])
                with self.assertRaises(expected):
                    asyncio.run(DeviceLink(service, self.base).dl_loop())


if __name__ == '__main__':
    unittest.main()
