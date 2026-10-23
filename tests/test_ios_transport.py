"""Inherited remote transports must not change an approved local USB route."""
import os
import unittest
from unittest.mock import patch

from lawliet_mobile.core import UserError
from lawliet_mobile.iphone_connection import (
    USB_TRANSPORT_OVERRIDES, discover, require_local_usb_environment,
)
from lawliet_mobile.ios_apps import collect_apps
from lawliet_mobile.ios_backup import collect_selected
from lawliet_mobile.tools import collect, devices


class IPhoneTransportTests(unittest.TestCase):
    def test_every_nonempty_override_refused_without_value_disclosure(self):
        for name in USB_TRANSPORT_OVERRIDES:
            for value in ('private-host:1234', '0', ' '):
                with self.subTest(name=name, value_kind=value == '0'):
                    with patch.dict(os.environ, {name: value}, clear=True):
                        before = dict(os.environ)
                        with self.assertRaises(UserError) as failure:
                            require_local_usb_environment()
                        self.assertIn(name, str(failure.exception))
                        self.assertNotIn('private-host', str(failure.exception))
                        self.assertEqual(dict(os.environ), before)

    def test_empty_overrides_and_unrelated_environment_are_unchanged(self):
        env = {name: '' for name in USB_TRANSPORT_OVERRIDES}
        env.update({'PYMOBILEDEVICE3_UDID': 'explicit-argv-takes-precedence', 'OTHER_SETTING': 'kept'})
        with patch.dict(os.environ, env, clear=True):
            before = dict(os.environ)
            require_local_usb_environment()
            self.assertEqual(dict(os.environ), before)

    def test_inventory_and_backup_refuse_before_resolution_or_case_writes(self):
        serial = '00008120-0012345678901234'
        with patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': 'private-host:1234'}, clear=True), \
                patch('lawliet_mobile.runner_lease.lease') as lease, \
                patch('lawliet_mobile.ios_backup.command') as command, \
                patch('lawliet_mobile.provider_contacts._create_collection') as create:
            for collect in (collect_apps, collect_selected):
                with self.subTest(collector=collect.__name__):
                    with self.assertRaisesRegex(UserError, 'USBMUXD_SOCKET_ADDRESS'):
                        collect(None, None, None, serial)
            lease.assert_not_called()
            command.assert_not_called()
            create.assert_not_called()

    def test_usb_discovery_never_runs_remote_usbmux_override(self):
        with patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': 'private-host:1234'}, clear=True), \
                patch('lawliet_mobile.iphone_connection.command') as command, \
                patch('lawliet_mobile.iphone_connection.run') as run:
            with self.assertRaisesRegex(UserError, 'USBMUXD_SOCKET_ADDRESS'):
                discover(None)
            command.assert_not_called()
            run.assert_not_called()

    def test_full_backup_also_refuses_remote_transport_before_staging(self):
        with patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': 'private-host:1234'}, clear=True), \
                patch('lawliet_mobile.provider_contacts._create_collection') as create:
            for profile in (None, 'ios-backup', 'ios-apps', 'ios-selected'):
                with self.subTest(profile=profile), self.assertRaisesRegex(UserError, 'USBMUXD_SOCKET_ADDRESS'):
                    collect(None, None, None, 'ios', '00008120-0012345678901234', profile=profile)
            create.assert_not_called()

    def test_shared_discovery_preserves_android_and_refuses_only_iphone(self):
        def unavailable(workspace, name):
            self.assertEqual(name, 'adb')
            raise UserError('Synthetic ADB unavailable')
        with patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': 'private-host:1234'}, clear=True), \
                patch('lawliet_mobile.tools.command', side_effect=unavailable), \
                patch('lawliet_mobile.tools.execute') as execute:
            found = devices(None)
            self.assertEqual(found[0]['platform'], 'android')
            self.assertEqual(found[0]['status'], 'tool_missing')
            self.assertEqual(found[1]['platform'], 'ios')
            self.assertEqual(found[1]['status'], 'discovery_refused')
            self.assertNotIn('private-host', str(found))
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
