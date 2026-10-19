"""Exercise actual CLI parsing/dispatch; fake only the physical ADB transport."""
import contextlib
import io
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.cli import main
from lawliet_mobile.core import create_case


class ContactsCLIScope(unittest.TestCase):
    def test_explicit_user_reaches_every_provider_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / 'cases'
            create_case(workspace, 'A')
            commands = []

            def transport(argv, output, timeout, **kwargs):
                commands.append(argv)
                if argv[-1] == 'get-state':
                    text = 'device\n'
                else:
                    args = shlex.split(argv[-1])
                    self.assertEqual(args[args.index('--user') + 1], '12')
                    self.assertEqual(args[args.index('--projection') + 1], '_id')
                    text = 'No result found.\n'
                output.write_text(text)
                stderr = Path(str(output) + '.stderr')
                stderr.write_text('')
                return {'argv': argv, 'returncode': 0,
                        'stdout': str(output), 'stderr': str(stderr)}

            with patch('lawliet_mobile.provider_contacts.command', return_value=['adb']), \
                    patch('lawliet_mobile.provider_contacts.execute', side_effect=transport), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = main(['--workspace', str(workspace), '--json', 'collect', 'android',
                    '--case', 'A', '--serial', 'TEST', '--profile', 'contacts-provider',
                    '--android-user', '12'])
            self.assertEqual(status, 0)
            self.assertEqual(len(commands), 3)  # state and two user-bound inventories

    def test_sms_only_options_rejected_for_contacts_before_collection(self):
        self.refuses('android', ['--profile', 'contacts-provider', '--sms-prefix', 'LM-SEED'])
        self.refuses('android', ['--profile', 'contacts-provider', '--max-sms', '2'])

    def test_user_rejected_for_other_profiles_or_platforms_before_collection(self):
        self.refuses('android', ['--profile', 'files', '--android-user', '12'])
        self.refuses('ios', ['--profile', 'sms-provider', '--android-user', '12'])

    def refuses(self, platform, extra):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / 'cases'
            create_case(workspace, 'A')
            with patch('lawliet_mobile.cli.collect_android', side_effect=AssertionError('no acquisition')), \
                    patch('lawliet_mobile.cli.collect', side_effect=AssertionError('no acquisition')), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = main(['--workspace', str(workspace), '--json', 'collect', platform,
                    '--case', 'A', '--serial', 'TEST', *extra])
            self.assertNotEqual(status, 0)


if __name__ == '__main__':
    unittest.main()
