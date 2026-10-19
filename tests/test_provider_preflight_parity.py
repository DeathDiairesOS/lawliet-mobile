"""The examiner's storage preview must use the actual collection budget."""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import create_case, UserError


class ProviderPreflightParity(unittest.TestCase):
    def test_bounded_sms_and_contacts_preview_match_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp); create_case(ws, 'A')
            disk = shutil._ntuple_diskusage(10 * 1024**3, 8 * 1024**3, 2 * 1024**3)
            with patch('lawliet_mobile.validation.shutil.disk_usage', return_value=disk), \
                 patch('lawliet_mobile.tools.command', return_value=['fixture-tool']), \
                 patch('lawliet_mobile.app_backend.collect_android', return_value={'status': 'failed', 'evidence_id': None}) as collect:
                for profile in ('sms-provider', 'contacts-provider'):
                    request = {'case': 'A', 'platform': 'android', 'profile': profile, 'serial': 'SYNTHETIC', 'max_gib': 20}
                    preview = handle(ws, {**request, 'action': 'preflight'})
                    self.assertTrue(preview['ready'])
                    self.assertEqual(preview['budget_bytes'], 64 * 1024**2)
                    handle(ws, {**request, 'action': 'collect'})
                    self.assertEqual(collect.call_args.args[7], preview['budget_bytes'])

    def test_general_acquisition_does_not_inherit_provider_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp); create_case(ws, 'A')
            disk = shutil._ntuple_diskusage(10 * 1024**3, 8 * 1024**3, 2 * 1024**3)
            with patch('lawliet_mobile.validation.shutil.disk_usage', return_value=disk), \
                 patch('lawliet_mobile.tools.command', return_value=['fixture-tool']), \
                 patch('lawliet_mobile.app_backend.collect_android') as collect:
                request = {'case': 'A', 'platform': 'android', 'profile': 'files', 'serial': 'SYNTHETIC', 'max_gib': 20}
                preview = handle(ws, {**request, 'action': 'preflight'})
                self.assertFalse(preview['ready'])
                self.assertEqual(preview['budget_bytes'], 20 * 1024**3)
                with self.assertRaises(UserError):
                    handle(ws, {**request, 'action': 'collect'})
                collect.assert_not_called()
