"""Live phone collection requires its dedicated MCP endpoint, including job dispatch."""
import json
import os
import subprocess
import sys
import unittest


class AcquisitionProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import mulder.server.app
        except ModuleNotFoundError:
            raise unittest.SkipTest('Requires patched Mulder interpreter')

    def probe(self, profile):
        code = '''import asyncio,json
from mulder.server.app import mcp,_tool_dispatch,_tool_dispatch_sync
import mulder.server.tools
print(json.dumps({"advertised":[t.name for t in asyncio.run(mcp.list_tools())],
"async_dispatch":list(_tool_dispatch),"sync_dispatch":list(_tool_dispatch_sync)}))
'''
        result = subprocess.run([sys.executable, '-P', '-c', code],
                                env={**os.environ, 'LAWLIET_MCP_PROFILE': profile},
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return {name: set(values) for name, values in json.loads(result.stdout).items()}

    def test_standard_has_no_sms_or_contacts_collection_in_any_dispatch_path(self):
        for surface, names in self.probe('standard').items():
            with self.subTest(surface=surface):
                self.assertTrue({'scan_evidence', 'run_aleapp', 'run_ileapp'} <= names)
                self.assertFalse({'collect_lawliet_android_sms', 'collect_lawliet_android_contacts'} & names)

    def test_sms_endpoint_retains_only_its_explicit_collection_and_review_tools(self):
        for surface, names in self.probe('android-sms').items():
            with self.subTest(surface=surface):
                self.assertEqual(names, {'collect_lawliet_android_sms', 'query_ancalor_review', 'list_ancalor_files'})

    def test_contacts_endpoint_retains_only_its_explicit_collection_and_review_tools(self):
        for surface, names in self.probe('android-contacts').items():
            with self.subTest(surface=surface):
                self.assertEqual(names, {'collect_lawliet_android_contacts', 'query_ancalor_review', 'list_ancalor_files'})
