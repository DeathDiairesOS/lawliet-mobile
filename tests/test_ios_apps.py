"""Real synthetic iOS inventory subprocesses; never an attached phone."""
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest

from lawliet_mobile.core import UserError, connect, create_case, digest, select_artifacts, verify
from lawliet_mobile.ios_apps import collect_apps, inventory_records
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.tools import configure

UDID = '00000000-0000000000000001'
FIXTURE = '''import json,pathlib,plistlib,sys,time
p=pathlib.Path(__file__); name=p.stem; a=sys.argv[1:]
mode=(p.parent/'mode.txt').read_text(encoding='utf-8')
with (p.parent/'calls.jsonl').open('ab') as f:f.write((json.dumps([name,a])+'\\n').encode())
if a==['--version']:
    print(name+' '+('1.1.1' if mode=='old' and name=='ideviceinstaller' else '1.2.0' if name=='ideviceinstaller' else '1.4.0'))
    sys.exit(0)
assert a[:2]==['-u','00000000-0000000000000001']
if name=='ideviceinfo':
    assert a[2:]==['--simple','--xml']
    if mode=='timeout':time.sleep(10)
    value={'UniqueDeviceID':a[1],'DeviceName':'Synthetic café 東京','ProductType':'iPhone17,2','ProductVersion':'26.0'}
    if mode=='wrong_device':value['UniqueDeviceID']='00000000-0000000000000002'
else:
    assert a[2:]==['list','--all','--xml']
    value=[{'CFBundleIdentifier':'com.example.chat','CFBundleDisplayName':'Synthetic café chat','CFBundleShortVersionString':'2.3','ApplicationType':'User'},
           {'CFBundleIdentifier':'com.apple.mobilesafari','CFBundleDisplayName':'Safari','CFBundleVersion':'123','ApplicationType':'System'}]
    if mode=='empty':value=[]
    if mode=='malformed':value={'invalid':'root'}
    if mode=='oversize':
        sys.stdout.buffer.write(b'x'*65536);sys.exit(0)
sys.stdout.buffer.write(plistlib.dumps(value))
if mode=='denied' and name=='ideviceinstaller':
    sys.stderr.buffer.write(b'synthetic inventory denied\\n');sys.exit(9)
'''


class IOSAppsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='lawliet-ios-apps-')
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.workspace = self.base / 'cases café'
        create_case(self.workspace, 'A'); create_case(self.workspace, 'B')
        self.mode = self.base / 'mode.txt'; self.mode.write_text('success', encoding='utf-8')
        for name in ('ideviceinstaller', 'ideviceinfo'):
            path = self.base / (name + '.py'); path.write_text(FIXTURE, encoding='utf-8')
            configure(self.workspace, name, path, python=sys.executable)

    def calls(self):
        return [json.loads(line) for line in (self.base / 'calls.jsonl').read_text(encoding='utf-8').splitlines()]

    def run_collection(self, mode='success', **kwargs):
        self.mode.write_text(mode, encoding='utf-8')
        foreign = digest(self.workspace / 'B/case.sqlite')
        with connect(self.workspace, 'A') as (root, db):
            result = collect_apps(root, db, self.workspace, UDID, **kwargs)
            if result['evidence_id']:
                analysis = native_analyze(root, db, result['evidence_id'])
                rows = select_artifacts(db, evidence=result['evidence_id'])
                self.assertEqual(analysis['status'], 'complete')
                for source in db.execute('SELECT * FROM files WHERE evidence_id=?', (result['evidence_id'],)):
                    self.assertEqual(digest(root / 'evidence' / result['evidence_id'] / source['path']), source['sha256'])
            else:
                rows = []
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(digest(self.workspace / 'B/case.sqlite'), foreign)
        return result, rows

    def test_collect_preserve_and_native_index_exact_inventory(self):
        result, rows = self.run_collection()
        self.assertEqual(result['status'], 'complete', result)
        self.assertEqual({r['category'] for r in rows}, {'apps', 'device'})
        self.assertEqual(len(rows), 3)
        app = next(r for r in rows if r['title'] == 'com.example.chat')
        self.assertEqual(app['body'], 'Synthetic café chat · Version 2.3 · User')
        self.assertEqual(app['source_ref'], 'plist:array[index=0]')
        self.assertEqual(app['logical_path'], 'ios-apps.plist')
        self.assertIsNone(app['timestamp']); self.assertIsNone(app['timestamp_raw'])
        folder = Path(result['path'])
        for original, published in [('apps.stdout', 'ios-apps.plist'), ('device.stdout', 'ios-device.plist')]:
            self.assertEqual((folder / original).read_bytes(), (folder / published).read_bytes())
        self.assertEqual(app['source_sha256'], digest(folder / 'apps.stdout'))
        receipt = json.loads((folder / 'collection.json').read_bytes())
        self.assertEqual(receipt['tools']['ideviceinstaller']['version'], 'ideviceinstaller 1.2.0')
        for name, tool in receipt['tools'].items():
            self.assertEqual(tool['executable_sha256'], digest(self.base / (name + '.py')))
            self.assertTrue(tool['interpreter_sha256'])
        self.assertEqual(self.calls(), [['ideviceinstaller', ['--version']], ['ideviceinfo', ['--version']],
            ['ideviceinfo', ['-u', UDID, '--simple', '--xml']],
            ['ideviceinstaller', ['-u', UDID, 'list', '--all', '--xml']]])

    def test_nonzero_output_is_retained_but_never_indexed_as_apps(self):
        result, rows = self.run_collection('denied')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual([r['category'] for r in rows], ['device'])
        self.assertEqual(result['errors'][0]['kind'], 'command_failed')
        self.assertTrue((Path(result['path']) / 'apps.stdout').is_file())
        self.assertFalse((Path(result['path']) / 'ios-apps.plist').exists())

    def test_malformed_inventory_is_partial_not_empty_success(self):
        result, rows = self.run_collection('malformed')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(rows), 1)
        self.assertEqual(result['errors'][0]['kind'], 'invalid_or_bounded_output')

    def test_empty_inventory_retains_explicit_scope_limit(self):
        result, rows = self.run_collection('empty')
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(len(rows), 1)
        self.assertEqual(result['coverage'][1]['state'], 'collected_empty')
        self.assertEqual(result['coverage'][1]['records'], 0)
        self.assertIn('does not establish device-wide absence', result['scope'])

    def test_old_cli_refused_before_any_device_query(self):
        result, rows = self.run_collection('old')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(rows, [])
        self.assertEqual([call[1] for call in self.calls()], [['--version'], ['--version']])
        self.assertEqual(result['errors'][0]['kind'], 'unsupported_version')

    def test_mismatched_device_identity_stops_before_application_query(self):
        result, rows = self.run_collection('wrong_device')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(rows, [])
        self.assertEqual(result['errors'][0]['kind'], 'device_mismatch')
        self.assertEqual(len(self.calls()), 3)
        self.assertFalse((Path(result['path']) / 'ios-device.plist').exists())

    def test_storage_threshold_refuses_oversized_inventory(self):
        result, rows = self.run_collection('oversize', max_bytes=16384)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['evidence_id'])
        self.assertEqual(rows, [])
        self.assertFalse((Path(result['path']) / 'ios-apps.plist').exists())
        self.assertTrue(any(error['kind'] == 'resource_or_output_refusal' for error in result['errors']))

    def test_timeout_is_retained_without_a_success_claim(self):
        result, rows = self.run_collection('timeout', timeout=1)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(rows, [])
        self.assertTrue(any(error['kind'] == 'timeout' for error in result['errors']))

    def test_linked_collections_parent_never_runs_a_tool(self):
        foreign = self.base / 'foreign'; foreign.mkdir()
        (self.workspace / 'A/collections').symlink_to(foreign, target_is_directory=True)
        with connect(self.workspace, 'A') as (root, db), self.assertRaises((UserError, OSError)):
            collect_apps(root, db, self.workspace, UDID)
        self.assertFalse((self.base / 'calls.jsonl').exists())
        self.assertEqual(list(foreign.iterdir()), [])

    def test_invalid_scope_refused_before_collection(self):
        with connect(self.workspace, 'A') as (root, db):
            for serial, limit in [('../foreign', 16384), (UDID, 0), (UDID, 17*1024**2)]:
                with self.subTest(serial=serial, limit=limit), self.assertRaises(UserError):
                    collect_apps(root, db, self.workspace, serial, max_bytes=limit)
            self.assertFalse((root / 'collections').exists())

    def test_invalid_property_lists_fail_without_partial_rows(self):
        path = self.base / 'ios-apps.plist'
        for raw in (b'<plist>', plistlib.dumps([{'CFBundleIdentifier': 'valid'}, {}]),
                    b'<!DOCTYPE plist [<!ENTITY x "expanded">]><plist><array><string>&x;</string></array></plist>'):
            path.write_bytes(raw)
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                inventory_records(path)


if __name__ == '__main__':
    unittest.main()
