import hashlib
import json
import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile import evidence_viewer as viewer
from lawliet_mobile.core import UserError, connect, create_case, import_evidence


class EvidenceViewerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.workspace = self.base/'cases'
        create_case(self.workspace, 'one'); create_case(self.workspace, 'two')
        self.counter = 0

    def imported(self, root, db, payload):
        self.counter += 1
        source = self.base/f'input-{self.counter}'
        source.write_bytes(payload)
        eid = import_evidence(root, db, source)[0]
        return db.execute('SELECT id FROM files WHERE evidence_id=?', (eid,)).fetchone()[0]

    def test_exact_offsets_invalid_utf8_and_window_split_codepoint(self):
        raw = b'A\xff\x00'+ '😀'.encode()+b'\r\nEND'
        with connect(self.workspace, 'one') as (root, db):
            fid = self.imported(root, db, raw)
            result = viewer.inspect_file(root, db, fid, offset=1, length=5)
            self.assertEqual(bytes.fromhex(result['hex']), raw[1:6])
            self.assertEqual((result['offset'], result['end_offset_exclusive']), (1, 6))
            self.assertEqual(result['window_sha256'], hashlib.sha256(raw[1:6]).hexdigest())
            self.assertEqual(result['text']['errors'][0]['start_offset'], 1)
            self.assertEqual(result['text']['error_count'], 2)
            self.assertTrue(result['original_unchanged'])
            chunks = [bytes.fromhex(viewer.inspect_file(root, db, fid, offset=i, length=3)['hex']) for i in range(0, len(raw), 3)]
            self.assertEqual(b''.join(chunks), raw)
            self.assertEqual(viewer.inspect_file(root, db, fid, offset=100)['hex'], '')

    def test_utf16_boundaries_and_latin1_are_explicit(self):
        raw = b'\xff\xfeA\x00\x00'
        with connect(self.workspace, 'one') as (root, db):
            fid = self.imported(root, db, raw)
            result = viewer.inspect_file(root, db, fid, encoding='utf-16-le')
            self.assertTrue(result['text']['text'].startswith('\ufeffA'))
            self.assertEqual(result['text']['errors'][0]['start_offset'], 4)
            self.assertFalse(result['text']['byte_order_mark_removed'])
            self.assertEqual(viewer.inspect_file(root, db, fid, encoding='latin-1')['text']['error_count'], 0)

    def test_json_duplicate_keys_numeric_lexemes_and_escaped_null(self):
        raw = b'{"a":1,"a":900719925474099312345,"small":1.200e-09,"nul":"\\u0000"}'
        with connect(self.workspace, 'one') as (root, db):
            fid = self.imported(root, db, raw)
            parsed = viewer.inspect_file(root, db, fid, format_name='json')['structured']
            self.assertEqual(parsed['state'], 'parsed'); tree = parsed['tree']
            self.assertEqual(tree['duplicate_keys'], ['a'])
            self.assertEqual([x[0] for x in tree['pairs']], ['a', 'a', 'small', 'nul'])
            self.assertEqual(tree['pairs'][1][1]['lexeme'], '900719925474099312345')
            self.assertEqual(tree['pairs'][2][1]['lexeme'], '1.200e-09')
            self.assertFalse(parsed['source_offsets'])

    def test_xml_refuses_dtd_entities_processing_instructions_and_old_expat(self):
        with connect(self.workspace, 'one') as (root, db):
            for payload in [b'<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>',
                            b'<!DOCTYPE r SYSTEM "http://127.0.0.1:1/dtd"><r/>', b'<?include x?><r/>']:
                fid = self.imported(root, db, payload)
                result = viewer.inspect_file(root, db, fid, format_name='xml')
                self.assertEqual(result['structured']['state'], 'unsupported-or-invalid')
                self.assertEqual(result['hex'], payload.hex())
            with patch.object(viewer.expat, 'EXPAT_VERSION', 'expat_2.6.0'), self.assertRaises(ValueError):
                viewer._xml(b'<r/>')
            fid = self.imported(root, db, b'<r b="2" a="1">text<!--c--><x/></r>')
            tree = viewer.inspect_file(root, db, fid, format_name='xml')['structured']['tree']
            self.assertEqual(tree['attributes'], [['b', '2'], ['a', '1']])
            self.assertEqual(tree['children'][0], {'kind': 'text', 'value': 'text'})

    def test_binary_xml_plist_typed_bytes_and_duplicate_dictionary_refusal(self):
        with connect(self.workspace, 'one') as (root, db):
            for fmt in [plistlib.FMT_XML, plistlib.FMT_BINARY]:
                fid = self.imported(root, db, plistlib.dumps({'blob': b'\x00\xff', 'number': 42}, fmt=fmt))
                result = viewer.inspect_file(root, db, fid, format_name='plist')['structured']
                self.assertEqual(result['state'], 'parsed', result)
                self.assertEqual(dict(result['tree']['pairs'])['blob']['base64'], 'AP8=')
            duplicate = b'<plist version="1.0"><dict><key>x</key><string>one</string><key>x</key><string>two</string></dict></plist>'
            fid = self.imported(root, db, duplicate)
            result = viewer.inspect_file(root, db, fid, format_name='plist')['structured']
            self.assertEqual(result['state'], 'unsupported-or-invalid'); self.assertIn('Duplicate', result['error'])

    def test_limits_invalid_input_and_worker_timeout_keep_raw_window(self):
        with connect(self.workspace, 'one') as (root, db):
            for raw in [b'['*600+b'0'+b']'*600, b'\xffinvalid-json', b'{"n":NaN}']:
                fid = self.imported(root, db, raw)
                result = viewer.inspect_file(root, db, fid, format_name='json')
                self.assertNotEqual(result['structured']['state'], 'parsed')
                self.assertEqual(result['hex'], raw.hex())
            fid = self.imported(root, db, b' '* (viewer.MAX_STRUCTURED+1))
            with patch.object(viewer.subprocess, 'run') as child:
                result = viewer.inspect_file(root, db, fid, format_name='json')
                child.assert_not_called(); self.assertEqual(result['structured']['state'], 'resource-limited')
            fid = self.imported(root, db, b'{}')
            with patch.object(viewer.subprocess, 'run', side_effect=subprocess.TimeoutExpired('test', 5)):
                result = viewer.inspect_file(root, db, fid, format_name='json')
                self.assertEqual(result['structured']['state'], 'resource-limited'); self.assertEqual(result['hex'], '7b7d')
            for kwargs in [{'length': 65537}, {'offset': True}, {'format_name': 'unknown-binary'}, {'encoding': 'guess'}]:
                with self.assertRaises(UserError): viewer.inspect_file(root, db, fid, **kwargs)

    def test_integrity_symlink_and_foreign_file_are_refused(self):
        with connect(self.workspace, 'one') as (root, db):
            fid = self.imported(root, db, b'original')
            row = db.execute('SELECT * FROM files WHERE id=?', (fid,)).fetchone()
            path = root/'evidence'/row['evidence_id']/row['path']
            path.chmod(0o600); path.write_bytes(b'changed!')
            with self.assertRaisesRegex(UserError, 'integrity'): viewer.inspect_file(root, db, fid)
            path.unlink(); path.symlink_to(self.base/'input-1')
            with self.assertRaisesRegex(UserError, 'Unsafe'): viewer.inspect_file(root, db, fid)
        with connect(self.workspace, 'two') as (root, db):
            with self.assertRaises(UserError): viewer.inspect_file(root, db, fid)

    def test_actual_stdio_bridge_exact_window_and_scoping(self):
        with connect(self.workspace, 'one') as (root, db):
            fid = self.imported(root, db, b'{"x":1,"x":2}\xff')
        def call(case='one', **values):
            proc = subprocess.run([sys.executable, '-m', 'lawliet_mobile.app_backend'],
                input=json.dumps({'workspace': str(self.workspace), 'case': case,
                                  'action': 'evidence-inspect', 'file_id': fid, **values}),
                text=True, capture_output=True, check=False)
            result = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0 if result['ok'] else 1)
            return result
        result = call(offset=1, length=4, format='json')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['result']['hex'], b'"x":'.hex())
        self.assertEqual(result['result']['offset'], 1)
        self.assertEqual(result['result']['structured']['state'], 'unsupported-or-invalid')
        self.assertFalse(call(case='two')['ok'])
        self.assertFalse(call(length=65537)['ok'])
