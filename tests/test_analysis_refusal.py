"""Real refused input and failed plugin execution remain durable and distinguishable."""
import json
import plistlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.core import UserError, connect, create_case, digest, import_evidence, verify, iter_artifacts
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.tools import configure, external_analyze
from lawliet_mobile.coverage_ledger import ledger_page
from lawliet_mobile.report import write_jsonl_export


class AnalysisRefusalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'A')
        self.encrypted = self.base / 'encrypted'
        self.encrypted.mkdir()
        (self.encrypted / 'Manifest.plist').write_bytes(plistlib.dumps({'IsEncrypted': True}))
        (self.encrypted / 'payload').write_bytes(b'synthetic encrypted-declared inaccessible bytes')

    def assert_refusal(self, root, db, eid):
        run = db.execute('SELECT * FROM runs ORDER BY rowid DESC LIMIT 1').fetchone()
        detail = json.loads(run['detail'])
        self.assertEqual(run['status'], 'failed')
        self.assertIs(detail['execution_started'], False)
        self.assertEqual(detail['preflight_refusal'], 'encrypted_input_requires_decryption')
        self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0], 0)
        entries = ledger_page(root, db)['entries']
        self.assertTrue(any(e.get('reason_code') == detail['preflight_refusal'] for e in entries))
        self.assertFalse(any(e['state'] in {'parsed', 'searched-with-no-finding'} for e in entries))
        out = self.base / (run['id'] + '.jsonl')
        if not out.exists():
            write_jsonl_export(root, db, out, iter(()), {'evidence': eid, 'run': run['id']})
        metadata = json.loads(Path(str(out) + '.coverage.json').read_text())
        observations = metadata['coverage_context']['observations']
        self.assertTrue(any(e.get('reason_code') == detail['preflight_refusal']
                            and e.get('execution_started') is False for e in observations))
        self.assertEqual(metadata['export_scope']['records'], 0)
        self.assertTrue(verify(root, db)['ok'])
        return run['id']

    def test_native_encrypted_refusal_survives_reopen_and_export(self):
        originals = {p.name: digest(p) for p in self.encrypted.iterdir()}
        with connect(self.workspace, 'A') as (root, db):
            eid = import_evidence(root, db, self.encrypted, 'ios')[0]
            with self.assertRaisesRegex(UserError, 'Encrypted'):
                native_analyze(root, db, eid)
            run_id = self.assert_refusal(root, db, eid)
        with connect(self.workspace, 'A') as (root, db):
            self.assertEqual(self.assert_refusal(root, db, eid), run_id)
        self.assertEqual(originals, {p.name: digest(p) for p in self.encrypted.iterdir()})

    def test_external_refusal_never_resolves_or_launches_tool(self):
        with connect(self.workspace, 'A') as (root, db):
            eid = import_evidence(root, db, self.encrypted, 'ios')[0]
            with patch('lawliet_mobile.tools.command', side_effect=AssertionError('Tool resolved')):
                with self.assertRaisesRegex(UserError, 'decrypted extraction'):
                    external_analyze(root, db, self.workspace, eid, 'ileapp')
            self.assert_refusal(root, db, eid)

    def test_actual_plugin_exit_preserves_log_and_healthy_records(self):
        source = self.base / 'mmssms.db'
        with closing(sqlite3.connect(source)) as fixture:
            fixture.executescript('CREATE TABLE sms(_id,thread_id,address,date,type,body);'
                                 "INSERT INTO sms VALUES(1,1,'+15550100',1700000000000,1,'healthy');")
            fixture.commit()
        before = digest(source)
        plugin = self.base / 'plugin.py'
        plugin.write_text("import sys\nprint('PARTIAL OUTPUT RETAINED')\n"
                          "sys.stderr.write('CONTROLLED PLUGIN FAILURE\\n')\nsys.exit(17)\n")
        configure(self.workspace, 'exiftool', plugin)
        with connect(self.workspace, 'A') as (root, db):
            eid = import_evidence(root, db, source, 'android')[0]
            native_analyze(root, db, eid)
            with self.assertRaisesRegex(UserError, 'ExifTool exited 17'):
                external_analyze(root, db, self.workspace, eid, 'exiftool')
            run = db.execute("SELECT * FROM runs WHERE engine='exiftool'").fetchone()
            self.assertEqual(run['status'], 'failed')
            self.assertEqual(json.loads(run['detail'])['returncode'], 17)
            logs = root / 'runs' / run['id']
            self.assertIn('CONTROLLED PLUGIN FAILURE', (logs / 'metadata.json.stderr').read_text())
            self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0], 1)
            entries = ledger_page(root, db)['entries']
            self.assertTrue(any(e['state'] == 'parser-failed' for e in entries))
            out = self.base / 'plugin-failure.jsonl'
            write_jsonl_export(root, db, out, iter_artifacts(db, evidence=eid, limit=None), {'evidence': eid})
            metadata = json.loads(Path(str(out) + '.coverage.json').read_text())
            self.assertTrue(any(e['reason_code'] == 'processing_error'
                                for e in metadata['coverage_context']['observations']))
            self.assertTrue(verify(root, db)['ok'])
        self.assertEqual(digest(source), before)
