"""Failure injection for paired JSON/CSV exports; original inputs stay untouched."""
import csv
import json
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.core import UserError, audit, connect, create_case, digest
from lawliet_mobile.report import write_export


class ExportPairIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        create_case(self.base / 'cases', 'A')

    def test_both_formats_have_hash_bound_pair_and_audit(self):
        with connect(self.base / 'cases', 'A') as (root, db):
            for fmt in ('json', 'csv'):
                path = self.base / ('output.' + fmt)
                result = write_export(root, db, path, fmt, [{'body': 'évidence'}])
                self.assertEqual(result, str(path.resolve()))
                companion = Path(result + '.coverage.json')
                self.assertEqual(json.loads(companion.read_text())['export_sha256'], digest(path))
                receipt = json.loads(db.execute("SELECT detail FROM audit WHERE action='export.created' ORDER BY id DESC LIMIT 1").fetchone()[0])
                self.assertEqual(receipt['sha256'], digest(path))
                self.assertEqual(receipt['coverage_sha256'], digest(companion))

    def test_existing_output_or_companion_never_overwritten(self):
        with connect(self.base / 'cases', 'A') as (root, db):
            for fmt in ('json', 'csv'):
                for existing in ('output', 'companion'):
                    path = self.base / (fmt + existing)
                    companion = Path(str(path) + '.coverage.json')
                    protected = path if existing == 'output' else companion
                    protected.write_bytes(b'KEEP')
                    with self.assertRaises(FileExistsError):
                        write_export(root, db, path, fmt, [])
                    self.assertEqual(protected.read_bytes(), b'KEEP')
                    self.assertFalse((companion if existing == 'output' else path).exists())

    def test_live_and_dangling_symlinks_refused_for_both_paths(self):
        with connect(self.base / 'cases', 'A') as (root, db):
            for fmt in ('json', 'csv'):
                for which in ('output', 'companion'):
                    for live in (True, False):
                        name = fmt + which + str(live)
                        path = self.base / name
                        companion = Path(str(path) + '.coverage.json')
                        target = self.base / (name + '-target')
                        if live:
                            target.write_bytes(b'KEEP')
                        link = path if which == 'output' else companion
                        link.symlink_to(target)
                        with self.assertRaises(UserError):
                            write_export(root, db, path, fmt, [])
                        self.assertTrue(link.is_symlink())
                        self.assertEqual(target.read_bytes() if live else target.exists(), b'KEEP' if live else False)

    def test_case_evidence_and_original_input_protected(self):
        from lawliet_mobile.app_backend import handle
        source = self.base / 'input.jsonl'
        source.write_text('{"category":"messages","body":"original","data":{}}\n')
        handle(self.base / 'cases', {'case': 'A', 'action': 'import', 'path': str(source), 'format': 'jsonl'})
        with connect(self.base / 'cases', 'A') as (root, db):
            before = digest(source)
            for fmt in ('json', 'csv'):
                for target in (source, root / 'case.sqlite', root / 'evidence' / 'new-output'):
                    with self.assertRaises(UserError):
                        write_export(root, db, target, fmt, [])
            self.assertEqual(digest(source), before)

    def test_audit_insert_then_failure_rolls_back_and_removes_pair(self):
        def fail(db, action, detail):
            audit(db, action, detail)
            raise RuntimeError('injected audit failure')
        with connect(self.base / 'cases', 'A') as (root, db):
            before = db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            for fmt in ('json', 'csv'):
                path = self.base / fmt
                with patch('lawliet_mobile.report.audit', side_effect=fail), self.assertRaises(RuntimeError):
                    write_export(root, db, path, fmt, [])
                self.assertFalse(path.exists())
                self.assertFalse(Path(str(path) + '.coverage.json').exists())
                self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], before)

    def test_partial_companion_write_failure_removes_pair(self):
        original = Path.open
        class FailingWriter:
            def __init__(self, handle): self.handle = handle
            def __enter__(self): return self
            def __exit__(self, *args): self.handle.close()
            def write(self, data):
                self.handle.write(data[:10])
                raise OSError('injected partial write')
        def opening(path, *args, **kwargs):
            handle = original(path, *args, **kwargs)
            return FailingWriter(handle) if str(path).endswith('.coverage.json') and args[0] == 'x' else handle
        with connect(self.base / 'cases', 'A') as (root, db):
            for fmt in ('json', 'csv'):
                path = self.base / fmt
                with patch.object(Path, 'open', opening), self.assertRaises(OSError):
                    write_export(root, db, path, fmt, [])
                self.assertFalse(path.exists())
                self.assertFalse(Path(str(path) + '.coverage.json').exists())

    def test_serialization_failure_removes_output(self):
        with connect(self.base / 'cases', 'A') as (root, db):
            path = self.base / 'bad.json'
            with self.assertRaises(TypeError):
                write_export(root, db, path, 'json', [{'body': object()}])
            self.assertFalse(path.exists())

    def test_csv_formula_prefixes_stay_escaped_and_unicode_preserved(self):
        values = ['=1+1', '+cmd', '-1', '@SUM(A1)', '\tformula', '\rformula', 'évidence', None]
        with connect(self.base / 'cases', 'A') as (root, db):
            path = self.base / 'safe.csv'
            write_export(root, db, path, 'csv', [{'body': value} for value in values])
            with path.open(newline='') as stream:
                actual = [row['body'] for row in csv.DictReader(stream)]
            self.assertEqual(actual, ["'" + value for value in values[:6]] + ['évidence', ''])

    def test_actual_cli_limited_exports_have_unknown_window_extent(self):
        from lawliet_mobile.app_backend import handle
        source = self.base / 'window-input.jsonl'
        source.write_text(''.join(json.dumps({'category': 'messages', 'body': 'row ' + str(n), 'data': {}}) + '\n' for n in range(3)))
        handle(self.base / 'cases', {'case': 'A', 'action': 'import', 'path': str(source), 'format': 'jsonl'})
        for fmt in ('json', 'csv'):
            path = self.base / ('limited.' + fmt)
            proc = subprocess.run([sys.executable, '-m', 'lawliet_mobile', '--workspace', str(self.base / 'cases'),
                '--json', 'timeline', '--case', 'A', '--limit', '1', '--format', fmt, '--out', str(path)],
                text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(json.loads(proc.stdout)['records'], 1)
            if fmt == 'json':
                self.assertEqual(len(json.loads(path.read_text())), 1)
            else:
                with path.open(newline='') as stream:
                    self.assertEqual(len(list(csv.DictReader(stream))), 1)
            companion = json.loads(Path(str(path) + '.coverage.json').read_text())
            scope = companion['export_scope']
            self.assertEqual(scope['selection'], 'provided-record-window')
            self.assertEqual(scope['extent'], 'unknown')
            self.assertIsNone(scope['truncated'])
            self.assertFalse(scope['empty_result'])
            self.assertEqual(companion['export_sha256'], digest(path))

    def test_empty_lists_do_not_claim_complete_scope(self):
        with connect(self.base / 'cases', 'A') as (root, db):
            for fmt in ('json', 'csv'):
                path = self.base / ('empty.' + fmt)
                write_export(root, db, path, fmt, [])
                scope = json.loads(Path(str(path) + '.coverage.json').read_text())['export_scope']
                self.assertTrue(scope['empty_result'])
                self.assertIsNone(scope['truncated'])
                self.assertEqual(scope['extent'], 'unknown')
                self.assertEqual(scope['selection'], 'provided-record-window')
