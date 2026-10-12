"""HTML/coverage pair refusal, failure cleanup and scope regression checks."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, audit, connect, create_case, digest
from lawliet_mobile.report import write_report


class HtmlPairIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / 'cases'
        create_case(self.workspace, 'A')
        self.source = self.base / 'input.jsonl'
        self.source.write_text(''.join(json.dumps({'category': 'messages',
            'body': 'selected <script>alert(1)</script> __NAME__ ' + str(n),
            'data': {'number': n}}) + '\n' for n in range(3)))
        self.eid = handle(self.workspace, {'case': 'A', 'action': 'import',
            'path': str(self.source), 'format': 'jsonl'})['evidence_id']

    def test_preview_hashes_scope_rendering_and_return_contract(self):
        with connect(self.workspace, 'A') as (root, db):
            path = self.base / 'preview.html'
            before = digest(self.source)
            result = write_report(root, db, path, filters={'query': 'selected'}, preview_limit=1)
            self.assertEqual(set(result), {'path', 'records', 'integrity_ok', 'truncated'})
            self.assertEqual(result['records'], 1)
            self.assertTrue(result['truncated'])
            text = path.read_text()
            self.assertEqual(text.count('<article class="record"'), 1)
            self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt; __NAME__', text)
            self.assertNotIn('<script>alert(1)</script>', text)
            self.assertIn('additional rows exist', text)
            companion = Path(str(path) + '.coverage.json')
            coverage = json.loads(companion.read_text())
            self.assertTrue(coverage['export_scope']['truncated'])
            self.assertEqual(coverage['export_scope']['preview_limit'], 1)
            self.assertEqual(coverage['export_sha256'], digest(path))
            receipt = json.loads(db.execute("SELECT detail FROM audit WHERE action='report.created' ORDER BY id DESC LIMIT 1").fetchone()[0])
            self.assertEqual(receipt['filters'], {'query': 'selected'})
            self.assertEqual(receipt['sha256'], digest(path))
            self.assertEqual(receipt['coverage_sha256'], digest(companion))
            self.assertEqual(digest(self.source), before)

    def test_empty_filtered_report_keeps_explicit_evidence_context(self):
        with connect(self.workspace, 'A') as (root, db):
            path = self.base / 'empty.html'
            result = write_report(root, db, path, filters={'query': 'absent', 'evidence': self.eid})
            self.assertEqual(result['records'], 0)
            self.assertFalse(result['truncated'])
            coverage = json.loads(Path(str(path) + '.coverage.json').read_text())
            self.assertEqual({r['evidence_id'] for r in coverage['coverage_context']['observations']}, {self.eid})
            self.assertEqual(coverage['export_scope']['records'], 0)

    def test_existing_output_and_companion_are_preserved(self):
        with connect(self.workspace, 'A') as (root, db):
            for which in ('output', 'companion'):
                path = self.base / (which + '.html')
                companion = Path(str(path) + '.coverage.json')
                protected, other = (path, companion) if which == 'output' else (companion, path)
                protected.write_bytes(b'KEEP')
                with self.assertRaises(FileExistsError):
                    write_report(root, db, path)
                self.assertEqual(protected.read_bytes(), b'KEEP')
                self.assertFalse(other.exists())

    def test_output_and_companion_live_or_dangling_symlinks_refused(self):
        with connect(self.workspace, 'A') as (root, db):
            for which in ('output', 'companion'):
                for live in (True, False):
                    path = self.base / (which + str(live) + '.html')
                    companion = Path(str(path) + '.coverage.json')
                    target = self.base / (which + str(live) + '-target')
                    if live:
                        target.write_bytes(b'KEEP')
                    link = path if which == 'output' else companion
                    link.symlink_to(target)
                    with self.assertRaises(UserError):
                        write_report(root, db, path)
                    self.assertTrue(link.is_symlink())
                    if live:
                        self.assertEqual(target.read_bytes(), b'KEEP')
                    else:
                        self.assertFalse(target.exists())

    def test_source_case_metadata_and_companion_input_protected(self):
        companion_source = self.base / 'new.html.coverage.json'
        companion_source.write_text(json.dumps({'category': 'messages', 'body': 'distinct companion input', 'data': {}}) + '\n')
        handle(self.workspace, {'case': 'A', 'action': 'import', 'path': str(companion_source), 'format': 'jsonl'})
        with connect(self.workspace, 'A') as (root, db):
            original_hash = digest(self.source)
            companion_hash = digest(companion_source)
            for path in (self.source, root / 'case.sqlite', root / 'evidence' / 'new.html', self.base / 'new.html'):
                with self.assertRaises(UserError):
                    write_report(root, db, path)
            self.assertEqual(digest(self.source), original_hash)
            self.assertEqual(digest(companion_source), companion_hash)

    def test_partial_output_and_companion_write_failures_clean_owned_files(self):
        original_open = Path.open
        class PartialWriter:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def write(self, value):
                self.stream.write(value[:20])
                raise OSError('injected partial write')
        with connect(self.workspace, 'A') as (root, db):
            before = db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            for which in ('output', 'companion'):
                path = self.base / (which + '.html')
                companion = Path(str(path) + '.coverage.json')
                target = path if which == 'output' else companion
                def opening(item, *args, **kwargs):
                    stream = original_open(item, *args, **kwargs)
                    return PartialWriter(stream) if item == target and args[0] == 'x' else stream
                with patch.object(Path, 'open', opening), self.assertRaises(OSError):
                    write_report(root, db, path)
                self.assertFalse(path.exists())
                self.assertFalse(companion.exists())
                self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], before)

    def test_racing_exclusive_create_preserves_unowned_file(self):
        original_open = Path.open
        with connect(self.workspace, 'A') as (root, db):
            for which in ('output', 'companion'):
                path = self.base / (which + '.html')
                companion = Path(str(path) + '.coverage.json')
                target = path if which == 'output' else companion
                def opening(item, *args, **kwargs):
                    if item == target and args[0] == 'x':
                        with original_open(item, 'w') as stream:
                            stream.write('OTHER WRITER')
                    return original_open(item, *args, **kwargs)
                with patch.object(Path, 'open', opening), self.assertRaises(FileExistsError):
                    write_report(root, db, path)
                self.assertEqual(target.read_text(), 'OTHER WRITER')
                self.assertFalse((companion if which == 'output' else path).exists())

    def test_audit_failure_rolls_back_only_export_savepoint(self):
        def fail(db, action, detail):
            audit(db, action, detail)
            raise RuntimeError('injected audit failure')
        with connect(self.workspace, 'A') as (root, db):
            audit(db, 'test.pending', {'retain': True})
            before = db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            path = self.base / 'audit.html'
            with patch('lawliet_mobile.report.audit', side_effect=fail), self.assertRaises(RuntimeError):
                write_report(root, db, path)
            self.assertFalse(path.exists())
            self.assertFalse(Path(str(path) + '.coverage.json').exists())
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], before)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='test.pending'").fetchone()[0], 1)

    def test_companion_hash_failure_cleans_pair(self):
        original_digest = digest
        def fail(path):
            if str(path).endswith('.html.coverage.json'):
                raise OSError('injected hash failure')
            return original_digest(path)
        with connect(self.workspace, 'A') as (root, db):
            path = self.base / 'hash.html'
            with patch('lawliet_mobile.core.digest', side_effect=fail), self.assertRaises(OSError):
                write_report(root, db, path)
            self.assertFalse(path.exists())
            self.assertFalse(Path(str(path) + '.coverage.json').exists())

    def test_malformed_scope_and_preview_rejected_before_output_or_audit(self):
        with connect(self.workspace, 'A') as (root, db):
            before = db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            for filters in (False, [], '', 0):
                with self.assertRaises(UserError):
                    write_report(root, db, self.base / 'not-created' / 'scope.html', filters=filters)
            for limit in (True, False, 1.0, '1', 0, -1, 10001):
                with self.assertRaises(UserError):
                    write_report(root, db, self.base / 'not-created' / 'limit.html', preview_limit=limit)
            self.assertFalse((self.base / 'not-created').exists())
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], before)

    def test_scoped_cards_and_warnings_exclude_unrelated_case_counts(self):
        other = self.base / 'UNRELATED_CANARY.jsonl'
        other.write_text(json.dumps({'category': 'messages', 'body': 'UNRELATED_CANARY', 'data': {}}) + '\n')
        other_eid = handle(self.workspace, {'case': 'A', 'action': 'import', 'path': str(other), 'format': 'jsonl'})['evidence_id']
        with connect(self.workspace, 'A') as (root, db):
            db.execute("INSERT INTO runs(id,evidence_id,engine,started_at,status,detail) VALUES(?,?,?,'2026-01-01','failed',?)",
                ('unrelated-run', other_eid, 'UNRELATED_CANARY', 'UNRELATED_CANARY'))
            folder = root / 'collections' / 'unrelated'
            folder.mkdir(parents=True)
            (folder / 'collection.json').write_text(json.dumps({'status': 'failed', 'profile': 'UNRELATED_CANARY',
                'coverage': [{'source': 'UNRELATED_CANARY', 'state': 'access_denied'}]}))
            for name, filters, limit, expected_sources in (
                ('selected', {'evidence': self.eid}, None, 1),
                ('preview', {}, 1, 1),
                ('empty', {'evidence': self.eid, 'query': 'missing'}, None, 0)):
                path = self.base / (name + '.html')
                write_report(root, db, path, filters=filters, preview_limit=limit)
                text = path.read_text()
                self.assertIn('<strong>' + str(expected_sources) + '</strong><span>Evidence sources</span>', text)
                self.assertNotIn('<span>Files verified</span>', text)
                self.assertNotIn('<span>Analysis runs</span>', text)
                self.assertNotIn('Case includes incomplete acquisition attempts:', text)
                if name != 'preview':
                    self.assertNotIn('UNRELATED_CANARY', text)
            full = self.base / 'full.html'
            write_report(root, db, full)
            text = full.read_text()
            self.assertIn('<strong>2</strong><span>Evidence sources</span>', text)
            self.assertIn('<span>Files verified</span>', text)
            self.assertIn('<span>Analysis runs</span>', text)
            self.assertIn('Case includes incomplete acquisition attempts:', text)
