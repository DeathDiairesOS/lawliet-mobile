"""Read-only retained query view controls; synthetic CaseDB and files, no Docker."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import unittest
import tempfile
from unittest.mock import patch
from lawliet_mobile import core, sqlite_workspace as sw
from lawliet_mobile.child_output import ChildOutputs


class ResultView(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.ws = self.base / 'cases'
        core.create_case(self.ws, 'A'); core.create_case(self.ws, 'B')
        source = self.base / 'source.sqlite'; db = sqlite3.connect(source)
        db.execute('CREATE TABLE typed(n INTEGER,txt TEXT,payload BLOB,r REAL)')
        db.executemany('INSERT INTO typed VALUES(?,?,?,?)', [(i, 'café <tag> 🐈 ' + str(i), b'\x00\xff', float('inf') if i == 0 else 1.25) for i in range(5)])
        db.commit(); db.close()
        self.connection = core.connect(self.ws, 'A'); self.root, self.db = self.connection.__enter__()
        self.addCleanup(self.connection.__exit__, None, None, None)
        core.import_evidence(self.root, self.db, source, 'android')
        self.fid = self.db.execute('SELECT id FROM files').fetchone()[0]
        result = sw.query(self.root, self.db, self.fid, 'SELECT n AS same,txt AS same,payload,NULL,r FROM typed ORDER BY n')
        self.rid = result['run_id']; self.folder = self.root / 'runs' / self.rid
        self.original = (self.folder / 'result.jsonl').read_bytes()
        self.original_detail = json.loads(self.db.execute('SELECT detail FROM runs WHERE id=?', (self.rid,)).fetchone()[0])

    def view(self, **kwargs): return sw.read_result(self.root, self.db, self.rid, **kwargs)

    def resign(self, raw, *, changes=None, request_raw=None):
        """Construct a fully audited synthetic producer output for shape controls."""
        detail = copy.deepcopy(self.original_detail)
        (self.folder / 'result.jsonl').write_bytes(raw)
        detail['result_sha256'] = hashlib.sha256(raw).hexdigest()
        if changes: detail.update(changes)
        if request_raw is not None: (self.folder / 'query.json').write_bytes(request_raw)
        receipt = core.json_text(detail).encode(); (self.folder / 'receipt.json').write_bytes(receipt)
        events = [(event['action'], json.loads(event['detail'])) for event in self.db.execute('SELECT * FROM audit ORDER BY id')]
        self.db.execute('DELETE FROM audit')
        for action, value in events:
            if action == 'sqlite_query.started' and value.get('run_id') == self.rid:
                value['query_sha256'] = hashlib.sha256((self.folder / 'query.json').read_bytes()).hexdigest()
            if action == 'sqlite_query.finished' and value.get('run_id') == self.rid:
                value.update(receipt_sha256=hashlib.sha256(receipt).hexdigest(), result_sha256=detail['result_sha256'])
            core.audit(self.db, action, value)
        self.db.execute('UPDATE runs SET records=?,detail=? WHERE id=?', (detail['rows_returned'], core.json_text(detail), self.rid)); self.db.commit()

    def test_paging_typed_values_duplicate_columns_and_identity(self):
        first = self.view(limit=2); middle = self.view(offset=2, limit=2); last = self.view(offset=4, limit=2)
        self.assertEqual(first['columns'][:2], ['same', 'same'])
        self.assertIsNone(first['rows'][0][3]); self.assertEqual(first['rows'][0][2], {'sqlite_blob_hex': '00ff'})
        self.assertEqual(first['rows'][0][4], {'sqlite_nonfinite_float': 'inf'})
        self.assertIn('🐈', first['rows'][0][1]); self.assertEqual(middle['rows'][0][0], 2)
        self.assertTrue(first['has_more']); self.assertTrue(middle['has_more']); self.assertFalse(last['has_more'])
        self.assertEqual(last['rows'][0][0], 4); self.assertEqual(self.view(offset=999)['rows'], [])
        self.assertEqual(first['run_id'], self.rid); self.assertEqual(first['total_rows'], 5)
        self.assertEqual(first['result_sha256'], hashlib.sha256(self.original).hexdigest())
        self.assertIn('query output only', first['integrity_scope'])

    def test_reader_does_not_open_sqlite_or_execute_query(self):
        with patch.object(sw.sqlite3, 'connect', side_effect=AssertionError('No SQLite engine in retained-file reader')):
            self.assertEqual(self.view()['total_rows'], 5)

    def test_cross_case_and_strict_cursor_refuse(self):
        with core.connect(self.ws, 'B') as (root, db):
            with self.assertRaises(core.UserError): sw.read_result(root, db, self.rid)
        for value in (True, -1, 1.5, '1'):
            with self.subTest(value=value), self.assertRaises(core.UserError): self.view(offset=value)
        for value in (False, 0, 1001, '1'):
            with self.subTest(value=value), self.assertRaises(core.UserError): self.view(limit=value)

    def test_hash_tamper_all_three_files_refuses(self):
        for name in ('receipt.json', 'query.json', 'result.jsonl'):
            path = self.folder / name; original = path.read_bytes(); path.write_bytes(original + b' ')
            try:
                with self.subTest(name=name), self.assertRaises(core.UserError): self.view()
            finally: path.write_bytes(original)

    def test_links_and_fifo_refuse_for_all_control_and_result_files(self):
        for name in ('receipt.json', 'query.json', 'result.jsonl'):
            path = self.folder / name; held = self.base / ('held-' + name); path.rename(held)
            for kind in ('symlink', 'hardlink', 'fifo'):
                if kind == 'symlink': path.symlink_to(held)
                elif kind == 'hardlink': os.link(held, path)
                else: os.mkfifo(path)
                try:
                    with self.subTest(name=name, kind=kind), self.assertRaises(core.UserError): self.view()
                finally: path.unlink()
            held.rename(path)

    def test_actual_sparse_view_limits_refuse_before_hash_or_parse(self):
        bounds = {'receipt.json': sw.MAX_RESULT_VIEW_RECEIPT_BYTES, 'query.json': sw.MAX_RESULT_VIEW_QUERY_BYTES, 'result.jsonl': sw.MAX_OUTPUT_BYTES}
        for name, maximum in bounds.items():
            path = self.folder / name; original = path.read_bytes()
            with path.open('wb') as stream: stream.truncate(maximum + 1)
            try:
                with self.subTest(name=name), self.assertRaises(core.UserError): self.view()
            finally: path.write_bytes(original)

    def test_parent_replacement_between_reads_refuses(self):
        foreign = self.base / 'foreign'; shutil.copytree(self.folder, foreign)
        before = {p.name: p.read_bytes() for p in foreign.iterdir() if p.is_file()}
        original_read = ChildOutputs.read; swapped = False
        def read(outputs, name, *args, **kwargs):
            nonlocal swapped
            data = original_read(outputs, name, *args, **kwargs)
            if name == 'receipt.json' and not swapped:
                self.folder.rename(self.folder.with_name('HELD')); self.folder.symlink_to(foreign, target_is_directory=True); swapped = True
            return data
        with patch.object(ChildOutputs, 'read', read), self.assertRaises(core.UserError): self.view()
        self.assertEqual({p.name: p.read_bytes() for p in foreign.iterdir() if p.is_file()}, before)

    def test_leaf_replacement_during_read_refuses(self):
        real_fdopen = os.fdopen; path = self.folder / 'result.jsonl'; swapped = False
        target_inode = path.stat().st_ino
        class Reader:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): self.stream.__enter__(); return self
            def __exit__(self, *args): return self.stream.__exit__(*args)
            def read(self, count):
                nonlocal swapped
                data = self.stream.read(count)
                if not swapped:
                    fresh = path.with_name('replacement'); fresh.write_bytes(b'[999]\n'); fresh.replace(path); swapped = True
                return data
        def fdopen(fd, *args, **kwargs):
            stream = real_fdopen(fd, *args, **kwargs)
            return Reader(stream) if os.fstat(fd).st_ino == target_inode else stream
        with patch.object(os, 'fdopen', side_effect=fdopen), self.assertRaises(core.UserError): self.view()
        self.assertTrue(swapped)

    def test_result_replacement_after_hash_returns_verified_snapshot_only(self):
        original_sha = hashlib.sha256; path = self.folder / 'result.jsonl'; swapped = False
        def sha(data=b'', *args, **kwargs):
            nonlocal swapped
            result = original_sha(data, *args, **kwargs)
            if data == self.original and not swapped:
                fresh = path.with_name('replacement'); fresh.write_bytes(b'[999,"FOREIGN",null,null,0]\n'); fresh.replace(path); swapped = True
            return result
        with patch.object(sw.hashlib, 'sha256', side_effect=sha): result = self.view(limit=1)
        self.assertTrue(swapped); self.assertEqual(result['rows'][0][0], 0)
        self.assertNotIn('FOREIGN', str(result['rows'])); self.assertEqual(result['result_sha256'], original_sha(self.original).hexdigest())

    def test_parent_replacement_after_hash_refuses_before_return(self):
        original_sha = hashlib.sha256; foreign = self.base / 'foreign'; shutil.copytree(self.folder, foreign); swapped = False
        def sha(data=b'', *args, **kwargs):
            nonlocal swapped
            result = original_sha(data, *args, **kwargs)
            if data == self.original and not swapped:
                self.folder.rename(self.folder.with_name('HELD')); self.folder.symlink_to(foreign, target_is_directory=True); swapped = True
            return result
        with patch.object(sw.hashlib, 'sha256', side_effect=sha), self.assertRaises(core.UserError): self.view()
        self.assertTrue(swapped)

    def test_entire_stream_validated_even_when_bad_row_is_off_page(self):
        lines = self.original.splitlines(keepends=True); lines[-1] = b'[999]\n'; self.resign(b''.join(lines))
        with self.assertRaises(core.UserError): self.view(limit=1)

    def test_strict_json_rows_and_typed_cell_shapes_refuse(self):
        bad_rows = [b'null\n', b'{"x":1}\n', b'[true,1,2,3,4]\n', b'[NaN,1,2,3,4]\n', b'[1e999,1,2,3,4]\n', b'[0,"text",{"sqlite_blob_hex":"a"},null,0]\n', b'[0,"text",{"sqlite_blob_hex":"00","sqlite_blob_hex":"ff"},null,0]\n', b'[0,"text",{"sqlite_nonfinite_float":"Infinity"},null,0]\n', b'[0,"text",[],null,0]\n', b'[0,"text",null,null,0', b'\xff\n']
        for row in bad_rows:
            self.resign(row, changes={'rows_returned': 1})
            with self.subTest(row=row), self.assertRaises(core.UserError): self.view()

    def test_count_state_and_metadata_types_refuse_even_with_matching_hashes(self):
        for changes in ({'rows_returned': 4}, {'rows_returned': True}, {'state': 'empty'}, {'columns': ['only one']}, {'columns': [True] * 5}, {'truncated': 1}):
            self.resign(self.original, changes=changes)
            with self.subTest(changes=changes), self.assertRaises(core.UserError): self.view()

    def test_strict_receipt_query_and_run_metadata(self):
        path = self.folder / 'query.json'; original = path.read_bytes()
        # The query hash can be valid and still contain ambiguous decoded JSON.
        self.resign(self.original, request_raw=b'{"query":"one","query":"two"}')
        with self.assertRaises(core.UserError): self.view()
        # Restore fully coherent request then tamper only mutable row detail.
        detail = json.loads(self.db.execute('SELECT detail FROM runs').fetchone()[0]); detail['query_sha256'] = hashlib.sha256(original).hexdigest()
        self.resign(self.original, changes=detail, request_raw=original)
        self.db.execute('UPDATE runs SET detail=?', ('{}',))
        with self.assertRaises(core.UserError): self.view()

    def test_unique_start_end_and_audit_chain_preserved(self):
        end = json.loads(self.db.execute("SELECT detail FROM audit WHERE action='sqlite_query.finished'").fetchone()[0])
        core.audit(self.db, 'sqlite_query.finished', end); self.db.commit()
        with self.assertRaises(core.UserError): self.view()
        self.db.execute("UPDATE audit SET detail='{}' WHERE action='sqlite_query.started'")
        with self.assertRaisesRegex(core.UserError, 'audit'): self.view()


if __name__ == '__main__': unittest.main()
