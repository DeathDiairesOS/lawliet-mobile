"""Expected logical files compare audited declarations with inventory, not devices."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, audit, connect, create_case, digest
from lawliet_mobile.coverage_ledger import build_ledger, record_observation, portable_summary
from lawliet_mobile.portable_coverage import checked_scope
from lawliet_mobile.report import write_jsonl_export, write_report


class ExpectedSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve(); self.ws = self.base / 'cases'
        create_case(self.ws, 'A')
        self.eids = []
        for name in ('selected', 'other'):
            source = self.base / (name + '.jsonl')
            source.write_text(json.dumps({'category': 'messages', 'body': name, 'data': {}}) + '\n')
            self.eids.append(handle(self.ws, {'case': 'A', 'action': 'import', 'path': str(source), 'format': 'jsonl'})['evidence_id'])

    def request(self, source='expected/短信.db', **overrides):
        return dict({'state': 'requested', 'source': source, 'category': 'messages',
            'tool_version': 'ileapp/declared-version', 'actor': 'examiner', 'reason': 'expected from scoped intake',
            'evidence_id': self.eids[0], 'expectation_kind': 'retained-logical-file-v1'}, **overrides)

    def gaps(self, root, db):
        return [row for row in build_ledger(root, db)['entries'] if row.get('module_role') == 'expected']

    def inventory(self, db, eid, logical, path):
        db.execute('INSERT INTO files(evidence_id,path,logical_path,sha256,size) VALUES(?,?,?,?,?)',
            (eid, path, logical, '0' * 64, 0))

    def test_missing_is_separate_derived_gap_and_request_unchanged(self):
        with connect(self.ws, 'A') as (root, db):
            original = record_observation(db, self.request())
            before = list(map(tuple, db.execute('SELECT * FROM audit ORDER BY id')))
            gap, = self.gaps(root, db)
            self.assertEqual(gap['state'], 'collection-unresolved')
            self.assertEqual(gap['reason_code'], 'expected_file_not_in_inventory')
            self.assertEqual(gap['axis'], 'acquisition')
            self.assertEqual(gap['expectation_id'], original['id'])
            self.assertEqual(gap['tool_version'], 'ileapp/declared-version')
            self.assertEqual(gap['category'], 'messages')
            self.assertIsNone(gap['run_id'])
            self.assertIn(original, build_ledger(root, db)['entries'])
            self.assertEqual(list(map(tuple, db.execute('SELECT * FROM audit ORDER BY id'))), before)

    def test_exact_evidence_and_full_path_not_basename_prefix_or_other_source(self):
        with connect(self.ws, 'A') as (root, db):
            record_observation(db, self.request('dir/a.db'))
            self.inventory(db, self.eids[1], 'dir/a.db', 'other-exact')
            for n, source in enumerate(('a.db', 'dir/a.db/child', 'other/dir/a.db', 'dir/A.db')):
                self.inventory(db, self.eids[0], source, 'nonmatch' + str(n))
            self.assertEqual(self.gaps(root, db)[0]['inventory_matches'], 0)
            self.inventory(db, self.eids[0], 'dir/a.db', 'exact')
            self.assertEqual(self.gaps(root, db), [])
            self.inventory(db, self.eids[0], 'dir/a.db', 'duplicate')
            gap, = self.gaps(root, db)
            self.assertEqual(gap['reason_code'], 'expected_file_mapping_ambiguous')
            self.assertEqual(gap['inventory_matches'], 2)

    def test_existing_real_file_adds_no_gap_or_parsing_promotion(self):
        with connect(self.ws, 'A') as (root, db):
            source = db.execute('SELECT logical_path FROM files WHERE evidence_id=?', (self.eids[0],)).fetchone()[0]
            before = build_ledger(root, db)['entries']
            requested = record_observation(db, self.request(source))
            self.assertEqual(build_ledger(root, db)['entries'], before + [requested])
            self.assertEqual(self.gaps(root, db), [])

    def test_inventory_addition_resolves_without_rewriting_request_or_probing(self):
        with connect(self.ws, 'A') as (root, db):
            record_observation(db, self.request('later.db'))
            self.assertEqual(len(self.gaps(root, db)), 1)
            before = list(map(tuple, db.execute('SELECT * FROM audit ORDER BY id')))
            payload = root / 'evidence' / self.eids[0] / 'later.db'
            payload.write_bytes(b'public synthetic supplied bytes')
            db.execute('INSERT INTO files(evidence_id,path,logical_path,sha256,size) VALUES(?,?,?,?,?)',
                (self.eids[0], 'later.db', 'later.db', digest(payload), payload.stat().st_size))
            with patch.object(Path, 'open', side_effect=AssertionError('No byte probes allowed')), patch.object(Path, 'stat', side_effect=AssertionError('No filesystem probes allowed')):
                self.assertEqual(self.gaps(root, db), [])
            self.assertEqual(list(map(tuple, db.execute('SELECT * FROM audit ORDER BY id'))), before)

    def test_malformed_expectations_refuse_without_audit(self):
        with connect(self.ws, 'A') as (root, db):
            before = db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            invalid = [self.request(path) for path in ('', '/abs', '../a', 'a/../b', './a', 'a/./b', 'a//b', 'a/', 'a\\b', 'a:b', 'a\x00b', 'a\nb', 'a\x7fb', 'a\u202eb')]
            invalid += [self.request(**changes) for changes in ({'state': 'collected'}, {'expectation_kind': 'v2'}, {'expectation_kind': None}, {'evidence_id': None}, {'evidence_id': ''}, {'evidence_id': 'foreign'}, {'evidence_id': []})]
            for value in invalid:
                with self.subTest(value=value), self.assertRaises(UserError):
                    record_observation(db, value)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], before)

    def test_legacy_requests_and_unbound_text_never_infer_missing_files(self):
        with connect(self.ws, 'A') as (root, db):
            value = self.request(); del value['expectation_kind']
            record_observation(db, value)
            record_observation(db, {**value, 'evidence_id': None, 'source': 'https://remote.invalid/manifest'})
            self.assertEqual(self.gaps(root, db), [])

    def test_tampered_audit_refuses_projection_and_new_expectation(self):
        with connect(self.ws, 'A') as (root, db):
            record_observation(db, self.request())
            db.execute("UPDATE audit SET detail='{}' WHERE action='coverage.recorded'")
            count = db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            with self.assertRaisesRegex(UserError, 'integrity'):
                self.gaps(root, db)
            with self.assertRaisesRegex(UserError, 'integrity'):
                record_observation(db, self.request('another.db'))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], count)

    def test_projected_audited_expectation_shape_revalidated(self):
        with connect(self.ws, 'A') as (root, db):
            audit(db, 'coverage.recorded', self.request('../invalid'))
            with self.assertRaises(UserError):
                self.gaps(root, db)

    def test_zero_result_selected_context_opaque_and_unselected_canaries_absent(self):
        with connect(self.ws, 'A') as (root, db):
            record_observation(db, self.request('MISSING_NAME_CANARY.db'))
            record_observation(db, self.request('OTHER_NAME_CANARY.db', evidence_id=self.eids[1]))
            path = self.base / 'empty.jsonl'
            result = write_jsonl_export(root, db, path, [], {'evidence': self.eids[0], 'query': 'nothing'})
            text = Path(result['coverage_path']).read_text(); data = json.loads(text)
            rows = data['coverage_context']['observations']
            gap, = [row for row in rows if row['reason_code'] == 'expected_file_not_in_inventory']
            self.assertEqual(gap['module_role'], 'expected')
            self.assertEqual(gap['module'], 'ileapp')
            self.assertNotIn('source_path', gap)
            self.assertNotIn('CANARY', text)
            self.assertEqual({row['evidence_id'] for row in rows}, {self.eids[0]})
            html = self.base / 'empty.html'
            write_report(root, db, html, filters={'evidence': self.eids[0], 'query': 'nothing'})
            self.assertNotIn('CANARY', html.read_text())
            self.assertIn('expected_file_not_in_inventory', html.read_text())
            self.assertNotIn('CANARY', Path(str(html) + '.coverage.json').read_text())

    def test_selected_run_keeps_acquisition_gap_and_expected_module_role(self):
        with connect(self.ws, 'A') as (root, db):
            db.execute("INSERT INTO runs(id,evidence_id,engine,started_at,status) VALUES('selected-run',?,'native','2026-01-01','complete')", (self.eids[0],))
            record_observation(db, self.request())
            scope = checked_scope(db, {'run': 'selected-run'})
            data = portable_summary(build_ledger(root, db), {'evidence_ids': [], 'source_pairs': [], **scope})
            gap, = [r for r in data['coverage_context']['observations'] if r['reason_code'] == 'expected_file_not_in_inventory']
            self.assertEqual(gap['axis'], 'acquisition')
            self.assertEqual(gap['module'], 'ileapp')
            self.assertEqual(gap['module_role'], 'expected')
            self.assertEqual(gap['state'], 'collection-unresolved')

    def test_untrusted_reason_override_is_not_exported(self):
        with connect(self.ws, 'A') as (root, db):
            record_observation(db, self.request())
            gap, = self.gaps(root, db)
            # Serialized/caller-supplied dicts do not retain trusted projection type.
            forged = dict(gap)
            data = portable_summary({'entries': [forged]}, {'coverage_evidence_ids': self.eids[:1]})
            row, = data['coverage_context']['observations']
            self.assertEqual(row['reason_code'], 'collection_state_unknown')
            self.assertNotIn('module_role', row)
            with self.assertRaises(UserError):
                record_observation(db, self.request(reason_code='expected_file_not_in_inventory'))
