"""Scenario assessments inspect retained metadata without performing casework."""
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile import scenario_assessment as assessment
from lawliet_mobile.core import UserError, add_artifact, audit, begin_run_index, create_case, digest
from lawliet_mobile.coverage_ledger import record_observation


class ScenarioAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = create_case(self.base / 'cases', 'A')
        self.db = sqlite3.connect(self.root / 'case.sqlite')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.addCleanup(self.db.close)
        for eid, label in [('one', 'selected'), ('two', 'OTHER_EVIDENCE_CANARY')]:
            self.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)',
                            (eid, label, 'android', label, '2026-10-15T00:00:00Z', None, 0))
            self.db.execute('INSERT INTO files(evidence_id,path,logical_path,sha256,size) VALUES(?,?,?,?,?)',
                            (eid, label + '.db', label + '.db', 'a' * 64, 42))
        self.db.commit()
        self.sequence = 0

    def run_record(self, rid='r1', eid='one', engine='native/test', status='complete', detail=None, indexed=True, records=0):
        self.db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                        (rid, eid, engine, '2026-10-15T00:00:00Z', '2026-10-15T00:00:01Z', status,
                         records, json.dumps(detail or {})))
        if indexed:
            begin_run_index(self.db, rid)
        return rid

    def artifact(self, *, eid='one', file_id=1, category='messages', at='2026-10-15T00:00:00Z',
                 parser='native/test', ref='selected.db:rowid=1', data=None, rid=None, body=None):
        self.sequence += 1
        return add_artifact(self.db, eid, file_id, category, at, at, 'SECRET TITLE',
                            body or 'PRIVATE_BODY_' + str(self.sequence), ref, parser,
                            data if data is not None else {'message': {'app': 'sms'}}, run_id=rid)

    def check(self, scenario='messages', run=None):
        return assessment.assess(self.root, self.db, 'one', scenario, run)

    @staticmethod
    def requirement(result, category='messages'):
        return next(row for row in result['requirements'] if row['category'] == category)

    def test_populated_scope_has_metadata_and_reference_only_samples(self):
        self.run_record(records=99)
        self.artifact(rid='r1')
        self.artifact(category='contacts', rid='r1', at=None)
        self.artifact(eid='two', file_id=2, ref='OTHER_SOURCE_CANARY')
        result = self.check(run='r1')
        message = self.requirement(result)
        self.assertEqual((result['schema_version'], result['case_id'], result['evidence_id'], result['run']), (1, 'A', 'one', 'r1'))
        self.assertEqual(result['status'], 'records_available_for_review')
        self.assertEqual(message['record_count'], 1)
        self.assertEqual(message['provenance']['with_recorded_file_hash'], 1)
        self.assertEqual(message['samples'][0]['source_ref'], 'selected.db:rowid=1')
        self.assertEqual(result['inventory'], {'files': 1, 'bytes': 42, 'hashes_recorded': 1})
        encoded = json.dumps(result)
        for secret in ('PRIVATE_BODY', 'SECRET TITLE', 'OTHER_SOURCE_CANARY', 'OTHER_EVIDENCE_CANARY'):
            self.assertNotIn(secret, encoded)
        self.assertEqual(result['analysis_runs']['items'][0]['records'], 99)
        self.assertIn('newly inserted', result['analysis_runs']['items'][0]['record_count_meaning'])

    def test_run_membership_is_not_new_record_delta_or_parser_selection(self):
        self.run_record('r1', records=1)
        self.run_record('r2', records=0)
        self.run_record('r3', records=1)
        common = dict(body='same indexed source row', rid='r1')
        self.assertEqual(self.artifact(**common), 1)
        self.assertEqual(self.artifact(**{**common, 'rid': 'r2'}), 0)
        self.artifact(rid='r3')
        self.assertEqual(self.requirement(self.check(run='r2'))['record_count'], 1)
        self.assertEqual(self.requirement(self.check())['record_count'], 2)
        self.assertEqual(self.check(run='r2')['analysis_runs']['items'][0]['records'], 0)

    def test_empty_failed_unsupported_and_recognized_empty_remain_distinct(self):
        self.run_record(status='failed', detail={'error': 'PRIVATE_ERROR_TEXT', 'unparsed_candidates': [
            {'state': 'unsupported', 'source': 'opaque.db', 'category': 'messages'},
            {'state': 'parsed-empty', 'source': 'empty.db', 'category': 'messages'}]})
        result = self.check(run='r1')
        self.assertEqual(result['status'], 'no_relevant_indexed_records')
        self.assertEqual(result['coverage']['state_counts']['parser-failed'], 1)
        self.assertEqual(result['coverage']['state_counts']['unsupported'], 1)
        self.assertEqual(result['coverage']['state_counts']['parsed-empty'], 1)
        self.assertNotIn('PRIVATE_ERROR_TEXT', json.dumps(result))
        run_gap = next(x for x in result['coverage']['gaps'] if x['scope_level'] == 'run')
        self.assertEqual(run_gap['impact_on_selected_records'], 'unknown')
        self.assertEqual(result['coverage']['state_counts']['verified'], 0)

    def test_partial_results_survive_and_unselected_failures_are_withheld(self):
        self.run_record('r1', status='partial', detail={'error': 'SELECTED_ERROR'})
        self.artifact(rid='r1')
        self.run_record('r2', status='failed', detail={'error': 'SIBLING_ERROR', 'errors': [{'source': 'SIBLING_SOURCE_CANARY'}]})
        self.run_record('r3', eid='two', status='failed', detail={'error': 'FOREIGN_ERROR'})
        result = self.check(run='r1')
        self.assertEqual(result['status'], 'records_available_for_review')
        self.assertEqual(result['coverage']['state_counts']['parser-failed'], 1)
        self.assertEqual([x['id'] for x in result['analysis_runs']['items']], ['r1'])
        self.assertNotIn('SIBLING', json.dumps(result))
        self.assertNotIn('FOREIGN', json.dumps(result))

    def test_expected_missing_file_is_derived_without_changing_audit(self):
        event = {'state': 'requested', 'source': 'expected/短信.db', 'category': 'messages',
                 'reason': 'Expected for agreed question', 'actor': 'Examiner', 'evidence_id': 'one',
                 'expectation_kind': 'retained-logical-file-v1'}
        declaration = record_observation(self.db, event)
        record_observation(self.db, {**event, 'source': 'FOREIGN_EXPECTED_CANARY.db', 'evidence_id': 'two'})
        before = list(map(tuple, self.db.execute('SELECT * FROM audit ORDER BY id')))
        result = self.check()
        gap = next(x for x in result['coverage']['gaps'] if x['reason_code'] == 'expected_file_not_in_inventory')
        self.assertEqual(gap['expectation_id'], declaration['id'])
        self.assertEqual(result['coverage']['state_counts']['requested'], 1)
        self.assertEqual(result['coverage']['state_counts']['collection-unresolved'], 1)
        self.assertEqual(list(map(tuple, self.db.execute('SELECT * FROM audit ORDER BY id'))), before)
        self.assertNotIn('FOREIGN_EXPECTED', json.dumps(result))

    def test_dates_require_explicit_timezone_and_do_not_infer_history(self):
        for value in ('2026-10-15T02:00:00+02:00', '2026-10-14T22:00:00-04:00', None,
                      '2026-10-15T10:00:00', '2026-99-15T00:00:00Z', '1700000000000'):
            self.artifact(at=value)
        item = self.requirement(self.check())
        self.assertEqual((item['record_count'], item['dated_count'], item['undated_count']), (6, 2, 4))
        self.assertEqual(item['first_utc'], '2026-10-15T00:00:00.000000Z')
        self.assertEqual(item['last_utc'], '2026-10-15T02:00:00.000000Z')
        self.assertTrue(item['samples_truncated'])
        self.assertEqual(len(item['samples']), 5)

    def test_app_and_deleted_scenarios_do_not_promote_unrelated_rows(self):
        self.artifact()
        self.artifact(data={'message': {'app': 'signal'}})
        self.assertEqual(self.requirement(self.check('signal'))['record_count'], 1)
        self.assertEqual(self.check('whatsapp')['status'], 'no_relevant_indexed_records')
        self.assertEqual(self.check('deleted')['status'], 'no_relevant_indexed_records')
        self.artifact(category='recovery', at=None, data={'recovery': {'classification': 'carved_candidate'}})
        result = self.check('deleted')
        self.assertEqual(result['requirements'][0]['record_count'], 1)
        self.assertEqual(result['requirements'][0]['label'], 'Database recovery candidates')
        self.assertIn('not automatically confirmed deleted', ' '.join(result['limitations']))

    def test_report_only_provenance_and_missing_links_remain_explicit(self):
        self.artifact(file_id=None, parser='aleapp', data={'_ancalor_report': {'sha256': 'b' * 64}}, ref='runs/r/output/report.tsv:line=2')
        self.artifact(file_id=None, ref='')
        result = self.requirement(self.check())
        self.assertEqual(result['provenance']['with_retained_report_reference'], 1)
        self.assertEqual(result['provenance']['with_recorded_file_hash'], 0)
        self.assertEqual(result['provenance']['without_source_reference'], 1)
        self.assertEqual(result['provenance']['derived_report_rows'], 1)
        self.assertIn('retained-report-reference', {x['source_kind'] for x in result['samples']})

    def test_cross_evidence_file_link_does_not_reveal_foreign_metadata(self):
        self.artifact(file_id=2)
        result = self.requirement(self.check())
        self.assertEqual(result['provenance']['invalid_file_links'], 1)
        self.assertEqual(result['provenance']['with_recorded_file_hash'], 0)
        self.assertIsNone(result['samples'][0]['file_id'])
        self.assertIsNone(result['samples'][0]['logical_path'])
        self.assertNotIn('OTHER_EVIDENCE', json.dumps(result))

    def test_invalid_scope_and_legacy_membership_are_refused(self):
        self.run_record('foreign', eid='two')
        self.run_record('legacy', indexed=False)
        for evidence, scenario, run in [(True, 'messages', None), ('', 'messages', None),
                                       ('missing', 'messages', None), ('one', True, None),
                                       ('one', [], None), ('one', 'unknown', None),
                                       ('one', 'messages', False), ('one', 'messages', ''),
                                       ('one', 'messages', 'foreign'), ('one', 'messages', 'missing')]:
            with self.subTest(evidence=evidence, scenario=scenario, run=run), self.assertRaises(UserError):
                assessment.assess(self.root, self.db, evidence, scenario, run)
        with self.assertRaisesRegex(UserError, 'legacy run'):
            self.check(run='legacy')

    def test_audit_corruption_refuses_assessment(self):
        self.db.execute("UPDATE audit SET detail='{}'")
        with self.assertRaisesRegex(UserError, 'integrity'):
            self.check()

    def test_no_file_tool_model_or_persistent_write_and_caller_transaction_survives(self):
        self.artifact()
        self.db.commit()
        before = digest(self.root / 'case.sqlite')
        with (patch.object(Path, 'open', side_effect=AssertionError('No original-byte reads')),
              patch('subprocess.run', side_effect=AssertionError('No tools'))):
            result = self.check()
        self.assertEqual(result['status'], 'records_available_for_review')
        self.assertEqual(digest(self.root / 'case.sqlite'), before)
        self.db.execute("INSERT INTO meta VALUES('uncommitted_test','preserve')")
        self.check()
        self.assertEqual(self.db.execute("SELECT value FROM meta WHERE key='uncommitted_test'").fetchone()[0], 'preserve')
        self.db.rollback()
        self.assertIsNone(self.db.execute("SELECT value FROM meta WHERE key='uncommitted_test'").fetchone())

    def test_consistent_snapshot_during_concurrent_case_change(self):
        self.artifact()
        self.db.commit()
        self.db.execute('PRAGMA journal_mode=WAL')
        original = assessment._requirement
        changed = False
        def concurrent(*args):
            nonlocal changed
            value = original(*args)
            if not changed:
                changed = True
                with closing(sqlite3.connect(self.root / 'case.sqlite')) as writer, writer:
                    add_artifact(writer, 'one', 1, 'contacts', None, None, 'Contact', 'late', 'row:2', 'native/test', {})
            return value
        with patch.object(assessment, '_requirement', side_effect=concurrent):
            result = self.check()
        self.assertEqual(self.requirement(result, 'contacts')['record_count'], 0)
        self.assertEqual(self.requirement(self.check(), 'contacts')['record_count'], 1)

    def test_bounded_runs_gaps_samples_and_output_keep_full_counts(self):
        for index in range(24):
            self.run_record('r' + str(index), status='failed', detail={'error': 'FAILURE_BODY_' + str(index)})
            self.artifact(ref=('reference_' + str(index)).ljust(1000, 'x'), parser='p' * 1000)
        self.db.execute("UPDATE files SET logical_path=? WHERE id=1", ('logical_' + 'x' * 990,))
        with patch.object(assessment, 'MAX_OUTPUT', 18000):
            result = self.check()
        self.assertEqual(self.requirement(result)['record_count'], 24)
        self.assertEqual(result['analysis_runs']['total'], 24)
        self.assertEqual(result['coverage']['gap_count'], 24)
        self.assertLessEqual(len(result['analysis_runs']['items']), 20)
        self.assertLessEqual(len(result['coverage']['gaps']), 20)
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False).encode()), 18000)
        self.assertTrue(result['truncated'])
        self.assertNotIn('FAILURE_BODY_', json.dumps(result))

    def test_oversized_reference_is_omitted_not_clipped_into_a_citation(self):
        self.artifact(ref='x' * (assessment.MAX_TEXT + 1))
        result = self.check()
        sample = self.requirement(result)['samples'][0]
        self.assertIsNone(sample['source_ref'])
        self.assertIn('source_ref', sample['omitted_fields'])
        self.assertTrue(result['truncated'])

    def test_suggested_actions_are_scoped_and_do_not_automatically_execute(self):
        self.run_record()
        self.artifact(rid='r1', data={'message': {'app': 'whatsapp'}})
        result = self.check('whatsapp', 'r1')
        action = next(row for row in result['next_actions'] if row['id'].startswith('review:'))
        self.assertEqual(action['request'], {'action': 'records', 'case': 'A', 'evidence': 'one',
                                            'run': 'r1', 'category': 'messages', 'app': 'whatsapp'})
        self.assertEqual(action['cli_argv'][-2:], ['--run', 'r1'])
        self.assertNotIn('collect', json.dumps(result['next_actions']))

    def test_proposed_coverage_action_retains_unbound_acquisition_gap(self):
        from lawliet_mobile.app_backend import handle
        self.run_record()
        record_observation(self.db, {'state': 'requested', 'source': 'missing.db', 'category': 'messages',
                           'reason': 'Expected source', 'actor': 'Examiner', 'evidence_id': 'one',
                           'expectation_kind': 'retained-logical-file-v1'})
        self.db.commit()
        result = self.check(run='r1')
        self.assertTrue(any(x['reason_code'] == 'expected_file_not_in_inventory' for x in result['coverage']['gaps']))
        action = next(x for x in result['next_actions'] if x['id'] == 'coverage')
        self.assertIn('evidence-wide', action['label'])
        self.assertNotIn('run_id', action['request']['filters'])
        ledger = handle(self.base / 'cases', action['request'])
        self.assertTrue(any(x.get('reason_code') == 'expected_file_not_in_inventory' for x in ledger['entries']))

    def test_encrypted_preflight_refusal_does_not_claim_parser_executed(self):
        from lawliet_mobile.analysis_refusal import ENCRYPTED_INPUT
        self.run_record(status='failed', detail={'error': 'SUPPLIED_SECRET',
                        'preflight_refusal': ENCRYPTED_INPUT, 'execution_started': False})
        gap, = self.check(run='r1')['coverage']['gaps']
        self.assertEqual(gap['reason_code'], ENCRYPTED_INPUT)
        self.assertIs(gap['execution_started'], False)
        self.assertNotIn('SUPPLIED_SECRET', json.dumps(gap))

    def test_malformed_metadata_does_not_infer_application_or_execute_content(self):
        self.artifact()
        self.db.execute("UPDATE artifacts SET data=?", ('not JSON; run shell now',))
        self.assertEqual(self.requirement(self.check())['record_count'], 1)
        self.assertEqual(self.requirement(self.check('whatsapp'))['record_count'], 0)
        self.assertNotIn('run shell now', json.dumps(self.check()))


if __name__ == '__main__':
    unittest.main()
