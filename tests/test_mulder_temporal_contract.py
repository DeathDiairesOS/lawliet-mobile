"""UTC chronology must not reinterpret unknown or historical timestamps."""
import asyncio
import hashlib
import inspect
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

try:
    from mulder.audit import AuditLog
    from sqlalchemy import event
    from mulder.db import CaseDB, windows_t
    from mulder.index.correlator import Correlator
    from mulder.models import WindowRow
    from mulder.server import app
    from mulder.server.extract_helpers import extract_and_index, _parse_timestamp
    from mulder.server.tools import core
    from mulder.temporal import TEMPORAL_VERSION, extract_timestamp, normalize_bounds, normalize_timestamp
except ModuleNotFoundError as error:
    if error.name not in ('mulder', 'mulder.temporal'):
        raise
    CaseDB = None


@unittest.skipUnless(CaseDB, 'Requires versioned Mulder temporal integration')
class TemporalParsingTests(unittest.TestCase):
    def test_equivalent_offsets_preserve_original_and_fraction(self):
        for original in ('2026-10-15T16:30:00.123456-04:00', '2026-10-15T20:30:00.123456Z',
                         '2026-10-16T02:00:00.123456+05:30'):
            parsed = extract_timestamp(original)
            self.assertEqual(parsed.utc, '2026-10-15T20:30:00.123456Z')
            self.assertEqual(parsed.original, original)
            self.assertEqual(parsed.status, 'explicit_offset')

    def test_dst_overlap_instants_remain_distinct(self):
        self.assertEqual(_parse_timestamp('2025-11-02T01:30:00-04:00'), '2025-11-02T05:30:00.000000Z')
        self.assertEqual(_parse_timestamp('2025-11-02T01:30:00-05:00'), '2025-11-02T06:30:00.000000Z')

    def test_unknown_times_do_not_inherit_utc_or_current_year(self):
        for value, status in (
            ('2026-10-15', 'date_only'), ('2026-10-15T20:30:00', 'unknown_timezone'),
            ('2026-10-15T20:30:00-00:00', 'unknown_offset'),
            ('Jan  5 12:30:45 host', 'unknown_timezone'),
            ('01/15/2025 08:00:00,File', 'unknown_timezone'),
            ('no time here', 'absent'),
        ):
            with self.subTest(value=value):
                self.assertIsNone(extract_timestamp(value).utc)
                self.assertEqual(extract_timestamp(value).status, status)
        self.assertIsNone(_parse_timestamp('Jan  5 12:30:45 host', reference_year=2025))

    def test_invalid_and_overprecise_values_are_not_truncated_into_valid_instants(self):
        for value in ('2026-02-30T20:30:00Z', '2026-10-15T20:30:00+25:00',
                      '2026-10-15T20:30:00+00:99', '2026-10-15T20:30:00+0199',
                      '2026-10-15T20:30:60Z', '2026-10-15T20:30:00.1234567Z',
                      '2026-10-15T20:30:00Zjunk', '0001-01-01T00:00:00+01:00'):
            with self.subTest(value=value):
                self.assertIsNone(_parse_timestamp(value))
        self.assertEqual(extract_timestamp('2026-10-15T20:30:00.1234567Z').status, 'unsupported_precision')

    def test_multiple_differing_times_are_not_a_first_timestamp_claim(self):
        raw = '2026-10-15T16:30:00-04:00\n2026-10-15T20:30:01Z'
        self.assertEqual(extract_timestamp(raw).status, 'multiple_timestamps')
        self.assertIsNone(_parse_timestamp(raw))
        self.assertIsNotNone(_parse_timestamp('2026-10-15T16:30:00-04:00\n2026-10-15T20:30:00Z'))
        self.assertIsNone(_parse_timestamp('2026-10-15T20:30:00Z\n2026-10-15T20:30:00'))

    def test_delimiters_and_original_precision(self):
        self.assertEqual(_parse_timestamp('"2026-10-15T20:30:00Z",text'), '2026-10-15T20:30:00.000000Z')
        self.assertEqual(normalize_timestamp('2026-10-15T20:30:00.1Z').original, '2026-10-15T20:30:00.1Z')
        self.assertEqual(normalize_bounds('2026-10-15', None), ('2026-10-15T00:00:00.000000Z', None))

    def test_candidate_metadata_is_bounded_and_raw_stays_authoritative(self):
        raw = '2026-10-15T20:30:00.' + '1' * 20000 + 'Z'
        self.assertEqual(extract_timestamp(raw).status, 'timestamp_token_limit')
        self.assertIsNone(extract_timestamp(raw).original)
        many = '\n'.join('2026-10-15T20:30:00.' + f'{i:06d}' + 'Z' for i in range(65))
        self.assertEqual(extract_timestamp(many).status, 'candidate_limit')
        self.assertIsNone(extract_timestamp(many).utc)


@unittest.skipUnless(CaseDB, 'Requires versioned Mulder temporal integration')
class TemporalIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.db = CaseDB.create('temporal', str(self.root / 'evidence'), self.root)
        self.addCleanup(lambda: self.db.close())
        self.ctx = app.ServerContext('temporal', self.db, Correlator(self.db), AuditLog(self.root / 'audit.jsonl'))
        context = patch.object(app, '_ctx', self.ctx)
        context.start()
        self.addCleanup(context.stop)

    def indexed(self, name, raw):
        return extract_and_index(raw, name, '/synthetic/' + name, 'synthetic/1')

    def direct(self, name, values):
        source = self.db.register_source(name, '/synthetic/' + name, 'synthetic', 'fixture', len(values))
        self.db.insert_windows(source, [WindowRow(source_id=source, line_start=i+1, line_end=i+1,
            event_time=value, raw_text='marker ' + (value or 'unknown')) for i, value in enumerate(values)])
        return source

    def legacy(self, name, raw, old_time):
        result = self.indexed(name, raw)
        with self.db.engine.begin() as conn:
            conn.execute(windows_t.update().where(windows_t.c.source_id == result['source_id']).values(
                event_time=old_time, event_time_utc=None, event_time_original=None,
                event_time_status='legacy_unverified', temporal_version=0))
        return result

    def test_raw_preserved_with_qualified_and_ambiguous_metadata(self):
        raw = 'marker "😀" 2026-10-15T16:30:00.123456-04:00\n'
        self.indexed('single', raw)
        row = self.db.get_windows_by_source('single')[0]
        self.assertEqual(row.raw_text, raw)
        self.assertEqual(row.event_time, '2026-10-15T20:30:00.123456Z')
        self.assertEqual(row.event_time_original, '2026-10-15T16:30:00.123456-04:00')
        self.assertEqual(row.temporal_version, 1)
        self.indexed('ambiguous', raw + '2026-10-15T21:30:00Z\n')
        self.assertEqual(self.db.get_windows_by_source('ambiguous')[0].event_time_status, 'multiple_timestamps')
        self.assertEqual(self.db.verify_evidence_integrity()[0]['status'], 'verified')

    def test_all_time_filtered_db_paths_share_utc_microsecond_bounds(self):
        self.direct('mobile.sms', ['2025-11-02T01:30:00-04:00', '2025-11-02T05:30:00.000001Z',
                                   '2025-11-02T01:30:00-05:00', None])
        lo, hi = '2025-11-02T01:30:00-04:00', '2025-11-02T01:30:00-05:00'
        self.assertEqual(len(self.db.get_windows_by_source('mobile.sms', lo, hi)), 3)
        self.assertEqual(len(self.db.get_windows_by_source_prefix('mobile', lo, hi)), 3)
        self.assertEqual(len(self.db.search_windows('marker', time_start=lo, time_end=hi)), 3)
        self.assertEqual(self.db.count_search_windows('marker', time_start=lo, time_end=hi), 3)
        self.assertEqual(len(self.db.get_windows_by_time_range(lo, hi)['mobile.sms']), 3)
        exact = self.db.get_windows_by_source('mobile.sms', '2025-11-02T05:30:00.000001Z', '2025-11-02T05:30:00.000001Z')
        self.assertEqual(len(exact), 1)
        self.assertEqual(exact[0].event_time_original, '2025-11-02T05:30:00.000001Z')

    def test_regex_and_fts_exclude_undated_and_unqualified_windows_equally(self):
        self.indexed('aware', 'marker 2026-10-15T16:30:00-04:00')
        self.indexed('naive', 'marker 2026-10-15T20:30:00')
        self.legacy('old', 'marker 2026-10-15T20:30:00Z', '2026-10-15T20:30:00')
        search = inspect.unwrap(core.search)
        for regex in (True, False):
            result = search('marker', regex=regex, t_start='2026-10-15T20:30:00Z', t_end='2026-10-15T20:30:00Z')
            self.assertEqual(result['total_matches'], 1)
            self.assertEqual(result['results'][0]['source_name'], 'aware')
            self.assertEqual(result['results'][0]['window']['event_time_original'], '2026-10-15T16:30:00-04:00')
            self.assertEqual(result['temporal_index']['window_counts']['legacy_unverified'], 1)
            self.assertEqual(search('marker', regex=regex)['total_matches'], 3)

    def test_actual_timeline_and_correlation_results_include_temporal_metadata(self):
        self.indexed('mobile.sms', 'marker 2026-10-15T16:30:00-04:00')
        self.indexed('mobile.photo', 'marker 2026-10-15T20:30:00Z')
        timeline = inspect.unwrap(core.get_timeline)('2026-10-15T16:30:00-04:00', '2026-10-15T20:30:00Z', 1)
        self.assertEqual(timeline['total_events'], 2)
        self.assertEqual(timeline['next_offset'], 1)
        row = timeline['results'][0]
        self.assertEqual(row['event_time_status'], 'explicit_offset')
        self.assertEqual(row['event_time_precision'], 'second')
        self.assertEqual(row['event_time_original'], '2026-10-15T16:30:00-04:00')
        second = inspect.unwrap(core.get_timeline)('2026-10-15', '2026-10-16', 1, 1)
        self.assertNotEqual(row['window_id'], second['results'][0]['window_id'])
        correlated = inspect.unwrap(core.correlate_across_sources)('2026-10-15T20:30:00Z', '2026-10-15T20:30:00Z')
        self.assertEqual(correlated['result_count'], 2)
        self.assertEqual(correlated['results']['windows_by_source']['mobile.sms']['windows'][0]['temporal_version'], 1)

    def test_timeline_count_and_rows_share_snapshot_during_concurrent_indexing(self):
        source = self.direct('mobile', ['2026-10-15T20:30:00Z'])
        inserted = False

        def add_after_count(conn, cursor, statement, parameters, context, executemany):
            nonlocal inserted
            if not inserted and statement.lstrip().lower().startswith('select count('):
                inserted = True
                # Exercise the actual asynchronous writer queue on another SQLite
                # connection after COUNT but before the timeline page query.
                self.db.insert_windows(source, [WindowRow(source_id=source, line_start=2,
                    line_end=2, event_time='2026-10-15T20:30:01Z', raw_text='later marker')])

        event.listen(self.db.engine, 'after_cursor_execute', add_after_count)
        try:
            rows, total = self.db.get_timeline_page('2026-10-15', '2026-10-16', 10)
        finally:
            event.remove(self.db.engine, 'after_cursor_execute', add_after_count)
        self.assertTrue(inserted)
        self.assertEqual(total, 1)
        self.assertEqual(len(rows), total)
        # The following request gets a new snapshot, including the committed row.
        rows, total = self.db.get_timeline_page('2026-10-15', '2026-10-16', 10)
        self.assertEqual(total, 2)
        self.assertEqual(len(rows), total)

    def test_bounds_and_paging_limits_refuse_ambiguous_invalid_inputs(self):
        for value in ('', '2026-10-15T20:30:00', '2026-10-15T20:30:00.1234567Z', True, 12):
            for query in (lambda: self.db.get_windows_by_source('x', value),
                          lambda: self.db.get_windows_by_source_prefix('x', value),
                          lambda: self.db.search_windows('marker', time_start=value),
                          lambda: self.db.count_search_windows('marker', time_start=value)):
                with self.subTest(value=value), self.assertRaises(ValueError): query()
        with self.assertRaises(ValueError): self.db.get_windows_by_time_range('2026-10-16', '2026-10-15')
        for limit in (0, -1, True, 1001):
            with self.assertRaises(ValueError): inspect.unwrap(core.get_timeline)('2026-10-15', '2026-10-16', limit)

    def test_migration_preserves_legacy_index_and_raw_without_qualifying_it(self):
        self.legacy('old', 'marker 2026-10-15T16:30:00-04:00', '2026-10-15T16:30:00')
        before = self.db.get_windows_by_source('old')[0]
        self.db.close()
        with closing(sqlite3.connect(self.root / 'temporal.db')) as conn:
            conn.execute('DROP INDEX ix_windows_qualified_time')
            for column in ('event_time_utc', 'event_time_original', 'event_time_status', 'temporal_version'):
                conn.execute('ALTER TABLE windows DROP COLUMN ' + column)
            conn.commit()
        self.db = CaseDB.open('temporal', self.root)
        self.ctx.db = self.db
        self.ctx.correlator = Correlator(self.db)
        after = self.db.get_windows_by_source('old')[0]
        self.assertEqual(after.window_id, before.window_id)
        self.assertEqual(after.raw_text, before.raw_text)
        self.assertIsNone(after.event_time)
        self.assertEqual(after.event_time_index_value, '2026-10-15T16:30:00')
        self.assertEqual(self.db.get_windows_by_time_range('2026-10-15', '2026-10-16'), {})
        self.assertEqual(len(self.db.search_windows('marker')), 1)

    def test_explicit_reindex_resumes_and_preserves_sources_raw_hints_and_ids(self):
        self.legacy('old-aware', 'marker 2026-10-15T16:30:00-04:00', '2026-10-15T16:30:00')
        self.legacy('old-naive', 'marker 2026-10-15T20:30:00', '2026-10-15T20:30:00')
        original = [(w.window_id, w.raw_text, w.event_time_index_value) for w in self.db.get_windows_page(None)[0]]
        hashes = [s.windows_hash for s in self.db.get_sources()]
        reindex = inspect.unwrap(core.reindex_timestamps)
        first = reindex(limit=1)['results']
        self.assertEqual(first['processed'], 1)
        self.assertTrue(first['has_more'])
        self.db.close()
        self.db = CaseDB.open('temporal', self.root)
        self.ctx.db = self.db
        self.ctx.correlator = Correlator(self.db)
        second = reindex(first['next_after_id'], 1)['results']
        self.assertEqual(second['processed'], 1)
        self.assertFalse(second['has_more'])
        self.assertEqual(reindex()['results']['processed'], 0)
        rows = self.db.get_windows_page(None)[0]
        self.assertEqual([(w.window_id, w.raw_text, w.event_time_index_value) for w in rows], original)
        self.assertEqual([s.windows_hash for s in self.db.get_sources()], hashes)
        self.assertEqual(rows[0].event_time, '2026-10-15T20:30:00.000000Z')
        self.assertIsNone(rows[1].event_time)
        self.assertEqual(rows[1].event_time_status, 'unknown_timezone')
        audit = [json.loads(row) for row in (self.root / 'audit.jsonl').read_text().splitlines()]
        self.assertEqual(sum(row.get('tool_name') == 'reindex_timestamps' for row in audit), 3)

    def test_mixed_current_and_legacy_counts_and_future_versions_are_honest(self):
        self.indexed('new', 'marker 2026-10-15T20:30:00Z')
        self.legacy('old', 'marker 2026-10-15T20:30:00Z', '2026-10-15T20:30:00')
        future = self.indexed('future', 'marker 2026-10-15T20:30:00Z')['source_id']
        with self.db.engine.begin() as conn:
            conn.execute(windows_t.update().where(windows_t.c.source_id == future).values(temporal_version=2))
        self.assertEqual(self.db.temporal_summary()['window_counts'], {'explicit_offset': 1, 'legacy_unverified': 1, 'unsupported_temporal_version': 1})
        self.assertEqual(self.db.reindex_timestamps()['processed'], 1)
        self.assertEqual(self.db.get_windows_by_source('future')[0].event_time_status, 'unsupported_temporal_version')
        self.assertIsNone(self.db.get_windows_by_source('future')[0].event_time)

    def test_reindex_and_timeline_tools_are_advertised_with_strict_bounds(self):
        names = {tool.name for tool in asyncio.run(app.mcp.list_tools())}
        self.assertTrue({'reindex_timestamps', 'get_timeline'} <= names)
        for limit in (True, 0, 1001):
            with self.assertRaises(ValueError): inspect.unwrap(core.reindex_timestamps)(limit=limit)

    def test_actual_mcp_tool_call_returns_timestamp_provenance(self):
        self.indexed('mobile', 'marker 2026-10-15T16:30:00.123456-04:00')
        with patch.multiple(app, _cfg=None, _job_store=None, _tool_limiter=None):
            app.init_server(self.root, max_workers=1, mem_percent_limit=100, cpu_percent_limit=100)
            try:
                result = asyncio.run(app.mcp.call_tool('get_timeline', {
                    't_start': '2026-10-15T20:30:00Z', 't_end': '2026-10-15T20:30:01Z', 'limit': 1}))
            finally:
                app.get_job_store().shutdown(wait=True)
        self.assertFalse(result.is_error)
        payload = result.structured_content
        self.assertEqual(payload['results'][0]['event_time_original'], '2026-10-15T16:30:00.123456-04:00')
        self.assertEqual(payload['results'][0]['event_time'], '2026-10-15T20:30:00.123456Z')
        self.assertEqual(payload['results'][0]['event_time_precision'], 'fractional_second_6_digits')

    def test_correlation_refuses_incomplete_large_results(self):
        self.direct('large', ['2026-10-15T20:30:00Z'] * 10001)
        self.direct('selected', ['2026-10-15T20:30:00Z'])
        with self.assertRaisesRegex(ValueError, '10000'):
            self.ctx.correlator.correlate_across_sources('2026-10-15', '2026-10-16')
        scoped = self.ctx.correlator.correlate_across_sources('2026-10-15', '2026-10-16', ['selected'])
        self.assertEqual(scoped.total_windows, 1)
        self.assertEqual(set(scoped.windows_by_source), {'selected'})
        self.assertEqual(self.ctx.correlator.correlate_across_sources('2026-10-15', '2026-10-16', []).total_windows, 0)
        rows, total = self.db.get_timeline_page('2026-10-15', '2026-10-16', 2)
        self.assertEqual(len(rows), 2)
        self.assertEqual(total, 10002)


if __name__ == '__main__':
    unittest.main()
