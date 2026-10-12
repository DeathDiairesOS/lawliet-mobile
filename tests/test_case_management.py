"""Case administration, persistence, isolation and audit regression checks."""
import json
import tempfile
import unittest
from pathlib import Path

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, connect, create_case, verify


class CaseManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        create_case(self.workspace, 'CASE-A', 'Client review', 'Examiner A')
        create_case(self.workspace, 'CASE-B', 'Other client')

    def call(self, action, case='CASE-A', **values):
        return handle(self.workspace, {'action': action, 'case': case, **values})

    def test_existing_case_read_does_not_migrate_or_assert_status(self):
        path = self.workspace / 'CASE-A' / 'case.sqlite'
        original = path.read_bytes()
        result = self.call('case-management')
        self.assertEqual(result['profile']['status'], 'Untriaged')
        self.assertEqual(result['profile']['owner'], 'Examiner A')
        self.assertEqual(result['tasks'], [])
        self.assertEqual(path.read_bytes(), original)

    def test_metadata_queue_does_not_require_artifact_table(self):
        # A minimal case metadata fixture proves this route cannot depend on
        # reading the large forensic artifact table merely to list cases.
        with connect(self.workspace, 'CASE-A') as (_, db):
            db.execute('DROP TABLE artifacts')
        rows = self.call('cases', include_records=False)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r['records'] is None for r in rows))
        self.assertEqual(next(r for r in rows if r['id'] == 'CASE-A')['owner'], 'Examiner A')

    def test_persistence_queue_summary_and_audit(self):
        result = self.call('case-update', revision=0, values={
            'client': 'Reference 123', 'owner': 'Reviewer B', 'priority': 'High',
            'status': 'In progress', 'due_date': '2026-11-01',
            'objective': 'Review available messages', 'scope': 'Supplied backup only'})
        self.assertEqual(result['profile']['revision'], 1)
        self.assertEqual(self.call('case-management')['profile'], result['profile'])
        queue = next(c for c in self.call('cases') if c['id'] == 'CASE-A')
        self.assertEqual(queue['client'], 'Reference 123')
        self.assertEqual(queue['status'], 'In progress')
        self.assertEqual(self.call('case-management', case='CASE-B')['profile']['status'], 'Untriaged')
        with connect(self.workspace, 'CASE-A') as (root, db):
            self.assertTrue(verify(root, db)['ok'])
            receipt = json.loads(db.execute("SELECT detail FROM audit WHERE action='case.details_updated'").fetchone()[0])
            self.assertEqual(receipt['before']['status'], 'Untriaged')
            self.assertEqual(receipt['after']['status'], 'In progress')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)

    def test_stale_edit_fails_and_noop_does_not_duplicate_history(self):
        self.call('case-update', revision=0, values={'status': 'Review'})
        with self.assertRaisesRegex(UserError, 'another window'):
            self.call('case-update', revision=0, values={'status': 'Closed'})
        before = self.call('case-management')
        after = self.call('case-update', revision=1, values={'status': 'Review'})
        self.assertEqual(before, after)

    def test_invalid_changes_are_atomic(self):
        for values in ({'status': 'Approved'}, {'priority': 'magic'}, {'due_date': '2026-02-30'},
                       {'due_date': '20261101'}, {'scope': 'x'*8001}, {'owner': None},
                       {'schema_version': 9}, {'notes': '\x00'}, []):
            with self.subTest(values=str(values)[:80]), self.assertRaises(UserError):
                self.call('case-update', revision=0, values=values)
        self.assertEqual(self.call('case-management')['profile']['revision'], 0)

    def test_tasks_resume_reopen_and_are_case_scoped(self):
        task = self.call('case-task-add', text='Check missing browser history')['tasks'][0]
        self.assertEqual(self.call('case-management')['summary']['open_tasks'], 1)
        with self.assertRaisesRegex(UserError, 'Unknown task'):
            self.call('case-task-update', case='CASE-B', task_id=task['id'], completed=True, revision=0)
        self.call('case-task-update', task_id=task['id'], completed=True, revision=0)
        with self.assertRaisesRegex(UserError, 'another window'):
            self.call('case-task-update', task_id=task['id'], completed=False, revision=0)
        reopened = self.call('case-task-update', task_id=task['id'], completed=False, revision=1)
        self.assertEqual(reopened['summary']['open_tasks'], 1)
        self.assertEqual(reopened['tasks'][0]['revision'], 2)
        with connect(self.workspace, 'CASE-A') as (root, db):
            self.assertTrue(verify(root, db)['ok'])

    def test_tasks_are_bounded_and_paginated(self):
        for text in ('', '  ', 'x'*2001, None):
            with self.assertRaises(UserError):
                self.call('case-task-add', text=text)
        for i in range(102):
            self.call('case-task-add', text=f'Follow-up {i}')
        first = self.call('case-management')
        second = self.call('case-management', offset=100)
        self.assertEqual(len(first['tasks']), 100)
        self.assertTrue(first['has_more'])
        self.assertEqual(len(second['tasks']), 2)
        self.assertFalse(second['has_more'])
        self.assertEqual(len({t['id'] for t in first['tasks'] + second['tasks']}), 102)
        self.assertEqual(len(first['activity']), 30)


if __name__ == '__main__':
    unittest.main()
