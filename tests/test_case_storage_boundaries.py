"""Case identity must be established before desktop or CLI writes are allowed."""
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile import core
from lawliet_mobile.desktop_bridge import DesktopBridge


class CaseStorageBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / 'workspace # percent%'
        self.a = core.create_case(self.workspace, 'A', 'Case A')
        self.b = core.create_case(self.workspace, 'B', 'Case B')

    def refuse(self, case='A', message=None):
        assertion = self.assertRaisesRegex(core.UserError, message) if message else self.assertRaises(core.UserError)
        with assertion, core.connect(self.workspace, case):
            self.fail('An aliased or mismatched database must not be yielded to a writer')

    def test_regular_case_commits_and_escaped_workspace_uri_is_preserved(self):
        with core.connect(self.workspace, 'A') as (root, db):
            self.assertEqual(root, self.a.resolve())
            self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone()[0], 1)
            db.execute("INSERT INTO meta VALUES ('boundary_test', 'committed')")
        with core.connect(self.workspace, 'A') as (_, db):
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key='boundary_test'").fetchone()[0], 'committed')

    def test_missing_database_is_not_created(self):
        (self.a / 'case.sqlite').unlink()
        self.refuse(message='Unknown case')
        self.assertFalse((self.a / 'case.sqlite').exists())

    def test_database_removed_after_check_is_not_recreated_by_sqlite(self):
        actual = sqlite3.connect
        def removed(*args, **kwargs):
            (self.a / 'case.sqlite').unlink()
            return actual(*args, **kwargs)
        with patch.object(core.sqlite3, 'connect', side_effect=removed):
            with self.assertRaises(sqlite3.OperationalError), core.connect(self.workspace, 'A'):
                self.fail('A disappeared database must not be created again')
        self.assertFalse((self.a / 'case.sqlite').exists())

    def test_database_replaced_during_connection_is_refused(self):
        actual = sqlite3.connect
        before = core.digest(self.b / 'case.sqlite')
        def replaced(*args, **kwargs):
            (self.a / 'case.sqlite').rename(self.a / 'original.sqlite')
            shutil.copyfile(self.b / 'case.sqlite', self.a / 'case.sqlite')
            return actual(*args, **kwargs)
        with patch.object(core.sqlite3, 'connect', side_effect=replaced):
            self.refuse(message='changed while opening')
        self.assertEqual(core.digest(self.b / 'case.sqlite'), before)

    def test_linked_database_cannot_modify_another_case_through_desktop(self):
        before = core.digest(self.b / 'case.sqlite')
        (self.a / 'case.sqlite').unlink()
        os.link(self.b / 'case.sqlite', self.a / 'case.sqlite')
        bridge = DesktopBridge(self.workspace, timeout=15)
        try:
            response = bridge.request({'action': 'case-update', 'case': 'A',
                'values': {'client': 'must not enter B'}, 'revision': 0})
        finally:
            bridge._close()
        self.assertFalse(response['ok'], response)
        self.assertIn('single-link', response['error'])
        self.assertEqual(core.digest(self.b / 'case.sqlite'), before)

    def test_copied_foreign_database_is_refused_before_yield_or_pragma(self):
        shutil.copyfile(self.b / 'case.sqlite', self.a / 'case.sqlite')
        statements = []
        actual = sqlite3.connect
        def tracked(*args, **kwargs):
            db = actual(*args, **kwargs)
            db.set_trace_callback(statements.append)
            return db
        with patch.object(core.sqlite3, 'connect', side_effect=tracked):
            self.refuse(message='identity does not match')
        self.assertFalse(any(text.lstrip().upper().startswith(('PRAGMA', 'INSERT', 'UPDATE', 'DELETE'))
                             for text in statements), statements)

    def test_missing_metadata_is_refused(self):
        with sqlite3.connect(self.a / 'case.sqlite') as db:
            db.execute("DELETE FROM meta WHERE key='case_id'")
        db.close()
        self.refuse(message='identity does not match')

    def test_nonregular_database_is_refused_before_sqlite(self):
        (self.a / 'case.sqlite').unlink()
        (self.a / 'case.sqlite').mkdir()
        with patch.object(core.sqlite3, 'connect', side_effect=AssertionError('must not open')):
            self.refuse(message='regular, single-link')

    def test_aliased_sidecars_are_refused_before_sqlite_can_recover_or_write(self):
        before = core.digest(self.b / 'case.sqlite')
        for suffix in ('-journal', '-wal', '-shm'):
            with self.subTest(suffix=suffix):
                companion = self.a / ('case.sqlite' + suffix)
                os.link(self.b / 'case.sqlite', companion)
                try:
                    with patch.object(core.sqlite3, 'connect', side_effect=AssertionError('must not open')):
                        self.refuse(message='companion')
                finally:
                    companion.unlink()
        self.assertEqual(core.digest(self.b / 'case.sqlite'), before)

    @unittest.skipUnless(os.name == 'posix', 'POSIX symbolic-link fixture; Windows junction tested separately')
    def test_symbolic_database_and_case_directory_are_refused(self):
        before = core.digest(self.b / 'case.sqlite')
        (self.a / 'case.sqlite').unlink()
        (self.a / 'case.sqlite').symlink_to(self.b / 'case.sqlite')
        self.refuse(message='single-link')
        (self.workspace / 'ALIAS').symlink_to(self.b, target_is_directory=True)
        self.refuse('ALIAS', 'regular directory')
        self.assertEqual(core.digest(self.b / 'case.sqlite'), before)

    @unittest.skipUnless(os.name == 'nt', 'Windows directory-junction fixture')
    def test_windows_case_junction_is_refused_even_inside_workspace(self):
        alias = self.workspace / 'ALIAS'
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(alias), str(self.b)],
                       check=True, capture_output=True)
        try:
            self.refuse('ALIAS', 'regular directory')
        finally:
            alias.rmdir()


if __name__ == '__main__':
    unittest.main()
