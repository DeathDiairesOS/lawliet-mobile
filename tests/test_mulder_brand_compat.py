"""Current and historical review folders retain the same case boundaries."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lawliet_mobile.core import UserError, create_case
from lawliet_mobile.mulder_ownership import bind_review_case

try:
    from mulder.audit import AuditLog
    from mulder.db import CaseDB
    from mulder.server import app
    from mulder.server.tools import phone, lawliet_sqlite_workspace
except ModuleNotFoundError as error:
    if error.name != 'mulder':
        raise
    phone = lawliet_sqlite_workspace = None


@unittest.skipUnless(phone, 'Requires patched Mulder runtime')
class MulderReviewFolderCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.parent = CaseDB.create('active', str(self.base), self.base)
        self.addCleanup(self.parent.close)
        self.ctx = SimpleNamespace(case_id='active', db=self.parent,
                                   audit=AuditLog(self.base / 'active-audit.jsonl'))
        context = patch.object(app, '_ctx', self.ctx)
        context.start()
        self.addCleanup(context.stop)

    def test_current_and_historical_direct_children(self):
        for folder in ('lawliet-review', 'ancalor-review'):
            create_case(self.base / folder, 'retained')
            case = self.base / folder / 'retained'
            bind_review_case(case, self.parent.db_path)
            self.assertEqual(phone._ancalor_review_case(str(case)), case)
            self.assertEqual(lawliet_sqlite_workspace._review_case(str(case)), case)

    def test_other_active_case_refused_for_both_names(self):
        for folder in ('lawliet-review', 'ancalor-review'):
            create_case(self.base / 'other' / folder, 'foreign')
            case = self.base / 'other' / folder / 'foreign'
            with self.assertRaises(UserError):
                phone._ancalor_review_case(str(case))
            with self.assertRaises(UserError):
                lawliet_sqlite_workspace._review_case(str(case))

    def test_symlink_review_container_refused(self):
        create_case(self.base / 'outside', 'retained')
        (self.base / 'lawliet-review').symlink_to(self.base / 'outside', target_is_directory=True)
        case = self.base / 'lawliet-review' / 'retained'
        with self.assertRaises(UserError):
            phone._ancalor_review_case(str(case))
        with self.assertRaises(UserError):
            lawliet_sqlite_workspace._review_case(str(case))

    def test_unbound_direct_children_do_not_inherit_active_case_scope(self):
        for folder in ('lawliet-review', 'ancalor-review'):
            case = create_case(self.base / folder, 'unbound')
            for resolve in (phone._ancalor_review_case, lawliet_sqlite_workspace._review_case):
                with self.assertRaisesRegex(UserError, 'not bound'):
                    resolve(str(case))
