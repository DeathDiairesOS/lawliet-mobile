"""Current and historical review folders retain the same case boundaries."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lawliet_mobile.core import UserError, create_case

try:
    from mulder.server.tools import phone, ancalor_sqlite_workspace
except ModuleNotFoundError as error:
    if error.name != 'mulder':
        raise
    phone = ancalor_sqlite_workspace = None


@unittest.skipUnless(phone, 'Requires patched Mulder runtime')
class MulderReviewFolderCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.ctx = SimpleNamespace(db=SimpleNamespace(db_path=self.base / 'active.db'))
        for module in (phone, ancalor_sqlite_workspace):
            context = patch.object(module, 'get_ctx', return_value=self.ctx)
            context.start()
            self.addCleanup(context.stop)

    def test_current_and_historical_direct_children(self):
        for folder in ('lawliet-review', 'ancalor-review'):
            create_case(self.base / folder, 'retained')
            case = self.base / folder / 'retained'
            self.assertEqual(phone._ancalor_review_case(str(case)), case)
            self.assertEqual(ancalor_sqlite_workspace._review_case(str(case)), case)

    def test_other_active_case_refused_for_both_names(self):
        for folder in ('lawliet-review', 'ancalor-review'):
            create_case(self.base / 'other' / folder, 'foreign')
            case = self.base / 'other' / folder / 'foreign'
            with self.assertRaises(ValueError):
                phone._ancalor_review_case(str(case))
            with self.assertRaises(UserError):
                ancalor_sqlite_workspace._review_case(str(case))

    def test_symlink_review_container_refused(self):
        create_case(self.base / 'outside', 'retained')
        (self.base / 'lawliet-review').symlink_to(self.base / 'outside', target_is_directory=True)
        case = self.base / 'lawliet-review' / 'retained'
        with self.assertRaises(ValueError):
            phone._ancalor_review_case(str(case))
        with self.assertRaises(UserError):
            ancalor_sqlite_workspace._review_case(str(case))
