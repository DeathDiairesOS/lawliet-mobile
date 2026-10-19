"""Successful subprocess exits must not conceal retained-case evidence damage."""
import json
import tempfile
import unittest
from pathlib import Path

from lawliet_mobile import tools
from lawliet_mobile.core import UserError, connect, create_case, import_evidence, verify


class PostParserIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base/'cases'
        create_case(self.workspace, 'A')
        source = self.base/'input'; source.mkdir()
        (source/'original.txt').write_text('ORIGINAL')
        with connect(self.workspace, 'A') as (root, db):
            self.eid = import_evidence(root, db, source, 'unknown')[0]
            self.retained = root/'evidence'/self.eid/'original.txt'

    def assert_damage_refused(self, engine, mutation):
        worker = self.base/'worker.py'
        output = ("out=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);"
                  "(out/'fixture.tsv').write_text('Field\\nUNTRUSTED_RESULT\\n')\n"
                  if engine in ('aleapp', 'ileapp') else
                  "print(json.dumps([{'SourceFile':str(pathlib.Path(sys.argv[-1])/'original.txt'),'FileName':'original.txt'}]))\n")
        worker.write_text('import pathlib,sys,json\n'+mutation+'\n'+output)
        tools.configure(self.workspace, engine, worker)
        with connect(self.workspace, 'A') as (root, db):
            with self.assertRaisesRegex(UserError, 'after external tool execution'):
                tools.external_analyze(root, db, self.workspace, self.eid, engine, 5)
            run = db.execute('SELECT * FROM runs').fetchone()
            detail = json.loads(run['detail'])
            self.assertEqual((run['status'], run['records']), ('failed', 0))
            self.assertEqual(detail['returncode'], 0)
            self.assertFalse(detail['post_execution_integrity']['ok'])
            self.assertTrue(detail['post_execution_integrity']['failures'])
            self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0], 0)
            self.assertTrue((root/'runs'/run['id']/Path(detail['stdout']).name).is_file())
            self.assertFalse(verify(root, db)['ok'])
            # No automatic restoration or retry can erase the damaged original.
            with self.assertRaisesRegex(UserError, 'Integrity check failed'):
                tools.external_analyze(root, db, self.workspace, self.eid, engine, 5)
            self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0], 1)

    def test_aleapp_overwritten_retained_original_rejects_successful_output(self):
        self.assert_damage_refused('aleapp', f'pathlib.Path({str(self.retained)!r}).write_text("CHANGED")')

    def test_ileapp_deleted_retained_original_rejects_successful_output(self):
        self.assert_damage_refused('ileapp', f'pathlib.Path({str(self.retained)!r}).unlink()')

    def test_exiftool_untracked_retained_file_rejects_successful_output(self):
        added = self.retained.parent/'untracked.txt'
        self.assert_damage_refused('exiftool', f'pathlib.Path({str(added)!r}).write_text("UNTRACKED")')


if __name__ == '__main__':
    unittest.main()
