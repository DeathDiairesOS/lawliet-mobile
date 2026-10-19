"""Real SQLite page quotas must not publish rolled-back report results."""
import hashlib,json,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import UserError,connect,create_case,verify
from lawliet_mobile.parsed_import import import_parsed
import lawliet_mobile.parsed_import as module

class ParsedImportDiskQuota(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.ws=self.base/'cases';create_case(self.ws,'A')

    def source(self,folder=False,large=True):
        if folder:
            p=self.base/'reports';p.mkdir();(p/'Other.tsv').write_text('A\tB\nsmall\tprelude\nlarge\t'+('X'*200000 if large else 'value')+'\n')
        else:
            p=self.base/'source.jsonl';p.write_text(json.dumps({'category':'messages','body':'small prelude','data':{}})+'\n'+json.dumps({'category':'messages','body':'X'*200000 if large else 'last row','data':{}})+'\n')
        return p

    def assert_failed_zero(self,root,db):
        r=db.execute('SELECT status,records,detail FROM runs ORDER BY rowid DESC LIMIT 1').fetchone()
        self.assertEqual((r['status'],r['records']),('failed',0));self.assertIn('runner_ownership',json.loads(r['detail']))
        self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM artifact_runs').fetchone()[0],0)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='parsed_import.complete'").fetchone()[0],0)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='parsed_import.failed'").fetchone()[0],1)
        self.assertTrue(verify(root,db)['ok'])

    def body_quota(self,folder):
        p=self.source(folder);sourcefiles=[p] if p.is_file() else list(p.iterdir());hashes={f:hashlib.sha256(f.read_bytes()).hexdigest() for f in sourcefiles}
        with connect(self.ws,'A') as (root,db):
            originalmax=db.execute('PRAGMA max_page_count').fetchone()[0];pages=db.execute('PRAGMA page_count').fetchone()[0];db.execute(f'PRAGMA max_page_count={pages+20}')
            with self.assertRaisesRegex(UserError,'database or disk is full'):
                import_parsed(root,db,p,'jsonl')
            self.assert_failed_zero(root,db)
            detail=json.loads(db.execute('SELECT detail FROM runs').fetchone()[0]);self.assertEqual(detail['sqlite_error_name'],'SQLITE_FULL')
            db.execute(f'PRAGMA max_page_count={originalmax}')
            r=import_parsed(root,db,p,'jsonl');self.assertEqual(r['records'],2)
            self.assertEqual([(r['status'],r['records']) for r in db.execute('SELECT status,records FROM runs ORDER BY rowid')],[('failed',0),('complete',2)])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],2)
            self.assertTrue(verify(root,db)['ok'])
        self.assertEqual(hashes,{f:hashlib.sha256(f.read_bytes()).hexdigest() for f in sourcefiles})

    def test_jsonl_real_full_rolls_back_and_persists_failed_then_retries(self):self.body_quota(False)
    def test_folder_real_full_rolls_back_and_persists_failed_then_retries(self):self.body_quota(True)

    def test_completion_metadata_quota_never_commits_rows_first(self):
        for folder in [False,True]:
            with self.subTest(folder=folder):
                # Separate case/source per branch so prior failure history is not reused.
                if folder:create_case(self.ws,'B')
                p=self.source(folder,large=False)
                with connect(self.ws,'B' if folder else 'A') as (root,db):
                    db.execute('CREATE TABLE quota_fill(payload BLOB)');db.commit();pages=db.execute('PRAGMA page_count').fetchone()[0];db.execute(f'PRAGMA max_page_count={pages+20}')
                    actual=module.audit
                    def exhaust(database,action,detail):
                        if action=='parsed_import.complete':database.execute('INSERT INTO quota_fill VALUES(zeroblob(200000))')
                        return actual(database,action,detail)
                    with patch.object(module,'audit',side_effect=exhaust):
                        with self.assertRaisesRegex(UserError,'database or disk is full'):import_parsed(root,db,p,'jsonl')
                    self.assert_failed_zero(root,db)

    def test_other_sqlite_error_records_failed_not_running(self):
        p=self.source(large=False)
        with connect(self.ws,'A') as (root,db):
            with patch.object(module,'add_artifact',side_effect=sqlite3.OperationalError('controlled invalid SQLite operation')):
                with self.assertRaisesRegex(UserError,'controlled invalid'):import_parsed(root,db,p,'jsonl')
            self.assert_failed_zero(root,db)

    def test_unwritable_terminal_metadata_is_explicitly_unresolved(self):
        p=self.source(large=False)
        with connect(self.ws,'A') as (root,db):
            class UnwritableFailure:
                def __getattr__(self,name):return getattr(db,name)
                def execute(self,sql,args=()):
                    if sql.startswith('UPDATE runs SET status=') and args[0]=='failed':raise sqlite3.OperationalError('controlled failure-state storage unavailable')
                    return db.execute(sql,args)
            actual=module.audit
            def fail_complete(database,action,detail):
                if action=='parsed_import.complete':raise sqlite3.OperationalError('controlled finalization failure')
                return actual(database,action,detail)
            with patch.object(module,'audit',side_effect=fail_complete):
                with self.assertRaisesRegex(UserError,'terminal state could not be recorded.*unresolved'):
                    import_parsed(root,UnwritableFailure(),p,'jsonl')
            self.assertEqual(db.execute('SELECT status,records FROM runs').fetchone()[:],('running',0))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='parsed_import.complete'").fetchone()[0],0)
            self.assertTrue(verify(root,db)['ok'])

    def test_real_startup_quota_rolls_back_unaudited_run_in_same_connection(self):
        p=self.source(large=False)
        with connect(self.ws,'A') as (root,db):
            originalmax=db.execute('PRAGMA max_page_count').fetchone()[0]
            pages=db.execute('PRAGMA page_count').fetchone()[0]
            db.execute(f'PRAGMA max_page_count={pages+1}')
            with self.assertRaises(sqlite3.Error):import_parsed(root,db,p,'jsonl')
            self.assertFalse(db.in_transaction)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='parsed_import.started'").fetchone()[0],0)
            db.execute(f'PRAGMA max_page_count={originalmax}')
            result=import_parsed(root,db,p,'jsonl');self.assertEqual(result['records'],2)
            self.assertEqual([(r['status'],r['records']) for r in db.execute('SELECT status,records FROM runs')],[('complete',2)])
            self.assertTrue(verify(root,db)['ok'])
