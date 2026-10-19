"""MCP acquisition boundary must reject unsafe scope before invoking ADB."""
import inspect
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from lawliet_mobile.core import create_case, UserError
from lawliet_mobile.mulder_ownership import bind_review_case

try:
    from mulder.server.tools.phone import collect_lawliet_android_sms
except ImportError:
    collect_lawliet_android_sms = None


@unittest.skipUnless(collect_lawliet_android_sms, 'Requires patched Mulder runtime')
class MulderSMSProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.workspace = self.base/'lawliet-review'
        create_case(self.workspace, 'A'); self.case = self.workspace/'A'
        self.collect = inspect.unwrap(collect_lawliet_android_sms)
        parent=self.base/'active.db'
        with closing(sqlite3.connect(parent)) as db:
            db.execute('CREATE TABLE case_metadata(case_id TEXT,ingested_at TEXT)')
            db.execute("INSERT INTO case_metadata VALUES('active','2026-10-14-test')")
            db.commit()
        bind_review_case(self.case,parent)
        self.ctx = SimpleNamespace(db=SimpleNamespace(db_path=self.base/'active.db'))

    def test_invalid_parameters_never_collect(self):
        bad = [{'serial':x} for x in ('', '-x', 'a b', 'a/b', True)]
        for field,values in [('timeout_seconds',[True,0,301,1.5]),('max_bytes',[True,0,64*1024**2+1]),('max_messages',[True,0,20001]),('android_user',[True,-1,2147483648]),('prefix',['','x\n','x'*129,True])]:
            bad.extend({field:v} for v in values)
        with patch('lawliet_mobile.provider_sms.collect_sms', side_effect=AssertionError('Must not collect')):
            for params in bad:
                with self.subTest(params=params), self.assertRaises(ValueError):
                    self.collect(**{'case_path':str(self.case),'serial':'FIXTURE',**params})

    def test_foreign_case_and_symlink_never_collect(self):
        foreign = self.base/'foreign'; create_case(foreign, 'B')
        link = self.workspace/'linked'; link.symlink_to(self.case)
        with patch('mulder.server.tools.phone.get_ctx', return_value=self.ctx), patch('lawliet_mobile.provider_sms.collect_sms', side_effect=AssertionError('Must not collect')):
            for case in (foreign/'B',link):
                with self.subTest(case=case), self.assertRaises((ValueError,UserError)):
                    self.collect(str(case),'FIXTURE')

    def test_other_active_parent_never_reaches_collector(self):
        parent=self.base/'OTHER.db'
        with closing(sqlite3.connect(parent)) as db:
            db.execute('CREATE TABLE case_metadata(case_id TEXT,ingested_at TEXT)')
            db.execute("INSERT INTO case_metadata VALUES('OTHER','2026-10-14-test')");db.commit()
        ctx=SimpleNamespace(db=SimpleNamespace(db_path=parent))
        before=(self.case/'case.sqlite').read_bytes()
        with patch('mulder.server.tools.phone.get_ctx',return_value=ctx),patch('lawliet_mobile.provider_sms.collect_sms',side_effect=AssertionError('Must not collect')):
            with self.assertRaisesRegex(UserError,'another'):
                self.collect(str(self.case),'FIXTURE')
        self.assertEqual((self.case/'case.sqlite').read_bytes(),before)

    def test_exact_profile_and_caps_dispatch_with_failure_preserved(self):
        receipt = {'status':'failed','records':0,'coverage':[{'state':'failed'}]}
        with patch('mulder.server.tools.phone.get_ctx', return_value=self.ctx), patch('lawliet_mobile.provider_sms.collect_sms', return_value=receipt) as call:
            result = self.collect(str(self.case),'FIXTURE',7,10,'LM-SEED',30,4096)
            args,kw = call.call_args
            self.assertEqual((args[0],args[2],args[3]),(self.case,self.workspace,'FIXTURE'))
            self.assertEqual(kw,{'timeout':30,'max_bytes':4096,'max_messages':7,'user':10,'prefix':'LM-SEED'})
            self.assertEqual(result['collection'],receipt)
            self.assertNotIn('records',result)
