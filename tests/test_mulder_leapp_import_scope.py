"""Mobile import adapters must consume only active-case authorized inputs."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.core import create_case, connect
from lawliet_mobile.mulder_ownership import bind_review_case
try:
    from mulder.db import CaseDB
    from mulder.server import app
    from mulder.server.tools import phone
    from mulder.server.case_scope import resolve_case_read_path
except ImportError:
    app = None


@unittest.skipUnless(app, 'Requires scoped Mulder mobile-import adapter')
class MobileInputScopeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve(); self.store = self.base/'cases'
        self.evidence = {}; self.review = {}
        for name in ('A', 'B'):
            source = self.base/('evidence-'+name); source.mkdir(); self.evidence[name] = source
            (source/'chat.txt').write_text('10/01/26, 09:00 - Jamie: '+name+'_PRIVATE_CHAT\n')
            (source/'contact.vcf').write_text('BEGIN:VCARD\nVERSION:3.0\nFN:Jamie '+name+'\nTEL:+12025550101\nEND:VCARD\n')
            with closing(sqlite3.connect(source/'mmssms.db')) as db:
                db.execute('CREATE TABLE sms(_id INTEGER,address TEXT,date INTEGER,type INTEGER,body TEXT)')
                db.execute('INSERT INTO sms VALUES(1,?,1700000000000,1,?)', ('+12025550101',name+'_PRIVATE_SMS')); db.commit()
            parent = CaseDB.create(name, str(source), self.store); parent.close()
            workspace = self.store/'lawliet-review'; create_case(workspace, name+'-review')
            self.review[name] = workspace/(name+'-review')
            bind_review_case(self.review[name], self.store/(name+'.db'))
        for name,value in [('_cfg',app.ServerConfig(self.store)),('_ctx',None),('_job_store',None),('_active_case_operations',0),('_transition_owner',None),('_transition_depth',0)]:
            p=patch.object(app,name,value);p.start();self.addCleanup(p.stop)
        token=app._bound_case.set(app._UNBOUND_CASE);self.addCleanup(app._bound_case.reset,token)
        app.load_case('A');self.addCleanup(self.close_case)
        output=self.base/'synthetic-leapp-output';output.mkdir()
        (output/'Messages.tsv').write_text('Timestamp\tBody\n2023-09-20T20:09:49Z\tA_PRIVATE_REPORT\n')
        self.retained=phone._retain_leapp_output(output,'tc_test_owned','aleapp')

    def close_case(self):
        if app._ctx:
            app._ctx.db.close();app._ctx=None

    def call(self,name,**args):return app._tool_dispatch_sync[name](**args)

    def counts(self,name):
        root=self.review[name]
        with connect(root.parent,root.name) as (_,db):
            return tuple(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in ('evidence','artifacts','audit'))

    def test_foreign_retained_report_refused_without_import_then_owner_passes(self):
        original=hashlib.sha256((self.retained/'Messages.tsv').read_bytes()).hexdigest()
        app.load_case('B');before=self.counts('B')
        with patch('lawliet_mobile.parsed_import.import_parsed',side_effect=AssertionError('Foreign report reached importer')) as child:
            with self.assertRaises(ValueError):
                self.call('import_ancalor_leapp_review',case_path=str(self.review['B']),report_path=str(self.retained))
            child.assert_not_called()
        self.assertEqual(self.counts('B'),before)
        app.load_case('A')
        result=self.call('import_ancalor_leapp_review',case_path=str(self.review['A']),report_path=str(self.retained))
        self.assertEqual(result['import']['records'],1);self.assertTrue(result['integrity']['ok'])
        with connect(self.review['A'].parent,self.review['A'].name) as (_,db):
            self.assertIn('A_PRIVATE_REPORT',db.execute('SELECT body FROM artifacts').fetchone()[0])
        self.assertEqual(hashlib.sha256((self.retained/'Messages.tsv').read_bytes()).hexdigest(),original)

    def test_unclaimed_legacy_and_symlink_reports_fail_closed(self):
        unclaimed=self.store/'retained-tools'/'legacy';unclaimed.mkdir()
        (unclaimed/'Messages.tsv').write_text('Timestamp\tBody\n2020-01-01T00:00:00Z\tUNCLAIMED\n')
        link=self.store/'retained-tools'/'linked';link.symlink_to(self.retained)
        before=self.counts('A')
        with patch('lawliet_mobile.parsed_import.import_parsed',side_effect=AssertionError('Unproven input reached importer')) as child:
            for path in (unclaimed,link,self.evidence['A']):
                with self.subTest(path=path),self.assertRaises(ValueError):
                    self.call('import_ancalor_leapp_review',case_path=str(self.review['A']),report_path=str(path))
            child.assert_not_called()
        self.assertEqual(self.counts('A'),before)

    def test_foreign_export_and_native_inputs_refused_before_case_creation(self):
        before=sorted((self.store/'lawliet-review').iterdir())
        with patch('lawliet_mobile.core.create_case',side_effect=AssertionError('Foreign input created a review case')) as child:
            for name,file in [('run_ancalor_export_review','contact.vcf'),('run_ancalor_native_review','mmssms.db')]:
                with self.subTest(tool=name):
                    result=self.call(name,evidence_path=str(self.evidence['B']/file))
                    self.assertEqual(result['status'],'error');self.assertEqual(result['error_type'],'case_scope_invalid')
            child.assert_not_called()
        self.assertEqual(sorted((self.store/'lawliet-review').iterdir()),before)
        self.assertEqual(app.get_ctx().db.get_source_count(),0)

    def test_foreign_chat_input_refused_before_import(self):
        before=self.counts('A')
        with patch('lawliet_mobile.messages.import_chat',side_effect=AssertionError('Foreign chat reached importer')) as child:
            with self.assertRaises(ValueError):
                self.call('import_ancalor_chat_review',case_path=str(self.review['A']),evidence_path=str(self.evidence['B']/'chat.txt'),date_order='mdy')
            child.assert_not_called()
        self.assertEqual(self.counts('A'),before)

    def test_all_four_routes_refuse_without_active_case_before_child_calls(self):
        ctx=app._ctx;app._ctx=None
        try:
            with patch('lawliet_mobile.core.create_case',side_effect=AssertionError('No-case creation')) as creator,patch('lawliet_mobile.messages.import_chat',side_effect=AssertionError('No-case chat')) as chat,patch('lawliet_mobile.parsed_import.import_parsed',side_effect=AssertionError('No-case report')) as report:
                for name,file in [('run_ancalor_export_review','contact.vcf'),('run_ancalor_native_review','mmssms.db')]:
                    result=self.call(name,evidence_path=str(self.evidence['A']/file))
                    self.assertEqual(result['status'],'error');self.assertEqual(result['error_type'],'case_scope_invalid')
                for name,args in [('import_ancalor_chat_review',{'evidence_path':str(self.evidence['A']/'chat.txt'),'date_order':'mdy'}),('import_ancalor_leapp_review',{'report_path':str(self.retained)})]:
                    with self.assertRaises(RuntimeError):self.call(name,case_path=str(self.review['A']),**args)
                creator.assert_not_called();chat.assert_not_called();report.assert_not_called()
        finally:app._ctx=ctx

    def test_same_case_export_native_and_chat_run_real_importers(self):
        before={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.evidence['A'].iterdir()}
        export=self.call('run_ancalor_export_review',evidence_path=str(self.evidence['A']/'contact.vcf'))
        native=self.call('run_ancalor_native_review',evidence_path=str(self.evidence['A']/'mmssms.db'),platform='android')
        chat=self.call('import_ancalor_chat_review',case_path=str(self.review['A']),evidence_path=str(self.evidence['A']/'chat.txt'),date_order='mdy',year_century=2000)
        self.assertEqual(export['status'],'success');self.assertGreaterEqual(export['result']['records'],1)
        self.assertEqual(native['status'],'success');self.assertGreaterEqual(native['result']['records'],1)
        self.assertTrue(export['result']['originals_unchanged']);self.assertTrue(native['result']['originals_unchanged']);self.assertTrue(chat['integrity']['ok'])
        self.assertEqual({p:hashlib.sha256(p.read_bytes()).hexdigest() for p in before},before)

    def test_claimed_derived_file_remains_valid_for_export(self):
        output=self.base/'synthetic-contact-output';output.mkdir()
        (output/'contact.vcf').write_bytes((self.evidence['A']/'contact.vcf').read_bytes())
        retained=phone._retain_leapp_output(output,'tc_derived_contact','synthetic')
        result=self.call('run_ancalor_export_review',evidence_path=str(retained/'contact.vcf'))
        self.assertEqual(result['status'],'success');self.assertGreaterEqual(result['result']['records'],1)

    def test_native_container_profile_keeps_stricter_root_policy(self):
        # Shared scope validation must run before any container setup/intake.
        with patch.dict('os.environ',{'LAWLIET_MCP_PROFILE':'native-container'}),patch('lawliet_mobile.native_container.configured',side_effect=AssertionError('Foreign input reached profile setup')) as setup:
            result=self.call('run_ancalor_native_review',evidence_path=str(self.evidence['B']/'mmssms.db'))
            self.assertEqual(result['error_type'],'case_scope_invalid');setup.assert_not_called()


if __name__=='__main__':unittest.main()
