"""Readiness observations must not become acquisition or privilege claims."""
import json
import hashlib
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,verify,UserError
from lawliet_mobile.phone_assessment import assess_android,provider_state


class AssessmentScopeTests(unittest.TestCase):
    def test_only_successful_exact_provider_responses_establish_readability(self):
        self.assertEqual(provider_state('No result found.\n'),'readable_empty')
        self.assertEqual(provider_state('Row: 0 _id=5\nRow: 1 _id=6\n'),'readable_ids_only')
        for raw,code,err in [('No result found.\n',1,''),('No result found.\n',0,'warning'),
                ('Error: No result found.\n',0,''),('Row: 0 _id=5\nError\n',0,''),
                ('Row: 0 _id=5\nRow: 1 _id=5\n',0,''),('Row: 1 _id=5\n',0,''),
                ('Error while accessing provider\njava.lang.IllegalArgumentException: Invalid column typeof(calendar_id)\n',0,''),
                ('',0,'')]:
            with self.subTest(raw=raw,code=code,err=err):
                self.assertEqual(provider_state(raw,code,err),'unresolved')
        self.assertEqual(provider_state('No result found.\n',0,'java.lang.SecurityException: denied'),'access_denied')

    def assess(self,*,user=None,current=('10','10'),provider_stderr='',provider_exit=0,large=False):
        with tempfile.TemporaryDirectory() as tmp:
            ws=Path(tmp)/'cases';create_case(ws,'A');commands=[];users=iter(current)
            def transport(argv,out,timeout,**kwargs):
                commands.append(argv);stderr='';code=0
                if large:raw='x'*2048
                elif argv[-1]=='get-state':raw='device\n'
                elif argv[-1]=='getprop':raw='[ro.product.model]: [SM-A176U]\n[ro.soc.model]: [s5e8535]\n[ro.build.fingerprint]: [test-build]\n'
                elif argv[-1]=='get-current-user':raw=next(users)+'\n'
                elif argv[-1]=='su':raw='/system/bin/su\n'
                elif '--projection' in argv[-1]:
                    args=shlex.split(argv[-1]);self.assertEqual(args[args.index('--user')+1],str(10 if user is None else user))
                    self.assertEqual(args[args.index('--projection')+1],'_id')
                    raw='No result found.\n';stderr=provider_stderr;code=provider_exit
                else:raw='2026-10-15T12:00:00+0000\n'
                out.write_text(raw);err=Path(str(out)+'.stderr');err.write_text(stderr)
                return {'argv':argv,'returncode':code,'stdout':str(out),'stderr':str(err)}
            with connect(ws,'A') as(root,db),patch('lawliet_mobile.phone_assessment.command',return_value=['adb']), \
                    patch('lawliet_mobile.phone_assessment.execute',side_effect=transport):
                budget=patch('lawliet_mobile.phone_assessment.MAX_ASSESSMENT_BYTES',1024) if large else patch('lawliet_mobile.phone_assessment.MAX_ASSESSMENT_BYTES',8*1024**2)
                with budget:result=assess_android(root,db,ws,'TEST',android_user=user)
                saved=json.loads(Path(result['path']).read_text())
                self.assertEqual(saved,{k:v for k,v in result.items() if k!='path'})
                finished=json.loads(db.execute("SELECT detail FROM audit WHERE action='assessment.finished'").fetchone()[0])
                self.assertEqual(finished['sha256'],hashlib.sha256(Path(result['path']).read_bytes()).hexdigest())
                self.assertTrue(verify(root,db)['ok'])
                self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
                self.assertFalse(any(part in {'install','grant','root','unlock','setprop','su -c'} for cmd in commands for part in cmd))
                return result,commands

    def test_current_profile_change_keeps_queries_bound_and_marks_partial(self):
        result,commands=self.assess(current=('10','11'))
        self.assertEqual((result['android_user'],result['status']),(10,'partial'))
        self.assertEqual(len(result['providers']),4)
        self.assertFalse(result['collection_performed'])
        self.assertIn('not acquisition',result['providers']['calendars']['scope'])

    def test_explicit_user_does_not_query_or_switch_foreground_user(self):
        result,commands=self.assess(user=12,current=())
        self.assertEqual((result['status'],result['android_user']),('assessed',12))
        self.assertFalse(any(cmd[-1]=='get-current-user' for cmd in commands))

    def test_unknown_current_user_stops_before_provider_probes(self):
        result,commands=self.assess(current=('unknown',))
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['providers'],{})
        self.assertFalse(any('--projection' in cmd[-1] for cmd in commands))

    def test_su_path_and_empty_providers_do_not_qualify_full_filesystem(self):
        result,_=self.assess(user=0,current=())
        self.assertEqual(result['root_command'],'present_unverified')
        self.assertFalse(result['full_filesystem_qualified'])
        self.assertEqual(result['device']['ro.soc.model'],'s5e8535')
        self.assertEqual(result['routes'][-1]['state'],'not_established')

    def test_failed_provider_exit_never_becomes_empty_success(self):
        result,_=self.assess(user=0,current=(),provider_exit=1)
        self.assertTrue(all(p['state']=='unresolved' for p in result['providers'].values()))

    def test_over_budget_response_stops_before_next_command(self):
        result,commands=self.assess(large=True)
        self.assertEqual(result['status'],'failed')
        self.assertEqual(len(commands),1)

    def test_linked_assessment_parent_rejected_before_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);ws=base/'cases';create_case(ws,'A')
            foreign=base/'foreign';foreign.mkdir()
            (ws/'A/assessments').symlink_to(foreign)
            with connect(ws,'A') as(root,db), \
                    patch('lawliet_mobile.phone_assessment.execute',side_effect=AssertionError('no transport')):
                with self.assertRaises((OSError,UserError)):
                    assess_android(root,db,ws,'TEST',android_user=0)
            self.assertEqual(list(foreign.iterdir()),[])

    def test_rejected_log_link_is_not_reopened_for_final_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);ws=base/'cases';create_case(ws,'A')
            foreign=base/'foreign';foreign.write_text('FOREIGN_MARKER')
            def transport(argv,out,timeout,**kwargs):
                out.symlink_to(foreign)
                stderr=Path(str(out)+'.stderr');stderr.write_text('')
                return {'argv':argv,'returncode':0,'stdout':str(out),'stderr':str(stderr)}
            with connect(ws,'A') as(root,db), \
                    patch('lawliet_mobile.phone_assessment.command',return_value=['adb']), \
                    patch('lawliet_mobile.phone_assessment.execute',side_effect=transport):
                result=assess_android(root,db,ws,'TEST',android_user=0)
            self.assertEqual(result['status'],'failed')
            self.assertNotIn('state.txt',result['log_hashes'])
            self.assertEqual([x['name'] for x in result['unverified_logs']],['state.txt'])
            self.assertNotIn('FOREIGN_MARKER',Path(result['path']).read_text())
            self.assertEqual(foreign.read_text(),'FOREIGN_MARKER')

    def test_precreated_report_link_is_not_overwritten_or_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);ws=base/'cases';create_case(ws,'A')
            foreign=base/'foreign';foreign.write_text('UNCHANGED')
            def transport(argv,out,timeout,**kwargs):
                report=out.parent/'assessment.json'
                if not report.exists():report.symlink_to(foreign)
                out.write_text('device\n' if argv[-1]=='get-state' else '')
                stderr=Path(str(out)+'.stderr');stderr.write_text('')
                return {'argv':argv,'returncode':0,'stdout':str(out),'stderr':str(stderr)}
            with connect(ws,'A') as(root,db), \
                    patch('lawliet_mobile.phone_assessment.command',return_value=['adb']), \
                    patch('lawliet_mobile.phone_assessment.execute',side_effect=transport):
                result=assess_android(root,db,ws,'TEST',android_user=0)
            self.assertEqual(result['status'],'failed')
            self.assertIsNone(result['path'])
            self.assertEqual(foreign.read_text(),'UNCHANGED')


if __name__=='__main__':unittest.main()
