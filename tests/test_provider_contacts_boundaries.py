import json,shlex,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,verify,UserError
from lawliet_mobile.provider_contacts import collect_contacts
from lawliet_mobile.acquisition import collect_android

class Boundaries(unittest.TestCase):
    def run_collection(self,*,user=None,current=('10','10'),ids='Row: 0 _id=7\n',max_contacts=5,max_bytes=65536,through_host=False):
        with tempfile.TemporaryDirectory() as t:
            ws=Path(t)/'cases';create_case(ws,'A');commands=[];users=iter(current)
            def fake(argv,output,timeout,**kw):
                commands.append(argv)
                if argv[-1]=='get-state':text='device\n'
                elif argv[-3:]==['shell','am','get-current-user']:text=next(users)+'\n'
                else:
                    a=shlex.split(argv[-1]);self.assertEqual(a[a.index('--user')+1],str(user if user is not None else 10))
                    column=a[a.index('--projection')+1];where=a[a.index('--where')+1] if '--where'in a else None
                    text=ids if column=='_id' and where is None else 'Row: 0 display_name=Test\n' if column=='display_name' else 'No result found.\n'
                output.write_bytes(text.encode('utf-8'));err=Path(str(output)+'.stderr');err.write_text('')
                return {'argv':argv,'returncode':0,'stdout':str(output),'stderr':str(err)}
            with connect(ws,'A') as(root,db),patch('lawliet_mobile.provider_contacts.command',return_value=['adb']),patch('lawliet_mobile.provider_contacts.execute',side_effect=fake):
                result=collect_android(root,db,ws,'TEST',profile='contacts-provider',android_user=user) if through_host else collect_contacts(root,db,ws,'TEST',user=user,max_contacts=max_contacts,max_bytes=max_bytes)
                self.assertTrue(verify(root,db)['ok'])
                total=sum(p.stat().st_size for p in Path(result['path']).iterdir() if p.is_file())
                return result,commands,total
    def test_observed_user_is_pinned_and_change_is_partial(self):
        r,c,_=self.run_collection(current=('10','11'))
        self.assertEqual((r['android_user'],r['status'],r['exported_contacts']),(10,'partial',1))
        self.assertEqual(sum(x[-3:]==['shell','am','get-current-user'] for x in c),2)
    def test_explicit_user_does_not_use_current_profile(self):
        r,c,_=self.run_collection(user=12,current=())
        self.assertEqual((r['status'],r['android_user']),('complete',12))
        self.assertFalse(any(x[-3:]==['shell','am','get-current-user']for x in c))
    def test_unknown_user_refuses_before_provider(self):
        r,c,_=self.run_collection(current=('bad',))
        self.assertEqual((r['status'],r['exported_contacts']),('failed',0))
        self.assertFalse(any('--projection'in x[-1]for x in c))
    def test_count_limit_refuses_before_fields(self):
        r,c,_=self.run_collection(ids='Row: 0 _id=7\nRow: 1 _id=8\n',max_contacts=1)
        self.assertEqual((r['status'],r['exported_contacts']),('failed',0))
        self.assertFalse(any('display_name'in x[-1]for x in c))
    def test_final_metadata_budget_refuses_derived_output(self):
        r,c,total=self.run_collection(max_bytes=1024,user=10)
        self.assertEqual((r['status'],r['exported_contacts'],r['evidence_id']),('failed',0,None))
        self.assertLessEqual(total,1024)
    def test_existing_acquisition_default_900_is_accepted(self):
        r,c,_=self.run_collection(through_host=True)
        self.assertEqual(r['status'],'complete')
    def test_host_explicit_android_user_reaches_fixed_provider_queries(self):
        r,c,_=self.run_collection(through_host=True,user=12,current=())
        self.assertEqual((r['status'],r['android_user']),('complete',12))
        self.assertFalse(any(x[-3:]==['shell','am','get-current-user'] for x in c))
    def test_invalid_limits_never_resolve_adb(self):
        with patch('lawliet_mobile.provider_contacts.command',side_effect=AssertionError('no command')):
            for kw in ({'user':True},{'user':-1},{'timeout':True},{'max_contacts':1.5},{'max_bytes':0}):
                with self.subTest(kw=kw),self.assertRaises(UserError):collect_contacts(None,None,None,'TEST',**kw)
    def test_symlink_collection_parent_refuses_before_adb(self):
        with tempfile.TemporaryDirectory() as t:
            ws=Path(t)/'cases';create_case(ws,'A');foreign=Path(t)/'foreign';foreign.mkdir();(ws/'A/collections').symlink_to(foreign)
            with connect(ws,'A')as(root,db),patch('lawliet_mobile.provider_contacts.command',return_value=['adb']),patch('lawliet_mobile.provider_contacts.execute',side_effect=AssertionError('no phone')):
                with self.assertRaises((OSError,UserError)):collect_contacts(root,db,ws,'TEST')
            self.assertEqual(list(foreign.iterdir()),[])
