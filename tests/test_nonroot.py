import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import create_case,connect,verify
from lawliet_mobile.phone_assessment import provider_state,assess_android

class NonrootTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'qa')
    def intake(self,name,content):
        source=self.base/name;source.write_text(content)
        result=handle(self.ws,{'action':'import-evidence','case':'qa','path':str(source)})
        rows=handle(self.ws,{'action':'records','case':'qa','evidence':result['evidence_id']})['records']
        return result,rows
    def test_xml_sms_mms_rcs_and_calls(self):
        result,rows=self.intake('sms.xml','''<smses count="2"><sms address="+12025550100" date="1791640800123" type="1" body="First &amp; second"/><mms date="1791640800456" msg_box="2" s_chat="1"><parts><part ct="text/plain" text="Multimedia text"/><part ct="image/png" cl="x.png" data="YWJj"/></parts><addrs><addr type="151" address="+12025550100"/><addr type="137" address="insert-address-token"/></addrs></mms></smses>''')
        self.assertEqual(result['analysis']['status'],'complete');self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]['body'],'First & second');self.assertEqual(rows[0]['timestamp'],'2026-10-10T14:00:00.123000Z')
        self.assertEqual(rows[1]['data']['message']['app'],'rcs');self.assertEqual(rows[1]['timestamp'],'2026-10-10T14:00:00.456000Z')
        self.assertNotIn('YWJj',str(rows[1]['data']))
        result,rows=self.intake('calls.xml','<calls count="1"><call number="+12025550100" date="1791640800000" duration="42" type="3"/></calls>')
        self.assertEqual(rows[0]['category'],'calls');self.assertIn('missed',rows[0]['title'])
    def test_malformed_count_and_entities_fail_without_partial_records(self):
        for text in ['<smses count="2"><sms address="x" date="1" type="1" body="a"/></smses>', '<!DOCTYPE smses [<!ENTITY bad "boom">]><smses/>','<smses><sms']:
            result,rows=self.intake('bad.xml',text)
            self.assertEqual(result['analysis']['status'],'partial');self.assertEqual(rows,[])
    def test_provider_denial_not_success_even_with_zero_exit(self):
        self.assertEqual(provider_state('java.lang.SecurityException: Permission Denial'),'access_denied')
        self.assertEqual(provider_state('No result found.'),'readable_empty')
        self.assertEqual(provider_state('Row: 0 _id=42'),'readable_ids_only')
        self.assertEqual(provider_state('unexpected'),'unresolved')
    def test_assessment_logs_denial_and_never_changes_permissions(self):
        commands=[]
        def execute(argv,out,timeout):
            commands.append(argv);out=Path(out);out.parent.mkdir(parents=True,exist_ok=True)
            content='device\n' if argv[-1]=='get-state' else 'java.lang.SecurityException: Permission Denial' if 'query' in argv else ''
            out.write_text(content);err=Path(str(out)+'.stderr');err.write_text('')
            return {'argv':argv,'returncode':0,'stderr':str(err)}
        with connect(self.ws,'qa') as (root,db),patch('lawliet_mobile.phone_assessment.command',return_value=['adb']),patch('lawliet_mobile.phone_assessment.execute',side_effect=execute):
            r=assess_android(root,db,self.ws,'SERIAL')
            self.assertEqual(r['status'],'assessed');self.assertTrue(all(x['state']=='access_denied' for x in r['providers'].values()))
            self.assertTrue(Path(r['path']).is_file());self.assertTrue(verify(root,db)['ok'])
            self.assertFalse(any(x in {'install','grant','root','unlock','setprop'} for c in commands for x in c))
