import subprocess
import unittest
from unittest.mock import patch
from lawliet_mobile.iphone_connection import discover,describe
from lawliet_mobile.core import UserError

PHONE='00008140-001605620EF3001C'
class IPhoneConnectionTests(unittest.TestCase):
    def runner(self,calls,trust=True):
        def run(argv,**kwargs):
            calls.append(argv)
            if argv[0]=='id':out=PHONE+'\n';code=0
            elif argv[0]=='info':out={'ProductType':'iPhone17,2','ProductVersion':'26.6.1','DeviceName':'Owned test phone'}[argv[-1]];code=0
            else:out='validated' if trust else 'not paired';code=0 if trust else 1
            return subprocess.CompletedProcess(argv,code,out,'')
        return run
    @patch('lawliet_mobile.iphone_connection.command',return_value=['id'])
    @patch('lawliet_mobile.iphone_connection.tool_executable',side_effect=lambda x:{'ideviceinfo':'info','idevicepair':'pair'}[x])
    def test_connected_metadata_and_validation_are_read_only(self,*_):
        calls=[];r=describe('.',PHONE,self.runner(calls))
        self.assertEqual(r['trust'],'trusted');self.assertEqual(r['version'],'26.6.1')
        self.assertEqual(calls[-1],['pair','-u',PHONE,'validate'])
        self.assertTrue(all('backup' not in c and 'pair' not in c[1:] and 'unpair' not in c for c in calls))
    @patch('lawliet_mobile.iphone_connection.command',return_value=['id'])
    @patch('lawliet_mobile.iphone_connection.tool_executable',side_effect=lambda x:{'ideviceinfo':'info','idevicepair':'pair'}[x])
    def test_untrusted_is_not_connected_and_trusted(self,*_):
        self.assertEqual(describe('.',PHONE,self.runner([],False))['trust'],'trust_required')
    @patch('lawliet_mobile.iphone_connection.command',return_value=['id'])
    def test_bad_identifiers_and_disconnection(self,*_):
        for value in ('-u','host:port','../phone','a'*200):
            with self.subTest(value=value),self.assertRaises(UserError):describe('.',value,self.runner([]))
        def disconnected(argv,**kwargs):return subprocess.CompletedProcess(argv,0,'','')
        with self.assertRaises(UserError):describe('.',PHONE,disconnected)
    @patch('lawliet_mobile.iphone_connection.command',return_value=['id'])
    def test_timeout_and_bad_discovery_fail_explicitly(self,*_):
        def timed(argv,**kwargs):raise subprocess.TimeoutExpired(argv,5)
        with self.assertRaises(UserError):discover('.',timed)
        def invalid(argv,**kwargs):return subprocess.CompletedProcess(argv,0,'unexpected\n','')
        with self.assertRaises(UserError):discover('.',invalid)
    @patch('lawliet_mobile.iphone_connection.command',return_value=['id'])
    @patch('lawliet_mobile.iphone_connection.tool_executable',return_value=None)
    def test_missing_metadata_tools_preserves_detection(self,*_):
        r=describe('.',PHONE,self.runner([]));self.assertEqual(r['status'],'connected');self.assertEqual(r['trust'],'not_checked');self.assertIn('unavailable',r['error'])

    @patch('lawliet_mobile.iphone_connection.command',side_effect=UserError('not installed'))
    @patch('lawliet_mobile.iphone_connection.configuration',return_value={})
    @patch('lawliet_mobile.iphone_connection.tool_executable',return_value='/opt/homebrew/bin/idevice_id')
    def test_gui_path_fallback_without_overriding_config(self,*_):
        calls=[]
        def runner(argv,**kwargs):
            calls.append(argv);return subprocess.CompletedProcess(argv,0,PHONE+'\n','')
        self.assertEqual(len(discover('.',runner)['devices']),1)
        self.assertEqual(calls,[['/opt/homebrew/bin/idevice_id','-l']])
        with patch('lawliet_mobile.iphone_connection.configuration',return_value={'idevice_id':'/missing/user-pin'}):
            with self.assertRaises(UserError):discover('.',runner)
