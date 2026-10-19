"""Run staging and lost daemon-response boundaries; no daemon needed."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile import container_runner as cr
from lawliet_mobile.core import UserError

class ContainerBoundaries(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name).resolve()/'case';self.root.mkdir()
  self.cid='a'*64;self.cfg={};self.expected={}
  self.stopped={'State':{'Running':False,'Paused':False,'Restarting':False,'Status':'exited'}}
 def test_linked_runs_cannot_create_foreign_entries(self):
  foreign=self.root.parent/'foreign';foreign.mkdir();(self.root/'runs').symlink_to(foreign)
  with self.assertRaises(UserError):cr.create_run_directory(self.root,'0'*12)
  self.assertEqual(list(foreign.iterdir()),[])
 def test_linked_case_ancestor_cannot_create_runs(self):
  alias=self.root.parent/'alias';alias.symlink_to(self.root)
  with self.assertRaises(UserError):cr.create_run_directory(alias,'0'*12)
  self.assertFalse((self.root/'runs').exists())
 def test_existing_run_cannot_be_reused(self):
  run=cr.create_run_directory(self.root,'0'*12);keep=run/'retained';keep.write_text('original')
  with self.assertRaises(UserError):cr.create_run_directory(self.root,'0'*12)
  self.assertEqual(keep.read_text(),'original')
 def test_new_run_is_private(self):
  run=cr.create_run_directory(self.root,'0'*12)
  self.assertEqual(run.stat().st_mode&0o777,0o700)
 def removal(self,replies):
  with patch.object(cr,'owned_state',return_value=self.stopped),patch.object(cr,'docker',side_effect=replies):
   return cr.remove_stopped(self.cfg,self.cid,self.expected)
 def test_lost_successful_removal_confirmed_by_inventory(self):
  self.assertEqual(self.removal([subprocess.TimeoutExpired('rm',10),subprocess.CompletedProcess([],0,'b'*64+'\n','')]),self.stopped)
 def test_failed_response_with_confirmed_absence(self):
  self.assertEqual(self.removal([subprocess.CompletedProcess([],1,'','lost'),subprocess.CompletedProcess([],0,'','')]),self.stopped)
 def test_daemon_failure_is_not_absence(self):
  with self.assertRaisesRegex(UserError,'daemon unavailable'):
   self.removal([subprocess.TimeoutExpired('rm',10),subprocess.CompletedProcess([],1,'','offline')])
 def test_still_present_is_not_removed(self):
  with self.assertRaisesRegex(UserError,'still exists'):
   self.removal([subprocess.TimeoutExpired('rm',10),subprocess.CompletedProcess([],0,self.cid+'\n','')])
 def test_malformed_inventory_is_not_absence(self):
  with self.assertRaisesRegex(UserError,'malformed'):
   self.removal([subprocess.TimeoutExpired('rm',10),subprocess.CompletedProcess([],0,'partial-id\n','')])
 def test_active_worker_not_removed(self):
  self.stopped['State']['Running']=True
  with patch.object(cr,'owned_state',return_value=self.stopped),patch.object(cr,'docker') as docker:
   with self.assertRaises(UserError):cr.remove_stopped(self.cfg,self.cid,self.expected)
   docker.assert_not_called()
