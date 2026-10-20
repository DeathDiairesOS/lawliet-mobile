"""Actual staging race regressions. No daemon or production/case inputs used."""
import hashlib,os,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile import sqlite_container as sc
from lawliet_mobile.runner_lease import CURRENT
from lawliet_mobile.core import UserError,digest

class StagingTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name).resolve();self.folder=self.base/'case/runs/abcdef012345';self.folder.mkdir(parents=True)
  self.foreign=self.base/'foreign';self.foreign.mkdir();self.canary=self.foreign/'database.sqlite';self.canary.write_bytes(b'FOREIGN-CASE-CANARY');self.canary.chmod(0o640);self.hash=digest(self.canary);self.mode=stat.S_IMODE(self.canary.stat().st_mode)
  self.input=self.base/'source.sqlite';self.input.write_bytes(b'SYNTHETIC-INPUT')
  self.owner={'nonce':'a'*32};self.root=self.base/'case';self.cfg={'image':sc.IMAGE,'bootstrap_sha256':digest(sc.WORKER)}
  self.selected=[('',{'retained_path':str(self.input),'size':self.input.stat().st_size,'sha256':digest(self.input)})]
  self.request={'query':'SELECT 1','parameters':[],'row_limit':10,'max_output_bytes':1024,'timeout_seconds':1,'worker_source_sha256':digest(Path(sc.__file__).with_name('sqlite_workspace.py')),'container_execution_profile':sc.execution_profile()}
 def unchanged(self):
  self.assertEqual(digest(self.canary),self.hash);self.assertEqual(stat.S_IMODE(self.canary.stat().st_mode),self.mode)
  self.assertEqual(sorted(p.name for p in self.foreign.iterdir()),['database.sqlite'])
 def run_refused(self,mutation):
  token=CURRENT.set({'root':str(self.root),'identity':self.owner})
  try:
   with patch.object(sc,'validate_config',return_value=self.cfg),patch.object(sc,'docker',side_effect=AssertionError('Daemon must not be reached')) as docker,mutation:
    with self.assertRaises((UserError,OSError)):sc.run(self.root,'abcdef012345',self.owner,self.cfg,self.selected,self.request,self.folder)
    docker.assert_not_called()
  finally:CURRENT.reset(token)
  self.unchanged()
 def test_swapped_top_level_staging_directories_refuse_before_any_daemon(self):
  actual=sc._Staging.mkdir
  def race(staged,name):
   actual(staged,name)
   if name=='container-input':
    p=self.folder/name;p.rename(self.folder/'held-input');p.symlink_to(self.foreign,target_is_directory=True)
  self.run_refused(patch.object(sc._Staging,'mkdir',race))
 def test_run_directory_swapped_with_foreign_link_refuses(self):
  actual=sc._Staging.mkdir
  def race(staged,name):
   actual(staged,name)
   if name=='container-input':
    self.folder.rename(self.folder.with_name('owned-run-moved'));self.folder.symlink_to(self.foreign,target_is_directory=True)
  self.run_refused(patch.object(sc._Staging,'mkdir',race))
 def test_leaf_symlink_cannot_truncate_or_chmod_foreign_file(self):
  actual=sc._Staging.write
  def race(staged,name,data):
   if name=='container-input/database.sqlite':(self.folder/name).symlink_to(self.canary)
   return actual(staged,name,data)
  self.run_refused(patch.object(sc._Staging,'write',race))
 def test_leaf_hardlink_cannot_truncate_or_chmod_foreign_file(self):
  actual=sc._Staging.write
  def race(staged,name,data):
   if name=='container-input/database.sqlite':os.link(self.canary,self.folder/name)
   return actual(staged,name,data)
  self.run_refused(patch.object(sc._Staging,'write',race))
 def test_directory_swapped_after_leaf_open_writes_only_owned_inode_then_refuses(self):
  with sc._Staging(self.folder) as staged:
   staged.mkdir('container-input');actual=os.open;replaced=False
   if os.name=='nt':
    from lawliet_mobile.windows_files import WindowsDirectory
    create=WindowsDirectory.new_file
    def protected(directory):
     nonlocal replaced
     value=create(directory);replaced=True
     with self.assertRaises(OSError):(self.folder/'container-input').rename(self.folder/'held-input')
     return value
    with patch.object(WindowsDirectory,'new_file',protected):staged.write('container-input/database.sqlite',b'OWNED-COPY')
    self.assertTrue(replaced);self.assertEqual(staged.read('container-input/database.sqlite',100),b'OWNED-COPY')
    self.unchanged();return
   def race(path,flags,*args,**kwargs):
    nonlocal replaced
    fd=actual(path,flags,*args,**kwargs)
    if path=='database.sqlite' and flags&os.O_WRONLY and not replaced:
     replaced=True;p=self.folder/'container-input';p.rename(self.folder/'held-input');p.symlink_to(self.foreign,target_is_directory=True)
    return fd
   with patch.object(os,'open',side_effect=race),self.assertRaises((UserError,OSError)):staged.write('container-input/database.sqlite',b'OWNED-COPY')
   self.assertTrue(replaced);self.assertEqual((self.folder/'held-input/database.sqlite').read_bytes(),b'OWNED-COPY')
  self.unchanged()
 def test_input_source_final_symlink_refuses_before_copy(self):
  self.input.unlink();self.input.symlink_to(self.canary)
  self.run_refused(patch.object(sc,'MAX_INPUT',sc.MAX_INPUT))
 def test_opened_input_code_and_control_bytes_are_exact_and_readonly(self):
  with sc._Staging(self.folder) as staged:
   for name in ('container-input','container-control','container-code'):staged.mkdir(name)
   for name,data in [('container-input/database.sqlite',b'INPUT'),('container-control/request.json',b'{"test":true}'),('container-code/sqlite_workspace.py',b'# code\n')]:
    staged.write(name,data);self.assertEqual(staged.read(name,100),data);self.assertEqual(stat.S_IMODE((self.folder/name).stat().st_mode),0o444)
 def test_pinned_bootstrap_outside_package_preserves_controlled_worker_qualification(self):
  worker=self.base/'qualified_bootstrap.py';worker.write_bytes(b'# separately pinned synthetic qualification worker\n')
  token=CURRENT.set({'root':str(self.root),'identity':self.owner})
  try:
   with patch.object(sc,'WORKER',worker):
    cfg={**self.cfg,'bootstrap_sha256':digest(worker)};request={**self.request,'container_execution_profile':sc.execution_profile()}
    with patch.object(sc,'validate_config',return_value=cfg),patch.object(sc,'inventory',return_value=[]),patch.object(sc,'docker',side_effect=UserError('synthetic create boundary')) as docker:
     with self.assertRaisesRegex(UserError,'synthetic create boundary'):sc.run(self.root,'abcdef012345',self.owner,cfg,self.selected,request,self.folder)
     self.assertEqual(docker.call_count,1);self.assertEqual(docker.call_args.args[1][0],'create')
    self.assertEqual((self.folder/'container-control/bootstrap.py').read_bytes(),worker.read_bytes())
  finally:CURRENT.reset(token)
  self.unchanged()
 def test_readback_refuses_link_and_size_limit(self):
  with sc._Staging(self.folder) as staged:
   staged.mkdir('container-input');staged.write('container-input/a',b'INPUT')
   with self.assertRaises(UserError):staged.read('container-input/a',2)
   (self.folder/'container-input/link').symlink_to(self.canary)
   with self.assertRaises((UserError,OSError)):staged.read('container-input/link',100)
  self.unchanged()
 def test_traversal_cannot_create_foreign_files(self):
  with sc._Staging(self.folder) as staged:
   for name in ('../foreign/new','/absolute','a//b','a/./b','a\\b'):
    with self.subTest(name=name),self.assertRaises((UserError,OSError)):staged.write(name,b'bad')
  self.unchanged()

if __name__=='__main__':unittest.main()
