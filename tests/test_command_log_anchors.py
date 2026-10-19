"""Actual benign children exercise log identity and existing runner contracts."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile import runner_lease
from lawliet_mobile.core import UserError,create_case,connect
from lawliet_mobile.tools import execute


@unittest.skipUnless(os.name=='posix','Descriptor log anchoring requires POSIX')
class CommandLogAnchors(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.raw=Path(self.temp.name);self.base=self.raw.resolve()

    def child(self,script):
        return [sys.executable,'-c',script]

    def test_regular_overwrite_cwd_binary_logs_and_receipt_compatibility(self):
        folder=self.base/'logs';folder.mkdir();out=folder/'stdout';err=folder/'stdout.stderr'
        out.write_bytes(b'OLD LONG STDOUT');err.write_bytes(b'OLD LONG STDERR')
        inodes=(out.stat().st_ino,err.stat().st_ino)
        argv=self.child("import sys,os;sys.stdout.buffer.write(b'new\\x00');sys.stderr.write('err');assert os.getcwd()==sys.argv[1];sys.exit(7)")+[str(folder)]
        result=execute(argv,out,cwd=folder)
        self.assertEqual(result['returncode'],7)
        self.assertEqual(out.read_bytes(),b'new\x00');self.assertEqual(err.read_text(),'err')
        self.assertEqual((out.stat().st_ino,err.stat().st_ino),inodes)
        self.assertEqual(result['argv'],argv)
        self.assertEqual((result['stdout'],result['stderr']),(str(out),str(err)))
        self.assertEqual(result['process_status_kind'],'direct child returncode')

    def test_creates_nested_parent_and_supports_normal_system_temp_alias(self):
        out=self.raw/'nested'/'more'/'stdout'
        result=execute(self.child("print('ok')"),out,timeout=2)
        self.assertEqual(result['returncode'],0)
        self.assertEqual(out.read_text(),'ok\n')

    def test_parent_symlink_refused_before_spawn(self):
        foreign=self.base/'foreign';foreign.mkdir();link=self.base/'link';link.symlink_to(foreign)
        with patch.object(runner_lease,'spawn',side_effect=AssertionError('no child')):
            with self.assertRaises((OSError,UserError)):execute(self.child('pass'),link/'stdout')
        self.assertEqual(list(foreign.iterdir()),[])

    def test_stdout_or_stderr_link_refused_without_truncating_other_log(self):
        for linked in ('stdout','stdout.stderr'):
            with self.subTest(linked=linked):
                folder=self.base/linked;folder.mkdir();out=folder/'stdout';err=folder/'stdout.stderr'
                out.write_text('OUT');err.write_text('ERR')
                foreign=folder/'foreign';foreign.write_text('UNCHANGED')
                target=folder/linked;target.unlink();target.symlink_to(foreign)
                other=err if target==out else out;before=other.read_bytes()
                with patch.object(runner_lease,'spawn',side_effect=AssertionError('no child')):
                    with self.assertRaises((OSError,UserError)):execute(self.child('pass'),out)
                self.assertEqual(foreign.read_text(),'UNCHANGED');self.assertEqual(other.read_bytes(),before)

    def test_hardlink_and_fifo_refused_before_spawn(self):
        foreign=self.base/'foreign';foreign.write_text('UNCHANGED')
        out=self.base/'hardlink';os.link(foreign,out)
        fifo=self.base/'fifo';os.mkfifo(fifo)
        with patch.object(runner_lease,'spawn',side_effect=AssertionError('no child')):
            for target in (out,fifo):
                with self.subTest(target=target),self.assertRaises((OSError,UserError)):
                    execute(self.child('pass'),target)
        self.assertEqual(foreign.read_text(),'UNCHANGED')

    def test_directory_replacement_at_spawn_cannot_redirect_open_streams(self):
        folder=self.base/'selected';folder.mkdir();moved=self.base/'original';foreign=self.base/'foreign';foreign.mkdir()
        (foreign/'stdout').write_text('FOREIGN OUT');(foreign/'stdout.stderr').write_text('FOREIGN ERR')
        original_spawn=runner_lease.spawn;children=[]
        def replaced(argv,**kwargs):
            folder.rename(moved);folder.symlink_to(foreign)
            self.assertEqual(os.fstat(kwargs['stdout'].fileno()).st_ino,(moved/'stdout').stat().st_ino)
            self.assertEqual(os.fstat(kwargs['stderr'].fileno()).st_ino,(moved/'stdout.stderr').stat().st_ino)
            value=original_spawn(argv,**kwargs);children.append(value[0]);return value
        with patch.object(runner_lease,'spawn',side_effect=replaced):
            with self.assertRaises((OSError,UserError)) as error:
                execute(self.child("print('child');import time;time.sleep(2)"),folder/'stdout',timeout=3)
        self.assertEqual((foreign/'stdout').read_text(),'FOREIGN OUT')
        self.assertEqual((foreign/'stdout.stderr').read_text(),'FOREIGN ERR')
        self.assertIsNotNone(children[0].poll());self.assertIn('error',error.exception.tool_result)

    def test_parent_replacement_before_leaf_open_cannot_create_foreign_logs(self):
        folder=self.base/'selected';folder.mkdir();moved=self.base/'original';foreign=self.base/'foreign';foreign.mkdir()
        original_open=os.open;replaced=[]
        def racing_open(path,flags,*args,**kwargs):
            if path=='stdout' and kwargs.get('dir_fd') is not None and flags&os.O_CREAT and not replaced:
                folder.rename(moved);folder.symlink_to(foreign);replaced.append(True)
            return original_open(path,flags,*args,**kwargs)
        with patch.object(os,'open',side_effect=racing_open), \
                patch.object(runner_lease,'spawn',side_effect=AssertionError('no child')):
            with self.assertRaises((OSError,UserError)):execute(self.child('pass'),folder/'stdout')
        self.assertTrue(replaced);self.assertEqual(list(foreign.iterdir()),[])

    def test_leaf_replacement_at_spawn_cannot_redirect_open_stream(self):
        out=self.base/'stdout';foreign=self.base/'foreign';foreign.write_text('UNCHANGED')
        original_spawn=runner_lease.spawn;children=[]
        def replaced(argv,**kwargs):
            out.unlink();out.symlink_to(foreign)
            self.assertNotEqual(os.fstat(kwargs['stdout'].fileno()).st_ino,foreign.stat().st_ino)
            value=original_spawn(argv,**kwargs);children.append(value[0]);return value
        with patch.object(runner_lease,'spawn',side_effect=replaced):
            with self.assertRaises(UserError):execute(self.child("print('child')"),out)
        self.assertEqual(foreign.read_text(),'UNCHANGED');self.assertIsNotNone(children[0].poll())

    def test_timeout_and_guard_failure_stop_child_and_retain_failure_receipt(self):
        original_spawn=runner_lease.spawn;children=[]
        def captured(argv,**kwargs):
            value=original_spawn(argv,**kwargs);children.append(value[0]);return value
        with patch.object(runner_lease,'spawn',side_effect=captured):
            with self.assertRaises(subprocess.TimeoutExpired) as expired:
                execute(self.child('import time;time.sleep(3)'),self.base/'timeout',timeout=.1)
            self.assertEqual(expired.exception.tool_result['error'],'timeout')
            def refuse():raise UserError('GUARD REFUSAL')
            with self.assertRaises(UserError) as denied:
                execute(self.child('import time;time.sleep(3)'),self.base/'guard',guard=refuse)
            self.assertEqual(denied.exception.tool_result['error'],'GUARD REFUSAL')
        self.assertTrue(all(child.poll() is not None for child in children))

    def test_case_lease_guardian_and_success_guard_remain_compatible(self):
        ws=self.base/'cases';create_case(ws,'A');calls=[]
        with connect(ws,'A') as(root,db),runner_lease.lease(root,db):
            result=execute(self.child("print('guarded')"),root/'logs/stdout',guard=lambda:calls.append(1))
        self.assertEqual(result['returncode'],0)
        self.assertIn('guardian exit status',result['process_status_kind'])
        self.assertGreaterEqual(len(calls),2)
        self.assertEqual(Path(result['stdout']).read_text(),'guarded\n')


if __name__=='__main__':unittest.main()
