"""Installer boundaries and repeatability without network access."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import bootstrap


class BootstrapTests(unittest.TestCase):
    def test_plan_has_no_install_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / 'runtime'
            result = subprocess.run([sys.executable, str(bootstrap.ROOT / 'tools/bootstrap.py'),
                                     '--plan', '--runtime', str(runtime)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(runtime.exists())

    def test_modified_lock_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'lock').write_text('changed')
            m = {'schema_version': 1, 'locks': {'core': {'path': 'lock', 'sha256': '0' * 64}},
                 'sources': {'mulder': {'patch': 'patch', 'patch_sha256': '0' * 64}}}
            (root / 'manifest').write_text(json.dumps(m))
            with patch.object(bootstrap, 'ROOT', root), patch.object(bootstrap, 'MANIFEST', root / 'manifest'):
                with self.assertRaisesRegex(RuntimeError, 'Setup input changed'):
                    bootstrap.checked_manifest()

    @unittest.skipUnless(os.name == 'posix', 'POSIX generated launchers')
    def test_wrapper_preserves_arguments_and_space_paths(self):
        with tempfile.TemporaryDirectory(prefix='lawliet wrapper ') as tmp:
            executable = Path(tmp) / 'run tool'
            bootstrap.wrapper(executable, ['/usr/bin/printf', '%s\n'])
            value = 'literal $(echo unsafe); space'
            self.assertEqual(subprocess.check_output([str(executable), value], text=True), value + '\n')

    def test_source_pin_rerun_and_modified_checkout_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'upstream'
            source.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(source), *args], stderr=subprocess.DEVNULL)
            git('init')
            git('config', 'user.email', 'fixture@example.invalid')
            git('config', 'user.name', 'Synthetic fixture')
            (source / 'example').write_text('baseline\n')
            git('add', 'example')
            git('commit', '-m', 'fixture')
            spec = {'url': str(source), 'commit': git('rev-parse', 'HEAD').decode().strip()}
            target = bootstrap.checkout(root / 'runtime', 'fixture', spec)
            self.assertEqual(bootstrap.checkout(root / 'runtime', 'fixture', spec), target)
            (target / 'example').write_text('local change\n')
            with self.assertRaisesRegex(RuntimeError, 'Modified source'):
                bootstrap.checkout(root / 'runtime', 'fixture', spec)
            self.assertEqual((target / 'example').read_text(), 'local change\n')


if __name__ == '__main__':
    unittest.main()
