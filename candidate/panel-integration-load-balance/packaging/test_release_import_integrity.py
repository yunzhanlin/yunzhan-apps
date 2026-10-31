"""Actual installer helper imports must preserve an immutable checked release."""
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent


class ReleaseImportIntegrityTests(unittest.TestCase):
    def test_normal_fresh_development_and_production_helper_imports_leave_signed_tree_exact(self):
        # Deliberately omit -B and ignore the test runner's Python environment.
        # These are the real import chains used by all three installer modes.
        code = '''import pathlib,runpy,sys
# Exercise Linux's bytecode-writing context even on hosts that disable it.
sys.dont_write_bytecode=False
release=pathlib.Path(sys.argv[1]);kind=sys.argv[2]
if kind in ('fresh','development'):
    runpy.run_path(str(release/('start-guard-install.py' if kind=='fresh' else 'development-upgrade.py')),run_name='release_import_probe')
else:
    module=runpy.run_path(str(release/'upgrade-release.py'),run_name='release_import_probe')
    class StopBeforeHostInventory(Exception):pass
    class Boundary:
        release=release
        def parents(self,*args):raise StopBeforeHostInventory()
    try:module['Upgrade'].start_guard(Boundary())
    except StopBeforeHostInventory:pass
    else:raise AssertionError('Expected explicit stop before host inventory')
'''
        for kind in ('fresh', 'development', 'production'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                release = pathlib.Path(temporary) / 'release'
                release.mkdir(mode=0o755)
                release.chmod(0o755)
                for name in ('start-guard-install.py', 'development-upgrade.py', 'upgrade-release.py',
                             'verify-release.sh', 'release-file-modes.py'):
                    shutil.copyfile(HERE / name, release / name)
                    (release / name).chmod(0o755 if name == 'verify-release.sh' else 0o644)
                (release / 'RELEASE').write_text('PANEL_FORMAT=1\nPANEL_VERSION=1.2.3\nPANEL_OS=linux\nPANEL_ARCH=amd64\n')
                (release / 'RELEASE').chmod(0o644)
                sums = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
                               for p in sorted(release.iterdir()))
                (release / 'SHA256SUMS').write_text(sums)
                (release / 'SHA256SUMS').chmod(0o644)
                def snapshot():
                    return {str(p.relative_to(release)): (p.lstat().st_mode, p.lstat().st_ino,
                            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
                            for p in [release, *release.rglob('*')]}
                before = snapshot()
                verifier = ['bash', str(release / 'verify-release.sh'), str(release)]
                initial = subprocess.run(verifier, capture_output=True, text=True, timeout=15)
                self.assertEqual(initial.returncode, 0, initial.stderr)
                result = subprocess.run([sys.executable, '-I', '-c', code, str(release), kind],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                checked = subprocess.run(verifier, capture_output=True, text=True, timeout=15)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                self.assertEqual(snapshot(), before)


if __name__ == '__main__':
    unittest.main()
