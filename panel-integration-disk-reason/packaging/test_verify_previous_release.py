"""Real shell/strict checksum/mode checks; no host install or service runner."""
import hashlib
import pathlib
import stat
import subprocess
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parent

class VerifyPreviousReleaseTests(unittest.TestCase):
    def fixture(self,root,helper=False):
        root.mkdir(mode=0o755)
        (root/'bin').mkdir(mode=0o755)
        (root/'web').mkdir(mode=0o755)
        values={'RELEASE':b'PANEL_FORMAT=1\nPANEL_VERSION=0.1.0-dev.old\nPANEL_OS=linux\nPANEL_ARCH=arm64\n','bin/panel':b'not executed','web/index.html':b'original public page'}
        if helper:values['release-file-modes.py']=b'raise SystemExit("untrusted target helper executed")\n'
        for name,data in values.items():
            path=root/name;path.write_bytes(data);path.chmod(0o755 if name=='bin/panel' else 0o644)
        checks=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in values.items())
        (root/'SHA256SUMS').write_text(checks);(root/'SHA256SUMS').chmod(0o644)
    def verify(self,root):
        return subprocess.run(['/bin/bash',str(ROOT/'verify-release.sh'),str(root)],capture_output=True,text=True,timeout=10)
    def identity(self,root):
        return {str(p.relative_to(root)):(p.lstat().st_ino,p.lstat().st_mode,p.lstat().st_mtime_ns,p.lstat().st_ctime_ns,hashlib.sha256(p.read_bytes()).hexdigest()if p.is_file()and not p.is_symlink()else None)for p in (root,*root.rglob('*'))}
    def test_old_payload_without_helper_and_payload_with_its_own_helper_use_candidate_policy(self):
        for helper in (False,True):
            with self.subTest(helper=helper),tempfile.TemporaryDirectory()as temporary:
                root=pathlib.Path(temporary)/'old';self.fixture(root,helper)
                before=self.identity(root);result=self.verify(root)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn('release public program modes verified',result.stdout)
                self.assertEqual(self.identity(root),before)
                self.assertEqual((root/'release-file-modes.py').exists(),helper)
    def test_bad_modes_and_checksum_still_refuse_without_repair(self):
        for bad in ('private-directory','private-public-file','non-executable-program','bad-checksum','linked-helper'):
            with self.subTest(bad=bad),tempfile.TemporaryDirectory()as temporary:
                root=pathlib.Path(temporary)/'old';self.fixture(root)
                if bad=='private-directory':(root/'web').chmod(0o700)
                elif bad=='private-public-file':(root/'web/index.html').chmod(0o600)
                elif bad=='non-executable-program':(root/'bin/panel').chmod(0o644)
                elif bad=='bad-checksum':(root/'web/index.html').write_bytes(b'changed')
                else:(root/'release-file-modes.py').symlink_to(ROOT/'release-file-modes.py')
                before=self.identity(root);result=self.verify(root)
                self.assertNotEqual(result.returncode,0,bad)
                self.assertEqual(self.identity(root),before)

if __name__=='__main__':unittest.main()
