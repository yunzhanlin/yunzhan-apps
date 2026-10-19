import grp
import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import unittest

spec=importlib.util.spec_from_file_location("waf_state_directory",pathlib.Path(__file__).with_name("waf-state-directory.py"))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class WAFStatePackagingTests(unittest.TestCase):
    def test_verified_helper_is_bundled_and_copied_before_release_commit(self):
        root=pathlib.Path(__file__).resolve().parents[1]
        installer=(root/'packaging/install.sh').read_text()
        copy=next(line for line in installer.splitlines() if line.startswith('cp -a "$HERE/bin"'))
        self.assertIn('"$HERE/waf-state-directory.py"',copy)
        self.assertLess(installer.index(copy),installer.index('"$RELEASE_DIR.tmp/verify-release.sh"'))
        builder=(root/'packaging/build-release.sh').read_text()
        self.assertIn('"$BUILD_ROOT/packaging/waf-state-directory.py"',builder)
        self.assertIn('first-install.py waf-state-directory.py',builder)


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0,"actual root Linux private fixture required")
class WAFStateDirectoryTests(unittest.TestCase):
    def test_check_is_read_only_and_create_preserves_existing_contents(self):
        with tempfile.TemporaryDirectory(prefix="panel-waf-state-test-") as directory:
            root=pathlib.Path(directory);target=root/"var/lib/panel-waf"
            module.prepare(root,False);self.assertFalse((root/"var").exists())
            module.prepare(root,True)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o750)
            self.assertEqual(target.stat().st_gid,grp.getgrnam("www-data").gr_gid)
            marker=target/"owned-fixture";marker.write_bytes(b"existing metadata must remain")
            before=target.stat().st_ino
            module.prepare(root,False);module.prepare(root,True)
            self.assertEqual(before,target.stat().st_ino);self.assertEqual(marker.read_bytes(),b"existing metadata must remain")

    def test_foreign_paths_are_not_repaired_or_followed(self):
        for kind in ("writable","private-mode","foreign-owner","foreign-group","symlink","ancestor-symlink"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix="panel-waf-state-test-") as directory:
                root=pathlib.Path(directory);module.prepare(root,True);target=root/"var/lib/panel-waf"
                if kind=="writable":target.chmod(0o777)
                elif kind=="private-mode":target.chmod(0o700)
                elif kind=="foreign-owner":os.chown(target,65534,target.stat().st_gid)
                elif kind=="foreign-group":os.chown(target,0,0)
                elif kind=="symlink":
                    retained=target.with_name("not-a-managed-target");target.rename(retained);target.symlink_to(retained)
                elif kind=="ancestor-symlink":
                    original=root/"var";retained=root/"not-a-managed-var";original.rename(retained);original.symlink_to(retained)
                before=target.lstat()
                for create in (False,True):
                    with self.assertRaises(ValueError):module.prepare(root,create)
                    after=target.lstat();self.assertEqual((before.st_mode,before.st_uid,before.st_gid,before.st_ino),(after.st_mode,after.st_uid,after.st_gid,after.st_ino))


if __name__=="__main__":unittest.main()
