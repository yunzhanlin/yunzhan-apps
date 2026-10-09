import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("native_build_directories", pathlib.Path(__file__).with_name("native-build-directories.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativeBuildPackagingTests(unittest.TestCase):
    def test_verified_helper_is_bundled_and_preflighted_before_upgrade_writes(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        installer = (root / "packaging/install.sh").read_text()
        check = 'python3 "$HERE/native-build-directories.py" check --root "$TARGET_ROOT"'
        create = 'python3 "$HERE/native-build-directories.py" create --root "$TARGET_ROOT"'
        self.assertLess(installer.index(check), installer.index('if ((PREFLIGHT_ONLY));then'))
        self.assertLess(installer.index(create), installer.index('systemctl stop panel panel-executor'))
        self.assertLess(installer.index(create), installer.index('ln -sfn "$RELEASE_DIR" "$CURRENT.new"'))
        copy = next(line for line in installer.splitlines() if line.startswith('cp -a "$HERE/bin"'))
        self.assertIn('"$HERE/native-build-directories.py"', copy)
        builder = (root / "packaging/build-release.sh").read_text()
        self.assertIn('"$BUILD_ROOT/packaging/native-build-directories.py"', builder)
        self.assertIn('waf-state-directory.py native-build-directories.py;', builder)
        development = (root / "dev/provision-app.sh").read_text()
        self.assertLess(development.index('"$PANEL_NATIVE_BUILD_PREPARER" check'), development.index('touch /etc/panel-development-vm'))
        self.assertLess(development.index('"$PANEL_NATIVE_BUILD_PREPARER" create'), development.index('systemctl stop panel.service'))
        migration = (root / "scripts/upgrade-running-development.sh").read_text()
        self.assertLess(migration.index('python3 "$RELEASE_PATH/native-build-directories.py" check'), migration.index('BACKUP='))
        self.assertLess(migration.index('python3 "$RELEASE_PATH/native-build-directories.py" create'), migration.index('systemctl stop panel panel-executor\nsqlite3'))

    def test_non_root_cannot_initialize_any_directory(self):
        with tempfile.TemporaryDirectory(prefix="panel-native-cache-refusal-") as directory:
            with mock.patch.object(module.os, "geteuid", return_value=501):
                for create in (False, True):
                    with self.assertRaises(ValueError):
                        module.prepare(directory, create)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "actual root Linux private fixture required")
class NativeBuildDirectoryTests(unittest.TestCase):
    def test_check_is_read_only_and_creation_does_not_repair_or_change_contents(self):
        with tempfile.TemporaryDirectory(prefix="panel-native-cache-test-") as directory:
            root = pathlib.Path(directory)
            target = root / "var/cache/panel-analytics-html-build"
            module.prepare(root, False)
            self.assertEqual(list(root.iterdir()), [])
            module.prepare(root, True)
            self.assertEqual((target.stat().st_uid, target.stat().st_gid, stat.S_IMODE(target.stat().st_mode)), (0, 0, 0o755))
            marker = target / "retained-private-build-evidence"
            marker.write_bytes(b"never prune or repair a previous compiler job")
            marker.chmod(0o600)
            before = target.stat()
            for create in (False, True):
                module.prepare(root, create)
                self.assertEqual((target.stat().st_ino, target.stat().st_mode), (before.st_ino, before.st_mode))
                self.assertEqual(marker.read_bytes(), b"never prune or repair a previous compiler job")
                self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)

    def test_foreign_paths_and_linked_ancestors_are_refused_without_repair(self):
        for kind in ("writable", "private-mode", "foreign-owner", "foreign-group", "symlink", "ancestor-symlink", "file"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="panel-native-cache-test-") as directory:
                root = pathlib.Path(directory)
                module.prepare(root, True)
                target = root / "var/cache/panel-analytics-html-build"
                if kind == "writable":
                    target.chmod(0o777)
                elif kind == "private-mode":
                    target.chmod(0o700)
                elif kind == "foreign-owner":
                    os.chown(target, 65534, 0)
                elif kind == "foreign-group":
                    os.chown(target, 0, 65534)
                elif kind in ("symlink", "file"):
                    retained = target.with_name("retained-original-cache")
                    target.rename(retained)
                    if kind == "symlink":
                        target.symlink_to(retained)
                    else:
                        target.write_bytes(b"foreign file must remain")
                elif kind == "ancestor-symlink":
                    original = root / "var"
                    retained = root / "retained-original-var"
                    original.rename(retained)
                    original.symlink_to(retained)
                before = target.lstat()
                for create in (False, True):
                    with self.assertRaises(ValueError):
                        module.prepare(root, create)
                    after = target.lstat()
                    self.assertEqual((before.st_mode, before.st_uid, before.st_gid, before.st_ino), (after.st_mode, after.st_uid, after.st_gid, after.st_ino))


if __name__ == "__main__":
    unittest.main()
