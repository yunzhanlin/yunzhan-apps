"""Real Root filesystem and actual isolated installer backup privacy regressions."""
import hashlib
import importlib.util
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("backup_directories", HERE / "backup-directories.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BackupDirectoryPolicyTests(unittest.TestCase):
    def test_nonroot_cannot_check_or_create(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            with mock.patch.object(module.os, "geteuid", return_value=501):
                for create in (False, True):
                    with self.assertRaisesRegex(ValueError, "requires root"):
                        module.prepare(root, create)
            self.assertEqual(list(root.iterdir()), [])

    def test_only_fresh_entrypoints_provision_backups_before_accounts_or_services(self):
        source = (HERE / "install.sh").read_text()
        check = 'python3 "$HERE/backup-directories.py" check --root "$TARGET_ROOT"'
        create = 'python3 "$HERE/backup-directories.py" create --root "$TARGET_ROOT"'
        self.assertLess(source.index('exec python3 "$HERE/development-upgrade.py"'), source.index(check))
        self.assertLess(source.index(check), source.index('fresh_apt_acquire apt-get update'))
        self.assertLess(source.index(check), source.index('if ((PREFLIGHT_ONLY));then'))
        self.assertLess(source.index('exec python3 "$HERE/upgrade-release.py" run'), source.index(create))
        self.assertIn('if ((FRESH)); then ' + create + '; fi', source)
        bulk = next(line for line in source.splitlines() if line.startswith('mkdir -p "$(dirname "$RELEASE_DIR")"'))
        self.assertNotIn('/var/backups/panel/', bulk)
        self.assertNotIn('chmod 0700 "$(prefix /var/backups/panel/system)"', source)
        for name in ("upgrade-release.py", "development-upgrade.py"):
            self.assertNotIn('backup-directories.py', (HERE / name).read_text())
        copy = next(line for line in source.splitlines() if line.startswith('cp -a "$HERE/bin"'))
        self.assertIn('"$HERE/backup-directories.py"', copy)
        build = (HERE / "build-release.sh").read_text()
        self.assertIn('"$BUILD_ROOT/packaging/backup-directories.py"', build)
        self.assertIn('backup-directories.py', next(line for line in build.splitlines() if 'printf' in line and 'SOURCE_INPUTS.json' in line))
        development = (HERE.parent / "dev/provision-app.sh").read_text()
        self.assertLess(development.index('"$PANEL_BACKUP_DIRECTORY_PREPARER" check'), development.index('touch /etc/panel-development-vm'))
        self.assertLess(development.index('"$PANEL_BACKUP_DIRECTORY_PREPARER" create'), development.index('systemctl stop panel.service'))
        self.assertNotIn('install -d -m 0700 /var/backups', development)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "actual Root Linux filesystem required")
class BackupDirectoryRootTests(unittest.TestCase):
    def temporary(self):
        return tempfile.TemporaryDirectory(prefix="panel-backup-private-c55-", dir="/tmp")

    def inventory(self, root):
        result = {}
        for path in [root, *sorted(root.rglob("*"))]:
            value = path.lstat()
            result[str(path.relative_to(root))] = (
                value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                value.st_gid, value.st_nlink, value.st_size if path.is_file() else None,
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else None,
                os.readlink(path) if path.is_symlink() else None,
            )
        return result

    def test_check_is_readonly_and_fresh_dirs_private_under_all_caller_umasks(self):
        for mask in (0o000, 0o022, 0o077, 0o777):
            with self.subTest(umask=oct(mask)), self.temporary() as temporary:
                root = pathlib.Path(temporary).resolve()
                before = self.inventory(root)
                module.prepare(root)
                self.assertEqual(self.inventory(root), before)
                prior = os.umask(mask)
                try:
                    module.prepare(root, True)
                finally:
                    os.umask(prior)
                for name in module.TARGETS:
                    value = (root / "var/backups/panel" / name).lstat()
                    self.assertEqual((stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid), (0o700, 0, 0))
                for name in ("var", "var/backups", "var/backups/panel"):
                    self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o755)

    def test_existing_private_contents_inode_permissions_and_owner_are_unchanged(self):
        with self.temporary() as temporary:
            root = pathlib.Path(temporary).resolve()
            module.prepare(root, True)
            for name in module.TARGETS:
                directory = root / "var/backups/panel" / name
                (directory / "original.sql").write_bytes(b"original secret backup\n")
                (directory / "original.sql").chmod(0o600)
                (directory / "old-failure.json").write_bytes(b'{"attempts":1048431,"state":"pending"}')
            before = self.inventory(root)
            for create in (False, True):
                module.prepare(root, create)
                self.assertEqual(self.inventory(root), before)

    def test_nonprivate_empty_or_populated_roots_refuse_without_any_repair(self):
        for name in module.TARGETS:
            for mode in (0o755, 0o750, 0o777, 0o711):
                for populated in (False, True):
                    with self.subTest(name=name, mode=oct(mode), populated=populated), self.temporary() as temporary:
                        root = pathlib.Path(temporary).resolve()
                        target = root / "var/backups/panel" / name
                        target.mkdir(parents=True)
                        target.chmod(mode)
                        if populated:
                            (target / "original.sql").write_bytes(b"never rewrite permissions or content")
                        before = self.inventory(root)
                        for create in (False, True):
                            with self.assertRaises(ValueError):
                                module.prepare(root, create)
                            self.assertEqual(self.inventory(root), before)

    def test_foreign_uid_gid_symlinks_and_files_cannot_redirect_provisioning(self):
        for kind in ("foreign-uid", "foreign-gid", "symlink", "dangling-link", "file", "fifo"):
            with self.subTest(kind=kind), self.temporary() as temporary:
                root = pathlib.Path(temporary).resolve()
                target = root / "var/backups/panel/mysql"
                target.parent.mkdir(parents=True)
                outside = root / "original-outside"; outside.mkdir(mode=0o700)
                (outside / "original.sql").write_bytes(b"not an install target")
                if kind in ("foreign-uid", "foreign-gid"):
                    target.mkdir(mode=0o700)
                    os.chown(target, 65534 if kind == "foreign-uid" else 0, 65534 if kind == "foreign-gid" else 0)
                elif kind == "symlink": target.symlink_to(outside)
                elif kind == "dangling-link": target.symlink_to(root / "missing")
                elif kind == "file": target.write_bytes(b"original non-directory")
                else: os.mkfifo(target)
                # Do not read a FIFO in the evidence inventory.
                before = self.inventory(root) if kind != "fifo" else (target.lstat(), self.inventory(outside))
                for create in (False, True):
                    with self.assertRaises((OSError, ValueError)):
                        module.prepare(root, create)
                    after = self.inventory(root) if kind != "fifo" else (target.lstat(), self.inventory(outside))
                    self.assertEqual(after, before)
                    self.assertFalse((root / "var/backups/panel/system").exists())

    def test_all_targets_are_prechecked_before_first_create(self):
        with self.temporary() as temporary:
            root = pathlib.Path(temporary).resolve()
            foreign = root / "var/backups/panel/sites"
            foreign.mkdir(parents=True); foreign.chmod(0o750)
            (foreign / "original.zip").write_bytes(b"preserve all data")
            before = self.inventory(root)
            with self.assertRaises(ValueError):module.prepare(root, True)
            self.assertEqual(self.inventory(root), before)

    def test_linked_or_writable_ancestors_and_staging_boundaries_refuse(self):
        for kind in ("var-link", "parent-link", "root-link", "root-intermediate-link", "writable", "foreign"):
            with self.subTest(kind=kind), self.temporary() as temporary:
                base = pathlib.Path(temporary).resolve(); root = base / "target"; root.mkdir()
                outside = base / "outside"; outside.mkdir()
                if kind == "var-link": (root / "var").symlink_to(outside)
                elif kind == "parent-link":
                    (root / "var/backups").mkdir(parents=True); (root / "var/backups/panel").symlink_to(outside)
                elif kind == "root-link":
                    root.rmdir(); root.symlink_to(outside)
                elif kind == "root-intermediate-link":
                    (outside / "nested").mkdir(); root.rmdir(); root.symlink_to(outside); root = root / "nested"
                else:
                    (root / "var").mkdir()
                    if kind == "writable": (root / "var").chmod(0o777)
                    else: os.chown(root / "var", 65534, 0)
                before = self.inventory(base)
                for create in (False, True):
                    with self.assertRaises((OSError, ValueError)):module.prepare(root, create)
                    self.assertEqual(self.inventory(base), before)

    def test_racing_existing_directory_is_validated_and_never_chmodded(self):
        with self.temporary() as temporary:
            root = pathlib.Path(temporary).resolve(); (root / "var/backups/panel").mkdir(parents=True)
            original = module.os.mkdir
            def competing(name, mode=0o777, *, dir_fd=None):
                if name == "mysql":
                    original(name, 0o750, dir_fd=dir_fd)
                    # The Root QA worker itself uses umask 077. Explicitly
                    # model the competing installer's non-private directory.
                    child = os.open(name, module.FLAGS, dir_fd=dir_fd)
                    try:os.fchmod(child, 0o750)
                    finally:os.close(child)
                    raise FileExistsError("another fresh installer created this path")
                return original(name, mode, dir_fd=dir_fd)
            with mock.patch.object(module.os, "mkdir", side_effect=competing), self.assertRaises(ValueError):
                module.prepare(root, True)
            self.assertEqual(stat.S_IMODE((root / "var/backups/panel/mysql").stat().st_mode), 0o750)

    def test_setgid_parent_does_not_make_new_backup_roots_group_readable(self):
        with self.temporary() as temporary:
            root = pathlib.Path(temporary).resolve(); parent = root / "var/backups/panel"
            parent.mkdir(parents=True); os.chown(parent, 0, 34567); parent.chmod(0o2755)
            before = parent.lstat()
            module.prepare(root, True)
            after = parent.lstat()
            self.assertEqual((before.st_ino, before.st_mode, before.st_uid, before.st_gid), (after.st_ino, after.st_mode, after.st_uid, after.st_gid))
            for name in module.TARGETS:
                value = (parent / name).lstat()
                self.assertEqual((stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid), (0o700, 0, 0))

    def fixture_release(self, base):
        release = base / "release"; release.mkdir()
        for name in ("bin", "web", "systemd", "config"): (release / name).mkdir()
        for name in ("panel", "panel-executor", "panel-start-guard"): (release / "bin" / name).write_bytes(b"fixture is never executed\n")
        (release / "web/index.html").write_text("isolated fixture")
        for name in ("install.sh", "verify-release.sh", "prune-releases.sh", "prune-releases.py", "first-install.py", "fresh-ssh-policy.py", "waf-state-directory.py", "native-build-directories.py", "backup-directories.py", "release-file-modes.py", "upgrade-release.py", "development-upgrade.py", "start-guard-install.py"):
            shutil.copyfile(HERE / name, release / name)
        (release / "RELEASE").write_text("PANEL_FORMAT=1\nPANEL_VERSION=0.1.0-dev.backupfixture55\nPANEL_OS=linux\nPANEL_ARCH=amd64\n")
        sums = "".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.relative_to(release).as_posix() + "\n" for p in sorted(release.rglob("*")) if p.is_file())
        (release / "SHA256SUMS").write_text(sums)
        spec = importlib.util.spec_from_file_location("fixture_release_modes", release / "release-file-modes.py")
        policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)
        policy.payload_modes(release, True)
        return release

    def install(self, release, root, preflight=False):
        command = ["bash", str(release / "install.sh"), "--root", str(root), "--no-services"]
        if preflight:command.append("--preflight-only")
        return subprocess.run(command, capture_output=True, text=True, timeout=20)

    def test_actual_isolated_installer_preflight_and_fresh_creation_and_private_read_denial(self):
        with self.temporary() as temporary:
            base = pathlib.Path(temporary).resolve(); base.chmod(0o755)
            release = self.fixture_release(base); root = base / "target"; root.mkdir(mode=0o755)
            before = self.inventory(root)
            result = self.install(release, root, True)
            self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(self.inventory(root), before)
            result = self.install(release, root)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in module.TARGETS:
                directory = root / "var/backups/panel" / name
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                (directory / "original-secret").write_bytes(b"root backup secret")
                (directory / "original-secret").chmod(0o644)
            public = base / "public-proof"; public.write_text("traversal permitted"); public.chmod(0o644)
            code = "import os,pathlib,sys;os.setgid(65534);os.setuid(65534);assert pathlib.Path(sys.argv[1]).read_text()=='traversal permitted'\nfor name in sys.argv[2:]:\n try:pathlib.Path(name).read_bytes()\n except PermissionError:continue\n raise AssertionError('backup accessible to an unrelated account')\n"
            denied = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(public), *[str(root / "var/backups/panel" / name / "original-secret")for name in module.TARGETS]], capture_output=True, text=True, timeout=10)
            self.assertEqual(denied.returncode, 0, denied.stderr)
            installed = root / "opt/panel/current/backup-directories.py"
            self.assertEqual(installed.read_bytes(), (HERE / "backup-directories.py").read_bytes())

    def test_actual_installer_refuses_existing_bad_root_without_touching_it(self):
        with self.temporary() as temporary:
            base = pathlib.Path(temporary).resolve(); release = self.fixture_release(base)
            root = base / "target"; root.mkdir(); target = root / "var/backups/panel/mysql"
            target.mkdir(parents=True); target.chmod(0o750); (target / "original.sql").write_bytes(b"original customer data")
            before = self.inventory(root)
            for preflight in (True, False):
                result = self.install(release, root, preflight)
                self.assertNotEqual(result.returncode, 0); self.assertIn("not repaired", result.stderr)
                self.assertEqual(self.inventory(root), before)

    def test_isolated_existing_release_staging_does_not_repair_backup_permissions(self):
        with self.temporary() as temporary:
            base = pathlib.Path(temporary).resolve(); release = self.fixture_release(base)
            root = base / "target"; root.mkdir(); (root / "etc").mkdir()
            (root / "etc/panel-release").write_text("version=0.1.0-dev.previous\narch=amd64\n")
            for name in module.TARGETS:
                target = root / "var/backups/panel" / name; target.mkdir(parents=True); target.chmod(0o750)
                (target / "original").write_bytes(b"retain backups across programme staging")
            backups = root / "var/backups"; before = self.inventory(backups)
            result = self.install(release, root)
            self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(self.inventory(backups), before)


if __name__ == "__main__":
    unittest.main()
