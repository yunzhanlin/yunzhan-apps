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
        self.assertIn('waf-state-directory.py native-build-directories.py release-file-modes.py upgrade-release.py;', builder)
        development = (root / "dev/provision-app.sh").read_text()
        self.assertLess(development.index('"$PANEL_NATIVE_BUILD_PREPARER" check'), development.index('touch /etc/panel-development-vm'))
        self.assertLess(development.index('"$PANEL_NATIVE_BUILD_PREPARER" create'), development.index('systemctl stop panel.service'))
        migration = (root / "scripts/upgrade-running-development.sh").read_text()
        self.assertLess(migration.index('python3 "$RELEASE_PATH/native-build-directories.py" check'), migration.index('BACKUP='))
        self.assertLess(migration.index('python3 "$RELEASE_PATH/native-build-directories.py" create'), migration.index('systemctl stop panel panel-executor\ncheck_queues\nsqlite3'))

    def test_non_root_cannot_initialize_any_directory(self):
        with tempfile.TemporaryDirectory(prefix="panel-native-cache-refusal-") as directory:
            with mock.patch.object(module.os, "geteuid", return_value=501):
                for create in (False, True):
                    with self.assertRaises(ValueError):
                        module.prepare(directory, create)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_runtime_cache_is_root_managed_without_reowning_legacy_compiler_output(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        installer = (root / "packaging/install.sh").read_text()
        self.assertNotIn("chown -R panel-build:panel-build /var/cache/panel-build", installer)
        self.assertNotIn("chmod 0755 /var/cache/panel-build", installer)
        unit = (root / "dev/panel-install@.service").read_text()
        writable = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths="))
        self.assertIn("/var/cache/panel-runtime-build", writable)
        self.assertNotIn("/var/cache/panel-build", writable)
        for name in ("install_linux.go", "php_extensions_linux.go", "redis_node_install_linux.go", "mysql_install_linux.go", "mariadb_install_linux.go", "app_ftp_runtime_linux.go"):
            code = (root / "internal/executor" / name).read_text()
            self.assertIn("prepareRuntimeBuildDirectory(", code)
            self.assertNotIn('"/var/cache/panel-build"', code)
        for name in ("install_linux.go", "php_extensions_linux.go", "redis_node_install_linux.go"):
            code = (root / "internal/executor" / name).read_text()
            self.assertIn("prepareRuntimeBuildWork(base)", code)
            self.assertNotIn("os.RemoveAll(work)", code)

    def test_native_compiler_scope_and_serialization_are_closed(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        unit = (root / "dev/panel-install@.service").read_text()
        for required in ("NoNewPrivileges=true", "ProtectControlGroups=true", "KillMode=control-group", "TasksMax=512"):
            self.assertIn(required, unit)
        self.assertIn("ProtectControlGroups=true", (root / "dev/panel-app-dependencies@.service").read_text())
        for name in ("install_linux.go", "app_ftp_runtime_linux.go"):
            self.assertIn("acquireRuntimeNativeBuildSerialization(", (root / "internal/executor" / name).read_text())
        scope = (root / "internal/executor/runtime_compiler_scope_linux.go").read_text()
        for required in ("unix.CGROUP2_SUPER_MAGIC", "unix.PidfdOpen", "unix.PidfdSendSignal", "syscall.Wait4", "apacheBodyCompilerSubreaper"):
            self.assertIn(required, scope)
        for required in ("pidfds map[int]compilerProcessReference", "compilerPIDFDTask", "unix.WNOWAIT|unix.WALL", "syscall.WNOHANG|unix.WALL", "len(s.pidfds) == 0 && noChildren", "s.pruneReapedLocked()"):
            self.assertIn(required, scope.replace("\t", " ") if required.startswith("pidfds ") else scope)
        self.assertIn("defer scope.Close()", (root / "internal/executor/install_linux.go").read_text())
        self.assertNotIn("defer scope.Root.Close()", (root / "internal/executor/install_linux.go").read_text())
        self.assertNotIn("syscall.Kill(-", scope)
        build = (root / "internal/executor/install_linux.go").read_text()
        self.assertIn("scope.collect()", build)
        self.assertNotIn("syscall.Kill(-cmd.Process.Pid", build)
        apache_unit = (root / "dev/panel-apache-body-build@.service").read_text()
        self.assertIn("ProtectControlGroups=true", apache_unit)
        runner = (root / "internal/executor/waf_engine_build_command_linux.go").read_text()
        for required in ("beginNativeCompilerScope(authority)", "scope.signalMembers()", "scope.collect()", "syscall.O_NONBLOCK", "log.Sync()", "runtimeBuildIdentityArgs(command.Program, command.Arguments...)"):
            self.assertIn(required, runner)
        self.assertNotIn("syscall.Kill(-",runner)
        for name in ("panel-waf-engine-build@.service", "panel-analytics-html-build@.service"):
            self.assertIn("ProtectControlGroups=true", (root / "dev" / name).read_text())
        self.assertNotIn("collectApacheBodyCompilerGroup", runner)
        old_process = (root / "internal/executor/apache_body_process_linux.go").read_text()
        self.assertNotIn("syscall.Kill(-", old_process)
        self.assertNotIn("Wait4(-", old_process)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "actual root Linux private fixture required")
class NativeBuildDirectoryTests(unittest.TestCase):
    def test_runtime_root_refuses_foreign_paths_and_preserves_legacy_and_completed_work(self):
        for kind in ("valid", "symlink", "foreign-owner", "foreign-group", "writable", "private-mode"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="panel-runtime-native-provision-") as directory:
                root = pathlib.Path(directory)
                module.prepare(root, True)
                cache = root / "var/cache/panel-runtime-build"
                legacy = root / "var/cache/panel-build"
                legacy.mkdir(mode=0o755)
                legacy_marker = legacy / "retained-untrusted-build"
                legacy_marker.write_bytes(b"do not chown or silently remove legacy evidence")
                os.chown(legacy, 65534, 65534)
                legacy_before = legacy.lstat()
                marker = cache / "previous-root-job"
                marker.write_bytes(b"retained native work")
                marker.chmod(0o600)
                if kind == "symlink":
                    original = cache.with_name("retained-original")
                    cache.rename(original); cache.symlink_to(original)
                elif kind == "foreign-owner": os.chown(cache, 65534, 0)
                elif kind == "foreign-group": os.chown(cache, 0, 65534)
                elif kind == "writable": cache.chmod(0o777)
                elif kind == "private-mode": cache.chmod(0o700)
                before = cache.lstat()
                for create in (False, True):
                    if kind == "valid": module.prepare(root, create)
                    else:
                        with self.assertRaises(ValueError): module.prepare(root, create)
                    after = cache.lstat()
                    self.assertEqual((before.st_mode,before.st_uid,before.st_gid,before.st_ino),(after.st_mode,after.st_uid,after.st_gid,after.st_ino))
                    self.assertEqual(marker.read_bytes(), b"retained native work")
                    self.assertEqual((legacy.stat().st_mode,legacy.stat().st_uid,legacy.stat().st_gid,legacy.stat().st_ino), (legacy_before.st_mode,legacy_before.st_uid,legacy_before.st_gid,legacy_before.st_ino))
                    self.assertEqual(legacy_marker.read_bytes(), b"do not chown or silently remove legacy evidence")

    def test_apache_private_namespaces_and_shared_lock_preserve_existing_evidence(self):
        with tempfile.TemporaryDirectory(prefix="panel-apache-native-provision-") as directory:
            root = pathlib.Path(directory)
            module.prepare(root, False)
            self.assertEqual(list(root.iterdir()), [])
            module.prepare(root, True)
            for name in ("apache-body-builds", "apache-body-requests", "apache-body-cancellations"):
                target = root / "var/lib/panel-executor" / name
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
                self.assertEqual((target.stat().st_uid, target.stat().st_gid), (0, 0))
                self.assertEqual(list(target.iterdir()), [])
            for name in ("var/cache/panel-apache-body-build", "var/cache/panel-apache-body", "var/lib/panel-apache-body", "opt/panel/app-modules/apache-waf/engines"):
                target = root / name
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
                self.assertEqual(list(target.iterdir()), [])
            lock = root / "var/lib/panel-executor/build.lock"
            lock.write_bytes(b"retained-lock-evidence")
            before = lock.stat()
            for create in (False, True):
                module.prepare(root, create)
                self.assertEqual(lock.stat().st_ino, before.st_ino)
                self.assertEqual(lock.read_bytes(), b"retained-lock-evidence")
            lock.chmod(0o644)
            for create in (False, True):
                with self.assertRaises(ValueError):
                    module.prepare(root, create)
                self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o644)

    def test_apache_paths_refuse_links_foreign_permissions_and_shared_lock(self):
        for name in ("var/cache/panel-apache-body-build", "var/cache/panel-apache-body", "var/lib/panel-apache-body", "var/lib/panel-executor/apache-body-builds", "var/lib/panel-executor/apache-body-requests", "var/lib/panel-executor/apache-body-cancellations", "opt/panel/app-modules/apache-waf/engines", "var/lib/panel-executor/build.lock"):
            for kind in ("symlink", "foreign-owner", "foreign-group", "writable"):
                with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory(prefix="panel-apache-native-refusal-") as directory:
                    root = pathlib.Path(directory)
                    module.prepare(root, True)
                    target = root / name
                    if kind == "symlink":
                        retained = target.with_name("retained-original")
                        target.rename(retained)
                        target.symlink_to(retained)
                    elif kind == "foreign-owner": os.chown(target, 65534, 0)
                    elif kind == "foreign-group": os.chown(target, 0, 65534)
                    else: target.chmod(0o777)
                    before = target.lstat()
                    for create in (False, True):
                        with self.assertRaises(ValueError): module.prepare(root, create)
                        after = target.lstat()
                        self.assertEqual((after.st_ino, after.st_mode, after.st_uid, after.st_gid), (before.st_ino, before.st_mode, before.st_uid, before.st_gid))

    def test_rule_feed_parent_refuses_foreign_state_without_repairs(self):
        for kind in ("writable", "private-mode", "foreign-owner", "foreign-group", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="panel-native-rules-test-") as directory:
                root = pathlib.Path(directory)
                module.prepare(root, True)
                target = root / "opt/panel/network-rule-feeds"
                if kind == "writable": target.chmod(0o777)
                elif kind == "private-mode": target.chmod(0o700)
                elif kind == "foreign-owner": os.chown(target, 65534, 0)
                elif kind == "foreign-group": os.chown(target, 0, 65534)
                else:
                    retained = target.with_name("retained-rules")
                    target.rename(retained); target.symlink_to(retained)
                before = target.lstat()
                for create in (False, True):
                    with self.assertRaises(ValueError): module.prepare(root, create)
                    after = target.lstat()
                    self.assertEqual((before.st_mode, before.st_uid, before.st_gid, before.st_ino), (after.st_mode, after.st_uid, after.st_gid, after.st_ino))

    def test_check_is_read_only_and_creation_does_not_repair_or_change_contents(self):
        with tempfile.TemporaryDirectory(prefix="panel-native-cache-test-") as directory:
            root = pathlib.Path(directory)
            target = root / "var/cache/panel-analytics-html-build"
            ids = root / "var/lib/panel-network-ids"
            module.prepare(root, False)
            self.assertEqual(list(root.iterdir()), [])
            module.prepare(root, True)
            self.assertEqual((ids.stat().st_uid, ids.stat().st_gid, stat.S_IMODE(ids.stat().st_mode)), (0, 0, 0o755))
            self.assertEqual(list(ids.iterdir()), [])  # no account/config/capture as part of a core update
            rules = root / "opt/panel/network-rule-feeds"
            self.assertEqual((rules.stat().st_uid, rules.stat().st_gid, stat.S_IMODE(rules.stat().st_mode)), (0, 0, 0o755))
            self.assertEqual(list(rules.iterdir()), [])  # empty data root only, no rules or native application installed
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

    def test_ids_parent_preflight_refuses_external_state_without_repairs(self):
        for kind in ("writable", "private-mode", "foreign-owner", "foreign-group", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="panel-native-ids-test-") as directory:
                root=pathlib.Path(directory)
                module.prepare(root, True)
                ids=root / "var/lib/panel-network-ids"
                if kind=="writable":ids.chmod(0o777)
                elif kind=="private-mode":ids.chmod(0o700)
                elif kind=="foreign-owner":os.chown(ids,65534,0)
                elif kind=="foreign-group":os.chown(ids,0,65534)
                else:
                    retained=ids.with_name("retained-ids")
                    ids.rename(retained);ids.symlink_to(retained)
                before=ids.lstat()
                for create in (False,True):
                    with self.assertRaises(ValueError):module.prepare(root,create)
                    after=ids.lstat()
                    self.assertEqual((before.st_mode,before.st_uid,before.st_gid,before.st_ino),(after.st_mode,after.st_uid,after.st_gid,after.st_ino))

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
