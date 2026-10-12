import pathlib
import subprocess
import tempfile
import unittest


class ApacheBodyCachePackagingTests(unittest.TestCase):
    def test_actual_package_checksum_pipeline_preserves_escaped_mount_names(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        builder = (root / "packaging/build-release.sh").read_text()
        pipeline = next(line.strip() for line in builder.splitlines() if line.strip().startswith("{ find bin web systemd config -type f"))
        self.assertIn("-print0", pipeline)
        self.assertIn("sort -z", pipeline)
        self.assertIn("xargs -0 shasum", pipeline)
        with tempfile.TemporaryDirectory(prefix="panel-own-cache-checksum-") as directory:
            base = pathlib.Path(directory)
            for name in ("bin", "web", "systemd", "config"):
                (base / name).mkdir()
            for name in ("RELEASE", "SOURCE_INPUTS.json", "BUILD_CHECKS.txt", "install.sh", "verify-release.sh", "prune-releases.sh", "prune-releases.py", "first-install.py", "waf-state-directory.py", "native-build-directories.py", "release-file-modes.py", "upgrade-release.py", "development-upgrade.py"):
                (base / name).write_bytes(b"owned checksum fixture\n")
            mount = base / "systemd" / r"var-cache-panel\x2dapache\x2dbody.mount"
            mount.write_bytes(b"owned exact escaped mount filename\n")
            (base / "web/owned space ' and quote").write_bytes(b"owned filename fixture\n")
            subprocess.run(["bash", "-eu", "-o", "pipefail", "-c", pipeline], cwd=base, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            checker = ["shasum", "-a", "256", "--strict", "-c"] if subprocess.check_output(["uname", "-s"]).strip() == b"Darwin" else ["sha256sum", "--strict", "-c"]
            verifier = (root / "packaging/verify-release.sh").read_text()
            self.assertIn("sha256sum --strict -c", verifier)
            self.assertIn("shasum -a 256 --strict -c", verifier)
            self.assertIn('"$(uname -s)" == Darwin', verifier)
            verified = subprocess.run([*checker, "SHA256SUMS"], cwd=base, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(verified.stdout.count(b": OK"), 15)
            sums = (base / "SHA256SUMS").read_bytes()
            (base / "SHA256SUMS").write_bytes(sums + b"malformed line cannot be skipped\n")
            malformed = subprocess.run([*checker, "SHA256SUMS"], cwd=base, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(malformed.returncode, 0)
            (base / "SHA256SUMS").write_bytes(sums)
            mount.write_bytes(b"owned tampered checksum fixture\n")
            refused = subprocess.run([*checker, "SHA256SUMS"], cwd=base, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(refused.returncode, 0)

    def test_fixed_mount_has_physical_byte_and_inode_limits_not_site_storage(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        name = r"var-cache-panel\x2dapache\x2dbody.mount"
        unit = (root / "dev" / name).read_text()
        settings = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line)
        self.assertEqual(settings["What"], "tmpfs")
        self.assertEqual(settings["Where"], "/var/cache/panel-apache-body")
        self.assertEqual(settings["Type"], "tmpfs")
        self.assertEqual(set(settings["Options"].split(",")), {"rw", "nodev", "nosuid", "noexec", "size=128M", "nr_inodes=4096", "mode=0755", "uid=0", "gid=0"})
        self.assertEqual(settings["DirectoryMode"], "0755")
        self.assertEqual(settings["ReadWriteOnly"], "yes")
        self.assertEqual(settings["TimeoutSec"], "10")
        self.assertEqual(settings["Requires"], "panel-apache-body-cache-check.service")
        self.assertEqual(settings["After"], "panel-apache-body-cache-check.service")
        self.assertNotIn("[Install]", unit)
        self.assertNotIn("%i", unit)
        self.assertNotIn("/srv/panel/sites", unit)

    def test_read_only_guard_cannot_mount_repair_or_hide_old_data(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        unit = (root / "dev/panel-apache-body-cache-check.service").read_text()
        settings = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line)
        self.assertEqual(settings["ExecStart"], "/opt/panel/bin/panel-executor --check-apache-body-cache-mount")
        self.assertEqual(settings["CapabilityBoundingSet"], "CAP_DAC_READ_SEARCH")
        self.assertEqual(settings["ProtectSystem"], "strict")
        self.assertEqual(settings["NoNewPrivileges"], "true")
        self.assertNotIn("ReadWritePaths", settings)
        self.assertNotIn("Environment", settings)
        self.assertNotIn("CAP_SYS_ADMIN", unit)
        self.assertNotIn("ExecStartPre", settings)
        source = (root / "internal/executor/apache_body_cache_linux.go").read_text()
        for marker in ("Fstatfs", "PROC_SUPER_MAGIC", "mnt_id:", "ReadDir(1)", "NOFOLLOW", "AvailableNodes", "MountInfoRoot"):
            self.assertIn(marker, source)
        for mutation in ("os.Remove", "os.Chmod", "os.Chown", "unix.Mount", "syscall.Mount"):
            self.assertNotIn(mutation, source)
        self.assertIn("return checkApacheBodyCacheMount(true)", source)
        self.assertIn("return checkApacheBodyCacheMount(false)", source)
        self.assertIn("return verifyApacheBodyCacheQuotaView(false)", source)

    def test_normal_packages_and_migration_include_mount_and_cold_start_gate(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        builder = (root / "packaging/build-release.sh").read_text()
        installer = (root / "packaging/install.sh").read_text()
        migration = (root / "scripts/upgrade-running-development.sh").read_text()
        development = (root / "dev/provision-app.sh").read_text()
        self.assertIn('"$BUILD_ROOT/dev/"*.mount', builder)
        self.assertIn('"$HERE/systemd/"*.mount', installer)
        self.assertIn('development-upgrade.py', migration)
        transaction = (root/'packaging/development-upgrade.py').read_text()
        self.assertIn("self.units = sorted((self.release/'systemd').iterdir())", transaction)
        self.assertIn('production.UNIT.fullmatch(source.name)', transaction)
        self.assertIn(r"var-cache-panel\x2dapache\x2dbody.mount", development)
        self.assertIn('(("var", "cache", "panel-apache-body"), 0o755)', (root / "packaging/native-build-directories.py").read_text())
        self.assertIn('(("var", "lib", "panel-apache-body"), 0o755)', (root / "packaging/native-build-directories.py").read_text())
        apache = (root / "dev/panel-apache.service").read_text()
        self.assertIn("RequiresMountsFor=/var/cache/panel-apache-body", apache)
        recover = "ExecStartPre=/opt/panel/bin/panel-executor --recover-apache-waf-config"
        prepare = "ExecStartPre=/opt/panel/bin/panel-executor --prepare-apache-body-runtime"
        self.assertLess(apache.index(recover), apache.index(prepare))
        self.assertLess(apache.index(prepare), apache.index("ExecStart="))
        self.assertIn("ReadWritePaths=/var/lib/panel-apache-body", apache)
        self.assertIn("ReadWritePaths=/var/lib/panel-apache-body", (root / "dev/panel-executor.service").read_text())
        activation = (root / "internal/executor/apache_body_activation_linux.go").read_text()
        self.assertIn('const apacheBodyMetadataDirectory = "/var/lib/panel-apache-body"', activation)
        self.assertNotIn('"/var/log/apache2/panel-waf.body.events.log"', activation)
        patch = (root / "internal/executor/assets/apache-body-metadata-only.patch").read_text()
        self.assertIn('open("/var/lib/panel-apache-body/events.log"', patch)
        self.assertNotIn('open("/var/log/apache2', patch)
        startup = (root / "internal/executor/apache_body_startup_linux.go").read_text()
        self.assertLess(startup.index("s.verifyApacheBodyTransition(ctx, cfg, cfg)"), startup.index("s.prepareApacheBodyStorage(ctx, cfg)"))
        self.assertNotIn("Config.Run", startup)
        self.assertNotIn("os.Remove", startup)
        self.assertIn('const ApacheWAFVersion = "2.3.0"', (root / "internal/core/apache_waf.go").read_text())

    def test_upgrade_preflight_is_before_any_host_or_service_mutation(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        installer = (root / "packaging/install.sh").read_text()
        guard = '"$HERE/bin/panel-executor" --check-apache-body-cache-upgrade'
        self.assertIn('if [[ "$TARGET_ROOT" == / ]]; then\n    ' + guard, installer)
        for mutation in ('apt-get update', 'useradd --system', 'mkdir -p "$(dirname "$RELEASE_DIR")"', 'exec 9>', 'systemctl stop panel', 'mv -Tf "$CURRENT.new"'):
            self.assertLess(installer.index(guard), installer.index(mutation))
        self.assertLess(installer.index('"$HERE/verify-release.sh" "$HERE"'), installer.index(guard))
        migration = (root / "scripts/upgrade-running-development.sh").read_text()
        self.assertIn('development-upgrade.py', migration)
        transaction = (root/'packaging/development-upgrade.py').read_text()
        self.assertIn("str(self.release/'bin/panel-executor'), '--check-apache-body-cache-upgrade'", transaction)
        self.assertLess(transaction.index('self.preflight()\n'), transaction.index('self.backup.mkdir(mode=0o700)'))
        self.assertLess(transaction.index('self.preflight()\n'), transaction.index('self.stop_writers()\n'))


if __name__ == "__main__":
    unittest.main()
