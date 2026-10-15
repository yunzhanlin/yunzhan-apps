"""Fixed installer supervision contracts, not real application acceptance."""
import pathlib
import unittest


class AppDependencyBudget(unittest.TestCase):
    def test_dependency_worker_has_fixed_resource_limits_and_original_timeout(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        unit = (root / "dev/panel-app-dependencies@.service").read_text()
        section = ""
        settings = {}
        for line in unit.splitlines():
            if line.startswith("["):
                section = line
            elif section == "[Service]" and "=" in line:
                key, value = line.split("=", 1)
                self.assertNotIn(key, settings, "Do not hide an earlier supervisor override")
                settings[key] = value
        expected = {
            "Type": "oneshot", "User": "root",
            "ExecStart": "/opt/panel/bin/panel-executor --install-app-dependencies %i",
            "TimeoutStartSec": "10min", "UMask": "0027",
            "NoNewPrivileges": "true", "ProtectHome": "true",
            "ProtectControlGroups": "true", "KillMode": "control-group",
            "MemoryHigh": "576M", "MemoryMax": "640M", "MemorySwapMax": "0",
            "TasksMax": "128", "CPUQuota": "100%",
        }
        self.assertEqual(settings, expected)

    def test_normal_installer_and_development_publish_same_template(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        builder = (root / "packaging/build-release.sh").read_text()
        installer = (root / "packaging/install.sh").read_text()
        self.assertIn('cp "$BUILD_ROOT/dev/"*.service', builder)
        self.assertIn('for unit in "$HERE/systemd/"*.service', installer)
        self.assertIn('/etc/systemd/system/$name', installer)
        self.assertIn('s#/opt/panel/bin/#/opt/panel/current/bin/#g', installer)
        development = (root / "dev/provision-app.sh").read_text()
        self.assertIn('panel-app-dependencies@', development)
        native = (root / "internal/executor/app_native_linux.go").read_text()
        self.assertIn('context.WithTimeout(context.Background(), budget)', native)
        self.assertIn('budget := 8 * time.Minute', native)
        self.assertIn('"NEEDRESTART_MODE=l"', native)
        for option in ('--download-only', '--no-download'):
            self.assertIn('"'+option+'"', native)
