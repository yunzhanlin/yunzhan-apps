"""Data-only rule delivery confinement; not a native/commercial acceptance claim."""
import pathlib
import unittest


class NetworkRuleFeedBudget(unittest.TestCase):
    def test_offline_fixed_entry_zero_capabilities_and_closed_writable_paths(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        unit = (root / "dev/panel-network-rulefeed-install@.service").read_text()
        settings = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line)
        expected = {"User": "root", "Group": "root", "ExecStart": "/opt/panel/bin/panel-executor --install-network-ids-rulefeed %i", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "NoNewPrivileges": "true", "PrivateNetwork": "true", "PrivateTmp": "true", "PrivateDevices": "true", "ProtectSystem": "strict", "ProtectHome": "true", "RestrictAddressFamilies": "AF_UNIX", "MemoryHigh": "192M", "MemoryMax": "256M", "MemorySwapMax": "0", "TasksMax": "16", "CPUQuota": "70%", "UMask": "0077", "TimeoutStartSec": "130s", "TimeoutStopSec": "10s", "KillMode": "control-group"}
        for key, value in expected.items():
            self.assertEqual(settings[key], value, key)
        self.assertEqual(settings["ReadWritePaths"].split(), ["/opt/panel/network-rule-feeds", "/var/lib/panel-executor/network-rule-feed-jobs"])
        self.assertNotIn("[Install]", unit)
        self.assertNotIn("ExecStartPre", settings)
        self.assertNotIn("ExecStartPost", settings)
        executor = (root / "dev/panel-executor.service").read_text()
        self.assertNotIn("/opt/panel/network-rule-feeds", executor)
        self.assertNotIn("CAP_SETUID", executor)
        provision = (root / "dev/provision-app.sh").read_text()
        self.assertIn("panel-network-rulefeed-install@", provision)
        packaging = (root / "packaging/native-build-directories.py").read_text()
        self.assertIn('(\"opt\", \"panel\", \"network-rule-feeds\")', packaging)

    def test_root_entry_does_not_download_activate_or_mutate_original_programs(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        source = (root / "internal/executor/app_threat_rulefeed_jobs_linux.go").read_text()
        entry = source[source.index("func RunNetworkIDSRuleFeedInstall("):]
        for forbidden in ("http.Get", "FetchRuleFeed", "exec.Command", "PrepareIDS", "os.Chown", "os.Remove", '"start"', '"enable"', "threatIDSYAML", "threatIDSSyntax"):
            self.assertNotIn(forbidden, entry)
        self.assertIn("store.verify(ctx, in, request.Selection.AppVersion, request.Selection.AppManifestSHA)", entry)
        self.assertIn("store.install(ctx, in, request.Selection.AppVersion, request.Selection.AppManifestSHA)", entry)
        self.assertIn('ruleFeedStoreWrite(root, "result.json"', entry)
        self.assertIn("syscall.LOCK_EX|syscall.LOCK_NB", entry)


if __name__ == "__main__":
    unittest.main()
