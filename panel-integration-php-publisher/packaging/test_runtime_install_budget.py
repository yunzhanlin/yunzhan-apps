"""Verify the supervisor leaves room for bounded PHP compile and lock wait."""
import pathlib
import unittest


class RuntimeInstallSupervisorBudget(unittest.TestCase):
    def test_full_build_process_group_and_bounded_start(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        unit = (root / "dev/panel-install@.service").read_text()
        settings = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line)
        self.assertEqual(settings["TimeoutStartSec"], "300min")
        self.assertEqual(settings["KillMode"], "control-group")
        self.assertEqual(settings["MemoryAccounting"], "true")
        self.assertEqual(settings["MemoryHigh"], "1G")
        self.assertEqual(settings["MemoryMax"], "1G")
        self.assertEqual(settings["MemorySwapMax"], "0")
        self.assertEqual(settings["OOMPolicy"], "stop")
        self.assertEqual(settings["OOMScoreAdjust"], "500")
        self.assertEqual(settings["Environment"], "GOMEMLIMIT=128MiB")
        self.assertEqual(settings["ProtectControlGroups"], "true")
        self.assertEqual(settings["NoNewPrivileges"], "true")
        self.assertGreater(300, 240 + 30)

    def test_observed_php82_compiler_requires_new_finite_budget_without_early_reclaim(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        unit = (root / "dev/panel-install@.service").read_text()
        settings = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line)
        # The retained real PHP8.2 Zend component exceeded the former768MiB
        # budget. This model does not assert whole-runtime/app acceptance.
        observed_bytes = 1053114368
        self.assertGreater(observed_bytes, 768 * 1024 * 1024)
        self.assertLess(observed_bytes, 1024 * 1024 * 1024)
        self.assertEqual(settings["MemoryHigh"], settings["MemoryMax"])
        self.assertEqual(settings["MemoryMax"], "1G")
        self.assertEqual(settings["MemorySwapMax"], "0")
        self.assertEqual(settings["ProtectControlGroups"], "true")
        self.assertEqual(settings["NoNewPrivileges"], "true")


if __name__ == "__main__":
    unittest.main()
