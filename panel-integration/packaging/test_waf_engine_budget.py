"""Request-body engine build supervision, not a business acceptance report."""
import pathlib
import unittest

class WAFBuildSupervisor(unittest.TestCase):
    def test_bounded_worker_and_read_only_live_configuration(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        unit = (root / 'dev/panel-waf-engine-build@.service').read_text()
        settings = dict(line.split('=', 1) for line in unit.splitlines() if '=' in line)
        self.assertEqual(settings['TimeoutStartSec'], '300min')
        self.assertEqual(settings['KillMode'], 'control-group')
        self.assertEqual(settings['CPUQuota'], '100%')
        self.assertEqual(settings['MemoryHigh'], '576M')
        self.assertEqual(settings['MemoryMax'], '640M')
        self.assertEqual(settings['TasksMax'], '256')
        self.assertEqual(settings['UMask'], '0077')
        self.assertEqual(settings['ProtectSystem'], 'strict')
        self.assertEqual(settings['NoNewPrivileges'], 'true')
        writable = settings['ReadWritePaths'].split()
        self.assertIn('/var/cache/panel-waf-build', writable)
        self.assertNotIn('/var/cache/panel-build', writable)
        for path in ('/etc/nginx', '/etc/panel', '/srv/panel/sites'):
            self.assertNotIn(path, writable)
        self.assertIn('/etc/nginx', settings['ReadOnlyPaths'].split())
        self.assertNotIn('CAP_SYS_ADMIN', settings['CapabilityBoundingSet'])
        self.assertEqual(settings['ExecStart'], '/opt/panel/bin/panel-executor --build-waf-engine %i')

    def test_all_make_phases_are_single_job_and_environment_is_not_inherited(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        plan = (root / 'internal/executor/waf_engine_build_plan.go').read_text()
        self.assertNotIn('"-j2"', plan)
        for args in ('[]string{"-j1"}', '[]string{"-j1", "install"}', '[]string{"-j1", "modules"}'):
            self.assertIn(args, plan)
        runner = (root / 'internal/executor/waf_engine_build_command_linux.go').read_text()
        self.assertIn('"MAKEFLAGS="', runner)
        self.assertNotIn('os.Environ()', runner)

if __name__ == '__main__':
    unittest.main()
