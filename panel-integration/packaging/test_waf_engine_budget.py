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
        self.assertEqual(settings['CPUQuota'], '200%')
        self.assertEqual(settings['MemoryMax'], '1G')
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

if __name__ == '__main__':
    unittest.main()
