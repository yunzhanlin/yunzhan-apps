"""Pinned optional build confinement, not commercial acceptance."""
import pathlib
import unittest

class AnalyticsHTMLBudget(unittest.TestCase):
    def test_fixed_optional_unit_cannot_mutate_sites_or_live_configuration(self):
        root=pathlib.Path(__file__).resolve().parents[1]
        unit=(root/'dev/panel-analytics-html-build@.service').read_text()
        settings=dict(line.split('=',1) for line in unit.splitlines() if '=' in line)
        for key,want in {'MemoryHigh':'576M','MemoryMax':'640M','MemorySwapMax':'0','TasksMax':'96','CPUQuota':'70%','KillMode':'control-group','UMask':'0077','ProtectSystem':'strict','NoNewPrivileges':'true','TimeoutStartSec':'300min'}.items():
            self.assertEqual(settings[key],want)
        self.assertEqual(settings['ExecStart'],'/opt/panel/bin/panel-executor --build-analytics-html %i')
        for path in ('/etc/panel','/etc/nginx','/srv/panel/sites'):
            self.assertNotIn(path,settings['ReadWritePaths'].split())
        self.assertNotIn('CAP_SYS_ADMIN',settings['CapabilityBoundingSet'])
        source=(root/'internal/executor/analytics_html_native_linux.go').read_text()
        self.assertNotIn('"-j2"',source)
        self.assertNotIn('os.Environ()',source)
        self.assertIn('patchAnalyticsNJSHeaders(original)',source)
        self.assertIn('"-e", "stderr", "-t", "-p"',source)

if __name__=='__main__': unittest.main()
