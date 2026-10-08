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

    def test_ui_budget_matches_worker_and_missing_status_is_not_uninstalled(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        view = (root / 'web/src/WafWorkspace.vue').read_text()
        self.assertIn('固定单路编译，最多 1 CPU / 640 MiB 内存，576 MiB 回收水位', view)
        self.assertNotIn('编译使用 2 CPU / 1 GiB', view)
        self.assertIn("!status ? (busy ? '正在读取真实状态' : '状态尚未核实')", view)
        self.assertNotIn("!status?.installed ? '未安装'", view)

    def test_rotation_refresh_reconciles_inventory_without_replacing_drafts(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        view = (root / 'web/src/WafWorkspace.vue').read_text()
        refresh = view.split('const refreshBodyRotation = ', 1)[1].split('function scheduleBodyRotationStatus', 1)[0]
        self.assertIn('createRotationRefresh<BodyRotationStatus>', refresh)
        self.assertIn('refreshBodyReport(true), refreshBodyArchives()', refresh)
        self.assertNotIn('loadConfig', refresh)
        self.assertNotIn('cfg.value =', refresh)
        self.assertIn('value.record?.history', refresh)
        self.assertNotIn('value.record?.checked_at', refresh)
        self.assertIn('node --test scripts/test-waf-rotation-refresh.mjs', (root / 'packaging/build-release.sh').read_text())

if __name__ == '__main__':
    unittest.main()
