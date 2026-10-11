"""Request-body engine build supervision, not a business acceptance report."""
import pathlib
import unittest

class WAFBuildSupervisor(unittest.TestCase):
    def test_apache_worker_is_independent_narrow_and_can_collect_dropped_uid(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        unit = (root / 'dev/panel-apache-body-build@.service').read_text()
        settings = dict(line.split('=', 1) for line in unit.splitlines() if '=' in line)
        self.assertEqual(settings['ExecStart'], '/opt/panel/bin/panel-executor --build-apache-body %i')
        self.assertEqual(settings['TimeoutStartSec'], '245min')
        self.assertEqual(settings['TimeoutStopSec'], '15s')
        self.assertEqual(settings['KillMode'], 'control-group')
        self.assertEqual(settings['SendSIGKILL'], 'true')
        self.assertEqual(settings['CPUQuota'], '85%')
        self.assertEqual(settings['MemoryHigh'], '576M')
        self.assertEqual(settings['MemoryMax'], '640M')
        self.assertEqual(settings['TasksMax'], '128')
        self.assertEqual(settings['UMask'], '0077')
        self.assertEqual(settings['NoNewPrivileges'], 'true')
        self.assertEqual(settings['ProtectSystem'], 'strict')
        self.assertEqual(set(settings['CapabilityBoundingSet'].split()), {'CAP_CHOWN', 'CAP_DAC_READ_SEARCH', 'CAP_SETUID', 'CAP_SETGID', 'CAP_KILL'})
        self.assertEqual(settings['AmbientCapabilities'], settings['CapabilityBoundingSet'])
        self.assertEqual(set(settings['ReadWritePaths'].split()), {
            '/var/lib/panel-executor/build.lock', '/var/lib/panel-executor/apache-body-builds',
            '/var/cache/panel-apache-body-build', '/opt/panel/app-modules/apache-waf/engines'})
        self.assertEqual(set(settings['ReadOnlyPaths'].split()), {
            '/var/lib/panel-executor/apache-body-requests', '/var/lib/panel-executor/apache-body-cancellations',
            '/opt/panel/runtimes/apache'})
        self.assertIn('panel-apache-body-build@', (root / 'dev/provision-app.sh').read_text())

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
        self.assertEqual(settings['MemorySwapMax'], '0')
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
        self.assertEqual(settings['AmbientCapabilities'],settings['CapabilityBoundingSet'])
        self.assertEqual(set(settings['CapabilityBoundingSet'].split()),{'CAP_CHOWN','CAP_DAC_OVERRIDE','CAP_SETUID','CAP_SETGID','CAP_FOWNER','CAP_KILL'})
        self.assertEqual(settings['ProtectControlGroups'],'true')
        worker=(root/'internal/executor/waf_engine_native_linux.go').read_text()
        self.assertLess(worker.index('verifyNginxNativeWorkerCapabilities()'),worker.index('readWAFEngineControl(wafEngineCancellations, id)'))

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
        self.assertIn('import { softwareInstallState } from "./softwareState"', view)
        self.assertIn('const installState = computed(() => softwareInstallState(', view)
        self.assertIn("installState === 'unknown' ? (busy ? '正在读取真实状态' : '安装状态待核对')", view)
        self.assertIn("installState === 'absent' ? '未安装'", view)
        self.assertIn('if (installState.value === "unknown")', view)
        self.assertIn("<template v-if=\"cfg && installState !== 'unknown'\">", view)
        self.assertIn('不能据此认定未安装', view)
        self.assertIn('node --test scripts/test-software-state.mjs', (root / 'packaging/build-release.sh').read_text())
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
