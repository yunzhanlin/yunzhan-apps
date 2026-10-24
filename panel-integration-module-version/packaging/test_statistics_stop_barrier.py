"""Actual Linux Root/flock fixtures; no host service or installed app changes."""
import contextlib
import fcntl
import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('statistics_stop_upgrade', pathlib.Path(__file__).with_name('upgrade-release.py'))
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'actual Linux Root/flock fixture required')
class StatisticsStopBarrierTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='statistics-stop-') as temporary:
            root = pathlib.Path(temporary)
            module = root/'etc/panel/security-apps/modules/website-statistics-v2'
            module.mkdir(mode=0o700, parents=True)
            for parent in module.parents:
                if parent == root:
                    break
                parent.chmod(0o700)
            lock = root/'etc/panel/security-apps/waf-configuration.lock'
            lock.write_bytes(b'')
            lock.chmod(0o600)
            transaction = upgrade.Upgrade(root/'candidate', root, mock.Mock(side_effect=AssertionError('unexpected host service call')))
            yield transaction, root, module, lock

    def test_real_shared_writer_blocks_all_stops_and_original_lock_is_unchanged(self):
        with self.fixture() as (transaction, root, module, lock):
            before = lock.lstat()
            with lock.open('rb') as writer:
                fcntl.flock(writer, fcntl.LOCK_SH)
                with mock.patch.object(upgrade.time, 'monotonic', side_effect=[0, 9]), self.assertRaisesRegex(ValueError, 'lease busy'):
                    transaction.stop_writers()
            transaction.run_command.assert_not_called()
            self.assertFalse(transaction.stopping)
            after = lock.lstat()
            self.assertEqual((before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_mtime_ns, before.st_ctime_ns),
                             (after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_mtime_ns, after.st_ctime_ns))
            self.assertEqual(lock.read_bytes(), b'')

    def test_retry_only_pre_acquisition_contention_then_hold_until_all_writers_proved_stopped(self):
        with self.fixture() as (transaction, root, module, lock), lock.open('rb') as writer:
            fcntl.flock(writer, fcntl.LOCK_SH)
            calls = []
            def release(interval):
                self.assertEqual(interval, 0.05)
                self.assertEqual(calls, [])
                fcntl.flock(writer, fcntl.LOCK_UN)
            def run(*args, **kwargs):
                with lock.open('rb') as observer:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(observer, fcntl.LOCK_SH | fcntl.LOCK_NB)
                calls.append(args)
                if args[1] == 'stop':
                    self.assertEqual(args, ('/usr/bin/systemctl', 'stop', *reversed(upgrade.PROGRAMS)))
                    return ''
                if args[1] == 'list-jobs':
                    return ''
                self.assertEqual(args[1], 'show')
                return 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=enabled\nMainPID=0\nControlPID=0\nControlGroup=\nResult=success'
            transaction.run_command = run
            with mock.patch.object(upgrade.time, 'sleep', side_effect=release) as sleep:
                transaction.stop_writers()
            self.assertEqual(sleep.call_count, 1)
            self.assertEqual(sum(args[1] == 'stop' for args in calls), 1)
            fcntl.flock(writer, fcntl.LOCK_SH | fcntl.LOCK_NB)

    def test_unsafe_existing_paths_refuse_without_any_service_or_permission_repair(self):
        for scenario in ('linked-module', 'public-module', 'linked-lock', 'hardlinked-lock',
                         'public-lock', 'nonempty-lock', 'missing-lock', 'linked-parent'):
            with self.subTest(scenario=scenario), self.fixture() as (transaction, root, module, lock):
                if scenario == 'linked-module':
                    module.rename(root/'retained-module')
                    module.symlink_to(root/'retained-module', target_is_directory=True)
                elif scenario == 'public-module':
                    module.chmod(0o755)
                elif scenario == 'linked-lock':
                    lock.rename(root/'retained-lock')
                    lock.symlink_to(root/'retained-lock')
                elif scenario == 'hardlinked-lock':
                    os.link(lock, root/'retained-lock')
                elif scenario == 'public-lock':
                    lock.chmod(0o644)
                elif scenario == 'nonempty-lock':
                    lock.write_bytes(b'unknown evidence')
                elif scenario == 'missing-lock':
                    lock.rename(root/'retained-lock')
                elif scenario == 'linked-parent':
                    parent = root/'etc/panel/security-apps'
                    parent.rename(root/'retained-security')
                    parent.symlink_to(root/'retained-security', target_is_directory=True)
                before = {str(p.relative_to(root)): (p.lstat().st_ino, p.lstat().st_mode, p.lstat().st_uid, p.lstat().st_nlink)
                          for p in root.rglob('*')}
                with self.assertRaises((ValueError, OSError)):
                    transaction.stop_writers()
                transaction.run_command.assert_not_called()
                after = {str(p.relative_to(root)): (p.lstat().st_ino, p.lstat().st_mode, p.lstat().st_uid, p.lstat().st_nlink)
                         for p in root.rglob('*')}
                self.assertEqual(before, after)

    def test_replaced_named_lock_after_acquisition_is_not_authority(self):
        with self.fixture() as (transaction, root, module, lock):
            real_flock = fcntl.flock
            def replace(fd, operation):
                real_flock(fd, operation)
                lock.rename(root/'original-lock')
                lock.write_bytes(b'')
                lock.chmod(0o600)
            with mock.patch.object(upgrade.fcntl, 'flock', side_effect=replace), self.assertRaisesRegex(ValueError, 'replaced'):
                transaction.stop_writers()
            transaction.run_command.assert_not_called()
            self.assertNotEqual(lock.lstat().st_ino, (root/'original-lock').lstat().st_ino)

    def test_stop_failure_releases_only_owned_descriptor_and_preserves_original_error(self):
        with self.fixture() as (transaction, root, module, lock):
            failure = RuntimeError('original stop failure')
            transaction.run_command = mock.Mock(side_effect=failure)
            with self.assertRaises(RuntimeError) as caught:
                transaction.stop_writers()
            self.assertIs(caught.exception, failure)
            self.assertEqual(transaction.run_command.call_count, 1)
            with lock.open('rb') as observer:
                fcntl.flock(observer, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_absent_application_is_not_created_or_installed(self):
        with tempfile.TemporaryDirectory(prefix='statistics-stop-absent-') as temporary:
            root = pathlib.Path(temporary)
            transaction = upgrade.Upgrade(root/'candidate', root)
            before = list(root.rglob('*'))
            with transaction.statistics_writer_stop_barrier():
                self.assertEqual(list(root.rglob('*')), before)
            self.assertEqual(list(root.rglob('*')), before)

    def test_development_layout_inherits_exact_same_barrier_and_stop_implementation(self):
        spec = importlib.util.spec_from_file_location('statistics_stop_development', pathlib.Path(__file__).with_name('development-upgrade.py'))
        development = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(development)
        self.assertNotIn('stop_writers', development.DevelopmentUpgrade.__dict__)
        self.assertNotIn('statistics_writer_stop_barrier', development.DevelopmentUpgrade.__dict__)
        self.assertEqual(development.DevelopmentUpgrade.statistics_writer_stop_barrier.__code__.co_code,
                         upgrade.Upgrade.statistics_writer_stop_barrier.__code__.co_code)


if __name__ == '__main__':
    unittest.main(verbosity=2)
