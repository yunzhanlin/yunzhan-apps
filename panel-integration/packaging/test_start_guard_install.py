"""Immutable interlock filesystem fixtures, not native systemd/boot proof."""
import importlib.util
import os
import pathlib
import stat
import sys
import unittest

HERE = pathlib.Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('own_start_guard', HERE/'start-guard-install.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
SPEC = importlib.util.spec_from_file_location('own_guard_support', HERE/'test_production_upgrade.py')
support = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(support)


class StartupInterlockPackagingTests(unittest.TestCase):
    def test_fixed_condition_is_before_constructors_without_skip_or_mutation(self):
        for unit in guard.SERVICES:
            self.assertEqual(guard.dropin(unit), ('[Service]\nExecCondition=+'+guard.GUARD+' '+unit+'\n').encode())
        with self.assertRaises(ValueError):
            guard.dropin('nginx.service')
        source = (HERE.parent/'cmd/startguard/main.go').read_text()
        self.assertIn('os.Exit(255)', source)
        for forbidden in ('core.OpenStore', 'executor.New', 'os.Remove', 'os.WriteFile', 'os.Getenv', 'flag.'):
            self.assertNotIn(forbidden, source)
        builder = (HERE/'build-release.sh').read_text()
        self.assertIn('./cmd/startguard)', builder)
        self.assertIn('development-upgrade.py start-guard-install.py;', builder)
        installer = (HERE/'install.sh').read_text()
        self.assertLess(installer.index('python3 "$HERE/start-guard-install.py" check'), installer.index('apt-get update'))
        self.assertLess(installer.index('python3 "$HERE/start-guard-install.py" install'), installer.index('restart_release_services || FAILED=1'))


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'actual root Linux ordinary ownership fixture required')
class StartupInterlockFilesystemTests(unittest.TestCase):
    def test_install_is_idempotent_private_umask_independent_and_retains_inode_bytes(self):
        with support.UpgradeTransactionTests().fixture() as (transaction, runner, root):
            original = os.umask(0o077)
            try:
                guard.install(transaction)
            finally:
                os.umask(original)
            targets = guard.inventory(transaction)
            identities = {}
            for path, data, mode in targets:
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat().st_mode & 0o777, mode)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o755)
                identities[str(path)] = path.stat().st_ino
            guard.install(transaction)
            self.assertEqual({str(path):path.stat().st_ino for path, _, _ in guard.inventory(transaction)}, identities)
            self.assertEqual([call for call in runner.calls if call[0] == '/usr/bin/systemctl'], [('/usr/bin/systemctl','daemon-reload')]*2)
            self.assertFalse(transaction.stopping)

    def test_every_foreign_existing_file_parent_and_link_refuses_whole_scope_before_write(self):
        for fault in ('binary', 'condition', 'writable', 'symlink', 'hardlink', 'parent'):
            with self.subTest(fault=fault), support.UpgradeTransactionTests().fixture() as (transaction, runner, root):
                target = root/'etc/systemd/system/panel.service.d'/guard.DROPIN
                target.parent.mkdir()
                if fault == 'parent':
                    target.parent.chmod(0o777)
                elif fault == 'binary':
                    binary = root/guard.GUARD.lstrip('/')
                    binary.parent.mkdir()
                    binary.write_bytes(b'foreign bytes')
                    binary.chmod(0o755)
                elif fault == 'symlink':
                    target.symlink_to(root/'unrelated')
                else:
                    target.write_bytes(guard.dropin('panel.service') if fault != 'condition' else b'foreign condition')
                    target.chmod(0o666 if fault == 'writable' else 0o644)
                    if fault == 'hardlink':
                        os.link(target, root/'unrelated')
                with self.assertRaises((ValueError, OSError)):
                    guard.install(transaction)
                self.assertEqual(runner.calls, [])
                self.assertFalse((root/'etc/systemd/system/panel-executor.service.d').exists())
                if fault != 'binary':
                    self.assertFalse((root/guard.GUARD.lstrip('/')).exists())

    def test_upgrade_installs_guard_before_pending_stop_and_retains_on_rollback(self):
        with support.UpgradeTransactionTests().fixture() as (transaction, runner, root):
            runner.fail_start_once = True
            command = transaction.run_command
            def checked(*args, **kwargs):
                if args[0] == '/usr/bin/systemctl' and args[1] == 'stop':
                    for target, data, mode in guard.inventory(transaction):
                        self.assertEqual(target.read_bytes(), data)
                        self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
                    self.assertTrue(transaction.pending_created)
                return command(*args, **kwargs)
            transaction.run_command = checked
            with self.assertRaises(RuntimeError):
                transaction.run()
            transaction.rollback()
            self.assertFalse(transaction.pending_created)
            self.assertTrue((root/guard.GUARD.lstrip('/')).exists())
            proof = transaction.backup/'startup-interlock.json'
            self.assertEqual(proof.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
