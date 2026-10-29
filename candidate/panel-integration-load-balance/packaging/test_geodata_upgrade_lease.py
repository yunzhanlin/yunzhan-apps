"""Existing inode fencing with real root Linux flock; not native service proof."""
import contextlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('geodata_lease_production_fixture', ROOT/'packaging/test_production_upgrade.py')
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
upgrade = fixtures.upgrade
SPEC = importlib.util.spec_from_file_location('geodata_lease_development_fixture', ROOT/'packaging/test_development_upgrade_safety.py')
development_fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(development_fixtures)


class GeoLeaseSourceOrder(unittest.TestCase):
    def test_both_layouts_and_recovery_take_fence_before_mutating_preparation(self):
        source = (ROOT/'packaging/upgrade-release.py').read_text()
        ordinary = source[source.index('    def run(self):'):source.index('    def rollback(self):')]
        self.assertLess(ordinary.index('self.acquire_geodata_lease()'), ordinary.index('self.backup.mkdir'))
        self.assertLess(ordinary.index("runtime-lifecycle.lock"), ordinary.index('self.acquire_geodata_lease()'))
        development = (ROOT/'packaging/development-upgrade.py').read_text()
        ordinary = development[development.index('    def run(self):'):development.index('    def rollback(self):')]
        self.assertLess(ordinary.index('self.acquire_geodata_lease()'), ordinary.index('self.backup.mkdir'))
        recovery = source[source.index('    def recover_preflight'):source.index('    def recover_layout_plan')]
        self.assertIn('self.acquire_geodata_lease()', recovery)
        # The original complete native queue checks stay mandatory, including
        # orphan verifiers. No unit stop/reset or queue exception is added.
        self.assertIn("'--check-program-upgrade-queues'", source)
        section = source[source.index('    def acquire_geodata_lease'):source.index('    def journal')]
        for forbidden in ('systemctl', 'chmod', 'chown', 'O_CREAT', 'sleep(', 'queue_check('):
            self.assertNotIn(forbidden, section)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                     'actual root Linux ownership and independent flock required')
class GeoLeaseRootTests(unittest.TestCase):
    fixture = fixtures.UpgradeTransactionTests.fixture
    kill_transaction_at = fixtures.UpgradeTransactionTests.kill_transaction_at

    def lease(self, root):
        path = root/'var/lib/panel-executor/statistics-geodata-instance.lock'
        path.write_bytes(b'')
        path.chmod(0o600)
        return path

    def installed(self, root, version):
        path = root/'etc/panel/security-apps/modules/website-statistics-v2/installed.json'
        path.parent.mkdir(mode=0o700, parents=True)
        path.write_text(json.dumps({'id': 'website-statistics-v2', 'version': version, 'settings': {}}))
        path.chmod(0o600)
        return path

    def acquire(self, transaction):
        transaction.preflight()
        transaction.lock(transaction.releases/'.release.lock', create=True)
        transaction.lock(transaction.path('/var/lib/panel-executor/runtime-lifecycle.lock'))
        transaction.acquire_geodata_lease()

    @contextlib.contextmanager
    def shared_child(self, path):
        code = "import fcntl,sys;f=open(sys.argv[1],'rb');fcntl.flock(f,fcntl.LOCK_SH);print('owned-shared',flush=True);sys.stdin.buffer.read(1)"
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', code, str(path)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(child.stdout.readline(), b'owned-shared\n')
            yield child
        finally:
            child.communicate(b'x', timeout=5)
            self.assertEqual(child.returncode, 0)

    def test_existing_shared_native_work_refuses_before_any_backup_or_program_stop(self):
        with self.fixture() as (transaction, runner, root):
            path = self.lease(root)
            identity = path.stat()
            with self.shared_child(path), self.assertRaisesRegex(ValueError, 'lease busy'):
                transaction.run()
            self.assertIsNone(transaction.backup)
            self.assertFalse(transaction.changed or transaction.stopping)
            self.assertFalse(any(len(c)>1 and c[1] in ('start', 'stop', 'reset-failed', 'daemon-reload') for c in runner.calls))
            self.assertEqual(path.stat(), identity)
            self.assertEqual(path.read_bytes(), b'')

    def test_ordinary_transaction_fences_new_readers_through_readiness_and_releases_on_close(self):
        with self.fixture() as (transaction, runner, root):
            path = self.lease(root)
            identity = path.stat()
            original = transaction.queue_check
            protected = []
            def complete_queue():
                original()
                if transaction.backup is not None:
                    with path.open('rb') as reader, self.assertRaises(BlockingIOError):
                        upgrade.fcntl.flock(reader, upgrade.fcntl.LOCK_SH | upgrade.fcntl.LOCK_NB)
                    protected.append(True)
            transaction.queue_check = complete_queue
            transaction.run()
            self.assertTrue(transaction.committed)
            self.assertGreaterEqual(len(protected), 4)
            self.assertEqual(len(transaction.locks), 1)  # unchanged release/runtime protocol
            self.assertEqual(path.stat(), identity)
            transaction.close()
            with path.open('rb') as reader:
                upgrade.fcntl.flock(reader, upgrade.fcntl.LOCK_SH | upgrade.fcntl.LOCK_NB)

    def test_development_layout_fences_new_readers_until_its_original_commit(self):
        with development_fixtures.DevelopmentUpgradeTransactionTests.fixture(self) as (transaction, runner, root):
            path = self.lease(root)
            identity = path.stat()
            original = transaction.queue_check
            protected = []
            def complete_queue():
                original()
                if transaction.backup is not None:
                    with path.open('rb') as reader, self.assertRaises(BlockingIOError):
                        upgrade.fcntl.flock(reader, upgrade.fcntl.LOCK_SH | upgrade.fcntl.LOCK_NB)
                    protected.append(True)
            transaction.queue_check = complete_queue
            transaction.run()
            self.assertTrue(transaction.committed)
            self.assertGreaterEqual(len(protected), 4)
            self.assertEqual(path.stat(), identity)
            transaction.close()
            with path.open('rb') as reader:
                upgrade.fcntl.flock(reader, upgrade.fcntl.LOCK_SH | upgrade.fcntl.LOCK_NB)

    def test_development_busy_reader_refuses_before_code_database_or_service_mutation(self):
        with development_fixtures.DevelopmentUpgradeTransactionTests.fixture(self) as (transaction, runner, root):
            path = self.lease(root)
            before = (root/'opt/panel/bin/panel').read_bytes()
            with self.shared_child(path), self.assertRaisesRegex(ValueError, 'lease busy'):
                transaction.run()
            self.assertIsNone(transaction.backup)
            self.assertFalse(transaction.changed or transaction.stopping)
            self.assertEqual((root/'opt/panel/bin/panel').read_bytes(), before)
            self.assertFalse(any(len(c)>1 and c[1] in ('start','stop','reset-failed','daemon-reload') for c in runner.calls))

    def test_absent_application_and_known_pre_geodata_versions_do_not_create_lease(self):
        for version in (None, '1.0', '2.0-compat1', '2.5.0'):
            with self.subTest(version=version), self.fixture() as (transaction, runner, root):
                if version is not None:
                    self.installed(root, version)
                self.acquire(transaction)
                transaction.validate_geodata_lease()
                self.assertFalse((root/'var/lib/panel-executor/statistics-geodata-instance.lock').exists())

    def test_geodata_capable_unknown_or_duplicate_installation_cannot_hide_missing_lease(self):
        for version in ('2.6.0', '2.7.0', 'invalid'):
            with self.subTest(version=version), self.fixture() as (transaction, runner, root):
                path = self.installed(root, version)
                before = path.read_bytes()
                with self.assertRaisesRegex(ValueError, 'lacks its existing lease'):
                    self.acquire(transaction)
                self.assertEqual(path.read_bytes(), before)
                self.assertIsNone(transaction.backup)
        with self.fixture() as (transaction, runner, root):
            path = self.installed(root, '2.5.0')
            path.write_text('{"id":"website-statistics-v2","version":"2.5.0","version":"2.6.0"}')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                self.acquire(transaction)

    def test_unsafe_existing_lease_is_refused_without_repair_or_replacement(self):
        for kind in ('writable', 'public', 'nonempty', 'owner', 'hardlink', 'symlink', 'directory', 'parent'):
            with self.subTest(kind=kind), self.fixture() as (transaction, runner, root):
                path = self.lease(root)
                if kind == 'writable': path.chmod(0o620)
                if kind == 'public': path.chmod(0o644)
                if kind == 'nonempty': path.write_bytes(b'owned unexpected bytes')
                if kind == 'owner': os.chown(path, 12345, 12345)
                if kind == 'hardlink': os.link(path, path.with_name('owned-linked'))
                if kind == 'symlink':
                    target = path.with_name('owned-target');path.rename(target);path.symlink_to(target)
                if kind == 'directory': path.unlink();path.mkdir(mode=0o700)
                if kind == 'parent': path.parent.chmod(0o777)
                # A refused pathname lookup may update a symlink's atime.
                # Keep every security/content identity field, not read-atime.
                stable = lambda s: tuple(getattr(s, n) for n in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
                identity = stable(path.lstat())
                parent_mode = path.parent.stat().st_mode
                with self.assertRaises((OSError, ValueError, upgrade.CommandFailure)):
                    self.acquire(transaction)
                self.assertEqual(stable(path.lstat()), identity)
                self.assertEqual(path.parent.stat().st_mode, parent_mode)
                self.assertIsNone(transaction.backup)

    def test_held_inode_replacement_cannot_turn_open_descriptor_into_named_authority(self):
        with self.fixture() as (transaction, runner, root):
            path = self.lease(root)
            self.acquire(transaction)
            path.rename(path.with_name('owned-original'))
            self.lease(root)
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                transaction.queue_check()
            self.assertFalse(transaction.changed or transaction.stopping)

    def test_absent_lease_or_installation_appearance_is_not_an_idle_proof(self):
        for change in ('lease', 'installation'):
            with self.subTest(change=change), self.fixture() as (transaction, runner, root):
                self.acquire(transaction)
                if change == 'lease': self.lease(root)
                else: self.installed(root, '2.6.0')
                with self.assertRaises(ValueError): transaction.queue_check()
                self.assertFalse(transaction.changed or transaction.stopping)

    def test_explicit_prepared_recovery_also_requires_same_existing_exclusion(self):
        with self.fixture() as (transaction, runner, root):
            path = self.lease(root)
            backup = self.kill_transaction_at(transaction, runner, root, 'prepared')
            runner.calls.clear()
            with self.shared_child(path):
                recovered = upgrade.Upgrade(backup, root, runner)
                try:
                    with self.assertRaisesRegex(ValueError, 'lease busy'):
                        recovered.recover(backup, check=True)
                    self.assertFalse(any(len(c)>1 and c[1] in ('stop','start','reset-failed','daemon-reload') for c in runner.calls))
                finally:
                    recovered.close()
            recovered = upgrade.Upgrade(backup, root, runner)
            try:
                self.assertEqual(recovered.recover(backup)['phase'], 'prepared')
            finally:
                recovered.close()


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                     'actual root Linux directory ownership and leases required')
class GeoWriterStopSharedNamespaceRootTests(unittest.TestCase):
    @contextlib.contextmanager
    def workspace(self):
        with tempfile.TemporaryDirectory(prefix='statistics-stop-shared-') as value:
            root = pathlib.Path(value)
            parent = root/'etc/panel/security-apps/modules'
            parent.mkdir(mode=0o755, parents=True)
            calls = []
            def forbid_command(*args):
                calls.append(args)
                raise AssertionError('directory/lease observation must not run a command')
            transaction = upgrade.Upgrade(root/'candidate', root, forbid_command)
            yield transaction, root, parent, calls

    @staticmethod
    def identities(root):
        result = {}
        for path in [root]+sorted(root.rglob('*')):
            s = path.lstat()
            result[str(path)] = (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                                 s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        return result

    def test_missing_statistics_accepts_safe_shared_parent_without_writes(self):
        for mode, group in ((0o700, 0), (0o755, 988), (0o2750, 988)):
            with self.subTest(mode=mode), self.workspace() as (transaction, root, parent, calls):
                os.chown(parent, 0, group)
                parent.chmod(mode)
                before = self.identities(root)
                with transaction.statistics_writer_stop_barrier():
                    self.assertFalse((parent/'website-statistics-v2').exists())
                self.assertEqual(self.identities(root), before)
                self.assertEqual(calls, [])

    def test_present_statistics_accepts_shared_container_keeps_private_leaf_and_existing_lock(self):
        for mode in (0o700, 0o711, 0o750, 0o755):
            with self.subTest(mode=mode), self.workspace() as (transaction, root, parent, calls):
                parent.chmod(mode)
                (parent/'website-statistics-v2').mkdir(mode=0o700)
                lock = parent.parent/'waf-configuration.lock'
                lock.write_bytes(b'')
                lock.chmod(0o600)
                before = self.identities(root)
                with transaction.statistics_writer_stop_barrier():
                    with lock.open('rb') as observer:
                        with self.assertRaises(BlockingIOError):
                            upgrade.fcntl.flock(observer, upgrade.fcntl.LOCK_SH | upgrade.fcntl.LOCK_NB)
                self.assertEqual((parent/'website-statistics-v2').stat().st_mode & 0o777, 0o700)
                self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
                with lock.open('rb') as observer:
                    upgrade.fcntl.flock(observer, upgrade.fcntl.LOCK_SH | upgrade.fcntl.LOCK_NB)
                self.assertEqual(self.identities(root), before)
                self.assertEqual(calls, [])

    def test_missing_leaf_cannot_hide_writable_foreign_or_linked_parent(self):
        for kind in ('writable', 'foreign-owner', 'linked-parent', 'linked-leaf'):
            with self.subTest(kind=kind), self.workspace() as (transaction, root, parent, calls):
                if kind == 'writable': parent.chmod(0o777)
                elif kind == 'foreign-owner': os.chown(parent, 988, 988)
                elif kind == 'linked-parent':
                    parent.rename(parent.with_name('original-modules'))
                    parent.symlink_to(parent.with_name('original-modules'), target_is_directory=True)
                else:
                    leaf = parent/'website-statistics-v2'
                    target = parent/'unrelated'
                    target.mkdir(mode=0o700)
                    leaf.symlink_to(target, target_is_directory=True)
                before = self.identities(root)
                with self.assertRaises((ValueError, OSError)):
                    with transaction.statistics_writer_stop_barrier():
                        self.fail('unsafe namespace treated as absent')
                self.assertEqual(self.identities(root), before)
                self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
