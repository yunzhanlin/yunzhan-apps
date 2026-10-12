"""Real root filesystem/SQLite development fixtures, not native systemd proof."""
import contextlib
import hashlib
import importlib.util
import json
import os
import pathlib
import sqlite3
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('development_upgrade', ROOT/'packaging/development-upgrade.py')
development = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(development)
SPEC = importlib.util.spec_from_file_location('development_fixture_support', ROOT/'packaging/test_production_upgrade.py')
support = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(support)


class DevelopmentUpgradePolicyTests(unittest.TestCase):
    def test_entrypoint_never_sources_metadata_or_provisions_host(self):
        wrapper = (ROOT/'scripts/upgrade-running-development.sh').read_text()
        self.assertIn('exec /usr/bin/python3 "$RELEASE_PATH/development-upgrade.py" run "$RELEASE_PATH"', wrapper)
        self.assertLess(wrapper.index('verify-release.sh'), wrapper.index('exec /usr/bin/python3'))
        source = pathlib.Path(development.__file__).read_text()
        for prohibited in ('useradd', 'apt-get', 'rmtree', "'enable'", "'restart'", "add_argument('--root'"):
            self.assertNotIn(prohibited, source)
        self.assertNotRegex(wrapper, r'(?m)^\s*(?:source|\.)\s+')
        self.assertNotIn('|| true', source+wrapper)
        self.assertEqual(development.QUEUES, ('jobs', 'runtime_jobs', 'mysql_jobs', 'acme_orders'))
        self.assertEqual(len(development.PROGRAMS), 4)

    def test_normal_payload_includes_checksum_bound_transaction(self):
        builder = (ROOT/'packaging/build-release.sh').read_text()
        self.assertIn('"$BUILD_ROOT/packaging/development-upgrade.py"', builder)
        self.assertIn('upgrade-release.py development-upgrade.py;', builder)
        self.assertIn('DevelopmentMarker = "/opt/panel/.development-upgrade.pending"', (ROOT/'internal/upgradeguard/guard.go').read_text())

    def test_initializers_cannot_run_before_startup_authorization(self):
        panel = (ROOT/'cmd/panel/main.go').read_text()
        self.assertLess(panel.index('upgradeguard.CheckStartup()'), panel.index('core.OpenStore('))
        self.assertLess(panel.index('upgradeguard.CheckStartup()'), panel.index('store.Recover()'))
        executor = (ROOT/'cmd/executor/main.go').read_text()
        daemon = executor[executor.index('if *install != "" {'):]
        self.assertLess(daemon.index('upgradeguard.CheckStartup()'), daemon.index('executor.RecoverApacheWAFConfiguration()'))
        terminal = executor[executor.index('if *terminalServer != "" {'):executor.index('if os.Geteuid() != 0 {')]
        self.assertLess(terminal.index('upgradeguard.CheckStartup()'), terminal.index('executor.ServeTerminalSocket('))


class DevelopmentRunner(support.Runner):
    def __call__(self, *args, **kwargs):
        if args[0] == '/usr/bin/python3' and pathlib.Path(args[1]).name in ('waf-state-directory.py', 'native-build-directories.py') and args[2:] == ('check',):
            self.calls.append(args)
            return ''
        if args == (str(self.root/'candidate/bin/panel-executor'), '--check-apache-body-cache-upgrade'):
            self.calls.append(args)
            return ''
        return super().__call__(*args, **kwargs)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'actual root Linux ordinary ownership fixture required')
class DevelopmentUpgradeTransactionTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, gateway_active=True, marker=True):
        with support.UpgradeTransactionTests().fixture(gateway_active) as (old, unused, root):
            (root/'opt/panel/current').unlink()
            (root/'etc/panel-release').unlink()
            for base in (root/'opt/panel', root/'candidate'):
                (base/'bin').mkdir(exist_ok=True)
                (base/'web').mkdir()
                for name in ('panel', 'panel-executor'):
                    (base/'bin'/name).write_bytes((('candidate-' if base.name == 'candidate' else 'original-')+name).encode())
                    (base/'bin'/name).chmod(0o755)
                (base/'web/index.html').write_text('candidate web' if base.name == 'candidate' else 'original web')
            (root/'opt/panel/bin/retained-helper').write_bytes(b'original unrelated helper')
            if marker:
                (root/'opt/panel/DEVELOPMENT_RELEASE').write_text('original development release\n')
            for helper in ('waf-state-directory.py', 'native-build-directories.py'):
                (root/'candidate'/helper).write_text('# owned read-only command fixture\n')
            lock = root/'opt/panel/.development-update.lock'
            lock.write_bytes(b'retained development lock content')
            lock.chmod(0o644)
            runner = DevelopmentRunner(root, gateway_active)
            transaction = development.DevelopmentUpgrade(root/'candidate', root, runner)
            try:
                yield transaction, runner, root
            finally:
                transaction.close()

    def snapshot(self, transaction, runner, root):
        return {'trees':{name:transaction.tree(root/'opt/panel'/name) for name in ('bin','web')},
                'units':{p.name:p.read_bytes() for p in (root/'etc/systemd/system').iterdir()},
                'marker':(root/'opt/panel/DEVELOPMENT_RELEASE').read_bytes() if (root/'opt/panel/DEVELOPMENT_RELEASE').exists() else None,
                'states':json.loads(json.dumps(runner.states))}

    def assert_restored(self, transaction, runner, root, snapshot):
        self.assertEqual(self.snapshot(transaction, runner, root), snapshot)
        self.assertFalse(transaction.pending_created)
        with sqlite3.connect(root/'var/lib/panel/panel.db') as db:
            self.assertEqual(db.execute('SELECT value FROM configuration').fetchone(), ('original',))
        self.assertEqual((root/'var/lib/panel/panel.db').stat().st_uid, 1001)

    def test_commit_preserves_gateway_enablement_inactive_timer_and_unrelated_bin(self):
        for active in (True, False):
            with self.subTest(gateway_active=active), self.fixture(active) as (transaction, runner, root):
                if not active:
                    runner.states[development.TIMER].update(ActiveState='inactive', SubState='dead', UnitFileState='disabled')
                states = json.loads(json.dumps(runner.states))
                transaction.run()
                self.assertTrue(transaction.committed)
                self.assertEqual(runner.states, states)
                self.assertFalse(transaction.pending_created)
                self.assertFalse((root/'opt/panel/.development-upgrade.pending').exists())
                self.assertEqual((root/'opt/panel/bin/panel').read_bytes(), b'candidate-panel')
                self.assertEqual((root/'opt/panel/bin/retained-helper').read_bytes(), b'original unrelated helper')
                self.assertEqual((root/'opt/panel/.development-update.lock').read_bytes(), b'retained development lock content')
                self.assertEqual(json.loads((transaction.backup/'transaction.json').read_text())['phase'], 'committed')
                self.assertTrue(all('nginx.service' not in call for call in runner.calls if call[0]=='/usr/bin/systemctl' and call[1] in ('start','stop')))

    def test_four_sql_queues_and_missing_schema_refuse_before_mutation(self):
        for table in development.QUEUES:
            with self.subTest(table=table), self.fixture() as (transaction, runner, root):
                with sqlite3.connect(root/'var/lib/panel/panel.db') as db:
                    db.execute(f"INSERT INTO {table} VALUES ('owned','running')")
                with self.assertRaises(ValueError):
                    transaction.run()
                self.assertFalse(transaction.stopping)
                self.assertEqual(list((root/'var/backups/panel/system').iterdir()), [])
        with self.fixture() as (transaction, runner, root):
            with sqlite3.connect(root/'var/lib/panel/panel.db') as db:
                db.execute('DROP TABLE mysql_jobs')
            with self.assertRaises(sqlite3.OperationalError):
                transaction.run()

    def test_shared_failed_but_empty_writer_reset_restores_development_trees_and_database(self):
        with self.fixture() as (transaction,runner,root):
            before=self.snapshot(transaction,runner,root)
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):transaction.run()
            runner.failed_stopped_unit='panel.service'
            transaction.rollback()
            self.assert_restored(transaction,runner,root,before)
            self.assertFalse(transaction.runtime_locked)
            evidence=transaction.backup/'stopped-failed-programs-1.json'
            self.assertEqual(evidence.stat().st_mode&0o777,0o600)
            self.assertEqual(json.loads(evidence.read_bytes())['services']['panel.service']['MainPID'],'0')
            self.assertEqual([c for c in runner.calls if c[1]=='reset-failed'],[('/usr/bin/systemctl','reset-failed','panel.service')])

    def test_shared_failed_writer_with_control_process_does_not_reset_or_restore_any_tree(self):
        with self.fixture() as (transaction,runner,root):
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):transaction.run()
            before=self.snapshot(transaction,runner,root);inode=transaction.database.stat().st_ino
            runner.failed_stopped_unit='panel.service';runner.stopped_overrides['panel.service']={'ControlPID':'23'}
            with self.assertRaises(RuntimeError):transaction.rollback()
            after=self.snapshot(transaction,runner,root)
            self.assertEqual(after['trees'],before['trees']);self.assertEqual(after['units'],before['units']);self.assertEqual(after['marker'],before['marker'])
            self.assertEqual(transaction.database.stat().st_ino,inode)
            self.assertTrue(transaction.pending_created)
            self.assertFalse(any(c[1]=='reset-failed' for c in runner.calls))

    def test_native_refusal_first_locked_and_after_stop_never_replaces_database(self):
        for point in (1,2,3):
            with self.subTest(check=point), self.fixture() as (transaction, runner, root):
                before = self.snapshot(transaction, runner, root)
                inode = (root/'var/lib/panel/panel.db').stat().st_ino
                runner.native_queue_fail_at = point
                with self.assertRaisesRegex(RuntimeError, 'native queue fixture refusal'):
                    transaction.run()
                transaction.rollback()
                self.assert_restored(transaction, runner, root, before)
                self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino, inode)
                if point == 3:
                    self.assertFalse((transaction.backup/'panel.db').exists())
                else:
                    self.assertEqual(list((root/'var/backups/panel/system').iterdir()), [])

    def test_late_queue_preserves_new_job_and_original_database_inode(self):
        with self.fixture() as (transaction, runner, root):
            before = self.snapshot(transaction, runner, root)
            inode = (root/'var/lib/panel/panel.db').stat().st_ino
            runner.inject_late_queue = True
            with self.assertRaises(ValueError):
                transaction.run()
            transaction.rollback()
            self.assert_restored(transaction, runner, root, before)
            self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino, inode)
            with sqlite3.connect(root/'var/lib/panel/panel.db') as db:
                self.assertEqual(db.execute("SELECT state FROM runtime_jobs WHERE id='late'").fetchone(), ('queued',))

    def test_start_failure_restores_exact_code_marker_units_and_database(self):
        for marker in (True, False):
            with self.subTest(original_marker=marker), self.fixture(marker=marker) as (transaction, runner, root):
                before = self.snapshot(transaction, runner, root)
                runner.fail_start_once = True
                with self.assertRaises(RuntimeError):
                    transaction.run()
                transaction.rollback()
                self.assert_restored(transaction, runner, root, before)
                self.assertTrue((transaction.backup/'failed-bin').exists())
                self.assertTrue((transaction.backup/'failed-web').exists())
                self.assertTrue((transaction.backup/'failed-panel.db').exists())

    def test_each_start_is_bound_to_live_owner_lease_and_exact_selected_program_bytes(self):
        with self.fixture() as (transaction, runner, root):
            start_records = []
            command = transaction.run_command
            def observe(*args, **kwargs):
                if args[0] == '/usr/bin/systemctl' and args[1] == 'start' and 'panel.service' in args:
                    record = json.loads((root/'opt/panel/.development-upgrade.pending').read_text())
                    self.assertEqual(set(record), {'format','version','pid','start_ticks','boot_id','lock_device','lock_inode','phase','panel_sha256','executor_sha256'})
                    self.assertEqual(record['format'], 2)
                    self.assertEqual(record['phase'], 'program-start')
                    self.assertEqual(record['pid'], os.getpid())
                    self.assertGreater(record['start_ticks'], 0)
                    lease = os.fstat(transaction.locks[0])
                    self.assertEqual((record['lock_device'],record['lock_inode']), (lease.st_dev,lease.st_ino))
                    for name, key in (('panel','panel_sha256'), ('panel-executor','executor_sha256')):
                        self.assertEqual(record[key], hashlib.sha256((root/'opt/panel/bin'/name).read_bytes()).hexdigest())
                    start_records.append(record)
                return command(*args, **kwargs)
            transaction.run_command = observe
            runner.fail_start_once = True
            with self.assertRaises(RuntimeError):
                transaction.run()
            transaction.rollback()
            self.assertEqual(len(start_records), 2)
            self.assertNotEqual(start_records[0]['panel_sha256'], start_records[1]['panel_sha256'])
            self.assertFalse(transaction.pending_created)

    def test_failure_between_bin_renames_recovers_original_tree_without_overwrite(self):
        with self.fixture() as (transaction, runner, root):
            before = self.snapshot(transaction, runner, root)
            rename = development.os.rename
            def interrupted(source, destination):
                if pathlib.Path(source) == root/'opt/panel/bin.new':
                    raise OSError('owned halfway bin switch fixture')
                return rename(source, destination)
            with mock.patch.object(development.os, 'rename', side_effect=interrupted):
                with self.assertRaisesRegex(OSError, 'halfway'):
                    transaction.run()
            transaction.rollback()
            self.assert_restored(transaction, runner, root, before)
            self.assertTrue((root/'opt/panel/bin.new').exists())  # Preserve failed stage evidence.

    def test_partial_unit_write_restores_only_this_transactions_unit_intents(self):
        with self.fixture() as (transaction, runner, root):
            before = self.snapshot(transaction, runner, root)
            atomic, attempts = transaction.atomic, []
            def fail(target, *args, **kwargs):
                if target.parent == root/'etc/systemd/system':
                    attempts.append(target)
                    if len(attempts) == 2:
                        raise OSError('owned partial unit fixture')
                return atomic(target, *args, **kwargs)
            with mock.patch.object(transaction, 'atomic', side_effect=fail):
                with self.assertRaisesRegex(OSError, 'partial unit'):
                    transaction.run()
            transaction.rollback()
            self.assert_restored(transaction, runner, root, before)
            self.assertEqual(len(transaction.replaced_units), 2)

    def test_new_job_identity_refuses_automatic_database_restore_and_keeps_maintenance(self):
        with self.fixture() as (transaction, runner, root):
            runner.inject_candidate_job = True
            with self.assertRaises(RuntimeError):
                transaction.run()
            inode = (root/'var/lib/panel/panel.db').stat().st_ino
            with self.assertRaisesRegex(RuntimeError, 'accepted job changes'):
                transaction.rollback()
            self.assertTrue(transaction.pending_created)
            self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino, inode)
            self.assertEqual((root/'opt/panel/bin/panel').read_bytes(), b'candidate-panel')

    def test_external_unit_or_tree_change_refuses_before_any_restore(self):
        for target in ('unit','tree'):
            with self.subTest(target=target), self.fixture() as (transaction, runner, root):
                runner.fail_start_once = True
                with self.assertRaises(RuntimeError):
                    transaction.run()
                if target == 'unit':
                    (root/'etc/systemd/system/panel.service').write_bytes(b'outside transaction')
                else:
                    (root/'opt/panel/web/index.html').write_bytes(b'outside transaction')
                inode = (root/'var/lib/panel/panel.db').stat().st_ino
                with self.assertRaises(ValueError):
                    transaction.rollback()
                self.assertTrue(transaction.pending_created)
                self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino, inode)
                self.assertEqual((root/'opt/panel/bin/panel').read_bytes(), b'candidate-panel')

    def test_linked_code_or_lock_and_retained_stage_never_start_transaction(self):
        for target in ('code','lock','stage'):
            with self.subTest(target=target), self.fixture() as (transaction, runner, root):
                if target == 'code':
                    (root/'opt/panel/web/linked').symlink_to(root/'candidate/web/index.html')
                elif target == 'lock':
                    (root/'opt/panel/.development-update.lock').unlink()
                    (root/'opt/panel/.development-update.lock').symlink_to(root/'unrelated')
                else:
                    (root/'opt/panel/web.new').mkdir()
                with self.assertRaises((OSError, ValueError)):
                    transaction.run()
                self.assertFalse(transaction.stopping)
                self.assertEqual(list((root/'var/backups/panel/system').iterdir()), [])

    def test_still_active_writer_never_backs_up_or_swaps_program(self):
        with self.fixture() as (transaction, runner, root):
            command = transaction.run_command
            def refuse(*args, **kwargs):
                if args[0] == '/usr/bin/systemctl' and args[1] == 'stop' and 'panel.service' in args:
                    raise RuntimeError('owned writer stop failure')
                return command(*args, **kwargs)
            transaction.run_command = refuse
            with self.assertRaisesRegex(RuntimeError, 'writer stop'):
                transaction.run()
            with self.assertRaisesRegex(RuntimeError, 'writer stop'):
                transaction.rollback()
            self.assertFalse(transaction.changed)
            self.assertFalse((transaction.backup/'panel.db').exists())
            self.assertTrue(transaction.pending_created)
            self.assertEqual((root/'opt/panel/bin/panel').read_bytes(), b'original-panel')


if __name__ == '__main__':
    unittest.main()
