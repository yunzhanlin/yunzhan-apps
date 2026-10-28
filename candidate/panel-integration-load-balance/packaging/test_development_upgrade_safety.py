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
    def test_direct_helper_refuses_relative_and_traversing_release_before_commands(self):
        for release in (pathlib.Path('candidate'),pathlib.Path('/opt/panel/../candidate'),pathlib.Path('//untrusted/candidate')):
            calls=[]
            transaction=development.DevelopmentUpgrade(release,runner=lambda *args,**kwargs:calls.append(args))
            with self.subTest(release=str(release)),self.assertRaises(ValueError):
                transaction.preflight()
            self.assertEqual(calls,[])

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
        self.assertIn('upgrade-release.py development-upgrade.py start-guard-install.py;', builder)
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
    def test_failed_unchanged_unit_upgrade_rolls_back_without_manager_reload(self):
        with self.fixture() as (transaction, runner, root):
            for source in (transaction.release/'systemd').glob('*.service'):
                data=source.read_bytes()
                (root/'etc/systemd/system'/source.name).write_bytes(data)
            transaction.backup=root/'initial-interlock-evidence'
            transaction.backup.mkdir(mode=0o700)
            transaction.start_guard(install=True)
            transaction.backup=None
            before={str(p):(p.stat().st_dev,p.stat().st_ino,p.stat().st_mtime_ns,p.stat().st_ctime_ns,p.read_bytes())for p in (root/'etc/systemd/system').rglob('*')if p.is_file()}
            runner.calls.clear()
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):
                transaction.run()
            transaction.rollback()
            after={str(p):(p.stat().st_dev,p.stat().st_ino,p.stat().st_mtime_ns,p.stat().st_ctime_ns,p.read_bytes())for p in (root/'etc/systemd/system').rglob('*')if p.is_file()}
            self.assertFalse(transaction.committed)
            self.assertEqual(before,after)
            self.assertEqual(transaction.replaced_units,{})
            self.assertFalse(any(call[:2]==('/usr/bin/systemctl','daemon-reload')for call in runner.calls))

    def test_unchanged_units_and_existing_interlock_preserve_inodes_without_manager_reload(self):
        with self.fixture() as (transaction, runner, root):
            for source in (transaction.release/'systemd').glob('*.service'):
                (root/'etc/systemd/system'/source.name).write_bytes(source.read_bytes())
            transaction.backup=root/'initial-interlock-evidence'
            transaction.backup.mkdir(mode=0o700)
            transaction.start_guard(install=True)
            transaction.backup=None
            before={str(p):(p.stat().st_dev,p.stat().st_ino,p.stat().st_mtime_ns,p.stat().st_ctime_ns,p.read_bytes())for p in (root/'etc/systemd/system').rglob('*')if p.is_file()}
            runner.calls.clear()
            transaction.run()
            after={str(p):(p.stat().st_dev,p.stat().st_ino,p.stat().st_mtime_ns,p.stat().st_ctime_ns,p.read_bytes())for p in (root/'etc/systemd/system').rglob('*')if p.is_file()}
            self.assertTrue(transaction.committed)
            self.assertEqual(before,after)
            self.assertEqual(transaction.replaced_units,{})
            self.assertFalse(any(call[:2]==('/usr/bin/systemctl','daemon-reload')for call in runner.calls))

    def test_second_development_preflight_has_only_release_serialization_not_runtime_lease(self):
        with self.fixture()as(transaction,runner,root):
            original=transaction.preflight;held=[]
            def inspect():
                held.append(len(transaction.locks));original()
            transaction.preflight=inspect;transaction.run()
            self.assertEqual(held,[0,1]);self.assertTrue(transaction.committed)

    def test_development_stage_starts_only_after_durable_timer_deferral_interlock_and_current_queue_proof(self):
        with self.fixture()as(transaction,runner,root):
            original=development.shutil.copytree;seen=[]
            def inspect(source,destination,*args,**kwargs):
                if pathlib.Path(destination)in(root/'opt/panel/bin.new',root/'opt/panel/web.new'):
                    self.assertEqual(runner.states[development.TIMER]['ActiveState'],'inactive')
                    self.assertEqual(len(transaction.locks),2)
                    self.assertEqual(runner.native_queue_calls,3)
                    self.assertEqual(json.loads((transaction.backup/'transaction.json').read_bytes())['phase'],'prepared')
                    transaction.validate_timer_declaration(json.loads((transaction.backup/'timer-deferred.json').read_bytes()))
                    self.assertTrue((root/'usr/lib/panel-program-upgrade/start-guard-v4').is_file())
                    seen.append(str(destination))
                return original(source,destination,*args,**kwargs)
            with mock.patch.object(development.shutil,'copytree',side_effect=inspect):transaction.run()
            self.assertEqual(len(seen),2);self.assertEqual(runner.native_queue_calls,6)

    def test_actual_kill_before_marker_and_after_owned_cleanup_restores_only_deferred_timer(self):
        support.UpgradeTransactionTests().assert_markerless_timer_gaps(self.fixture,development.DevelopmentUpgrade)

    def test_markerless_cleanup_requires_closed_timer_authority_and_never_replays_completion(self):
        support.UpgradeTransactionTests().assert_markerless_timer_authority(self.fixture,development.DevelopmentUpgrade)

    def test_timer_never_starts_under_pending_and_pre_marker_refusal_restores_original_timer(self):
        for refuse in(False,True):
            with self.subTest(refuse=refuse),self.fixture()as(transaction,runner,root):
                before=json.loads(json.dumps(runner.states))
                if refuse:
                    runner.native_queue_fail_at=3
                    with self.assertRaises(RuntimeError):transaction.run()
                    self.assertFalse(transaction.pending_created)
                    self.assertFalse(transaction.stopping)
                    transaction.rollback()
                else:transaction.run()
                self.assertEqual(runner.states,before)
                self.assertFalse(transaction.pending.exists())
                self.assertTrue((transaction.backup/'timer-restored.json').exists())

    def test_actual_killed_original_layout_owner_is_reconstructed_from_only_durable_evidence(self):
        for phase in ('prepared','writers-stopped','database-backed-up','switching-bin','switching-web','switching-marker','switching-units','program-swapped'):
            with self.subTest(phase=phase),self.fixture()as(transaction,runner,root):
                before=self.snapshot(transaction,runner,root)
                backup=support.UpgradeTransactionTests().kill_transaction_at(transaction,runner,root,phase)
                recovered=development.DevelopmentUpgrade(backup,root,runner)
                try:
                    result=recovered.recover(backup)
                    self.assertEqual(result['layout'],'development')
                    self.assertEqual(result['phase'],phase)
                    self.assert_restored(recovered,runner,root,before)
                    self.assertFalse((root/'opt/panel/current').exists())
                    self.assertFalse((root/'etc/panel-release').exists())
                finally:recovered.close()

    def test_reconstructed_development_refuses_foreign_original_candidate_previous_config_and_stage_inodes(self):
        for kind in ('bin','web','previous-bin','previous-web','stage','unit','marker','pending'):
            with self.subTest(kind=kind),self.fixture()as(transaction,runner,root):
                phase='switching-bin'if kind=='stage'else'program-swapped'
                backup=support.UpgradeTransactionTests().kill_transaction_at(transaction,runner,root,phase)
                target={'bin':root/'opt/panel/bin/panel','web':root/'opt/panel/web/index.html',
                        'previous-bin':backup/'previous-bin/panel','previous-web':backup/'previous-web/index.html',
                        'stage':root/'opt/panel/web.new/index.html','unit':root/'etc/systemd/system/panel.service',
                        'marker':root/'opt/panel/DEVELOPMENT_RELEASE','pending':root/'opt/panel/.development-upgrade.pending'}[kind]
                info=target.stat();data=target.read_bytes();target.rename(root/'retained-own-code')
                target.write_bytes(data);target.chmod(info.st_mode&0o777);os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns))
                runner.calls.clear()
                recovered=development.DevelopmentUpgrade(backup,root,runner)
                try:
                    with self.assertRaises(ValueError):recovered.recover(backup)
                    self.assertFalse((backup/'failed-panel.db').exists())
                    self.assertFalse(any(len(call)>1 and call[1]in('stop','start','daemon-reload','reset-failed')for call in runner.calls))
                    self.assertEqual(target.read_bytes(),data)
                finally:recovered.close()

    def test_actual_killed_committed_development_owner_finalizes_without_replacing_code_or_database(self):
        with self.fixture()as(transaction,runner,root):
            backup=support.UpgradeTransactionTests().kill_transaction_at(transaction,runner,root,'committed')
            before={str(path):path.stat().st_ino for base in(root/'opt/panel/bin',root/'opt/panel/web')for path in base.rglob('*')if path.is_file()}
            database_inode=(root/'var/lib/panel/panel.db').stat().st_ino
            runner.calls.clear()
            recovered=development.DevelopmentUpgrade(backup,root,runner)
            try:
                self.assertEqual(recovered.recover(backup)['phase'],'committed')
                self.assertEqual(before,{str(path):path.stat().st_ino for base in(root/'opt/panel/bin',root/'opt/panel/web')for path in base.rglob('*')if path.is_file()})
                self.assertEqual(database_inode,(root/'var/lib/panel/panel.db').stat().st_ino)
                self.assertFalse((root/'opt/panel/.development-upgrade.pending').exists())
                self.assertEqual([call for call in runner.calls if len(call)>1 and call[1]in('stop','start','daemon-reload')],
                                 [('/usr/bin/systemctl','stop',development.TIMER),('/usr/bin/systemctl','start',development.TIMER)])
            finally:recovered.close()

    def test_actual_killed_reverse_tree_and_database_restoration_reconstructs_without_evidence_overwrite(self):
        for phase in ('rollback-evidence-retained','restoring-web','restoring-bin','rollback-data-restored','rolled-back'):
            with self.subTest(phase=phase),self.fixture()as(transaction,runner,root):
                before=self.snapshot(transaction,runner,root)
                runner.fail_start_once=True
                backup=support.UpgradeTransactionTests().kill_transaction_at(transaction,runner,root,phase,rollback=True)
                failed=backup/'failed-panel.db';info=failed.stat();raw=failed.read_bytes()
                inode=(root/'var/lib/panel/panel.db').stat().st_ino
                recovered=development.DevelopmentUpgrade(backup,root,runner)
                try:
                    result=recovered.recover(backup)
                    self.assertEqual(result['phase'],phase)
                    self.assert_restored(recovered,runner,root,before)
                    self.assertEqual(failed.stat().st_ino,info.st_ino);self.assertEqual(failed.read_bytes(),raw)
                    if phase in('rollback-data-restored','rolled-back'):
                        self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino,inode)
                finally:recovered.close()

    def test_recovery_cannot_restore_over_foreign_same_byte_retained_failed_tree(self):
        with self.fixture()as(transaction,runner,root):
            runner.fail_start_once=True
            backup=support.UpgradeTransactionTests().kill_transaction_at(transaction,runner,root,'restoring-bin',rollback=True)
            target=backup/'failed-web/index.html';info=target.stat();data=target.read_bytes()
            target.rename(root/'retained-failed-web');target.write_bytes(data);target.chmod(info.st_mode&0o777);os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns))
            runner.calls.clear()
            recovered=development.DevelopmentUpgrade(backup,root,runner)
            try:
                with self.assertRaises(ValueError):recovered.recover(backup)
                self.assertFalse(any(len(call)>1 and call[1]in('stop','start','daemon-reload','reset-failed')for call in runner.calls))
                self.assertEqual(target.read_bytes(),data)
            finally:recovered.close()

    def test_actual_kill_between_reverse_tree_renames_resumes_original_without_replacing_failed_candidate(self):
        with self.fixture()as(transaction,runner,root):
            before=self.snapshot(transaction,runner,root)
            runner.fail_start_once=True
            def hook(current,suspend):
                rename=development.os.rename
                def stopped(source,target):
                    result=rename(source,target)
                    if pathlib.Path(target)==current.backup/'failed-web':suspend()
                    return result
                development.os.rename=stopped
            backup=support.UpgradeTransactionTests().kill_transaction_at(transaction,runner,root,None,rollback=True,hook=hook)
            self.assertFalse((root/'opt/panel/web').exists())
            inode=(backup/'failed-web').stat().st_ino
            recovered=development.DevelopmentUpgrade(backup,root,runner)
            try:
                recovered.recover(backup)
                self.assert_restored(recovered,runner,root,before)
                self.assertEqual((backup/'failed-web').stat().st_ino,inode)
                self.assertFalse((backup/'previous-web').exists())
            finally:recovered.close()

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
                'units':{p.name:p.read_bytes() for p in (root/'etc/systemd/system').iterdir() if p.is_file()},
                'marker':(root/'opt/panel/DEVELOPMENT_RELEASE').read_bytes() if (root/'opt/panel/DEVELOPMENT_RELEASE').exists() else None,
                'states':json.loads(json.dumps(runner.states))}

    def assert_restored(self, transaction, runner, root, snapshot):
        self.assertEqual(self.snapshot(transaction, runner, root), snapshot)
        self.assertFalse(transaction.pending_created)
        with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db')) as db, db:
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
                with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db')) as db, db:
                    db.execute(f"INSERT INTO {table} VALUES ('owned','running')")
                with self.assertRaises(ValueError):
                    transaction.run()
                self.assertFalse(transaction.stopping)
                self.assertEqual(list((root/'var/backups/panel/system').iterdir()), [])
        with self.fixture() as (transaction, runner, root):
            with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db')) as db, db:
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
        for point in (1,2,3,4):
            with self.subTest(check=point), self.fixture() as (transaction, runner, root):
                before = self.snapshot(transaction, runner, root)
                inode = (root/'var/lib/panel/panel.db').stat().st_ino
                runner.native_queue_fail_at = point
                with self.assertRaisesRegex(RuntimeError, 'native queue fixture refusal'):
                    transaction.run()
                transaction.rollback()
                self.assert_restored(transaction, runner, root, before)
                self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino, inode)
                if point in (3,4):
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
            with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db')) as db, db:
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

    def test_same_byte_foreign_code_or_config_inode_is_never_restored_over(self):
        for kind in ('unit','marker','installed-code','retained-original'):
            with self.subTest(kind=kind),self.fixture() as (transaction,runner,root):
                runner.fail_start_once=True
                with self.assertRaises(RuntimeError):transaction.run()
                target={'unit':root/'etc/systemd/system/panel.service','marker':transaction.marker,'installed-code':root/'opt/panel/web/index.html','retained-original':transaction.backup/'previous-web/index.html'}[kind]
                before=target.lstat()
                raw=target.read_bytes()
                target.rename(root/('retained-own-'+kind))
                target.write_bytes(raw)
                target.chmod(before.st_mode&0o777)
                os.utime(target,ns=(before.st_atime_ns,before.st_mtime_ns))
                inode=target.stat().st_ino
                self.assertNotEqual(inode,before.st_ino)
                database_inode=transaction.database.stat().st_ino
                bin_inode=(root/'opt/panel/bin').stat().st_ino
                with self.assertRaises(ValueError):transaction.rollback()
                self.assertEqual(target.stat().st_ino,inode)
                self.assertEqual(transaction.database.stat().st_ino,database_inode)
                self.assertEqual((root/'opt/panel/bin').stat().st_ino,bin_inode)
                self.assertFalse((transaction.backup/'failed-panel.db').exists())
                self.assertTrue(transaction.pending_created)

    def test_same_byte_candidate_stage_replacement_refuses_before_code_switch(self):
        with self.fixture() as (transaction,runner,root):
            original=transaction.journal
            replaced=[]
            def replace_stage(phase):
                original(phase)
                if phase=='database-backed-up':
                    target=root/'opt/panel/web.new/index.html'
                    info=target.stat()
                    raw=target.read_bytes()
                    target.rename(root/'retained-own-stage')
                    target.write_bytes(raw)
                    target.chmod(info.st_mode&0o777)
                    os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns))
                    replaced.append(target.stat().st_ino)
            with mock.patch.object(transaction,'journal',side_effect=replace_stage):
                with self.assertRaisesRegex(ValueError,'candidate changed'):transaction.run()
            # bin may already have switched; no foreign web.new is installed.
            self.assertTrue(transaction.changed)
            self.assertEqual(transaction.tree_intents,['bin'])
            transaction.rollback()
            self.assertEqual((root/'opt/panel/web.new/index.html').stat().st_ino,replaced[0])
            self.assertEqual((root/'opt/panel/web/index.html').read_text(),'original web')
            self.assertFalse(transaction.pending_created)


    def test_development_plan_retains_full_candidate_and_original_tree_inode_lineage(self):
        with self.fixture() as (transaction,runner,root):
            original=transaction.tree(root/'opt/panel/web',identities=True)
            transaction.run()
            plan_path=transaction.backup/'recovery-plan.json'
            self.assertEqual(plan_path.stat().st_mode&0o777,0o600)
            plan=json.loads(plan_path.read_bytes())
            self.assertEqual(plan['layout'],'development')
            self.assertNotIn('original_pointer',plan)
            self.assertEqual(plan['original_trees']['web'],json.loads(json.dumps(original)))
            self.assertEqual(plan['candidate'],transaction.code_inventory(transaction.backup/'candidate'))
            self.assertEqual((transaction.backup/'candidate/web/index.html').read_text(),'candidate web')
            self.assertEqual((transaction.backup/'candidate/development-upgrade.py').exists(),False)
            # Fixture lacks real packaged helpers; this is a filesystem-copy
            # contract case, not a signed release or restart recovery proof.

    def test_tree_rename_intents_are_durable_before_both_original_and_candidate_moves(self):
        with self.fixture() as (transaction,runner,root):
            rename=development.os.rename
            observed=[]
            def inspect(source,target):
                source,target=pathlib.Path(source),pathlib.Path(target)
                if source in (root/'opt/panel/bin',root/'opt/panel/web',root/'opt/panel/bin.new',root/'opt/panel/web.new'):
                    name=source.name.removesuffix('.new')
                    path=transaction.backup/('tree-rename-'+name+'.json')
                    self.assertEqual(path.stat().st_mode&0o777,0o600)
                    record=json.loads(path.read_bytes())
                    self.assertEqual(record['name'],name)
                    self.assertEqual(record['version'],transaction.version)
                    self.assertEqual(record['original'],json.loads(json.dumps(transaction.original_tree_identities[name])))
                    self.assertEqual(record['candidate'],json.loads(json.dumps(transaction.new_tree_identities[name])))
                    observed.append(name)
                return rename(source,target)
            with mock.patch.object(development.os,'rename',side_effect=inspect):
                transaction.run()
            self.assertEqual(observed,['bin','bin','web','web'])

    def test_first_tree_intent_write_failure_preserves_live_code_and_original_database_inode(self):
        with self.fixture() as (transaction,runner,root):
            before=self.snapshot(transaction,runner,root)
            db_inode=(root/'var/lib/panel/panel.db').stat().st_ino
            with mock.patch.object(transaction,'retain_tree_intent',side_effect=OSError('owned tree intent fsync failure')):
                with self.assertRaisesRegex(OSError,'tree intent fsync'):transaction.run()
            self.assertFalse(transaction.changed)
            self.assertEqual(transaction.tree_intents,[])
            transaction.rollback()
            self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino,db_inode)
            self.assert_restored(transaction,runner,root,before)

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
