"""Real filesystem/SQLite transaction fixtures, not native systemd acceptance."""
import contextlib
import importlib.util
import json
import os
import pathlib
import sqlite3
import stat
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('production_upgrade', pathlib.Path(__file__).with_name('upgrade-release.py'))
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)
ROOT = pathlib.Path(__file__).resolve().parents[1]


class UpgradePolicyTests(unittest.TestCase):
    def test_privileged_paths_never_skip_ancestry_via_cwd_dotdot_or_another_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            calls = []
            for release in (pathlib.Path('candidate'), root/'..'/'candidate', pathlib.Path('//untrusted/candidate'), root.parent/'outside-candidate'):
                transaction = upgrade.Upgrade(release, root, lambda *args, **kwargs:calls.append(args))
                with self.subTest(release=str(release)), self.assertRaises(ValueError):
                    transaction.preflight()
                self.assertEqual(calls, [])
            transaction = upgrade.Upgrade(root/'candidate', root)
            for path in (pathlib.Path('target'), root/'..'/'target', root.parent/'outside-target', pathlib.Path('//untrusted/target')):
                for operation in (transaction.parents, transaction.directory, transaction.file, transaction.exists,
                                  transaction.sync_directory, lambda p:transaction.atomic(p,b'not written',0o600)):
                    with self.subTest(path=str(path), operation=str(operation)), self.assertRaises(ValueError):
                        operation(path)
            for target in ('relative','/opt/../etc/target','//etc/target'):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    transaction.path(target)
            self.assertEqual(transaction.path('/etc/panel'), root/'etc/panel')

    def test_ordinary_entrypoint_is_before_nss_and_fresh_provisioning(self):
        installer = (ROOT/'packaging/install.sh').read_text()
        entry = 'exec python3 "$HERE/upgrade-release.py" run "$HERE"'
        self.assertLess(installer.index(entry), installer.index('getent group panel'))
        self.assertLess(installer.index(entry), installer.index('mkdir -p "$(dirname "$RELEASE_DIR")"'))
        self.assertLess(installer.index('python3 "$HERE/upgrade-release.py" check "$HERE"'), installer.index('if ((PREFLIGHT_ONLY));then'))
        self.assertIn('alternate roots require --no-services', installer)
        builder = (ROOT/'packaging/build-release.sh').read_text()
        self.assertIn('"$BUILD_ROOT/packaging/upgrade-release.py"', builder)
        self.assertIn('release-file-modes.py upgrade-release.py development-upgrade.py start-guard-install.py;', builder)
        source = pathlib.Path(upgrade.__file__).read_text()
        self.assertNotIn('apt-get', source)
        self.assertNotIn('rmtree', source)
        self.assertNotIn("'enable'", source)
        self.assertNotIn("'restart'", source)
        self.assertIn('signal.signal(signal.SIGTERM', source)
        self.assertIn('signal.signal(signal.SIGINT', source)
        self.assertNotIn("add_argument('--root'", source)

    def test_all_four_real_sqlite_queues_refuse_pending_and_missing_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            transaction = upgrade.Upgrade(root, runner=lambda *args, **kwargs: '')
            transaction.database = root/'panel.db'
            transaction.db_owner = os.geteuid()
            with sqlite3.connect(transaction.database) as db:
                for table in upgrade.QUEUES:
                    db.execute(f'CREATE TABLE {table}(id TEXT PRIMARY KEY,state TEXT)')
            transaction.database.chmod(0o600)
            transaction.queue_check()
            for table in upgrade.QUEUES:
                for state in ('queued', 'running'):
                    with self.subTest(table=table, state=state):
                        with sqlite3.connect(transaction.database) as db:
                            db.execute(f'INSERT INTO {table} VALUES (?,?)', ('owned', state))
                        with self.assertRaises(ValueError):
                            transaction.queue_check()
                        with sqlite3.connect(transaction.database) as db:
                            db.execute(f'DELETE FROM {table}')
            with sqlite3.connect(transaction.database) as db:
                db.execute('DROP TABLE runtime_jobs')
            with self.assertRaises(sqlite3.OperationalError):
                transaction.queue_check()

    def test_unsafe_wal_never_reaches_sqlite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            transaction = upgrade.Upgrade(root)
            transaction.database = root/'panel.db'
            transaction.db_owner = os.geteuid()
            transaction.database.write_bytes(b'not opened')
            transaction.database.chmod(0o600)
            (root/'panel.db-wal').symlink_to(root/'unrelated')
            with mock.patch.object(upgrade.sqlite3, 'connect', side_effect=AssertionError('unsafe link reached SQLite')):
                with self.assertRaises(ValueError):
                    with transaction.connect():
                        pass

    def test_stop_failure_or_still_active_writer_is_not_success(self):
        for failing in (True, False):
            calls = []
            def run(*args, **kwargs):
                calls.append(args)
                if args[1] == 'stop' and failing:
                    raise RuntimeError('actual runner fixture stop failure')
                return 'LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=1\nControlPID=0\nControlGroup=/system.slice/panel.service\nResult=success'
            transaction = upgrade.Upgrade(ROOT, runner=run)
            with self.assertRaises(RuntimeError):
                transaction.stop_writers()
            self.assertEqual(calls[0][1], 'stop')
            self.assertTrue(all('nginx.service' not in call for call in calls))

    def test_service_masks_failures_and_transitions_are_not_coerced_to_inactive(self):
        for field, value in (('LoadState','masked'), ('ActiveState','failed'), ('ActiveState','activating'), ('UnitFileState','masked'), ('UnitFileState','')):
            record = dict(LoadState='loaded', ActiveState='active', SubState='running', UnitFileState='enabled')
            record[field] = value
            transaction = upgrade.Upgrade(ROOT, runner=lambda *args: '\n'.join(k+'='+v for k,v in record.items()))
            with self.assertRaises(ValueError):
                transaction.state('panel.service')

    def test_stopped_writer_record_is_closed_and_fixed_scope(self):
        valid = 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=enabled\nMainPID=0\nControlPID=0\nControlGroup=\nResult=success'
        for raw in (valid+'\nMainPID=0', valid+'\nUnknown=0', valid.replace('MainPID=0','MainPID=00'), valid.replace('Result=success','Result=unknown'), valid.replace('UnitFileState=enabled','UnitFileState=masked'), 'x'*16385):
            with self.subTest(raw=raw[:120]):
                transaction = upgrade.Upgrade(ROOT, runner=lambda *args, **kwargs: raw)
                with self.assertRaises((ValueError,RuntimeError)):
                    transaction.stopped_program('panel.service')
        transaction = upgrade.Upgrade(ROOT, runner=lambda *args, **kwargs: valid)
        self.assertEqual(transaction.stopped_program('panel.service')['MainPID'], '0')
        with self.assertRaises(ValueError):
            transaction.stopped_program('nginx.service')


class Runner:
    """Scope-owned deterministic service state machine; no host service calls."""
    def __init__(self, root, gateway_active=True):
        self.root = root
        self.calls = []
        self.states = {unit:dict(LoadState='loaded',ActiveState='active',SubState='running',UnitFileState='enabled') for unit in upgrade.PROGRAMS}
        self.states[upgrade.TIMER] = dict(LoadState='loaded',ActiveState='active',SubState='waiting',UnitFileState='enabled')
        self.states['panel-mysql-overwrite-recovery.service'] = dict(LoadState='loaded',ActiveState='inactive',SubState='dead',UnitFileState='static')
        self.states['nginx.service'] = dict(LoadState='loaded',ActiveState='active' if gateway_active else 'inactive',SubState='running' if gateway_active else 'dead',UnitFileState='enabled' if gateway_active else 'disabled')
        self.fail_start_once = False
        self.inject_late_queue = False
        self.inject_candidate_job = False
        self.native_queue_calls = 0
        self.native_queue_fail_at = 0
        self.stop_count = 0
        self.failed_stopped_unit = None
        self.stopped_overrides = {}
        self.program_jobs = ''
    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        if pathlib.Path(args[0]).name == 'verify-release.sh':
            return 'checksums verified by fixture; not a signature acceptance'
        if args == (str(self.root/'candidate/bin/panel-executor'), '--check-program-upgrade-queues'):
            self.native_queue_calls += 1
            if self.native_queue_fail_at == self.native_queue_calls:
                raise RuntimeError('owned native queue fixture refusal')
            return ''  # Pure command contract fixture, not native queue proof.
        if args[0] == '/usr/bin/dpkg':
            return 'arm64'
        if args[0] == '/usr/bin/id':
            return '1001'
        if args[0] in ('/usr/sbin/nginx', '/usr/bin/curl'):
            return ''
        if args[0] != '/usr/bin/systemctl':
            raise AssertionError('unknown fixture command')
        if args[1] == 'show':
            if args[3] == '--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,ControlPID,ControlGroup,Result':
                value = dict(self.states[args[2]], MainPID='0',ControlPID='0',ControlGroup='',Result='success')
                value.update(self.stopped_overrides.get(args[2], {}))
                return '\n'.join(k+'='+v for k,v in value.items())
            if args[3] == '--property=User':
                return 'panel'
            if args[3] == '--property=MainPID':
                return '1234' if self.states['nginx.service']['ActiveState'] == 'active' else '0'
            return '\n'.join(k+'='+v for k,v in self.states[args[2]].items())
        if args[1] == 'daemon-reload':
            return ''
        if args[1] == 'list-jobs':
            return self.program_jobs
        if args[1] == 'reset-failed':
            for unit in args[2:]:
                if unit not in upgrade.PROGRAMS or self.states[unit]['ActiveState'] != 'failed':
                    raise AssertionError('failed reset outside exact stopped program fixture')
                self.states[unit].update(ActiveState='inactive',SubState='dead')
            return ''
        if args[1] not in ('stop', 'start'):
            raise AssertionError('fixture attempted enablement/restart or unrelated action')
        if args[1] == 'start' and self.fail_start_once:
            self.fail_start_once = False
            raise RuntimeError('candidate start fixture failure')
        for unit in args[2:]:
            if unit not in upgrade.PROGRAMS+(upgrade.TIMER,):
                raise AssertionError('gateway/unrelated service mutation')
            self.states[unit]['ActiveState'] = 'active' if args[1]=='start' else 'inactive'
            self.states[unit]['SubState'] = ('waiting' if unit==upgrade.TIMER else 'running') if args[1]=='start' else 'dead'
        if args[1] == 'stop' and 'panel.service' in args:
            self.stop_count += 1
            if self.failed_stopped_unit:
                self.states[self.failed_stopped_unit].update(ActiveState='failed',SubState='failed')
            if self.inject_late_queue and self.stop_count == 1:
                with sqlite3.connect(self.root/'var/lib/panel/panel.db') as db:
                    db.execute("INSERT INTO runtime_jobs VALUES ('late','queued')")
        if args[1] == 'start' and 'panel.service' in args and self.inject_candidate_job:
            self.inject_candidate_job = False
            with sqlite3.connect(self.root/'var/lib/panel/panel.db') as db:
                db.execute("INSERT INTO runtime_jobs VALUES ('external-root-change','succeeded')")
            raise RuntimeError('candidate start and external root change fixture')
        return ''


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0, 'actual root Linux ordinary ownership fixture required')
class UpgradeTransactionTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, gateway_active=True):
        with tempfile.TemporaryDirectory(prefix='panel-own-production-upgrade-') as temporary:
            root = pathlib.Path(temporary).resolve()
            for name in ('opt/panel/releases','etc/systemd/system','var/backups/panel/system','var/lib/panel-executor','var/lib/panel','usr/lib'):
                (root/name).mkdir(parents=True, exist_ok=True)
            (root/'var/backups/panel/system').chmod(0o700)
            os.chown(root/'var/lib/panel', 1001,1001)
            (root/'var/lib/panel').chmod(0o750)
            release = root/'candidate'
            release.mkdir()
            (release/'systemd').mkdir()
            (release/'verify-release.sh').write_text('#!/bin/sh\nexit 0\n')
            (release/'verify-release.sh').chmod(0o755)
            (release/'RELEASE').write_text('PANEL_FORMAT=1\nPANEL_VERSION=0.1.0-dev.fixture2\nPANEL_OS=linux\nPANEL_ARCH=arm64\n')
            for unit in upgrade.PROGRAMS+('panel-firewall.service',):
                (release/'systemd'/unit).write_text('[Service]\nExecStart=/opt/panel/bin/panel-executor\n')
                (root/'etc/systemd/system'/unit).write_text('# original root unit '+unit+'\n')
            previous = root/'opt/panel/releases/0.1.0-dev.fixture1'
            previous.mkdir()
            for program in (release, previous):
                (program/'bin').mkdir()
                for name in ('panel', 'panel-executor'):
                    (program/'bin'/name).write_bytes(('owned program '+program.name+' '+name).encode())
                    (program/'bin'/name).chmod(0o755)
            (release/'bin/panel-start-guard').write_bytes(b'owned inert interlock fixture; no native proof')
            (release/'bin/panel-start-guard').chmod(0o755)
            (root/'opt/panel/current').symlink_to(previous)
            (root/'etc/panel-release').write_text('version=0.1.0-dev.fixture1\narch=arm64\n')
            lock = root/'opt/panel/releases/.release.lock'
            lock.write_bytes(b'retained lock bytes')
            lock.chmod(0o644)
            lock = root/'var/lib/panel-executor/runtime-lifecycle.lock'
            lock.write_bytes(b'')
            lock.chmod(0o600)
            database = root/'var/lib/panel/panel.db'
            with sqlite3.connect(database) as db:
                for table in upgrade.QUEUES:
                    db.execute(f'CREATE TABLE {table}(id TEXT PRIMARY KEY,state TEXT)')
                db.execute('CREATE TABLE configuration(value TEXT)')
                db.execute("INSERT INTO configuration VALUES ('original')")
            database.chmod(0o600)
            os.chown(database,1001,1001)
            runner = Runner(root,gateway_active)
            transaction = upgrade.Upgrade(release,root,runner)
            try:
                yield transaction,runner,root
            finally:
                transaction.close()

    def test_commit_preserves_active_or_stopped_disabled_gateway_and_all_enablement(self):
        for active in (True, False):
            with self.subTest(gateway_active=active),self.fixture(active) as (transaction,runner,root):
                states = json.loads(json.dumps(runner.states))
                transaction.run()
                self.assertTrue(transaction.committed)
                self.assertFalse((root/'opt/panel/releases/.program-upgrade.pending').exists())
                self.assertEqual(runner.states,states)
                self.assertEqual(os.readlink(root/'opt/panel/current'),str(transaction.destination))
                self.assertEqual((root/'opt/panel/releases/.release.lock').read_bytes(),b'retained lock bytes')
                self.assertEqual(stat.S_IMODE((root/'opt/panel/releases/.release.lock').stat().st_mode),0o600)
                self.assertEqual(json.loads((transaction.backup/'transaction.json').read_text())['phase'],'committed')
                stops = [call for call in runner.calls if call[0]=='/usr/bin/systemctl' and call[1]=='stop']
                self.assertEqual(len(stops),2)
                self.assertTrue(all('nginx.service' not in call for call in stops))

    def test_first_queue_refusal_has_no_backup_stage_marker_or_service_mutation(self):
        with self.fixture() as (transaction,runner,root):
            with sqlite3.connect(root/'var/lib/panel/panel.db') as db:
                db.execute("INSERT INTO jobs VALUES ('busy','running')")
            with self.assertRaises(ValueError):
                transaction.run()
            self.assertEqual(list((root/'var/backups/panel/system').iterdir()),[])
            self.assertFalse(transaction.stopping)
            self.assertFalse(any(call[0]=='/usr/bin/systemctl' and call[1] in ('stop','start') for call in runner.calls))

    def test_late_queue_refusal_restores_services_and_retains_new_job_without_database_replacement(self):
        with self.fixture() as (transaction,runner,root):
            runner.inject_late_queue=True
            original_info=(root/'var/lib/panel/panel.db').stat()
            states=json.loads(json.dumps(runner.states))
            with self.assertRaises(ValueError):
                transaction.run()
            transaction.rollback()
            self.assertFalse(transaction.changed)
            self.assertEqual(runner.states,states)
            self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino,original_info.st_ino)
            with sqlite3.connect(root/'var/lib/panel/panel.db') as db:
                self.assertEqual(db.execute("SELECT state FROM runtime_jobs WHERE id='late'").fetchone(),('queued',))
            self.assertFalse((transaction.backup/'panel.db').exists())
            self.assertFalse(transaction.pending_created)

    def test_first_or_locked_native_queue_refusal_never_stops_services_or_creates_backup(self):
        for point in (1,2):
            with self.subTest(check=point),self.fixture() as (transaction,runner,root):
                runner.native_queue_fail_at=point
                before=(root/'var/lib/panel/panel.db').stat()
                with self.assertRaisesRegex(RuntimeError,'native queue fixture refusal'):
                    transaction.run()
                transaction.rollback()
                self.assertEqual(runner.native_queue_calls,point)
                self.assertEqual(list((root/'var/backups/panel/system').iterdir()),[])
                self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino,before.st_ino)
                self.assertFalse(any(call[0]=='/usr/bin/systemctl' and call[1] in ('stop','start') for call in runner.calls))

    def test_after_stop_native_queue_refusal_restores_services_without_database_backup_or_program_change(self):
        with self.fixture() as (transaction,runner,root):
            runner.native_queue_fail_at=3
            before=(root/'var/lib/panel/panel.db').stat()
            states=json.loads(json.dumps(runner.states))
            previous=os.readlink(root/'opt/panel/current')
            with self.assertRaisesRegex(RuntimeError,'native queue fixture refusal'):
                transaction.run()
            transaction.rollback()
            self.assertFalse(transaction.changed)
            self.assertFalse(transaction.pending_created)
            self.assertEqual(runner.states,states)
            self.assertEqual(os.readlink(root/'opt/panel/current'),previous)
            self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino,before.st_ino)
            self.assertFalse((transaction.backup/'panel.db').exists())
            self.assertEqual(json.loads((transaction.backup/'transaction.json').read_text())['phase'],'refused-before-program-change')

    def test_candidate_start_failure_restores_exact_pointer_marker_units_database_and_service_states(self):
        with self.fixture() as (transaction,runner,root):
            previous=os.readlink(root/'opt/panel/current')
            marker=(root/'etc/panel-release').read_bytes()
            units={path.name:path.read_bytes() for path in (root/'etc/systemd/system').iterdir() if path.is_file()}
            states=json.loads(json.dumps(runner.states))
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):
                transaction.run()
            transaction.rollback()
            self.assertEqual(os.readlink(root/'opt/panel/current'),previous)
            self.assertEqual((root/'etc/panel-release').read_bytes(),marker)
            self.assertEqual({path.name:path.read_bytes() for path in (root/'etc/systemd/system').iterdir() if path.is_file() and not path.name.startswith('.program-upgrade-')},units)
            self.assertTrue((root/'usr/lib/panel-program-upgrade/start-guard-v2').is_file())
            self.assertEqual(runner.states,states)
            with sqlite3.connect(root/'var/lib/panel/panel.db') as db:
                self.assertEqual(db.execute('SELECT value FROM configuration').fetchone(),('original',))
            self.assertEqual((root/'var/lib/panel/panel.db').stat().st_uid,1001)
            self.assertTrue(transaction.destination.exists())
            self.assertTrue((transaction.backup/'failed-panel.db').exists())
            self.assertFalse(transaction.pending_created)
            self.assertEqual(json.loads((transaction.backup/'transaction.json').read_text())['phase'],'rolled-back')

    def test_external_candidate_job_change_refuses_destructive_rollback_and_retains_interlock(self):
        with self.fixture() as (transaction,runner,root):
            runner.inject_candidate_job=True
            with self.assertRaises(RuntimeError):
                transaction.run()
            with self.assertRaisesRegex(RuntimeError,'accepted job changes'):
                transaction.rollback()
            self.assertTrue(transaction.pending_created)
            self.assertTrue(all(runner.states[unit]['ActiveState']=='inactive' for unit in upgrade.PROGRAMS))
            with sqlite3.connect(root/'var/lib/panel/panel.db') as db:
                self.assertEqual(db.execute("SELECT state FROM runtime_jobs WHERE id='external-root-change'").fetchone(),('succeeded',))
            self.assertEqual(os.readlink(root/'opt/panel/current'),str(transaction.destination))

    def test_failed_but_empty_stopped_program_retains_evidence_before_scoped_reset_and_rollback(self):
        with self.fixture() as (transaction,runner,root):
            states = json.loads(json.dumps(runner.states))
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):
                transaction.run()
            self.assertEqual(len(transaction.locks),1)
            runner.failed_stopped_unit='panel.service'
            original_reset=transaction.run_command
            def inspect_reset(*args, **kwargs):
                if args[1:]==('reset-failed','panel.service'):
                    evidence=transaction.backup/'stopped-failed-programs-1.json'
                    self.assertEqual(stat.S_IMODE(evidence.stat().st_mode),0o600)
                    saved=json.loads(evidence.read_bytes())
                    self.assertEqual(saved['services']['panel.service']['ActiveState'],'failed')
                    self.assertTrue(all(v['MainPID']=='0' and v['ControlPID']=='0' and v['ControlGroup']=='' for v in saved['services'].values()))
                return original_reset(*args, **kwargs)
            transaction.run_command=inspect_reset
            original_restore=transaction.restore_database
            def inspect_restore():
                self.assertEqual(len(transaction.locks),2,'runtime lease must be reacquired for database restore')
                original_restore()
            transaction.restore_database=inspect_restore
            transaction.rollback()
            self.assertEqual(runner.states,states)
            self.assertFalse(transaction.pending_created)
            self.assertEqual(len(transaction.locks),1)
            self.assertEqual([c for c in runner.calls if c[1]=='reset-failed'],[('/usr/bin/systemctl','reset-failed','panel.service')])

    def test_failed_service_with_process_cgroup_or_transition_never_resets_or_replaces_database(self):
        for override in ({'MainPID':'9'},{'ControlPID':'9'},{'ControlGroup':'/system.slice/panel.service'},{'ActiveState':'deactivating','SubState':'stop-sigterm'},{'LoadState':'masked'}):
            with self.subTest(override=override),self.fixture() as (transaction,runner,root):
                runner.fail_start_once=True
                with self.assertRaises(RuntimeError):transaction.run()
                before=transaction.database.stat().st_ino
                runner.failed_stopped_unit='panel.service';runner.stopped_overrides['panel.service']=override
                with self.assertRaises((ValueError,RuntimeError)):transaction.rollback()
                self.assertEqual(transaction.database.stat().st_ino,before)
                self.assertFalse(any(c[1]=='reset-failed' for c in runner.calls))
                self.assertTrue(transaction.pending_created)
                self.assertEqual(os.readlink(root/'opt/panel/current'),str(transaction.destination))

    def test_scheduled_program_job_and_unverifiable_job_inventory_never_reset(self):
        for jobs in ('12 panel.service start waiting','13 panel-mysql-overwrite-recovery.service start running','malformed', '\n'.join('1 unrelated.service start waiting' for _ in range(4097))):
            with self.subTest(jobs=jobs[:100]),self.fixture() as (transaction,runner,root):
                runner.fail_start_once=True
                with self.assertRaises(RuntimeError):transaction.run()
                runner.failed_stopped_unit='panel.service';runner.program_jobs=jobs
                before=transaction.database.stat().st_ino
                with self.assertRaises((ValueError,RuntimeError)):transaction.rollback()
                self.assertFalse(any(c[1]=='reset-failed' for c in runner.calls))
                self.assertEqual(transaction.database.stat().st_ino,before)
                self.assertTrue(transaction.pending_created)

    def test_failed_stop_evidence_write_failure_and_ineffective_reset_remain_closed(self):
        for failure in ('write','reset'):
            with self.subTest(failure=failure),self.fixture() as (transaction,runner,root):
                runner.fail_start_once=True
                with self.assertRaises(RuntimeError):transaction.run()
                runner.failed_stopped_unit='panel.service'
                before=transaction.database.stat().st_ino
                original_atomic=transaction.atomic;original_runner=transaction.run_command
                def atomic(target,*args,**kwargs):
                    if failure=='write' and target.name.startswith('stopped-failed-programs-'):raise OSError('own evidence fsync/write failure')
                    return original_atomic(target,*args,**kwargs)
                def run(*args,**kwargs):
                    if failure=='reset' and args[1]=='reset-failed':return ''
                    return original_runner(*args,**kwargs)
                transaction.atomic=atomic;transaction.run_command=run
                with self.assertRaises((RuntimeError,OSError)):transaction.rollback()
                self.assertEqual(transaction.database.stat().st_ino,before)
                self.assertTrue(transaction.pending_created)
                if failure=='write':self.assertFalse(any(c[1]=='reset-failed' for c in runner.calls))

    def test_retained_stage_or_backup_is_not_deleted(self):
        for target in ('stage','backup'):
            with self.subTest(target=target),self.fixture() as (transaction,runner,root):
                retained=(root/'opt/panel/releases/0.1.0-dev.fixture2.tmp') if target=='stage' else (root/'var/backups/panel/system/production-0.1.0-dev.fixture2')
                retained.mkdir(mode=0o700)
                (retained/'private-sentinel').write_bytes(b'do not overwrite')
                with self.assertRaises(ValueError):
                    transaction.run()
                self.assertEqual((retained/'private-sentinel').read_bytes(),b'do not overwrite')
                self.assertFalse(transaction.stopping)

    def test_original_signed_verifier_private_anchor_beneath_sticky_tmp_is_exactly_scoped(self):
        with self.fixture() as (transaction,runner,root):
            parent=root/'tmp';parent.mkdir();parent.chmod(0o1777)
            anchor=parent/'signed-private';anchor.mkdir(mode=0o700)
            release=anchor/'release';release.mkdir()
            transaction.parents(release)
            parent.chmod(0o777)
            with self.assertRaises(ValueError):
                transaction.parents(release)
            parent.chmod(0o1777);anchor.chmod(0o755)
            with self.assertRaises(ValueError):
                transaction.parents(release)
            anchor.chmod(0o700)
            foreign=root/'writable-other';foreign.mkdir();foreign.chmod(0o1777)
            with self.assertRaises(ValueError):
                transaction.parents(foreign/'release')


if __name__=='__main__':
    unittest.main()
