"""Real filesystem/SQLite transaction fixtures, not native systemd acceptance."""
import contextlib
import importlib.util
import json
import os
import pathlib
import signal
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
    def test_readiness_retries_only_transient_errors_with_fixed_url_and_bounded_attempts(self):
        calls=[]
        def transient(*args,**kwargs):
            calls.append((args,kwargs))
            if len(calls)==1:raise RuntimeError('owned listener not bound yet')
            if len(calls)==2:raise upgrade.subprocess.TimeoutExpired(args,3)
            return ''
        transaction=upgrade.Upgrade(ROOT,runner=transient)
        with mock.patch.object(upgrade.time,'sleep')as sleep:
            transaction.wait_readiness()
        self.assertEqual(len(calls),3)
        self.assertEqual(sleep.call_args_list,[mock.call(1),mock.call(1)])
        self.assertTrue(all(args==('/usr/bin/curl','-fsS','--max-time','2','http://127.0.0.1:19100/api/ready')and kwargs=={'timeout':3}for args,kwargs in calls))

    def test_readiness_failure_is_finite_and_untrusted_admission_errors_never_retry(self):
        for error,count in ((RuntimeError('owned unavailable'),30),(ValueError('owned unsafe'),1)):
            run=mock.Mock(side_effect=error)
            transaction=upgrade.Upgrade(ROOT,runner=run)
            with mock.patch.object(upgrade.time,'sleep')as sleep,self.assertRaises(type(error)):
                transaction.wait_readiness()
            self.assertEqual(run.call_count,count)
            self.assertEqual(sleep.call_count,count-1)

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
            with contextlib.closing(sqlite3.connect(transaction.database)) as db, db:
                for table in upgrade.QUEUES:
                    db.execute(f'CREATE TABLE {table}(id TEXT PRIMARY KEY,state TEXT)')
            transaction.database.chmod(0o600)
            transaction.queue_check()
            for table in upgrade.QUEUES:
                for state in ('queued', 'running'):
                    with self.subTest(table=table, state=state):
                        with contextlib.closing(sqlite3.connect(transaction.database)) as db, db:
                            db.execute(f'INSERT INTO {table} VALUES (?,?)', ('owned', state))
                        with self.assertRaises(ValueError):
                            transaction.queue_check()
                        with contextlib.closing(sqlite3.connect(transaction.database)) as db, db:
                            db.execute(f'DELETE FROM {table}')
            with contextlib.closing(sqlite3.connect(transaction.database)) as db, db:
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
        if args in ((str(self.root/'candidate/bin/panel-executor'), '--check-program-upgrade-queues'),
                    (str(self.root/'var/backups/panel/system/production-0.1.0-dev.fixture2/candidate/bin/panel-executor'), '--check-program-upgrade-queues'),
                    (str(self.root/'var/backups/panel/system/development-0.1.0-dev.fixture2/candidate/bin/panel-executor'), '--check-program-upgrade-queues')):
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
        if args[1]=='start' and upgrade.TIMER in args[2:]:
            if any((self.root/relative).exists() for relative in
                   ('opt/panel/releases/.program-upgrade.pending','opt/panel/.development-upgrade.pending')):
                raise AssertionError('database recovery timer started during maintenance')
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
                with contextlib.closing(sqlite3.connect(self.root/'var/lib/panel/panel.db')) as db, db:
                    db.execute("INSERT INTO runtime_jobs VALUES ('late','queued')")
        if args[1] == 'start' and 'panel.service' in args and self.inject_candidate_job:
            self.inject_candidate_job = False
            with contextlib.closing(sqlite3.connect(self.root/'var/lib/panel/panel.db')) as db, db:
                db.execute("INSERT INTO runtime_jobs VALUES ('external-root-change','succeeded')")
            raise RuntimeError('candidate start and external root change fixture')
        return ''


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0, 'actual root Linux ordinary ownership fixture required')
class UpgradeTransactionTests(unittest.TestCase):
    def assert_markerless_timer_gaps(self,fixture,factory):
        for checkpoint in ('prepared','committed','rolled-back'):
            with self.subTest(checkpoint=checkpoint),fixture()as(transaction,runner,root):
                if checkpoint=='rolled-back':runner.fail_start_once=True
                def hook(current,suspend):
                    if checkpoint=='prepared':
                        original=current.create_pending
                        def interrupted():
                            suspend()
                            original()
                        current.create_pending=interrupted
                    else:
                        original=current.remove_pending
                        def interrupted():
                            original()
                            suspend()
                        current.remove_pending=interrupted
                backup=self.kill_transaction_at(transaction,runner,root,None,
                                                rollback=checkpoint=='rolled-back',hook=hook)
                self.assertEqual(json.loads((backup/'transaction.json').read_bytes())['phase'],checkpoint)
                self.assertEqual(runner.states[upgrade.TIMER]['ActiveState'],'inactive')
                database=root/'var/lib/panel/panel.db';inode=database.stat().st_ino;raw=database.read_bytes()
                failed=backup/'failed-panel.db'
                evidence=(failed.stat().st_ino,failed.read_bytes())if failed.exists()else None
                runner.calls.clear()
                recovered=factory(backup,root,runner)
                try:
                    self.assertEqual(recovered.recover(backup)['phase'],checkpoint)
                    self.assertFalse(recovered.pending.exists())
                    self.assertEqual((database.stat().st_ino,database.read_bytes()),(inode,raw))
                    if evidence:self.assertEqual((failed.stat().st_ino,failed.read_bytes()),evidence)
                    self.assertEqual([call for call in runner.calls if len(call)>1 and call[1]in('stop','start','daemon-reload','reset-failed')],
                                     [('/usr/bin/systemctl','start',upgrade.TIMER)])
                    restored=backup/'timer-restored.json'
                    self.assertEqual(restored.stat().st_mode&0o777,0o600)
                    self.assertEqual(json.loads(restored.read_bytes()),json.loads((backup/'timer-deferred.json').read_bytes()))
                finally:recovered.close()
                # A later deliberate user stop must never be replayed by the
                # old transaction, including a markerless finalized receipt.
                runner.states[upgrade.TIMER].update(ActiveState='inactive',SubState='dead')
                runner.calls.clear();again=factory(backup,root,runner)
                try:
                    with self.assertRaises(ValueError):again.recover(backup)
                    self.assertEqual(runner.states[upgrade.TIMER]['ActiveState'],'inactive')
                    self.assertFalse(any(len(call)>1 and call[1]in('stop','start','daemon-reload','reset-failed')for call in runner.calls))
                    self.assertEqual((database.stat().st_ino,database.read_bytes()),(inode,raw))
                finally:again.close()

    def assert_markerless_timer_authority(self,fixture,factory):
        for kind in ('missing','format-bool','unknown','completed'):
            with self.subTest(kind=kind),fixture()as(transaction,runner,root):
                def hook(current,suspend):
                    original=current.remove_pending
                    def interrupted():
                        original();suspend()
                    current.remove_pending=interrupted
                backup=self.kill_transaction_at(transaction,runner,root,None,hook=hook)
                receipt=backup/'timer-deferred.json';value=json.loads(receipt.read_bytes())
                if kind=='missing':receipt.rename(root/'retained-deferred.json')
                elif kind=='completed':
                    completed=backup/'timer-restored.json';completed.write_bytes(receipt.read_bytes());completed.chmod(0o600)
                else:
                    if kind=='format-bool':value['format']=True
                    else:value['foreign']=1
                    receipt.write_text(json.dumps(value))
                database=root/'var/lib/panel/panel.db';before=(database.stat().st_ino,database.read_bytes())
                runner.calls.clear();recovered=factory(backup,root,runner)
                try:
                    with self.assertRaises(ValueError):recovered.recover(backup)
                    self.assertEqual(runner.states[upgrade.TIMER]['ActiveState'],'inactive')
                    self.assertFalse(any(len(call)>1 and call[1]in('stop','start','daemon-reload','reset-failed')for call in runner.calls))
                    self.assertEqual((database.stat().st_ino,database.read_bytes()),before)
                finally:recovered.close()

    def test_actual_kill_before_marker_and_after_owned_cleanup_restores_only_deferred_timer(self):
        self.assert_markerless_timer_gaps(self.fixture,upgrade.Upgrade)

    def test_markerless_cleanup_requires_closed_timer_authority_and_never_replays_completion(self):
        self.assert_markerless_timer_authority(self.fixture,upgrade.Upgrade)

    def test_timer_never_starts_under_pending_and_pre_marker_refusal_restores_original_timer(self):
        for refuse in (False,True):
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

    def kill_transaction_at(self, transaction, runner, root, phase, *, rollback=False, hook=None):
        """Actual child SIGKILL, still a filesystem/service-runner fixture."""
        state = root/'child-service-state.json'
        pid = os.fork()
        if pid==0:
            original = transaction.journal
            def suspend():
                descriptor = os.open(state,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(descriptor,'w') as stream:
                    json.dump({'services':runner.states,'fail_start_once':runner.fail_start_once},stream,sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.kill(os.getpid(),signal.SIGSTOP)
            def checkpoint(current):
                original(current)
                if current==phase:
                    suspend()
            transaction.journal = checkpoint
            if hook is not None:
                hook(transaction,suspend)
            try:
                transaction.run()
            except BaseException:
                if rollback:
                    try:
                        transaction.rollback()
                    except BaseException:
                        os._exit(63)
                else:
                    os._exit(61)
            os._exit(62)
        reaped = False
        try:
            waited,status = os.waitpid(pid,os.WUNTRACED)
            self.assertEqual(waited,pid)
            self.assertTrue(os.WIFSTOPPED(status),'child did not reach the requested durable checkpoint')
            os.kill(pid,signal.SIGKILL)
            waited,status = os.waitpid(pid,0)
            reaped = True
            self.assertTrue(os.WIFSIGNALED(status))
            self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)
        finally:
            if not reaped:
                try:
                    waited,_ = os.waitpid(pid,os.WNOHANG)
                    if waited==0:
                        os.kill(pid,signal.SIGKILL)
                        os.waitpid(pid,0)
                except (ProcessLookupError,ChildProcessError):
                    pass
        record = json.loads(state.read_bytes())
        runner.states = record['services']
        runner.fail_start_once = record['fail_start_once']
        return root/'var/backups/panel/system'/(transaction.layout+'-0.1.0-dev.fixture2')

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
            with contextlib.closing(sqlite3.connect(database)) as db, db:
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

    def test_every_managed_replace_has_private_fsynced_inode_intent_before_target_mutation(self):
        with self.fixture() as (transaction,runner,root):
            replace = upgrade.os.replace
            observed = []
            def inspect(source,target):
                target = pathlib.Path(target)
                if target == root/'opt/panel/current' or target == root/'etc/panel-release' or target.parent == root/'etc/systemd/system':
                    records = [json.loads(p.read_bytes()) for p in transaction.backup.glob('mutation-*.json')]
                    record = next(r for r in reversed(sorted(records,key=lambda r:r['stage'] or '')) if r['target']==str(target) and r['stage']==str(source))
                    info = pathlib.Path(source).lstat()
                    self.assertEqual(record['candidate']['identity'][:2],[info.st_dev,info.st_ino])
                    self.assertEqual(record['format'],1)
                    self.assertEqual(record['version'],transaction.version)
                    for p in transaction.backup.glob('mutation-*.json'):
                        self.assertEqual(p.stat().st_mode&0o777,0o600)
                    observed.append(str(target))
                return replace(source,target)
            with mock.patch.object(upgrade.os,'replace',side_effect=inspect):
                transaction.run()
            self.assertEqual(len(observed),len(transaction.original_units)+2)
            records=[json.loads(p.read_bytes()) for p in transaction.backup.glob('mutation-*.json')]
            self.assertEqual(len(records),len(observed)+3)
            pending=[r for r in records if r['target']==str(transaction.pending)]
            self.assertEqual(len(pending),3)
            self.assertEqual(sorted(r['kind'] for r in pending),['file-remove','file-replace','file-replace'])

    def test_actual_killed_owner_reconstructed_recovery_restores_previous_code_units_and_sqlite(self):
        for phase in ('prepared','writers-stopped','database-backed-up','program-swapped'):
            with self.subTest(phase=phase),self.fixture() as (transaction,runner,root):
                original = {path.name:path.read_bytes() for path in (root/'etc/systemd/system').iterdir()}
                previous = os.readlink(root/'opt/panel/current')
                states = json.loads(json.dumps(runner.states))
                backup = self.kill_transaction_at(transaction,runner,root,phase)
                recovered = upgrade.Upgrade(backup,root,runner)
                try:
                    result = recovered.recover(backup)
                    self.assertEqual(result['phase'],phase)
                    self.assertEqual(os.readlink(root/'opt/panel/current'),previous)
                    self.assertEqual({p.name:p.read_bytes() for p in (root/'etc/systemd/system').iterdir() if p.is_file()},original)
                    self.assertEqual(runner.states,states)
                    self.assertFalse((root/'opt/panel/releases/.program-upgrade.pending').exists())
                    with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db')) as db:
                        self.assertEqual(db.execute('SELECT value FROM configuration').fetchone(),('original',))
                    self.assertNotIn('nginx.service',[unit for call in runner.calls if len(call)>1 and call[1]in ('stop','start') for unit in call[2:]])
                finally:
                    recovered.close()

    def test_recovery_check_of_actual_killed_owner_is_read_only_and_holds_original_two_leases(self):
        with self.fixture() as (transaction,runner,root):
            backup = self.kill_transaction_at(transaction,runner,root,'program-swapped')
            before = {str(p):p.read_bytes() for base in (backup,root/'etc/systemd/system',root/'var/lib/panel') for p in base.rglob('*') if p.is_file()}
            runner.calls.clear()
            recovered = upgrade.Upgrade(backup,root,runner)
            try:
                summary = recovered.recover(backup,check=True)
                self.assertTrue(summary['database_restore'])
                self.assertEqual(len(recovered.locks),2)
                self.assertEqual(before,{str(p):p.read_bytes() for base in (backup,root/'etc/systemd/system',root/'var/lib/panel') for p in base.rglob('*') if p.is_file()})
                self.assertFalse(any(len(call)>1 and call[1]in ('stop','start','daemon-reload','reset-failed') for call in runner.calls))
            finally:
                recovered.close()

    def test_alive_original_owner_is_not_reconstructed_or_modified(self):
        with self.fixture() as (transaction,runner,root):
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):
                transaction.run()
            runner.calls.clear()
            recovered = upgrade.Upgrade(transaction.backup,root,runner)
            try:
                with self.assertRaisesRegex(ValueError,'still alive'):
                    recovered.recover(transaction.backup)
                self.assertEqual(runner.calls,[])
                self.assertEqual(recovered.locks,[])
                self.assertTrue(transaction.pending.exists())
            finally:
                recovered.close()

    def test_reconstructed_recovery_refuses_foreign_same_byte_inode_before_any_service_stop(self):
        for kind in ('unit','marker','pointer','pending','database','previous','candidate','lease'):
            with self.subTest(kind=kind),self.fixture() as (transaction,runner,root):
                backup = self.kill_transaction_at(transaction,runner,root,'program-swapped')
                target = {'unit':root/'etc/systemd/system/panel.service','marker':root/'etc/panel-release',
                          'pointer':root/'opt/panel/current','pending':root/'opt/panel/releases/.program-upgrade.pending',
                          'database':root/'var/lib/panel/panel.db','previous':root/'opt/panel/releases/0.1.0-dev.fixture1/bin/panel',
                          'candidate':backup/'candidate/bin/panel','lease':root/'opt/panel/releases/.release.lock'}[kind]
                info = target.lstat()
                data = os.readlink(target) if kind=='pointer' else target.read_bytes()
                target.rename(root/('retained-'+kind))
                if kind=='pointer':
                    target.symlink_to(data)
                else:
                    target.write_bytes(data)
                    target.chmod(info.st_mode&0o777)
                    os.chown(target,info.st_uid,info.st_gid)
                os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns),follow_symlinks=False)
                foreign = target.lstat().st_ino
                runner.calls.clear()
                recovered = upgrade.Upgrade(backup,root,runner)
                try:
                    with self.assertRaises(ValueError):
                        recovered.recover(backup)
                    self.assertEqual(target.lstat().st_ino,foreign)
                    self.assertFalse((backup/'failed-panel.db').exists())
                    self.assertFalse(any(len(call)>1 and call[1]in ('stop','start','daemon-reload','reset-failed') for call in runner.calls))
                finally:
                    recovered.close()

    def test_closed_recovery_plan_and_contiguous_ledger_refuse_without_live_writes(self):
        for kind in ('duplicate','unknown','format-bool','missing-intent','foreign-target'):
            with self.subTest(kind=kind),self.fixture() as (transaction,runner,root):
                backup = self.kill_transaction_at(transaction,runner,root,'program-swapped')
                if kind=='missing-intent':
                    (backup/'mutation-002.json').rename(root/'retained-intent.json')
                elif kind=='foreign-target':
                    path = backup/'mutation-002.json'
                    record = json.loads(path.read_bytes());record['target']=str(root/'etc/unrelated')
                    path.write_text(json.dumps(record))
                else:
                    path = backup/'recovery-plan.json'
                    record = json.loads(path.read_bytes())
                    if kind=='duplicate':
                        path.write_text('{"format":1,'+path.read_text()[1:])
                    else:
                        record['unreviewed']=True if kind=='unknown' else None
                        if kind=='format-bool':
                            record.pop('unreviewed');record['format']=True
                        path.write_text(json.dumps(record))
                runner.calls.clear()
                recovered = upgrade.Upgrade(backup,root,runner)
                try:
                    with self.assertRaises(ValueError):
                        recovered.recover(backup)
                    self.assertFalse(any(len(call)>1 and call[1]in ('stop','start','daemon-reload','reset-failed') for call in runner.calls))
                finally:
                    recovered.close()

    def test_database_restore_and_sidecar_remove_have_durable_inode_intents_before_mutations(self):
        with self.fixture() as (transaction,runner,root):
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):
                transaction.run()
            replace = upgrade.os.replace
            observed=[]
            def inspect(source,target):
                if pathlib.Path(target)==transaction.database:
                    records = [json.loads(p.read_bytes()) for p in sorted(transaction.backup.glob('mutation-*.json'))]
                    record = records[-1]
                    self.assertEqual(record['kind'],'database-replace')
                    self.assertEqual(record['candidate']['identity'][:2],[pathlib.Path(source).stat().st_dev,pathlib.Path(source).stat().st_ino])
                    self.assertEqual(record['candidate']['sha256'],transaction.validate_database_backup()['sha256'])
                    observed.append(record)
                return replace(source,target)
            with mock.patch.object(upgrade.os,'replace',side_effect=inspect):
                transaction.rollback()
            self.assertEqual(len(observed),1)

    def test_owned_stopped_database_sidecars_have_private_durable_intent_before_each_unlink(self):
        with self.fixture() as (transaction,runner,root):
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):transaction.run()
            paths=[]
            for suffix in ('-wal','-shm'):
                path=transaction.database.with_name(transaction.database.name+suffix)
                path.write_bytes(('owned stopped fixture '+suffix).encode());path.chmod(0o600);os.chown(path,1001,1001)
                paths.append(path)
            unlink=upgrade.os.unlink
            observed=[]
            def inspect(path,*args,**kwargs):
                if pathlib.Path(path)in paths:
                    record=json.loads(sorted(transaction.backup.glob('mutation-*.json'))[-1].read_bytes())
                    self.assertEqual(record['kind'],'database-remove')
                    self.assertEqual(record['target'],str(path))
                    self.assertEqual(record['before'],transaction.current_database_snapshot(path))
                    self.assertIsNone(record['candidate']);self.assertIsNone(record['stage'])
                    observed.append(path)
                return unlink(path,*args,**kwargs)
            with mock.patch.object(upgrade.os,'unlink',side_effect=inspect):transaction.remove_database_sidecars()
            self.assertEqual(observed,paths)
            self.assertTrue(all(not path.exists()for path in paths))

    def test_stopped_sidecar_intent_failure_or_foreign_same_byte_inode_is_not_removed(self):
        for kind in ('failure','foreign'):
            with self.subTest(kind=kind),self.fixture()as(transaction,runner,root):
                runner.fail_start_once=True
                with self.assertRaises(RuntimeError):transaction.run()
                path=transaction.database.with_name(transaction.database.name+'-wal')
                path.write_bytes(b'owned stopped sidecar fixture');path.chmod(0o600);os.chown(path,1001,1001)
                before=path.stat()
                original=transaction.mutation_evidence
                def change(intent):
                    if intent['kind']=='database-remove':
                        if kind=='failure':raise OSError('owned durable intent failure')
                        original(intent)
                        path.rename(root/'retained-owned-sidecar')
                        path.write_bytes(b'owned stopped sidecar fixture');path.chmod(0o600);os.chown(path,1001,1001)
                        os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
                    else:original(intent)
                with mock.patch.object(transaction,'mutation_evidence',side_effect=change):
                    with self.assertRaises((OSError,ValueError)):transaction.remove_database_sidecars()
                self.assertTrue(path.exists())
                self.assertEqual(path.read_bytes(),b'owned stopped sidecar fixture')
                self.assertEqual(transaction.database.stat().st_ino,transaction.original_database_inode[1])

    def test_actual_killed_committed_owner_finalizes_without_database_or_program_rollback(self):
        with self.fixture()as(transaction,runner,root):
            backup=self.kill_transaction_at(transaction,runner,root,'committed')
            inode=(root/'var/lib/panel/panel.db').stat().st_ino
            runner.calls.clear()
            recovered=upgrade.Upgrade(backup,root,runner)
            try:
                result=recovered.recover(backup)
                self.assertEqual(result['phase'],'committed')
                self.assertEqual(os.readlink(root/'opt/panel/current'),str(root/'opt/panel/releases/0.1.0-dev.fixture2'))
                self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino,inode)
                self.assertFalse((backup/'failed-panel.db').exists())
                self.assertEqual([call for call in runner.calls if len(call)>1 and call[1]in('stop','start','daemon-reload')],
                                 [('/usr/bin/systemctl','stop',upgrade.TIMER),('/usr/bin/systemctl','start',upgrade.TIMER)])
                self.assertFalse((root/'opt/panel/releases/.program-upgrade.pending').exists())
            finally:recovered.close()

    def test_actual_killed_rollback_is_reconstructed_without_overwriting_failed_sqlite_evidence(self):
        for phase in ('rollback-evidence-retained','rollback-data-restored','rolled-back'):
            with self.subTest(phase=phase),self.fixture()as(transaction,runner,root):
                runner.fail_start_once=True
                previous=os.readlink(root/'opt/panel/current')
                original_states=json.loads(json.dumps(runner.states))
                backup=self.kill_transaction_at(transaction,runner,root,phase,rollback=True)
                failed=backup/'failed-panel.db';info=failed.stat();raw=failed.read_bytes()
                database_inode=(root/'var/lib/panel/panel.db').stat().st_ino
                recovered=upgrade.Upgrade(backup,root,runner)
                try:
                    result=recovered.recover(backup)
                    self.assertEqual(result['phase'],phase)
                    self.assertEqual(failed.stat().st_ino,info.st_ino)
                    self.assertEqual(failed.read_bytes(),raw)
                    self.assertEqual(os.readlink(root/'opt/panel/current'),previous)
                    self.assertEqual(runner.states,original_states)
                    if phase!='rollback-evidence-retained':
                        self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino,database_inode)
                    self.assertFalse((root/'opt/panel/releases/.program-upgrade.pending').exists())
                    with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db'))as db:
                        self.assertEqual(db.execute('SELECT value FROM configuration').fetchone(),('original',))
                finally:recovered.close()

    def test_finalized_restoration_waits_for_listener_without_replaying_database_or_failed_evidence(self):
        for failures in (2,30):
            with self.subTest(failures=failures),self.fixture()as(transaction,runner,root):
                runner.fail_start_once=True
                backup=self.kill_transaction_at(transaction,runner,root,'rollback-data-restored',rollback=True)
                database=root/'var/lib/panel/panel.db';inode=database.stat().st_ino
                failed=backup/'failed-panel.db';failed_inode=failed.stat().st_ino;failed_bytes=failed.read_bytes()
                count=0
                def delayed(*args,**kwargs):
                    nonlocal count
                    if args[0]=='/usr/bin/curl':
                        count+=1
                        if count<=failures:raise RuntimeError('owned listener starting')
                    return runner(*args,**kwargs)
                recovered=upgrade.Upgrade(backup,root,delayed)
                try:
                    with mock.patch.object(upgrade.time,'sleep'):
                        if failures==30:
                            with self.assertRaises(RuntimeError):recovered.recover(backup)
                            self.assertTrue((root/'opt/panel/releases/.program-upgrade.pending').exists())
                            self.assertEqual(json.loads((backup/'transaction.json').read_bytes())['phase'],'rollback-data-restored')
                        else:
                            recovered.recover(backup)
                            self.assertFalse((root/'opt/panel/releases/.program-upgrade.pending').exists())
                    self.assertEqual(count,30 if failures==30 else 3)
                    self.assertEqual(database.stat().st_ino,inode)
                    self.assertEqual(failed.stat().st_ino,failed_inode)
                    self.assertEqual(failed.read_bytes(),failed_bytes)
                finally:recovered.close()

    def test_failed_snapshot_inode_change_and_missing_publication_authority_refuse_before_any_live_write(self):
        for kind in ('foreign','missing-proof','duplicate-proof'):
            with self.subTest(kind=kind),self.fixture()as(transaction,runner,root):
                runner.fail_start_once=True
                backup=self.kill_transaction_at(transaction,runner,root,'rollback-evidence-retained',rollback=True)
                if kind=='foreign':
                    path=backup/'failed-panel.db';info=path.stat();data=path.read_bytes();path.rename(root/'retained-failed-db')
                    path.write_bytes(data);path.chmod(0o600);os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns))
                elif kind=='missing-proof':
                    (backup/'failed-database-publish.json').rename(root/'retained-proof')
                else:
                    path=backup/'failed-database-publish.json';path.write_text('{"format":1,'+path.read_text()[1:])
                runner.calls.clear()
                recovered=upgrade.Upgrade(backup,root,runner)
                try:
                    with self.assertRaises(ValueError):recovered.recover(backup)
                    self.assertFalse(any(len(call)>1 and call[1]in('stop','start','daemon-reload','reset-failed')for call in runner.calls))
                finally:recovered.close()

    def test_failed_database_publication_is_complete_private_and_exclusive_before_snapshot_reuse(self):
        with self.fixture()as(transaction,runner,root):
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):transaction.run()
            publish=upgrade.rename_noreplace
            observed=[]
            def inspect(source,target):
                if target==transaction.backup/'failed-panel.db':
                    record=json.loads((transaction.backup/'failed-database-publish.json').read_bytes())
                    self.assertEqual(record['candidate'],transaction.private_database_stage_snapshot(pathlib.Path(source)))
                    self.assertEqual(pathlib.Path(source).stat().st_mode&0o777,0o600)
                    with contextlib.closing(sqlite3.connect(source))as db:self.assertEqual(db.execute('PRAGMA quick_check').fetchone(),('ok',))
                    self.assertFalse(pathlib.Path(target).exists());observed.append(record)
                return publish(source,target)
            with mock.patch.object(upgrade,'rename_noreplace',side_effect=inspect):transaction.rollback()
            self.assertEqual(len(observed),1)
            before=(transaction.backup/'failed-panel.db').stat().st_ino
            transaction.retain_failed_database()
            self.assertEqual((transaction.backup/'failed-panel.db').stat().st_ino,before)
            self.assertEqual(transaction.validate_database_backup(failed=True)['identity'][1],before)

    def test_kill_after_database_replace_before_phase_journal_preserves_already_restored_inode(self):
        with self.fixture()as(transaction,runner,root):
            runner.fail_start_once=True
            def hook(current,suspend):
                replace=upgrade.os.replace
                def stopped(source,target):
                    result=replace(source,target)
                    if pathlib.Path(target)==root/'var/lib/panel/panel.db':suspend()
                    return result
                upgrade.os.replace=stopped
            backup=self.kill_transaction_at(transaction,runner,root,None,rollback=True,hook=hook)
            inode=(root/'var/lib/panel/panel.db').stat().st_ino
            recovered=upgrade.Upgrade(backup,root,runner)
            try:
                recovered.recover(backup)
                self.assertEqual((root/'var/lib/panel/panel.db').stat().st_ino,inode)
                self.assertFalse((root/'opt/panel/releases/.program-upgrade.pending').exists())
            finally:recovered.close()

    def test_kill_after_complete_failed_snapshot_intent_before_publication_uses_only_bound_private_stage(self):
        with self.fixture()as(transaction,runner,root):
            runner.fail_start_once=True
            def hook(current,suspend):
                rename=upgrade.rename_noreplace
                def stopped(source,target):
                    if pathlib.Path(target)==current.backup/'failed-panel.db':suspend()
                    return rename(source,target)
                upgrade.rename_noreplace=stopped
            backup=self.kill_transaction_at(transaction,runner,root,None,rollback=True,hook=hook)
            self.assertFalse((backup/'failed-panel.db').exists())
            record=json.loads((backup/'failed-database-publish.json').read_bytes())
            stage=pathlib.Path(record['stage']);inode=stage.stat().st_ino
            recovered=upgrade.Upgrade(backup,root,runner)
            try:
                recovered.recover(backup)
                self.assertEqual((backup/'failed-panel.db').stat().st_ino,inode)
                self.assertFalse(stage.exists())
                self.assertFalse((root/'opt/panel/releases/.program-upgrade.pending').exists())
            finally:recovered.close()

    def test_real_escaped_systemd_mount_filename_survives_closed_candidate_inventory_and_recovery(self):
        with self.fixture()as(transaction,runner,root):
            name=r'var-cache-panel\x2dapache\x2dbody.mount'
            self.assertIsNotNone(upgrade.UNIT.fullmatch(name))
            (root/'candidate/systemd'/name).write_text('[Mount]\nWhat=tmpfs\nWhere=/var/cache/panel-apache-body\n')
            backup=self.kill_transaction_at(transaction,runner,root,'program-swapped')
            plan=json.loads((backup/'recovery-plan.json').read_bytes())
            self.assertIn('systemd/'+name,plan['candidate'])
            recovered=upgrade.Upgrade(backup,root,runner)
            try:
                recovered.recover(backup)
                self.assertFalse((root/'etc/systemd/system'/name).exists())
                self.assertFalse((root/'opt/panel/releases/.program-upgrade.pending').exists())
            finally:recovered.close()

    def test_same_byte_foreign_unit_marker_or_pointer_inode_refuses_before_any_data_restore(self):
        for kind in ('unit','marker','pointer','pending'):
            with self.subTest(kind=kind),self.fixture() as (transaction,runner,root):
                runner.fail_start_once=True
                with self.assertRaises(RuntimeError):transaction.run()
                target = {'unit':root/'etc/systemd/system/panel.service','marker':transaction.marker,'pointer':transaction.current,'pending':transaction.pending}[kind]
                before = target.lstat()
                value = os.readlink(target) if kind=='pointer' else target.read_bytes()
                target.rename(root/('retained-own-'+kind))
                if kind=='pointer':
                    target.symlink_to(value)
                    os.utime(target,ns=(before.st_atime_ns,before.st_mtime_ns),follow_symlinks=False)
                else:
                    target.write_bytes(value)
                    target.chmod(before.st_mode&0o777)
                    os.utime(target,ns=(before.st_atime_ns,before.st_mtime_ns))
                foreign = target.lstat().st_ino
                self.assertNotEqual(foreign,before.st_ino)
                database_inode=transaction.database.stat().st_ino
                original_files={p.name:p.read_bytes() for p in (root/'etc/systemd/system').iterdir() if p.is_file()}
                with self.assertRaisesRegex(ValueError,'inode'):transaction.rollback()
                self.assertEqual(target.lstat().st_ino,foreign)
                self.assertEqual(transaction.database.stat().st_ino,database_inode)
                self.assertFalse((transaction.backup/'failed-panel.db').exists())
                self.assertEqual({p.name:p.read_bytes() for p in (root/'etc/systemd/system').iterdir() if p.is_file()},original_files)
                self.assertTrue(transaction.pending_created)

    def test_durable_intent_failure_never_replaces_unit_and_known_prior_changes_roll_back(self):
        with self.fixture() as (transaction,runner,root):
            original=(root/'etc/systemd/system/panel.service').read_bytes()
            evidence=transaction.mutation_evidence
            def fail(intent):
                if intent['kind']=='file-replace' and pathlib.Path(intent['target']).parent==root/'etc/systemd/system':
                    raise OSError('owned intent fsync/write fixture failure')
                return evidence(intent)
            with mock.patch.object(transaction,'mutation_evidence',side_effect=fail):
                with self.assertRaisesRegex(OSError,'intent fsync/write'):transaction.run()
            self.assertEqual((root/'etc/systemd/system/panel.service').read_bytes(),original)
            transaction.rollback()
            self.assertFalse(transaction.pending_created)
            self.assertEqual((root/'etc/systemd/system/panel.service').read_bytes(),original)

    def test_same_byte_drift_after_intent_never_replaces_foreign_target(self):
        with self.fixture() as (transaction,runner,root):
            evidence=transaction.mutation_evidence
            foreign=[]
            def drift(intent):
                evidence(intent)
                target=pathlib.Path(intent['target'])
                if intent['kind']=='file-replace' and target.parent==root/'etc/systemd/system' and not foreign:
                    original=target.read_bytes()
                    target.rename(root/'retained-before-intent')
                    target.write_bytes(original)
                    target.chmod(0o644)
                    foreign.append((target,target.stat().st_ino))
            with mock.patch.object(transaction,'mutation_evidence',side_effect=drift):
                with self.assertRaisesRegex(ValueError,'after durable'):transaction.run()
            with self.assertRaisesRegex(ValueError,'inode'):transaction.rollback()
            self.assertEqual(foreign[0][0].stat().st_ino,foreign[0][1])
            self.assertFalse((transaction.backup/'failed-panel.db').exists())
            self.assertTrue(transaction.pending_created)

    def test_interruption_after_rename_uses_prewrite_inode_intent_for_same_process_rollback(self):
        with self.fixture() as (transaction,runner,root):
            marker=transaction.path('/etc/panel-release')
            original=marker.read_bytes()
            replace=upgrade.os.replace
            raised=[]
            def fail(source,target):
                result=replace(source,target)
                if pathlib.Path(target)==marker and not raised:
                    raised.append(True)
                    raise OSError('owned after-rename fixture')
                return result
            with mock.patch.object(upgrade.os,'replace',side_effect=fail):
                with self.assertRaisesRegex(OSError,'after-rename'):transaction.run()
            self.assertTrue(transaction.file_mutations[str(marker)])
            self.assertFalse(transaction.file_mutations[str(marker)][-1].get('applied',False))
            transaction.rollback()
            self.assertEqual(marker.read_bytes(),original)
            self.assertFalse(transaction.pending_created)
            self.assertEqual(json.loads((transaction.backup/'transaction.json').read_bytes())['phase'],'rolled-back')

    def test_deleted_new_managed_unit_is_not_confused_with_unapplied_absent_original(self):
        with self.fixture() as (transaction,runner,root):
            name='panel-extra.service'
            (transaction.release/'systemd'/name).write_text('[Service]\nExecStart=/opt/panel/bin/panel-executor\n')
            runner.fail_start_once=True
            with self.assertRaises(RuntimeError):transaction.run()
            target=root/'etc/systemd/system'/name
            self.assertIsNone(transaction.original_units[name])
            self.assertTrue(transaction.file_mutations[str(target)][-1]['applied'])
            target.unlink()
            with self.assertRaisesRegex(ValueError,'inode'):transaction.rollback()
            self.assertTrue(transaction.pending_created)
            self.assertFalse((transaction.backup/'failed-panel.db').exists())


    def test_private_complete_candidate_plan_precedes_live_mutations_and_is_immutable(self):
        with self.fixture() as (transaction,runner,root):
            evidence=transaction.mutation_evidence
            observed=[]
            def inspect(intent):
                plan_path=transaction.backup/'recovery-plan.json'
                self.assertEqual(plan_path.stat().st_mode&0o777,0o600)
                plan=json.loads(plan_path.read_bytes())
                self.assertEqual(plan['layout'],'production')
                self.assertEqual(plan['version'],transaction.version)
                self.assertEqual(plan['backup_inode'],transaction.backup.stat().st_ino)
                self.assertEqual(plan['owner']['pid'],os.getpid())
                held=[[os.fstat(fd).st_dev,os.fstat(fd).st_ino] for fd in transaction.locks]
                self.assertEqual(len(plan['owner']['leases']),2)
                self.assertIn(len(held),(1,2))
                self.assertEqual(plan['owner']['leases'][:len(held)],held)
                self.assertEqual(plan['candidate'],transaction.code_inventory(transaction.backup/'candidate'))
                observed.append(intent['kind'])
                return evidence(intent)
            with mock.patch.object(transaction,'mutation_evidence',side_effect=inspect):
                transaction.run()
            self.assertTrue(observed)
            self.assertEqual((transaction.backup/'candidate/RELEASE').read_bytes(),(transaction.release/'RELEASE').read_bytes())
            plan_path=transaction.backup/'recovery-plan.json'
            info=plan_path.stat()
            raw=plan_path.read_bytes()
            with self.assertRaisesRegex(ValueError,'must not be replaced'):
                transaction.retain_candidate_plan()
            self.assertEqual(plan_path.stat().st_ino,info.st_ino)
            self.assertEqual(plan_path.read_bytes(),raw)

    def test_source_drift_during_private_candidate_copy_keeps_partial_evidence_without_live_mutation(self):
        with self.fixture() as (transaction,runner,root):
            source=transaction.release/'bin/panel'
            original=source.read_bytes()
            opening=upgrade.os.open
            changed=[]
            def drift(path,*args,**kwargs):
                fd=opening(path,*args,**kwargs)
                # code_inventory reads twice before copy; change after the
                # retained copy opens its descriptor, not prior preflight.
                if pathlib.Path(path)==source and transaction.backup is not None and (transaction.backup/'candidate').exists() and not changed:
                    source.write_bytes(original+b'foreign drift')
                    changed.append(True)
                return fd
            before_pointer=os.readlink(root/'opt/panel/current')
            with mock.patch.object(upgrade.os,'open',side_effect=drift):
                with self.assertRaisesRegex(ValueError,'candidate source'):transaction.run()
            self.assertTrue(changed)
            self.assertFalse(transaction.stopping)
            self.assertFalse(transaction.changed)
            self.assertFalse((transaction.backup/'recovery-plan.json').exists())
            self.assertTrue((transaction.backup/'candidate').exists())
            self.assertEqual(os.readlink(root/'opt/panel/current'),before_pointer)
            for version in ('v1','v2','v3','v4'):
                self.assertFalse((root/('usr/lib/panel-program-upgrade/start-guard-'+version)).exists())
            self.assertFalse(any(c[0]=='/usr/bin/systemctl' and c[1] in ('start','stop') for c in runner.calls))

    def test_complete_candidate_inventory_rejects_links_specials_and_same_device_mounts(self):
        with self.fixture() as (transaction,runner,root):
            linked=transaction.release/'linked'
            linked.symlink_to(root/'outside')
            with self.assertRaisesRegex(ValueError,'linked, special'):transaction.code_inventory(transaction.release)
            linked.unlink()
            fifo=transaction.release/'fifo'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError,'linked, special'):transaction.code_inventory(transaction.release)
            fifo.unlink()
            mountinfo='1 0 0:1 / '+str(transaction.release)+' rw - tmpfs tmpfs rw\n'
            with mock.patch('builtins.open',mock.mock_open(read_data=mountinfo.encode())):
                with self.assertRaisesRegex(ValueError,'mounted candidate'):transaction.code_inventory(transaction.release)

    def test_same_byte_replaced_or_modified_backup_never_reaches_rollback_restore(self):
        for kind in ('inode','content','receipt'):
            with self.subTest(kind=kind),self.fixture() as (transaction,runner,root):
                runner.fail_start_once=True
                with self.assertRaises(RuntimeError):transaction.run()
                backup=transaction.backup/'panel.db'
                if kind=='inode':
                    info=backup.stat()
                    raw=backup.read_bytes()
                    backup.rename(transaction.backup/'retained-original-database')
                    backup.write_bytes(raw)
                    backup.chmod(0o600)
                    os.utime(backup,ns=(info.st_atime_ns,info.st_mtime_ns))
                    self.assertNotEqual(backup.stat().st_ino,info.st_ino)
                elif kind=='content':
                    with contextlib.closing(sqlite3.connect(backup)) as db, db:db.execute("UPDATE configuration SET value='foreign'")
                else:
                    receipt=transaction.backup/'database-backup.json'
                    receipt.write_text('{"format":1,"format":1,"version":"'+transaction.version+'","database":null}')
                inode=transaction.database.stat().st_ino
                pointer=os.readlink(transaction.current)
                with self.assertRaises(ValueError):transaction.rollback()
                self.assertEqual(transaction.database.stat().st_ino,inode)
                self.assertEqual(os.readlink(transaction.current),pointer)
                self.assertFalse((transaction.backup/'failed-panel.db').exists())
                self.assertTrue(transaction.pending_created)

    def test_database_receipt_failure_keeps_original_database_and_restarts_original_services(self):
        with self.fixture() as (transaction,runner,root):
            original=(root/'var/lib/panel/panel.db').stat().st_ino
            states=json.loads(json.dumps(runner.states))
            with mock.patch.object(transaction,'retain_database_receipt',side_effect=OSError('owned database receipt fsync failure')):
                with self.assertRaisesRegex(OSError,'receipt fsync'):transaction.run()
            self.assertFalse(transaction.changed)
            self.assertTrue((transaction.backup/'panel.db').exists())
            self.assertFalse((transaction.backup/'database-backup.json').exists())
            transaction.rollback()
            self.assertEqual(transaction.database.stat().st_ino,original)
            self.assertEqual(runner.states,states)
            self.assertFalse(transaction.pending_created)

    def test_real_atomic_marker_publication_never_overwrites_existing_file_or_link(self):
        with self.fixture() as (transaction,runner,root):
            source=root/'owned-marker-source'
            source.write_bytes(b'complete version marker\n')
            source.chmod(0o644)
            existing=root/'owned-marker-existing'
            existing.write_bytes(b'foreign existing marker')
            inode=existing.stat().st_ino
            with self.assertRaises(FileExistsError):upgrade.rename_noreplace(source,existing)
            self.assertEqual(existing.stat().st_ino,inode)
            self.assertEqual(existing.read_bytes(),b'foreign existing marker')
            link=root/'owned-marker-link'
            link.symlink_to(existing)
            with self.assertRaises(FileExistsError):upgrade.rename_noreplace(source,link)
            self.assertTrue(link.is_symlink())
            target=root/'owned-marker-published'
            source_inode=source.stat().st_ino
            upgrade.rename_noreplace(source,target)
            self.assertEqual(target.stat().st_ino,source_inode)
            self.assertEqual(target.read_bytes(),b'complete version marker\n')
            self.assertFalse(source.exists())

    def test_exclusive_pending_marker_has_durable_stage_identity_before_first_publication(self):
        with self.fixture() as (transaction,runner,root):
            evidence=transaction.mutation_evidence
            observed=[]
            def inspect(intent):
                if intent['target']==str(transaction.pending) and intent['kind']=='file-replace':
                    if not observed:
                        self.assertFalse(transaction.pending.exists())
                        self.assertIsNone(intent['before'])
                        stage=pathlib.Path(intent['stage'])
                        self.assertEqual(stage.read_bytes(),('version='+transaction.version+'\n').encode())
                        self.assertEqual(stage.stat().st_mode&0o777,0o644)
                        self.assertEqual(intent['candidate'],transaction.current_file_snapshot(stage))
                    observed.append(intent)
                return evidence(intent)
            with mock.patch.object(transaction,'mutation_evidence',side_effect=inspect):
                transaction.run()
            self.assertEqual(len(observed),2)
            self.assertIsNotNone(observed[1]['before'])
            self.assertFalse(transaction.pending.exists())
            self.assertEqual(transaction.file_mutations[str(transaction.pending)][-1]['candidate'],None)

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
            with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db')) as db, db:
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
            with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db')) as db, db:
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
            runner.native_queue_fail_at=4
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
            self.assertTrue((root/'usr/lib/panel-program-upgrade/start-guard-v4').is_file())
            self.assertEqual(runner.states,states)
            with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db')) as db, db:
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
            with contextlib.closing(sqlite3.connect(root/'var/lib/panel/panel.db')) as db, db:
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
