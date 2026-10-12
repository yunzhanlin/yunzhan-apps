#!/usr/bin/env python3
"""Fail-closed ordinary production upgrade; never provision a website gateway.

Only the real / host is supported by the CLI. Tests instantiate the transaction
with an isolated filesystem and command runner; those are not runtime switches.
An interrupted journal is retained for inspection, not silently retried.
"""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

PROGRAMS = ('panel-terminal.service', 'panel-terminal-root.service', 'panel-executor.service', 'panel.service')
TIMER = 'panel-mysql-overwrite-recovery.timer'
QUEUES = ('jobs', 'runtime_jobs', 'mysql_jobs', 'acme_orders')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*\Z')
UNIT = re.compile(r'(?:panel-[a-z0-9@.-]+|panel|var-cache-panel\\x2dapache\\x2dbody)\.(?:service|timer|mount)\Z')


def command(*args, timeout=60):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # No raw unit, credential, configuration or database output is exposed.
        raise RuntimeError('command failed: '+pathlib.Path(args[0]).name+' '+str(result.returncode))
    return result.stdout.strip()


class Upgrade:
    def __init__(self, release, root=pathlib.Path('/'), runner=command):
        self.release = pathlib.Path(release)
        self.root = pathlib.Path(root)
        self.run_command = runner
        self.locks = []
        self.stopping = False
        self.changed = False
        self.committed = False
        self.backup = None
        self.states = {}
        self.original_units = {}
        self.pending_created = False
        self.replaced_units = {}
        self.failed_stop_snapshots = 0

    def path(self, value):
        return self.root/value.lstrip('/')

    def directory(self, path, owner=0, private=False):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022 or (private and stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('untrusted upgrade directory')
        return info

    def parents(self, path):
        # Every traversed privileged parent must be ordinary and root controlled.
        for parent in reversed(path.parents):
            if parent == self.root or self.root in parent.parents:
                if parent == self.path('/tmp'):
                    # The original out-of-band signed verifier creates a root
                    # 0700 TemporaryDirectory beneath the ordinary sticky /tmp.
                    # Permit only that anchor, not arbitrary writable parents.
                    info = parent.lstat()
                    relative = path.relative_to(parent)
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o1777 or len(relative.parts) < 2:
                        raise ValueError('unsafe signed-upgrade temporary parent')
                    self.directory(parent/relative.parts[0], private=True)
                    continue
                self.directory(parent)

    def file(self, path, owner=0, mode=None, limit=2*1024*1024):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != owner or before.st_mode & 0o022 or (mode is not None and stat.S_IMODE(before.st_mode) != mode) or before.st_size > limit:
                raise ValueError('untrusted upgrade file')
            data = b''
            while len(data) <= limit:
                block = os.read(descriptor, min(65536, limit+1-len(data)))
                if not block:
                    break
                data += block
            after = os.fstat(descriptor)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if len(data) != before.st_size or identity(before) != identity(after):
                raise ValueError('upgrade file changed while reading')
            return data, before
        finally:
            os.close(descriptor)

    def payload_size(self):
        paths = [self.release]+list(self.release.rglob('*'))
        if len(paths) > 10000:
            raise ValueError('upgrade payload exceeds tree-check budget')
        size = 0
        for path in paths:
            info = path.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('upgrade payload is not exclusively root controlled')
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('linked or special upgrade payload')
            size += info.st_size
        return size

    def atomic(self, target, data, mode, uid=0, gid=0):
        descriptor, name = tempfile.mkstemp(prefix='.program-upgrade-'+target.name+'-', dir=target.parent)
        temporary = pathlib.Path(name)
        try:
            os.fchmod(descriptor, mode)
            os.fchown(descriptor, uid, gid)
            with os.fdopen(descriptor, 'wb', closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, target)
        self.sync_directory(target.parent)

    def sync_directory(self, path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def exists(self, path):
        return path.exists() or path.is_symlink()

    def state(self, unit):
        values = self.run_command('/usr/bin/systemctl', 'show', unit, '--property=LoadState,ActiveState,SubState,UnitFileState').splitlines()
        result = dict(line.split('=', 1) for line in values)
        if set(result) != {'LoadState', 'ActiveState', 'SubState', 'UnitFileState'} or result['LoadState'] != 'loaded' or result['ActiveState'] not in ('active', 'inactive') or result['UnitFileState'] not in ('enabled', 'disabled', 'static', 'indirect', 'enabled-runtime'):
            raise ValueError('service has a masked, failed, transitional or unsupported state')
        return result

    @contextlib.contextmanager
    def connect(self):
        # SQLite must never be the first process to follow an unsafe database
        # or WAL/SHM link. Contents are read by SQLite, not loaded into memory.
        for path in (self.database, self.database.with_name(self.database.name+'-wal'), self.database.with_name(self.database.name+'-shm')):
            if self.exists(path):
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.db_owner or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError('unsafe database or journal identity')
        connection = sqlite3.connect(self.database.as_uri()+'?mode=ro', uri=True, timeout=3)
        connection.execute('PRAGMA query_only=ON')
        deadline = time.monotonic()+10
        connection.set_progress_handler(lambda: int(time.monotonic()>deadline), 1000)
        try:
            yield connection
        finally:
            connection.close()

    def queue_check(self):
        with self.connect() as connection:
            if connection.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise ValueError('database integrity check failed')
            for table in QUEUES:
                if connection.execute(f"SELECT count(*) FROM {table} WHERE state IN ('queued','running')").fetchone() != (0,):
                    raise ValueError('wait for active panel, runtime, database or certificate jobs before upgrading')
        # Execute only the already verified root-controlled candidate. This
        # fixed-path reader starts no Service or worker and edits no records.
        # Repeated at preflight, under the leases, after strict writer stop,
        # after candidate readiness and before any database rollback.
        self.run_command(str(self.release/'bin/panel-executor'), '--check-program-upgrade-queues', timeout=10)

    def start_guard(self, install=False):
        location = pathlib.Path(__file__).with_name('start-guard-install.py')
        spec = importlib.util.spec_from_file_location('panel_fixed_start_guard', location)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        if install:
            guard.install(self)
            records = []
            for path, data, mode in guard.inventory(self):
                info = path.lstat()
                records.append({'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'mode':mode,'device':info.st_dev,'inode':info.st_ino})
            self.atomic(self.backup/'startup-interlock.json', (json.dumps({'format':1,'retained_on_rollback':True,'files':records}, sort_keys=True)+'\n').encode(), 0o600)
        else:
            guard.inventory(self)

    def preflight(self):
        self.parents(self.release)
        self.directory(self.release)
        payload_size = self.payload_size()
        self.file(self.release/'verify-release.sh', mode=0o755, limit=65536)
        self.run_command(str(self.release/'verify-release.sh'), str(self.release))
        fields = dict(line.split('=', 1) for line in self.file(self.release/'RELEASE')[0].decode('ascii').splitlines())
        if set(fields) != {'PANEL_FORMAT', 'PANEL_VERSION', 'PANEL_OS', 'PANEL_ARCH'} or fields['PANEL_FORMAT'] != '1' or fields['PANEL_OS'] != 'linux' or not VERSION.fullmatch(fields['PANEL_VERSION']) or fields['PANEL_ARCH'] not in ('amd64', 'arm64'):
            raise ValueError('invalid upgrade metadata')
        self.version = fields['PANEL_VERSION']
        if fields['PANEL_ARCH'] != self.run_command('/usr/bin/dpkg', '--print-architecture'):
            raise ValueError('upgrade architecture mismatch')
        self.current = self.path('/opt/panel/current')
        self.marker = self.path('/etc/panel-release')
        self.releases = self.path('/opt/panel/releases')
        self.database = self.path('/var/lib/panel/panel.db')
        for directory in (self.releases, self.marker.parent, self.path('/etc/systemd/system'), self.path('/var/backups/panel/system'), self.path('/var/lib/panel-executor')):
            self.parents(directory)
            self.directory(directory, private=directory == self.path('/var/backups/panel/system'))
        current_info = self.current.lstat()
        if not stat.S_ISLNK(current_info.st_mode) or current_info.st_uid != 0:
            raise ValueError('ordinary upgrade requires an owned production release pointer')
        self.previous = os.readlink(self.current)
        previous_path = pathlib.Path(self.previous)
        if previous_path.parent != self.releases or not VERSION.fullmatch(previous_path.name):
            raise ValueError('production release pointer is outside retained releases')
        self.directory(previous_path)
        self.run_command(str(self.release/'verify-release.sh'), str(previous_path))
        self.marker_bytes, self.marker_info = self.file(self.marker, mode=0o644, limit=256)
        expected_marker = 'version='+previous_path.name+'\narch='+fields['PANEL_ARCH']+'\n'
        if self.marker_bytes.decode('ascii') != expected_marker:
            raise ValueError('production marker and current release disagree')
        self.destination = self.releases/self.version
        for path in (self.destination, self.destination.with_name(self.version+'.tmp'), self.current.with_name('current.new'), self.marker.with_name(self.marker.name+'.upgrade-new'), self.releases/'.program-upgrade.pending'):
            if self.exists(path):
                raise ValueError('retained upgrade target or interrupted transaction exists; inspect it before retrying')
        database_info = self.database.lstat()
        self.db_owner, self.db_group = database_info.st_uid, database_info.st_gid
        if str(self.db_owner) != self.run_command('/usr/bin/id', '-u', 'panel') or str(self.db_group) != self.run_command('/usr/bin/id', '-g', 'panel'):
            raise ValueError('database does not belong to the fixed panel identity')
        self.parents(self.database.parent)
        self.directory(self.database.parent, owner=self.db_owner)
        if not stat.S_ISREG(database_info.st_mode) or database_info.st_nlink != 1 or stat.S_IMODE(database_info.st_mode) != 0o600 or self.db_owner == 0:
            raise ValueError('upgrade requires a private panel-owned ordinary database')
        if database_info.st_size > 16*1024*1024*1024:
            raise ValueError('panel database exceeds the bounded upgrade backup budget')
        for directory, required in ((self.releases, payload_size), (self.path('/var/backups/panel/system'), database_info.st_size*2), (self.database.parent, database_info.st_size)):
            if shutil.disk_usage(directory).free < required+32*1024*1024:
                raise ValueError('insufficient free space for candidate, private backup and rollback')
        self.queue_check()
        self.backup_path = self.path('/var/backups/panel/system')/('production-'+self.version)
        if self.exists(self.backup_path):
            raise ValueError('retained production backup exists; select a new release')
        self.units = sorted((self.release/'systemd').iterdir())
        if not self.units or len(self.units) > 64:
            raise ValueError('upgrade unit inventory invalid')
        for source in self.units:
            if not UNIT.fullmatch(source.name):
                raise ValueError('unrecognized production unit')
            self.file(source, mode=0o644, limit=65536)
            target = self.path('/etc/systemd/system')/source.name
            if self.exists(target):
                self.original_units[source.name] = self.file(target, mode=0o644, limit=65536)
            else:
                self.original_units[source.name] = None
            if self.exists(target.with_name(target.name+'.upgrade-new')):
                raise ValueError('retained unit stage exists')
        for unit in PROGRAMS+(TIMER, 'panel-mysql-overwrite-recovery.service', 'nginx.service'):
            self.states[unit] = self.state(unit)
        self.nginx_pid = self.run_command('/usr/bin/systemctl', 'show', 'nginx.service', '--property=MainPID', '--value')
        if not self.nginx_pid.isascii() or not self.nginx_pid.isdigit():
            raise ValueError('unverifiable gateway process identity')
        if any(self.states[unit]['ActiveState'] != 'active' for unit in PROGRAMS):
            raise ValueError('ordinary upgrade requires all four program services active; stopped programs are not automatically started')
        if self.states['panel-mysql-overwrite-recovery.service']['ActiveState'] != 'inactive':
            raise ValueError('database replacement recovery is active; wait before upgrading')
        if self.run_command('/usr/bin/systemctl', 'show', 'panel.service', '--property=User', '--value') != 'panel':
            raise ValueError('unexpected production panel owner')
        self.run_command('/usr/sbin/nginx', '-t')
        self.start_guard()

    def lock(self, path, create=False):
        self.parents(path)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        if create and not self.exists(path):
            descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            os.fchmod(descriptor, 0o600)
        else:
            descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            allowed_modes = (0o600, 0o644) if create else (0o600,)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or stat.S_IMODE(info.st_mode) not in allowed_modes:
                raise ValueError('unsafe production upgrade lock')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Earlier installers created the trusted release lock with 0644.
            # Upgrade that exact locked descriptor, never truncate or follow it.
            if create:
                os.fchmod(descriptor, 0o600)
            self.locks.append(descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def journal(self, phase):
        record = {'format': 1, 'version': self.version, 'previous': self.previous, 'phase': phase, 'services': self.states}
        self.atomic(self.backup/'transaction.json', (json.dumps(record, sort_keys=True)+'\n').encode(), 0o600)

    def create_pending(self):
        self.pending = self.releases/'.program-upgrade.pending'
        self.pending_bytes = ('version='+self.version+'\n').encode('ascii')
        descriptor = os.open(self.pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.fchmod(descriptor, 0o644)
            os.write(descriptor, self.pending_bytes)
            os.fsync(descriptor)
            self.pending_identity = os.fstat(descriptor)
            self.pending_created = True
        finally:
            os.close(descriptor)
        self.sync_directory(self.releases)

    def remove_pending(self):
        if not self.pending_created:
            return
        raw, info = self.file(self.pending, mode=0o644, limit=2048)
        if raw != self.pending_bytes or (info.st_dev, info.st_ino) != (self.pending_identity.st_dev, self.pending_identity.st_ino):
            raise ValueError('upgrade marker identity changed; preserve it for inspection')
        self.pending.unlink()
        self.sync_directory(self.releases)
        self.pending_created = False

    def stop_writers(self):
        self.run_command('/usr/bin/systemctl', 'stop', *reversed(PROGRAMS))
        stopped = {unit:self.stopped_program(unit) for unit in PROGRAMS}
        self.no_program_jobs()
        failed = [unit for unit in PROGRAMS if stopped[unit]['ActiveState'] == 'failed']
        if failed:
            # systemctl stop can leave a failed unit even with no remaining
            # process or cgroup (for example a killed ExecStartPre). Never
            # confuse that with running writers or relax ordinary preflight.
            # Preserve failure evidence before clearing only our fixed units.
            if self.backup is None or self.failed_stop_snapshots >= 8:
                raise ValueError('failed stop lacks bounded private transaction evidence')
            self.parents(self.backup)
            self.directory(self.backup, private=True)
            self.failed_stop_snapshots += 1
            target = self.backup/('stopped-failed-programs-'+str(self.failed_stop_snapshots)+'.json')
            if self.exists(target):
                raise ValueError('retained failed stop evidence must not be replaced')
            self.atomic(target, (json.dumps({'format':1,'services':stopped},sort_keys=True)+'\n').encode(), 0o600)
            if any(self.stopped_program(unit) != stopped[unit] for unit in PROGRAMS):
                raise RuntimeError('stopped writer evidence changed before failed state normalization')
            self.no_program_jobs()
            self.run_command('/usr/bin/systemctl', 'reset-failed', *failed)
        for unit in PROGRAMS:
            if self.stopped_program(unit)['ActiveState'] != 'inactive':
                raise RuntimeError('program writer did not stop; database must not be replaced')
        self.no_program_jobs()

    def stopped_program(self, unit):
        if unit not in PROGRAMS:
            raise ValueError('stopped writer check outside fixed program scope')
        raw = self.run_command('/usr/bin/systemctl', 'show', unit, '--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,ControlPID,ControlGroup,Result')
        names = {'LoadState','ActiveState','SubState','UnitFileState','MainPID','ControlPID','ControlGroup','Result'}
        if len(raw) > 16384:
            raise ValueError('stopped writer evidence exceeds budget')
        record = {}
        for line in raw.splitlines():
            fields = line.split('=', 1)
            if len(fields) != 2 or fields[0] not in names or fields[0] in record:
                raise ValueError('unknown or duplicate stopped writer property')
            record[fields[0]] = fields[1]
        if set(record) != names or record['LoadState'] != 'loaded' or record['UnitFileState'] not in ('enabled','disabled','static','indirect','enabled-runtime'):
            raise ValueError('unsafe stopped writer unit identity')
        if (record['ActiveState'],record['SubState']) not in (('inactive','dead'),('failed','failed')) or record['MainPID'] != '0' or record['ControlPID'] != '0' or record['ControlGroup'] != '':
            raise RuntimeError('program writer has processes, cgroup or a transitional state; database must not be replaced')
        if record['Result'] not in ('success','exit-code','signal','core-dump','timeout','watchdog','oom-kill','start-limit-hit','resources','protocol','exec-condition'):
            raise ValueError('unsupported stopped writer result')
        return record

    def no_program_jobs(self):
        raw = self.run_command('/usr/bin/systemctl', 'list-jobs', '--no-legend', '--no-pager')
        lines = raw.splitlines()
        if len(raw) > 1024*1024 or len(lines) > 4096:
            raise ValueError('systemd job inventory exceeds complete budget')
        for line in lines:
            fields = line.split()
            if len(fields) != 4 or not fields[0].isascii() or not fields[0].isdigit():
                raise ValueError('unverifiable systemd job inventory')
            if fields[1] in PROGRAMS+(TIMER,'panel-mysql-overwrite-recovery.service'):
                raise RuntimeError('program or database recovery job remains scheduled')

    def release_runtime(self):
        if len(self.locks) == 2:
            os.close(self.locks.pop())
        elif len(self.locks) != 1:
            raise ValueError('program start lacks exact release/runtime lease state')

    def start_previous_state(self):
        self.release_runtime()
        self.authorize_startup()
        self.run_command('/usr/bin/systemctl', 'start', *PROGRAMS)
        if self.states[TIMER]['ActiveState'] == 'active':
            self.run_command('/usr/bin/systemctl', 'start', TIMER)

    def startup_program_directory(self):
        target = pathlib.Path(os.readlink(self.current))
        if target.parent != self.releases or not VERSION.fullmatch(target.name):
            raise ValueError('startup program reference outside retained releases')
        self.directory(target)
        return target/'bin'

    def authorize_startup(self):
        if not self.pending_created or not self.locks:
            raise ValueError('program start lacks owned transaction marker or release lease')
        raw, info = self.file(self.pending, mode=0o644, limit=2048)
        if raw != self.pending_bytes or (info.st_dev, info.st_ino) != (self.pending_identity.st_dev, self.pending_identity.st_ino):
            raise ValueError('startup marker changed outside this transaction')
        lease = os.fstat(self.locks[0])
        if lease.st_uid != 0 or stat.S_IMODE(lease.st_mode) != 0o600 or lease.st_nlink != 1 or not stat.S_ISREG(lease.st_mode):
            raise ValueError('startup release lease identity invalid')
        process = pathlib.Path('/proc/self/stat').read_text()
        suffix = process[process.rindex(') ')+2:].split()
        ticks = int(suffix[19])
        boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if ticks <= 0 or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot):
            raise ValueError('startup owner boot identity unavailable')
        programs = self.startup_program_directory()
        digests = {name:hashlib.sha256(self.file(programs/name, mode=0o755, limit=256*1024*1024)[0]).hexdigest() for name in ('panel', 'panel-executor')}
        record = {'format':2, 'version':self.version, 'pid':os.getpid(), 'start_ticks':ticks, 'boot_id':boot, 'lock_device':lease.st_dev, 'lock_inode':lease.st_ino, 'phase':'program-start', 'panel_sha256':digests['panel'], 'executor_sha256':digests['panel-executor']}
        self.pending_bytes = (json.dumps(record, sort_keys=True)+'\n').encode('ascii')
        self.atomic(self.pending, self.pending_bytes, 0o644)
        self.pending_identity = self.pending.lstat()

    def switch(self, previous):
        temporary = self.current.with_name('current.new')
        os.symlink(previous, temporary)
        os.replace(temporary, self.current)
        self.sync_directory(self.current.parent)

    def restore_database(self):
        source = os.open(self.backup/'panel.db', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        descriptor = None
        try:
            before = os.fstat(source)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 16*1024*1024*1024:
                raise ValueError('unsafe or oversized private database backup')
            descriptor, name = tempfile.mkstemp(prefix='.program-upgrade-panel.db-', dir=self.database.parent)
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, self.db_owner, self.db_group)
            with os.fdopen(descriptor, 'wb', closefd=False) as destination:
                while True:
                    block = os.read(source, 1024*1024)
                    if not block:
                        break
                    destination.write(block)
                destination.flush()
                os.fsync(descriptor)
            after = os.fstat(source)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('backup changed during bounded streaming restore')
            os.replace(name, self.database)
            self.sync_directory(self.database.parent)
        finally:
            os.close(source)
            if descriptor is not None:
                os.close(descriptor)

    def run(self):
        self.preflight()
        self.lock(self.releases/'.release.lock', create=True)
        self.lock(self.path('/var/lib/panel-executor/runtime-lifecycle.lock'))
        # Recheck after locks. A completed preflight is not a mutation lease.
        self.preflight()
        self.backup = self.backup_path
        self.backup.mkdir(mode=0o700)
        (self.backup/'units').mkdir(mode=0o700)
        for name, value in self.original_units.items():
            if value is not None:
                self.atomic(self.backup/'units'/name, value[0], 0o600)
        self.atomic(self.backup/'panel-release', self.marker_bytes, 0o600)
        self.journal('prepared')
        # Independent immutable interlock remains installed on rollback. It
        # protects the original retained binaries before the pending marker
        # or the first code/unit mutation exists, including cold boot.
        self.start_guard(install=True)
        stage = self.destination.with_name(self.version+'.tmp')
        shutil.copytree(self.release, stage)
        self.run_command(str(stage/'verify-release.sh'), str(stage))
        self.create_pending()
        self.stopping = True
        if self.states[TIMER]['ActiveState'] == 'active':
            self.run_command('/usr/bin/systemctl', 'stop', TIMER)
        self.stop_writers()
        self.queue_check()
        self.journal('writers-stopped')
        with self.connect() as source, contextlib.closing(sqlite3.connect(self.backup/'panel.db')) as destination:
            source.backup(destination)
        os.chmod(self.backup/'panel.db', 0o600)
        descriptor = os.open(self.backup/'panel.db', os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.sync_directory(self.backup)
        self.journal('database-backed-up')
        os.rename(stage, self.destination)
        self.sync_directory(self.releases)
        # Set before the first pointer/unit mutation, including partial errors.
        self.changed = True
        self.switch(str(self.destination))
        self.atomic(self.marker, ('version='+self.version+'\narch='+self.run_command('/usr/bin/dpkg', '--print-architecture')+'\n').encode(), 0o644)
        for source in self.units:
            data = self.file(source, mode=0o644, limit=65536)[0]
            data = data.replace(b'/opt/panel/bin/', b'/opt/panel/current/bin/').replace(b'/opt/panel/web', b'/opt/panel/current/web').replace(b'development ', b'')
            target = self.path('/etc/systemd/system')/source.name
            original = self.original_units[source.name]
            current = self.file(target, mode=0o644, limit=65536) if self.exists(target) else None
            identity = lambda value: None if value is None else (value[0], value[1].st_dev, value[1].st_ino, value[1].st_mtime_ns, value[1].st_ctime_ns)
            if identity(current) != identity(original):
                raise ValueError('original unit changed during upgrade; refuse to overwrite it')
            self.replaced_units[source.name] = data
            self.atomic(target, data, 0o644)
        self.journal('program-swapped')
        self.run_command('/usr/bin/systemctl', 'daemon-reload')
        # Release the runtime lock before executor readiness requests, which
        # take shared runtime leases. Release serialization remains held.
        self.release_runtime()
        self.start_previous_state()
        for attempt in range(30):
            try:
                self.run_command('/usr/bin/curl', '-fsS', '--max-time', '2', 'http://127.0.0.1:19100/api/ready', timeout=3)
                break
            except (RuntimeError, subprocess.TimeoutExpired):
                if attempt == 29:
                    raise
                time.sleep(1)
        self.queue_check()
        for unit in PROGRAMS+(TIMER, 'nginx.service'):
            state = self.state(unit)
            if state['ActiveState'] != self.states[unit]['ActiveState'] or state['UnitFileState'] != self.states[unit]['UnitFileState']:
                raise RuntimeError('original program, timer or gateway state was not preserved')
        self.run_command('/usr/sbin/nginx', '-t')
        if self.run_command('/usr/bin/systemctl', 'show', 'nginx.service', '--property=MainPID', '--value') != self.nginx_pid:
            raise RuntimeError('website gateway master changed during the program upgrade')
        self.journal('committed')
        self.committed = True
        self.remove_pending()
        print('panel '+self.version+' upgraded; private rollback evidence: '+str(self.backup))

    def rollback(self):
        if self.committed:
            return
        if not self.stopping:
            if self.pending_created:
                self.journal('refused-before-services-stopped')
                self.remove_pending()
            return
        if not self.changed:
            self.start_previous_state()
            self.journal('refused-before-program-change')
            self.remove_pending()
            return
        if self.states[TIMER]['ActiveState'] == 'active':
            self.run_command('/usr/bin/systemctl', 'stop', TIMER)
        self.stop_writers()
        if len(self.locks) == 1:
            self.lock(self.path('/var/lib/panel-executor/runtime-lifecycle.lock'))
        elif len(self.locks) != 2:
            raise ValueError('rollback lacks exact release/runtime lease state')
        if self.state('panel-mysql-overwrite-recovery.service')['ActiveState'] != 'inactive':
            raise RuntimeError('database replacement recovery is active; rollback refused')
        # Never erase a newly accepted job during the candidate health window.
        # Such a transaction needs deliberate recovery, with evidence retained.
        self.queue_check()
        with self.connect() as failed, contextlib.closing(sqlite3.connect(self.backup/'failed-panel.db')) as evidence:
            failed.backup(evidence)
        os.chmod(self.backup/'failed-panel.db', 0o600)
        with contextlib.closing(sqlite3.connect(self.backup/'panel.db')) as old, self.connect() as current:
            for table in QUEUES:
                if old.execute(f'SELECT * FROM {table} ORDER BY id').fetchall() != current.execute(f'SELECT * FROM {table} ORDER BY id').fetchall():
                    raise RuntimeError('candidate accepted job changes; automatic database rollback refused')
        for name, candidate_bytes in self.replaced_units.items():
            value = self.original_units[name]
            target = self.path('/etc/systemd/system')/name
            current = self.file(target, mode=0o644, limit=65536)[0] if self.exists(target) else None
            if current not in (candidate_bytes, value[0] if value is not None else None):
                raise ValueError('unit changed outside this transaction; rollback refused')
            if value is None:
                if self.exists(target):
                    self.file(target, mode=0o644, limit=65536)
                    target.unlink()
            else:
                self.atomic(target, value[0], stat.S_IMODE(value[1].st_mode), value[1].st_uid, value[1].st_gid)
        self.switch(self.previous)
        self.atomic(self.marker, self.marker_bytes, stat.S_IMODE(self.marker_info.st_mode), self.marker_info.st_uid, self.marker_info.st_gid)
        for suffix in ('-wal', '-shm'):
            sidecar = self.database.with_name(self.database.name+suffix)
            if self.exists(sidecar):
                info = sidecar.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.db_owner or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError('unsafe stopped database journal; rollback refused')
                sidecar.unlink()
        self.restore_database()
        self.run_command('/usr/bin/systemctl', 'daemon-reload')
        self.start_previous_state()
        self.journal('rolled-back')
        for unit in PROGRAMS+(TIMER, 'nginx.service'):
            state = self.state(unit)
            if state['ActiveState'] != self.states[unit]['ActiveState'] or state['UnitFileState'] != self.states[unit]['UnitFileState']:
                raise RuntimeError('rollback service state could not be verified')
        self.remove_pending()

    def close(self):
        for descriptor in self.locks:
            os.close(descriptor)
        self.locks.clear()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'run'))
    parser.add_argument('release', type=pathlib.Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, 'production upgrade must run as root\n')
    transaction = Upgrade(args.release)
    def interrupted(signum, frame):
        raise RuntimeError('production upgrade interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if args.action == 'check':
            transaction.preflight()
            print('production upgrade preflight passed without changes')
        else:
            transaction.run()
    except BaseException as error:
        try:
            transaction.rollback()
        except BaseException:
            print('automatic rollback incomplete; service and data recovery cannot be confirmed; private transaction evidence and maintenance marker are retained for inspection', file=sys.stderr)
        parser.exit(1, 'production upgrade failed: '+str(error)+'\n')
    finally:
        transaction.close()


if __name__ == '__main__':
    main()
