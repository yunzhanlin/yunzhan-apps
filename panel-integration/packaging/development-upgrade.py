#!/usr/bin/env python3
"""Strict original-layout program transaction; never provision host resources.

The CLI supports only the real / host. Isolated roots and command runners are
test-only constructor arguments. Interrupted evidence is retained, not replayed.
"""
import argparse
import contextlib
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
import sys
import time

SPEC = importlib.util.spec_from_file_location('panel_program_upgrade', pathlib.Path(__file__).with_name('upgrade-release.py'))
production = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(production)
PROGRAMS, TIMER, QUEUES = production.PROGRAMS, production.TIMER, production.QUEUES


class DevelopmentUpgrade(production.Upgrade):
    def __init__(self, release, root=pathlib.Path('/'), runner=production.command):
        super().__init__(release, root, runner)
        self.old_trees = {}
        self.new_trees = {}
        self.tree_intents = []
        self.marker_changed = False
        self.runtime_locked = False

    def tree(self, base, identities=False):
        """Complete, bounded root-owned code inventory; no links or mounts."""
        self.parents(base)
        origin = self.directory(base)
        mounts = set()
        if sys.platform.startswith('linux'):
            with open('/proc/self/mountinfo', 'rb') as source:
                raw = source.read(4*1024*1024+1)
            if len(raw) > 4*1024*1024:
                raise ValueError('development mount inventory exceeds budget')
            for line in raw.decode('utf-8', 'strict').splitlines():
                fields = line.split(' ')
                if len(fields) < 10 or '-' not in fields:
                    raise ValueError('unverifiable development mount inventory')
                mounts.add(pathlib.Path(re.sub(r'\\([0-7]{3})', lambda m:chr(int(m[1], 8)), fields[4])))
        if any(point == base or base in point.parents for point in mounts):
            raise ValueError('mounted development tree; refuse traversal')
        values, count, total = {}, 0, 0
        pending = [base]
        while pending:
            path = pending.pop()
            info = path.lstat()
            count += 1
            if count > 10000 or info.st_dev != origin.st_dev or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('untrusted or excessive development tree')
            relative = str(path.relative_to(base))
            identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if stat.S_ISDIR(info.st_mode):
                with os.scandir(path) as entries:
                    for entry in entries:
                        pending.append(path/entry.name)
                        if len(pending)+count > 10000:
                            raise ValueError('development tree exceeds complete inventory budget')
                values[relative] = ('directory', stat.S_IMODE(info.st_mode), identity if identities else None)
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 256*1024*1024:
                raise ValueError('linked, special or oversized development code')
            total += info.st_size
            if total > 1024*1024*1024:
                raise ValueError('development tree exceeds byte budget')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(descriptor)
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                    raise ValueError('development code changed before read')
                digest, size = hashlib.sha256(), 0
                while True:
                    block = os.read(descriptor, 1024*1024)
                    if not block:
                        break
                    digest.update(block)
                    size += len(block)
                    if size > before.st_size:
                        raise ValueError('development code grew during read')
                after = os.fstat(descriptor)
                if size != info.st_size or (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != identity:
                    raise ValueError('development code changed during read')
                values[relative] = ('file', stat.S_IMODE(info.st_mode), size, digest.hexdigest(), identity if identities else None)
            finally:
                os.close(descriptor)
        return values

    def preflight(self):
        self.parents(self.release)
        self.directory(self.release)
        size = self.payload_size()
        self.file(self.release/'verify-release.sh', mode=0o755, limit=65536)
        self.run_command(str(self.release/'verify-release.sh'), str(self.release))
        fields = dict(line.split('=', 1) for line in self.file(self.release/'RELEASE', limit=256)[0].decode('ascii').splitlines())
        if set(fields) != {'PANEL_FORMAT', 'PANEL_VERSION', 'PANEL_OS', 'PANEL_ARCH'} or fields['PANEL_FORMAT'] != '1' or fields['PANEL_OS'] != 'linux' or not production.VERSION.fullmatch(fields['PANEL_VERSION']) or fields['PANEL_ARCH'] not in ('amd64', 'arm64'):
            raise ValueError('invalid development upgrade metadata')
        self.version = fields['PANEL_VERSION']
        if fields['PANEL_ARCH'] != self.run_command('/usr/bin/dpkg', '--print-architecture'):
            raise ValueError('development upgrade architecture mismatch')
        self.base = self.path('/opt/panel')
        self.marker = self.base/'DEVELOPMENT_RELEASE'
        self.pending = self.base/'.development-upgrade.pending'
        self.database = self.path('/var/lib/panel/panel.db')
        self.releases = self.base  # Marker operations use this fixed parent only.
        for directory in (self.base, self.path('/etc/systemd/system'), self.path('/var/backups/panel/system'), self.path('/var/lib/panel-executor')):
            self.parents(directory)
            self.directory(directory, private=directory == self.path('/var/backups/panel/system'))
        for path in (self.path('/etc/panel-release'), self.base/'current', self.base/'bin.new', self.base/'web.new', self.base/'bin/panel.new', self.base/'bin/panel-executor.new', self.pending, self.base/'releases/.program-upgrade.pending'):
            if self.exists(path):
                raise ValueError('production layout or retained development transaction exists')
        self.old_trees = {name:self.tree(self.base/name) for name in ('bin', 'web')}
        self.original_tree_identities = {name:self.tree(self.base/name, identities=True) for name in ('bin', 'web')}
        for name in ('panel', 'panel-executor'):
            self.file(self.base/'bin'/name, mode=0o755, limit=256*1024*1024)
            self.file(self.release/'bin'/name, mode=0o755, limit=256*1024*1024)
        self.marker_bytes = None
        self.marker_info = None
        if self.exists(self.marker):
            self.marker_bytes, self.marker_info = self.file(self.marker, mode=0o644, limit=256)
        database_info = self.database.lstat()
        self.db_owner, self.db_group = database_info.st_uid, database_info.st_gid
        if self.db_owner == 0 or str(self.db_owner) != self.run_command('/usr/bin/id', '-u', 'panel') or str(self.db_group) != self.run_command('/usr/bin/id', '-g', 'panel'):
            raise ValueError('database does not belong to the fixed panel identity')
        self.parents(self.database.parent)
        self.directory(self.database.parent, owner=self.db_owner)
        if not stat.S_ISREG(database_info.st_mode) or database_info.st_nlink != 1 or stat.S_IMODE(database_info.st_mode) != 0o600 or database_info.st_size > 16*1024*1024*1024:
            raise ValueError('unsafe or oversized development database')
        self.queue_check()
        self.backup_path = self.path('/var/backups/panel/system')/('development-'+self.version)
        if self.exists(self.backup_path):
            raise ValueError('retained development backup exists; select a new release')
        self.units = sorted((self.release/'systemd').iterdir())
        if not self.units or len(self.units) > 64:
            raise ValueError('invalid development unit inventory')
        self.original_units = {}
        for source in self.units:
            if not production.UNIT.fullmatch(source.name):
                raise ValueError('unrecognized development unit')
            self.file(source, mode=0o644, limit=65536)
            target = self.path('/etc/systemd/system')/source.name
            self.original_units[source.name] = self.file(target, mode=0o644, limit=65536) if self.exists(target) else None
        self.states = {unit:self.state(unit) for unit in PROGRAMS+(TIMER, 'panel-mysql-overwrite-recovery.service', 'nginx.service')}
        if any(self.states[unit]['ActiveState'] != 'active' for unit in PROGRAMS) or self.states['panel-mysql-overwrite-recovery.service']['ActiveState'] != 'inactive':
            raise ValueError('all program services must be active and database recovery idle')
        if self.run_command('/usr/bin/systemctl', 'show', 'panel.service', '--property=User', '--value') != 'panel':
            raise ValueError('unexpected development service owner')
        self.nginx_pid = self.run_command('/usr/bin/systemctl', 'show', 'nginx.service', '--property=MainPID', '--value')
        if not self.nginx_pid.isascii() or not self.nginx_pid.isdigit():
            raise ValueError('unverifiable gateway identity')
        self.run_command('/usr/sbin/nginx', '-t')
        for helper in ('waf-state-directory.py', 'native-build-directories.py'):
            self.file(self.release/helper, limit=128*1024)
            self.run_command('/usr/bin/python3', str(self.release/helper), 'check')
        self.run_command(str(self.release/'bin/panel-executor'), '--check-apache-body-cache-upgrade', timeout=10)
        code_size = sum(value[2] for tree in self.old_trees.values() for value in tree.values() if value[0] == 'file')
        for path, required in ((self.base, size+code_size), (self.backup_path.parent, code_size+database_info.st_size*2), (self.database.parent, database_info.st_size)):
            if shutil.disk_usage(path).free < required+32*1024*1024:
                raise ValueError('insufficient development stage, backup or rollback space')
        self.start_guard()

    def journal(self, phase):
        record = {'format':2, 'layout':'development', 'version':self.version, 'phase':phase, 'services':self.states, 'tree_intents':self.tree_intents, 'unit_intents':sorted(self.replaced_units), 'marker_intent':self.marker_changed}
        self.atomic(self.backup/'transaction.json', (json.dumps(record, sort_keys=True)+'\n').encode(), 0o600)

    def create_pending(self):
        self.pending_bytes = ('version='+self.version+'\n').encode('ascii')
        descriptor = os.open(self.pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.fchmod(descriptor, 0o644)
            if os.write(descriptor, self.pending_bytes) != len(self.pending_bytes):
                raise RuntimeError('incomplete development maintenance marker')
            os.fsync(descriptor)
            self.pending_identity = os.fstat(descriptor)
            self.pending_created = True
        finally:
            os.close(descriptor)
        self.sync_directory(self.base)

    def stop_timer(self):
        self.run_command('/usr/bin/systemctl', 'stop', TIMER)
        if self.state(TIMER)['ActiveState'] != 'inactive':
            raise RuntimeError('database timer did not stop')

    def verify_states(self):
        for unit in PROGRAMS+(TIMER, 'nginx.service'):
            current = self.state(unit)
            if current['ActiveState'] != self.states[unit]['ActiveState'] or current['UnitFileState'] != self.states[unit]['UnitFileState']:
                raise RuntimeError('original service activity or enablement changed')
        self.run_command('/usr/sbin/nginx', '-t')
        if self.run_command('/usr/bin/systemctl', 'show', 'nginx.service', '--property=MainPID', '--value') != self.nginx_pid:
            raise RuntimeError('website gateway process changed')

    def release_runtime(self):
        if self.runtime_locked:
            os.close(self.locks.pop())
            self.runtime_locked = False

    def startup_program_directory(self):
        return self.base/'bin'

    def run(self):
        self.preflight()
        self.lock(self.base/'.development-update.lock', create=True)
        self.lock(self.path('/var/lib/panel-executor/runtime-lifecycle.lock'))
        self.runtime_locked = True
        self.preflight()
        self.backup = self.backup_path
        self.backup.mkdir(mode=0o700)
        (self.backup/'units').mkdir(mode=0o700)
        for name, value in self.original_units.items():
            if value is not None:
                self.atomic(self.backup/'units'/name, value[0], 0o600)
        if self.marker_bytes is not None:
            self.atomic(self.backup/'DEVELOPMENT_RELEASE', self.marker_bytes, 0o600)
        for name in ('bin', 'web'):
            shutil.copytree(self.base/name, self.backup/name)
            if self.tree(self.backup/name) != self.old_trees[name]:
                raise ValueError('development backup differs from original code')
        self.journal('prepared')
        self.start_guard(install=True)
        shutil.copytree(self.base/'bin', self.base/'bin.new')
        for name in ('panel', 'panel-executor'):
            shutil.copyfile(self.release/'bin'/name, self.base/'bin.new'/name)
            (self.base/'bin.new'/name).chmod(0o755)
        shutil.copytree(self.release/'web', self.base/'web.new')
        self.new_trees = {name:self.tree(self.base/(name+'.new')) for name in ('bin', 'web')}
        self.create_pending()
        self.stopping = True
        self.stop_timer()
        self.stop_writers()
        self.queue_check()
        self.journal('writers-stopped')
        for name in ('bin', 'web'):
            if self.tree(self.base/name, identities=True) != self.original_tree_identities[name]:
                raise ValueError('original development code changed before switch')
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
        for name in ('bin', 'web'):
            if self.tree(self.base/(name+'.new')) != self.new_trees[name]:
                raise ValueError('development candidate changed before switch')
            self.tree_intents.append(name)
            self.changed = True
            self.journal('switching-'+name)
            os.rename(self.base/name, self.backup/('previous-'+name))
            self.sync_directory(self.base)
            self.sync_directory(self.backup)
            os.rename(self.base/(name+'.new'), self.base/name)
            self.sync_directory(self.base)
        self.candidate_marker = self.file(self.release/'RELEASE', limit=256)[0]
        self.marker_changed = True
        self.journal('switching-marker')
        current = self.file(self.marker, mode=0o644, limit=256)[0] if self.exists(self.marker) else None
        if current != self.marker_bytes:
            raise ValueError('development marker changed outside transaction')
        self.atomic(self.marker, self.candidate_marker, 0o644)
        for source in self.units:
            data = self.file(source, mode=0o644, limit=65536)[0]
            target = self.path('/etc/systemd/system')/source.name
            original = self.original_units[source.name]
            current = self.file(target, mode=0o644, limit=65536) if self.exists(target) else None
            identity = lambda value: None if value is None else (value[0], value[1].st_dev, value[1].st_ino, value[1].st_mtime_ns, value[1].st_ctime_ns)
            if identity(current) != identity(original):
                raise ValueError('original unit changed outside transaction')
            self.replaced_units[source.name] = data
            self.journal('switching-units')
            self.atomic(target, data, 0o644)
        self.journal('program-swapped')
        self.run_command('/usr/bin/systemctl', 'daemon-reload')
        self.release_runtime()
        self.start_previous_state()
        for attempt in range(30):
            try:
                self.run_command('/usr/bin/curl', '-fsS', '--max-time', '2', 'http://127.0.0.1:19100/api/ready', timeout=3)
                break
            except (RuntimeError, production.subprocess.TimeoutExpired):
                if attempt == 29:
                    raise
                time.sleep(1)
        self.queue_check()
        self.verify_states()
        self.journal('committed')
        self.committed = True
        self.remove_pending()
        print('development panel '+self.version+' upgraded; private rollback evidence: '+str(self.backup))

    def rollback(self):
        if self.committed or not self.stopping:
            return
        self.stop_timer()
        self.stop_writers()
        if not self.runtime_locked:
            self.lock(self.path('/var/lib/panel-executor/runtime-lifecycle.lock'))
            self.runtime_locked = True
        if not self.changed:
            self.release_runtime()
            self.start_previous_state()
            self.verify_states()
            self.journal('refused-before-program-change')
            self.remove_pending()
            return
        self.queue_check()
        with contextlib.closing(sqlite3.connect(self.backup/'panel.db')) as old, self.connect() as current:
            for table in QUEUES:
                if old.execute(f'SELECT * FROM {table} ORDER BY id').fetchall() != current.execute(f'SELECT * FROM {table} ORDER BY id').fetchall():
                    raise RuntimeError('candidate accepted job changes; database rollback refused')
        # Validate every target before the first recovery mutation.
        for name in self.tree_intents:
            previous = self.backup/('previous-'+name)
            installed = self.base/name
            if self.exists(previous):
                if self.tree(previous) != self.old_trees[name] or (self.exists(installed) and self.tree(installed) != self.new_trees[name]):
                    raise ValueError('development tree changed outside transaction; rollback refused')
            elif not self.exists(installed) or self.tree(installed) != self.old_trees[name]:
                raise ValueError('original development tree unavailable')
            if self.exists(self.backup/('failed-'+name)):
                raise ValueError('retained failed code exists; recovery cannot overwrite it')
        for name, candidate in self.replaced_units.items():
            target = self.path('/etc/systemd/system')/name
            original = self.original_units[name]
            value = self.file(target, mode=0o644, limit=65536)[0] if self.exists(target) else None
            if value not in (candidate, original[0] if original else None):
                raise ValueError('unit changed outside transaction; rollback refused')
        if self.marker_changed:
            value = self.file(self.marker, mode=0o644, limit=256)[0] if self.exists(self.marker) else None
            if value not in (self.candidate_marker, self.marker_bytes):
                raise ValueError('development marker changed outside transaction')
        if self.exists(self.backup/'failed-panel.db'):
            raise ValueError('failed database evidence already exists')
        with self.connect() as failed, contextlib.closing(sqlite3.connect(self.backup/'failed-panel.db')) as evidence:
            failed.backup(evidence)
        os.chmod(self.backup/'failed-panel.db', 0o600)
        for name in reversed(self.tree_intents):
            previous = self.backup/('previous-'+name)
            if self.exists(previous):
                if self.exists(self.base/name):
                    os.rename(self.base/name, self.backup/('failed-'+name))
                os.rename(previous, self.base/name)
                self.sync_directory(self.base)
                self.sync_directory(self.backup)
        for name in self.replaced_units:
            target = self.path('/etc/systemd/system')/name
            original = self.original_units[name]
            if original is not None:
                self.atomic(target, original[0], 0o644, original[1].st_uid, original[1].st_gid)
            elif self.exists(target):
                target.unlink()
                self.sync_directory(target.parent)
        if self.marker_changed:
            if self.marker_bytes is not None:
                self.atomic(self.marker, self.marker_bytes, 0o644)
            elif self.exists(self.marker):
                os.rename(self.marker, self.backup/'failed-development-release')
                self.sync_directory(self.base)
                self.sync_directory(self.backup)
        for suffix in ('-wal', '-shm'):
            sidecar = self.database.with_name(self.database.name+suffix)
            if self.exists(sidecar):
                info = sidecar.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.db_owner or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError('unsafe stopped database journal; rollback refused')
                sidecar.unlink()
        self.restore_database()
        self.run_command('/usr/bin/systemctl', 'daemon-reload')
        self.release_runtime()
        self.start_previous_state()
        self.verify_states()
        self.journal('rolled-back')
        self.remove_pending()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'run'))
    parser.add_argument('release', type=pathlib.Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, 'development upgrade must run as root\n')
    transaction = DevelopmentUpgrade(args.release)
    def interrupted(signum, frame):
        raise RuntimeError('development upgrade interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if args.action == 'check':
            transaction.preflight()
            print('development upgrade preflight passed without changes')
        else:
            transaction.run()
    except BaseException as error:
        try:
            transaction.rollback()
        except BaseException:
            print('automatic development rollback incomplete; private evidence and maintenance marker retained; recovery not confirmed', file=sys.stderr)
        parser.exit(1, 'development upgrade failed: '+str(error)+'\n')
    finally:
        transaction.close()


if __name__ == '__main__':
    main()
