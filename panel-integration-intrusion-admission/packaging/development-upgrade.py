#!/usr/bin/env python3
"""Strict original-layout program transaction; never provision host resources.

The CLI supports only the real / host. Isolated roots and command runners are
test-only constructor arguments. Recovery is explicit, never silently retried.
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
        self.new_tree_identities = {}
        self.tree_intents = []
        self.marker_changed = False
        self.runtime_locked = False
        self.layout = 'development'

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

    @staticmethod
    def stable_tree(values):
        # The outer directory's ctime changes when renamed. Every inode,
        # owner, mode, size, mtime, link count and digest remains mandatory.
        return {name:tuple(value[:-1])+(tuple(value[-1][:-1]),) for name,value in values.items()}

    def retain_tree_intent(self, name):
        if name not in ('bin','web'):
            raise ValueError('tree rename outside fixed development scope')
        target = self.backup/('tree-rename-'+name+'.json')
        if self.exists(target):
            raise ValueError('retained development tree intent must not be overwritten')
        record = {'format':1,'version':self.version,'name':name,
                  'original':self.original_tree_identities[name],'candidate':self.new_tree_identities[name]}
        raw = (json.dumps(record,sort_keys=True)+'\n').encode()
        if len(raw)>8*1024*1024:
            raise ValueError('development tree intent exceeds complete metadata budget')
        self.atomic(target,raw,0o600)
        if (self.tree(self.base/name,identities=True) != self.original_tree_identities[name]
                or self.tree(self.base/(name+'.new'),identities=True) != self.new_tree_identities[name]):
            raise ValueError('development tree inode changed after durable rename intent')

    @staticmethod
    def decode_tree_record(values):
        if not isinstance(values,dict):
            raise ValueError('invalid closed development recovery tree')
        inventory,decoded = {},{}
        for name,value in values.items():
            if not isinstance(value,list) or not value:
                raise ValueError('invalid development recovery tree entry')
            if value[0]=='directory' and len(value)==3:
                inventory[name] = {'kind':'directory','mode':value[1],'identity':value[2]}
            elif value[0]=='file' and len(value)==5:
                inventory[name] = {'kind':'file','mode':value[1],'size':value[2],'sha256':value[3],'identity':value[4]}
            else:
                raise ValueError('unknown development recovery tree entry')
            decoded[name] = tuple(value[:-1])+(tuple(value[-1]),)
        production.Upgrade.validate_inventory_record(inventory)
        return decoded

    def retain_development_stage(self):
        for name in ('bin','web'):
            base = self.base/(name+'.new')
            inventory = self.code_inventory(base)
            for relative,value in inventory.items():
                if value['kind']=='file':
                    descriptor = os.open(base/relative,os.O_RDONLY|os.O_NOFOLLOW)
                    try:
                        if self.file_snapshot(b'',os.fstat(descriptor))['identity']!=value['identity']:
                            raise ValueError('development stage changed before persistence')
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
            for relative,value in sorted(inventory.items(),key=lambda pair:len(pathlib.PurePath(pair[0]).parts),reverse=True):
                if value['kind']=='directory':
                    self.sync_directory(base if relative=='.' else base/relative)
            self.sync_directory(base.parent)
            if self.tree(base,identities=True)!=self.new_tree_identities[name]:
                raise ValueError('development stage changed during persistence')
        target = self.backup/'development-stage.json'
        if self.exists(target):
            raise ValueError('retained development stage receipt must not be overwritten')
        raw = (json.dumps({'format':1,'version':self.version,'trees':self.new_tree_identities},sort_keys=True)+'\n').encode()
        if len(raw)>8*1024*1024:
            raise ValueError('complete development stage receipt exceeds budget')
        self.atomic(target,raw,0o600)

    def recover_layout_plan(self, plan, arch):
        if self.exists(self.base/'current') or self.exists(self.path('/etc/panel-release')) or self.exists(self.base/'releases/.program-upgrade.pending'):
            raise ValueError('production layout cannot be reconstructed as development')
        original = plan['original_trees']
        if not isinstance(original,dict) or set(original)!={'bin','web'}:
            raise ValueError('development recovery original tree inventory is incomplete')
        self.original_tree_identities = {name:self.decode_tree_record(value) for name,value in original.items()}
        self.old_trees = {name:{relative:tuple(value[:-1])+(None,) for relative,value in tree.items()} for name,tree in self.original_tree_identities.items()}
        for name in ('bin','web'):
            if self.tree(self.backup/name)!=self.old_trees[name]:
                raise ValueError('private development code backup differs from complete original')
        marker = plan['original_marker']
        if marker is None:
            if self.exists(self.backup/'DEVELOPMENT_RELEASE'):
                raise ValueError('unexpected private original development marker')
            self.marker_bytes,self.marker_info = None,None
        else:
            self.valid_snapshot(marker)
            raw = self.file(self.backup/'DEVELOPMENT_RELEASE',mode=0o600,limit=256)[0]
            if hashlib.sha256(raw).hexdigest()!=marker['sha256']:
                raise ValueError('private development marker differs from recovery plan')
            self.marker_bytes,self.marker_info = raw,self.snapshot_info(marker)
        stage_path = self.backup/'development-stage.json'
        if self.exists(stage_path):
            stage = self.read_record(stage_path)
            if (set(stage)!={'format','version','trees'} or type(stage['format'])is not int or stage['format']!=1
                    or stage['version']!=self.version or not isinstance(stage['trees'],dict) or set(stage['trees'])!={'bin','web'}):
                raise ValueError('invalid complete development stage receipt')
            self.new_tree_identities = {name:self.decode_tree_record(value) for name,value in stage['trees'].items()}
            self.new_trees = {name:{relative:tuple(value[:-1])+(None,) for relative,value in tree.items()} for name,tree in self.new_tree_identities.items()}
        for name in ('bin','web'):
            proof = self.backup/('tree-rename-'+name+'.json')
            if self.exists(proof):
                record = self.read_record(proof)
                if (set(record)!={'format','version','name','original','candidate'} or type(record['format'])is not int or record['format']!=1
                        or record['version']!=self.version or record['name']!=name
                        or self.decode_tree_record(record['original'])!=self.original_tree_identities[name]
                        or name not in self.new_tree_identities or self.decode_tree_record(record['candidate'])!=self.new_tree_identities[name]):
                    raise ValueError('development rename intent lacks exact original/staged inode lineage')
                self.tree_intents.append(name)
        if self.tree_intents not in ([],['bin'],['bin','web']):
            raise ValueError('development tree intent order is not contiguous')
        self.validate_development_tree_lineage()

    def validate_restore_lineage(self):
        super().validate_restore_lineage()
        # Untouched stages are never recovery inputs or removal targets. A
        # changed bin can still be restored from its bound previous inode
        # while a foreign, unused web.new is preserved byte-for-byte. Every
        # live original and every moved candidate remains strictly bound.
        self.validate_development_tree_lineage(check_stages=False)

    def validate_development_tree_lineage(self, *, check_stages=True):
        for name in ('bin','web'):
            live,previous,new,failed = self.base/name,self.backup/('previous-'+name),self.base/(name+'.new'),self.backup/('failed-'+name)
            reverse = self.backup/('tree-restore-'+name+'.json')
            reversing = self.exists(reverse)
            if reversing:
                record = self.read_record(reverse)
                if (set(record)!={'format','version','name','original','candidate'} or type(record['format'])is not int or record['format']!=1
                        or record['version']!=self.version or record['name']!=name or name not in self.tree_intents
                        or self.decode_tree_record(record['original'])!=self.original_tree_identities[name]
                        or self.decode_tree_record(record['candidate'])!=self.new_tree_identities[name]):
                    raise ValueError('reverse development tree move lacks exact durable authority')
            if self.exists(failed) and not reversing:
                raise ValueError('failed development candidate lacks durable reverse intent')
            if name not in self.tree_intents:
                if self.exists(previous) or self.tree(live,identities=True)!=self.original_tree_identities[name]:
                    raise ValueError('untouched original development code inode changed')
                if check_stages and name in self.new_tree_identities and (not self.exists(new) or self.tree(new,identities=True)!=self.new_tree_identities[name]):
                    raise ValueError('untouched staged development code inode changed')
                continue
            if self.exists(previous):
                if self.stable_tree(self.tree(previous,identities=True))!=self.stable_tree(self.original_tree_identities[name]):
                    raise ValueError('retained previous development code inode changed')
                installed = self.exists(live)
                staged = self.exists(new)
                retained = self.exists(failed)
                if sum((installed,staged,retained))!=1:
                    raise ValueError('development candidate must exist at exactly one owned location')
                location = live if installed else (new if staged else failed)
                if self.stable_tree(self.tree(location,identities=True))!=self.stable_tree(self.new_tree_identities[name]):
                    raise ValueError('installed or staged development candidate inode changed')
            elif reversing:
                if (not self.exists(live) or self.stable_tree(self.tree(live,identities=True))!=self.stable_tree(self.original_tree_identities[name])
                        or self.exists(new)==self.exists(failed)):
                    raise ValueError('reversed development tree does not select owned original code')
                location = new if self.exists(new)else failed
                if self.stable_tree(self.tree(location,identities=True))!=self.stable_tree(self.new_tree_identities[name]):
                    raise ValueError('reversed failed development code inode changed')
            elif (not self.exists(live) or self.tree(live,identities=True)!=self.original_tree_identities[name]
                  or not self.exists(new) or self.tree(new,identities=True)!=self.new_tree_identities[name]):
                raise ValueError('development rename has no complete original and staged code')

    def retain_reverse_tree_intent(self, name):
        self.validate_development_tree_lineage(check_stages=False)
        target = self.backup/('tree-restore-'+name+'.json')
        if not self.exists(target):
            record = {'format':1,'version':self.version,'name':name,'original':self.original_tree_identities[name],
                      'candidate':self.new_tree_identities[name]}
            raw = (json.dumps(record,sort_keys=True)+'\n').encode()
            if len(raw)>8*1024*1024:
                raise ValueError('reverse development tree intent exceeds budget')
            self.atomic(target,raw,0o600)
        self.validate_development_tree_lineage(check_stages=False)

    def verify_recovery_original_code(self):
        for name in ('bin','web'):
            if self.stable_tree(self.tree(self.base/name,identities=True))!=self.stable_tree(self.original_tree_identities[name]):
                raise ValueError('restored development recovery does not select original code')
        current = self.file(self.marker,mode=0o644,limit=256)[0]if self.exists(self.marker)else None
        if current!=self.marker_bytes:
            raise ValueError('restored development recovery marker differs from original')

    def recovery_code_changed(self):
        self.marker_changed = bool(self.file_mutations.get(str(self.marker)))
        return bool(self.tree_intents) or self.marker_changed

    def recover_committed(self):
        for name in ('bin','web'):
            if self.stable_tree(self.tree(self.base/name,identities=True))!=self.stable_tree(self.new_tree_identities[name]):
                raise ValueError('committed development recovery no longer selects candidate code')
        if self.file(self.marker,mode=0o644,limit=256)[0]!=self.file(self.release/'RELEASE',limit=256)[0]:
            raise ValueError('committed development recovery marker changed')
        self.verify_recovery_candidate_units()
        self.defer_timer()
        self.stop_timer()
        self.verify_states()
        self.wait_readiness()
        self.remove_pending()
        self.restore_timer()
        self.journal('recovered-committed')

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
        self.original_database_inode = self.file_snapshot(b'',database_info)['identity'][:6]
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
        for path, required in ((self.base, size+code_size), (self.backup_path.parent, size+code_size+database_info.st_size*2), (self.database.parent, database_info.st_size)):
            if shutil.disk_usage(path).free < required+32*1024*1024:
                raise ValueError('insufficient development stage, backup or rollback space')
        self.start_guard()

    def journal(self, phase):
        record = {'format':2, 'layout':'development', 'version':self.version, 'phase':phase, 'services':self.states, 'tree_intents':self.tree_intents, 'unit_intents':sorted(self.replaced_units), 'marker_intent':self.marker_changed}
        self.atomic(self.backup/'transaction.json', (json.dumps(record, sort_keys=True)+'\n').encode(), 0o600)
        self.last_phase = phase

    def create_pending(self):
        super().create_pending()

    def stop_timer(self):
        self.run_command('/usr/bin/systemctl', 'stop', TIMER)
        if self.state(TIMER)['ActiveState'] != 'inactive':
            raise RuntimeError('database timer did not stop')

    def verify_states(self):
        self.verify_original_activity()
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
        self.sync_directory(self.backup.parent)
        (self.backup/'units').mkdir(mode=0o700)
        self.sync_directory(self.backup)
        for name, value in self.original_units.items():
            if value is not None:
                self.atomic(self.backup/'units'/name, value[0], 0o600)
        if self.marker_bytes is not None:
            self.atomic(self.backup/'DEVELOPMENT_RELEASE', self.marker_bytes, 0o600)
        for name in ('bin', 'web'):
            shutil.copytree(self.base/name, self.backup/name)
            if self.tree(self.backup/name) != self.old_trees[name]:
                raise ValueError('development backup differs from original code')
        self.retain_candidate_plan()
        self.defer_timer()
        self.journal('prepared')
        self.start_guard(install=True)
        shutil.copytree(self.base/'bin', self.base/'bin.new')
        for name in ('panel', 'panel-executor'):
            shutil.copyfile(self.release/'bin'/name, self.base/'bin.new'/name)
            (self.base/'bin.new'/name).chmod(0o755)
        shutil.copytree(self.release/'web', self.base/'web.new')
        self.new_trees = {name:self.tree(self.base/(name+'.new')) for name in ('bin', 'web')}
        self.new_tree_identities = {name:self.tree(self.base/(name+'.new'), identities=True) for name in ('bin', 'web')}
        self.retain_development_stage()
        self.stop_timer()
        self.queue_check()
        self.create_pending()
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
        self.retain_database_receipt()
        self.journal('database-backed-up')
        for name in ('bin', 'web'):
            if self.tree(self.base/(name+'.new'), identities=True) != self.new_tree_identities[name]:
                raise ValueError('development candidate changed before switch')
            self.retain_tree_intent(name)
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
        self.wait_readiness()
        self.queue_check()
        self.verify_states()
        self.journal('committed')
        self.committed = True
        self.remove_pending()
        self.restore_timer()
        print('development panel '+self.version+' upgraded; private rollback evidence: '+str(self.backup))

    def rollback(self):
        if self.committed:
            return
        if not self.stopping:
            super().rollback()
            return
        self.stop_timer()
        self.stop_writers()
        if not self.runtime_locked:
            self.lock(self.path('/var/lib/panel-executor/runtime-lifecycle.lock'))
            self.runtime_locked = True
        if not self.changed:
            # An unused foreign candidate is retained, never installed or
            # removed. Only the still-live original code/config is authority
            # to resume the original services without a database replacement.
            super().validate_restore_lineage()
            self.validate_development_tree_lineage(check_stages=False)
            self.release_runtime()
            self.start_previous_state()
            self.wait_readiness()
            self.verify_states()
            self.journal('refused-before-program-change')
            self.remove_pending()
            self.restore_timer()
            return
        self.queue_check()
        self.validate_restore_lineage()
        self.validate_database_backup()
        self.validate_database_lineage()
        with contextlib.closing(sqlite3.connect(self.backup/'panel.db')) as old, self.connect() as current:
            for table in QUEUES:
                if old.execute(f'SELECT * FROM {table} ORDER BY id').fetchall() != current.execute(f'SELECT * FROM {table} ORDER BY id').fetchall():
                    raise RuntimeError('candidate accepted job changes; database rollback refused')
        # Validate every target before the first recovery mutation.
        for name in self.tree_intents:
            previous = self.backup/('previous-'+name)
            installed = self.base/name
            if self.exists(previous):
                if (self.stable_tree(self.tree(previous, identities=True)) != self.stable_tree(self.original_tree_identities[name])
                        or (self.exists(installed) and self.stable_tree(self.tree(installed, identities=True)) != self.stable_tree(self.new_tree_identities[name]))):
                    raise ValueError('development tree changed outside transaction; rollback refused')
            elif not self.exists(installed) or self.stable_tree(self.tree(installed, identities=True)) != self.stable_tree(self.original_tree_identities[name]):
                raise ValueError('original development tree unavailable')
            if self.exists(self.backup/('failed-'+name)):
                if (self.exists(installed) and self.exists(previous)) or self.stable_tree(self.tree(self.backup/('failed-'+name),identities=True))!=self.stable_tree(self.new_tree_identities[name]):
                    raise ValueError('retained failed code changed; recovery cannot overwrite it')
        for name, candidate in self.replaced_units.items():
            target = self.path('/etc/systemd/system')/name
            self.validate_managed_file(target)
        if self.marker_changed:
            self.validate_managed_file(self.marker)
        self.retain_failed_database()
        self.journal('rollback-evidence-retained')
        for name in reversed(self.tree_intents):
            previous = self.backup/('previous-'+name)
            if self.exists(previous):
                self.retain_reverse_tree_intent(name)
                self.journal('restoring-'+name)
                if self.exists(self.base/name):
                    if self.exists(self.backup/('failed-'+name)):
                        raise ValueError('owned failed code must not be replaced')
                    os.rename(self.base/name, self.backup/('failed-'+name))
                    self.sync_directory(self.base)
                    self.sync_directory(self.backup)
                os.rename(previous, self.base/name)
                self.sync_directory(self.base)
                self.sync_directory(self.backup)
        for name in self.replaced_units:
            target = self.path('/etc/systemd/system')/name
            original = self.original_units[name]
            if original is not None and self.file(target,mode=0o644,limit=65536)[0]!=original[0]:
                self.atomic(target, original[0], 0o644, original[1].st_uid, original[1].st_gid)
            elif original is None and self.exists(target):
                self.remove_managed_file(target)
        if self.marker_changed:
            if self.marker_bytes is not None:
                if self.file(self.marker,mode=0o644,limit=256)[0]!=self.marker_bytes:
                    self.atomic(self.marker, self.marker_bytes, 0o644)
            elif self.exists(self.marker):
                self.validate_managed_file(self.marker)
                failed = self.backup/'failed-development-release'
                raw = self.file(self.marker,mode=0o644,limit=256)[0]
                if self.exists(failed):
                    if self.file(failed,mode=0o600,limit=256)[0]!=raw:
                        raise ValueError('retained failed development marker differs')
                else:
                    self.atomic(failed,raw,0o600)
                self.remove_managed_file(self.marker)
        self.remove_database_sidecars()
        self.restore_database()
        self.journal('rollback-data-restored')
        self.run_command('/usr/bin/systemctl', 'daemon-reload')
        self.release_runtime()
        self.start_previous_state()
        self.wait_readiness()
        self.verify_states()
        self.journal('rolled-back')
        self.remove_pending()
        self.restore_timer()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'run', 'recover-check', 'recover'))
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
        if args.action in ('recover-check','recover'):
            result = transaction.recover(args.release,check=args.action=='recover-check')
            print(json.dumps({'recovery':args.action,**result},sort_keys=True))
        elif args.action == 'check':
            transaction.preflight()
            print('development upgrade preflight passed without changes')
        else:
            transaction.run()
    except BaseException as error:
        for diagnostic in (production.public_queue_refusal_diagnostic(error), production.public_service_refusal_diagnostic(error)):
            if diagnostic is not None:
                print(json.dumps(diagnostic, sort_keys=True), file=sys.stderr)
        if args.action not in ('recover-check','recover'):
            try:
                transaction.rollback()
            except BaseException:
                print('automatic development rollback incomplete; private evidence and maintenance marker retained; recovery not confirmed', file=sys.stderr)
        parser.exit(1, 'development upgrade failed: '+str(error)+'\n')
    finally:
        transaction.close()


if __name__ == '__main__':
    main()
