#!/usr/bin/env python3
"""Explicit, locked release cleanup that preserves every recovery reference.

Preview is read-only. --apply deletes only fully checked obsolete program
directories; app data, backup journals, unknown stages and keys are never targets.
"""
import argparse
import fcntl
import json
import os
import pathlib
import re
import shutil
import stat
import sys

VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*\Z')
PHASES = {'prepared', 'writers-stopped', 'database-backed-up', 'program-swapped', 'committed', 'rolled-back', 'refused-before-services-stopped', 'refused-before-program-change'}
SERVICES = {'panel-terminal.service', 'panel-terminal-root.service', 'panel-executor.service', 'panel.service', 'panel-mysql-overwrite-recovery.timer', 'panel-mysql-overwrite-recovery.service', 'nginx.service'}
STATES = {'LoadState', 'ActiveState', 'SubState', 'UnitFileState'}
MAX_ENTRIES = 100000


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate recovery journal field')
        result[key] = value
    return result


def bounded_paths(iterator, maximum):
    result = []
    for path in iterator:
        if len(result) == maximum:
            raise ValueError('release cleanup inventory exceeds entry budget')
        result.append(path)
    return sorted(result)


class Pruner:
    def __init__(self, root=pathlib.Path('/'), keep=10):
        self.root = pathlib.Path(root)
        self.keep = keep
        self.owner = os.geteuid()
        self.releases = self.root/'opt/panel/releases'
        self.current = self.root/'opt/panel/current'
        self.backups = self.root/'var/backups/panel/system'
        self.lock_fd = None
        self.root_fd = None
        self.legacy_backups = False

    def directory(self, path, private=False):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or info.st_mode & 0o022 or (private and stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('unsafe release cleanup directory')
        return info

    def parents(self, path):
        for parent in reversed(path.parents):
            if parent == self.root or self.root in parent.parents:
                self.directory(parent)

    def file(self, path, mode=0o600, limit=65536):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != self.owner or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != mode or before.st_size > limit:
                raise ValueError('unsafe release recovery journal')
            blocks = []
            size = 0
            while size <= limit:
                block = os.read(descriptor, min(65536, limit+1-size))
                if not block:
                    break
                blocks.append(block)
                size += len(block)
            if size != before.st_size or identity(before) != identity(os.fstat(descriptor)):
                raise ValueError('recovery journal changed while reading')
            return b''.join(blocks), identity(before)
        finally:
            os.close(descriptor)

    def acquire(self, apply):
        if not self.root.is_absolute() or self.root != self.root.resolve(strict=True) or type(self.keep) is not int or not 1 <= self.keep <= 1000:
            raise ValueError('root must be canonical and keep must be 1 through 1000')
        if self.root == pathlib.Path('/') and self.owner != 0:
            raise ValueError('host release cleanup requires root, including private-journal preview')
        self.parents(self.releases)
        self.release_identity = identity(self.directory(self.releases))
        lock = self.releases/'.release.lock'
        self.lock_fd = os.open(lock, (os.O_RDWR if apply else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(self.lock_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in (0o600, 0o644):
            raise ValueError('unsafe release cleanup lock')
        # Never create/truncate/rechmod a lock during preview or cleanup.
        fcntl.flock(self.lock_fd, (fcntl.LOCK_EX if apply else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        self.lock_identity = identity(info)
        if identity(lock.lstat()) != self.lock_identity:
            raise ValueError('release lock replaced while acquiring cleanup lease')
        self.root_fd = os.open(self.releases, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if identity(os.fstat(self.root_fd)) != self.release_identity:
            raise ValueError('release directory changed while acquiring lock')

    def current_version(self):
        self.parents(self.current)
        info = self.current.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != self.owner:
            raise ValueError('current release must be an owned direct symlink')
        target = os.readlink(self.current)
        path = pathlib.Path(target)
        if path.parent != self.releases or path.as_posix() != target or not VERSION.fullmatch(path.name):
            raise ValueError('current release target is outside retained releases')
        self.directory(path)
        return path.name, (target, identity(info))

    def refs(self):
        protected = set()
        evidence = {}
        self.legacy_backups = False
        self.parents(self.backups)
        if not self.backups.exists() and not self.backups.is_symlink():
            return protected, evidence
        self.directory(self.backups, private=True)
        children = bounded_paths(self.backups.iterdir(), 1024)
        for directory in children:
            if directory.name.startswith('pre-update-'):
                name = directory.name[len('pre-update-'):]
                if not name.endswith('.db') or not VERSION.fullmatch(name[:-3]):
                    raise ValueError('unrecognized legacy database rollback backup')
                info = directory.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16*1024*1024*1024:
                    raise ValueError('unsafe legacy database rollback backup')
                evidence[directory] = (None, identity(info))
                self.legacy_backups = True
                continue
            if directory.name.startswith('development-'):
                if not VERSION.fullmatch(directory.name[len('development-'):]):
                    raise ValueError('unrecognized legacy development rollback backup')
                info = self.directory(directory, private=True)
                evidence[directory] = (None, identity(info))
                self.legacy_backups = True
                continue
            if not directory.name.startswith('production-'):
                continue
            version = directory.name.removeprefix('production-')
            if not VERSION.fullmatch(version):
                raise ValueError('unrecognized production recovery backup')
            self.directory(directory, private=True)
            raw, info = self.file(directory/'transaction.json')
            record = json.loads(raw, object_pairs_hook=closed_object)
            if not isinstance(record, dict) or set(record) != {'format', 'version', 'previous', 'phase', 'services'} or type(record['format']) is not int or record['format'] != 1 or record['version'] != version or not isinstance(record['phase'], str) or record['phase'] not in PHASES:
                raise ValueError('invalid or unknown recovery journal')
            services = record['services']
            if not isinstance(services, dict) or set(services) != SERVICES:
                raise ValueError('incomplete recovery service states')
            for state in services.values():
                if not isinstance(state, dict) or set(state) != STATES or any(not isinstance(value, str) for value in state.values()) or state['LoadState'] != 'loaded' or state['ActiveState'] not in ('active', 'inactive') or state['UnitFileState'] not in ('enabled', 'disabled', 'static', 'indirect', 'enabled-runtime'):
                    raise ValueError('invalid recovery service state')
            previous = record['previous']
            if not isinstance(previous, str):
                raise ValueError('invalid recovery program reference')
            previous_path = pathlib.Path(previous)
            if previous_path.parent != self.releases or previous_path.as_posix() != previous or not VERSION.fullmatch(previous_path.name):
                raise ValueError('recovery program reference outside retained releases')
            # A missing old release is not a reason to erase more evidence.
            self.directory(previous_path)
            protected.update((version, previous_path.name))
            evidence[directory/'transaction.json'] = (raw, info)
        if self.legacy_backups:
            # Old installers did not persist a reliable previous-program
            # reference. Never guess from backup dates or newest versions.
            # Retain all programs until the owner explicitly archives those
            # legacy backups with their associated program releases.
            for path in bounded_paths(self.releases.iterdir(), 2048):
                if VERSION.fullmatch(path.name):
                    self.directory(path)
                    protected.add(path.name)
        return protected, evidence

    def interlocks(self):
        for path in (self.releases/'.program-upgrade.pending', self.current.with_name('current.new')):
            if path.exists() or path.is_symlink():
                raise ValueError('program upgrade pending; release cleanup refused')
        children = bounded_paths(self.releases.iterdir(), 2048)
        for path in children:
            if path.name.endswith('.tmp') and VERSION.fullmatch(path.name[:-4]):
                raise ValueError('retained program stage; release cleanup refused')
        return children

    def mounted_paths(self):
        if sys.platform != 'linux':
            return set()
        # Kernel-provided namespace inventory detects same-device bind mounts,
        # not only the device-number changes detected by os.path.ismount.
        with open('/proc/self/mountinfo', 'rb') as source:
            raw = source.read(4*1024*1024+1)
        if len(raw) > 4*1024*1024:
            raise ValueError('mount inventory exceeds cleanup budget')
        result = set()
        for line in raw.decode('utf-8', 'strict').splitlines():
            fields = line.split(' ')
            if len(fields) < 10 or '-' not in fields:
                raise ValueError('unverifiable mount inventory')
            value = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4])
            result.add(pathlib.Path(value))
        return result

    def tree(self, path, mounts):
        self.directory(path)
        if any(point == path or path in point.parents for point in mounts):
            raise ValueError('nested mount in obsolete release; do not traverse it')
        paths = [path]+bounded_paths(path.rglob('*'), MAX_ENTRIES-1)
        snapshot = {}
        size = 0
        for entry in paths:
            info = entry.lstat()
            if entry in mounts or os.path.ismount(entry) or info.st_dev != self.release_identity[0] or info.st_uid != self.owner or info.st_mode & 0o022:
                raise ValueError('mounted or untrusted obsolete release')
            if not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise ValueError('linked or special obsolete release payload')
            snapshot[entry.relative_to(path).as_posix()] = identity(info)
            if stat.S_ISREG(info.st_mode):
                size += info.st_size
        return snapshot, size

    def plan(self):
        children = self.interlocks()
        version, current = self.current_version()
        protected, evidence = self.refs()
        protected.add(version)
        releases = []
        for path in children:
            if VERSION.fullmatch(path.name):
                releases.append((self.directory(path).st_mtime_ns, path.name))
        releases.sort(reverse=True)
        protected.update(name for _, name in releases[:self.keep])
        mounts = self.mounted_paths()
        candidates = []
        entries = 0
        for _, name in releases:
            if name in protected:
                continue
            snapshot, size = self.tree(self.releases/name, mounts)
            entries += len(snapshot)
            if entries > MAX_ENTRIES:
                raise ValueError('complete cleanup plan exceeds entry budget')
            candidates.append((name, snapshot, size))
        return version, current, protected, evidence, candidates

    def execute(self, apply=False, output=print):
        self.acquire(apply)
        version, current, protected, evidence, candidates = self.plan()
        if apply and not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError('fd-based safe release deletion is unavailable')
        count = 0
        total = 0
        if self.legacy_backups:
            output('retained all program versions: legacy rollback backups have no proven previous-program reference')
        for name, snapshot, size in candidates:
            # Recheck ALL recovery references and pointer before every deletion.
            self.interlocks()
            if self.current_version()[1] != current:
                raise ValueError('current release changed; cleanup refused')
            _, latest_evidence = self.refs()
            if latest_evidence != evidence or identity(os.fstat(self.lock_fd)) != self.lock_identity or identity((self.releases/'.release.lock').lstat()) != self.lock_identity or identity(self.releases.lstat()) != identity(os.fstat(self.root_fd)):
                raise ValueError('cleanup lock, release directory or recovery evidence changed')
            if self.tree(self.releases/name, self.mounted_paths())[0] != snapshot:
                raise ValueError('obsolete release changed; cleanup refused')
            if apply:
                # Python3.8-3.10 on supported older distributions do not have
                # rmtree(dir_fd=). Require its fd-based symlink-safe algorithm;
                # the checked root-owned parent remains locked and unchanged.
                shutil.rmtree(self.releases/name)
                os.fsync(self.root_fd)
                output(f'removed {name} ({size} bytes)')
            else:
                output(f'would remove {name} ({size} bytes)')
            count += 1
            total += size
        output(f'current={version} keep_newest={self.keep} candidates={count} bytes={total} mode={"apply" if apply else "preview"}')
        return count

    def close(self):
        for descriptor in (self.root_fd, self.lock_fd):
            if descriptor is not None:
                os.close(descriptor)
        self.root_fd = self.lock_fd = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, default=pathlib.Path('/'))
    parser.add_argument('--keep', type=int, default=10)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    pruner = Pruner(args.root, args.keep)
    try:
        pruner.execute(args.apply)
    except (OSError, ValueError) as error:
        parser.exit(1, 'release cleanup refused: '+str(error)+'\n')
    finally:
        pruner.close()


if __name__ == '__main__':
    main()
