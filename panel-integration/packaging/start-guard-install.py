#!/usr/bin/env python3
"""Install the fixed v1 service interlock; never start, enable or stop services.

The v1 binary and drop-ins are immutable once installed. A future incompatible
interlock needs a separately reviewed v2 transition, not an implicit overwrite.
Existing foreign files, links or writable parents are always a refusal.
"""
import argparse
import importlib.util
import os
import pathlib

SPEC = importlib.util.spec_from_file_location('panel_guard_upgrade', pathlib.Path(__file__).with_name('upgrade-release.py'))
production = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(production)

GUARD = '/usr/lib/panel-program-upgrade/start-guard-v1'
SERVICES = production.PROGRAMS+('panel-mysql-overwrite-recovery.service',)
DROPIN = '00-panel-program-start-guard.conf'


def dropin(unit):
    if unit not in SERVICES:
        raise ValueError('startup interlock outside fixed service scope')
    # ExecCondition precedes every ExecStartPre, including the API's executor
    # health probe. Exit 255 is a failed condition, never a successful skip.
    return ('[Service]\nExecCondition=+'+GUARD+' '+unit+'\n').encode('ascii')


def inventory(transaction):
    transaction.parents(transaction.release)
    transaction.directory(transaction.release)
    binary = transaction.file(transaction.release/'bin/panel-start-guard', mode=0o755, limit=16*1024*1024)[0]
    targets = [(transaction.path(GUARD), binary, 0o755)]
    for unit in SERVICES:
        targets.append((transaction.path('/etc/systemd/system')/(unit+'.d')/DROPIN, dropin(unit), 0o644))
    for target, data, mode in targets:
        # Missing only the newly scoped directories is permitted. Their
        # existing ancestry must already be exclusively root controlled.
        for parent in reversed(target.parents):
            if parent == transaction.root or transaction.root in parent.parents:
                if transaction.exists(parent):
                    transaction.directory(parent)
                elif parent not in (transaction.path('/usr/lib/panel-program-upgrade'), target.parent):
                    raise ValueError('startup guard prerequisite parent is absent')
        if transaction.exists(target) and transaction.file(target, mode=mode, limit=16*1024*1024)[0] != data:
            raise ValueError('existing startup interlock differs; immutable v1 cannot overwrite it')
    return targets


def install(transaction):
    targets = inventory(transaction)  # Whole-scope validation before writes.
    for target, data, mode in targets:
        if not transaction.exists(target.parent):
            target.parent.mkdir(mode=0o755)
            descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchmod(descriptor, 0o755)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            transaction.sync_directory(target.parent.parent)
        transaction.parents(target)
        if transaction.exists(target):
            if transaction.file(target, mode=mode, limit=16*1024*1024)[0] != data:
                raise ValueError('startup interlock changed during installation')
            continue
        transaction.atomic(target, data, mode)
    transaction.run_command('/usr/bin/systemctl', 'daemon-reload')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'install'))
    parser.add_argument('release', type=pathlib.Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, 'startup interlock installation requires root\n')
    transaction = production.Upgrade(args.release)
    try:
        transaction.parents(args.release)
        transaction.directory(args.release)
        transaction.file(args.release/'verify-release.sh', mode=0o755, limit=65536)
        transaction.run_command(str(args.release/'verify-release.sh'), str(args.release))
        if args.action == 'check':
            inventory(transaction)
        else:
            install(transaction)
        print('fixed program startup interlock '+args.action+' passed')
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, 'program startup interlock installation refused: '+str(error)+'\n')
    finally:
        transaction.close()


if __name__ == '__main__':
    main()
