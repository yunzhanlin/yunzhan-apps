#!/usr/bin/env python3
"""Install the fixed v2 service interlock; never start, enable or stop services.

The v1 binary is retained byte-for-byte. Only the two reviewed normal v1
program digests can authorize a recorded transition of the fixed conditions.
The v2 binary is immutable. Foreign files, links or writable parents refuse.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib

SPEC = importlib.util.spec_from_file_location('panel_guard_upgrade', pathlib.Path(__file__).with_name('upgrade-release.py'))
production = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(production)

GUARD = '/usr/lib/panel-program-upgrade/start-guard-v2'
LEGACY = '/usr/lib/panel-program-upgrade/start-guard-v1'
LEGACY_SHA = {
    'amd64':'31a497fdd653b13b1c3ab254e914a71f3a73f24313fa5aad2abfea14dcb13f9f',
    'arm64':'26daa8f5c8360000ab5471ccde5b5eec35c06439fdd777d12c75331bb283c61e',
}
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
    legacy = transaction.path(LEGACY)
    legacy_verified = False
    if transaction.exists(legacy):
        transaction.parents(legacy)
        data, _ = transaction.file(legacy, mode=0o755, limit=16*1024*1024)
        arch = transaction.run_command('/usr/bin/dpkg', '--print-architecture')
        if arch not in LEGACY_SHA or hashlib.sha256(data).hexdigest() != LEGACY_SHA[arch]:
            raise ValueError('unreviewed immutable v1 guard; transition refused')
        legacy_verified = True
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
        if transaction.exists(target):
            actual = transaction.file(target, mode=mode, limit=16*1024*1024)[0]
            legacy_condition = data.replace(GUARD.encode(), LEGACY.encode())
            if actual != data and not (mode == 0o644 and legacy_verified and actual == legacy_condition):
                raise ValueError('existing startup interlock differs; immutable v2 cannot overwrite it')
    return targets


def install(transaction):
    targets = inventory(transaction)  # Whole-scope validation before writes.
    originals = {}
    transitioning = False
    identity = lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    legacy = transaction.path(LEGACY)
    legacy_snapshot = transaction.file(legacy, mode=0o755, limit=16*1024*1024) if transaction.exists(legacy) else None
    if legacy_snapshot is not None:
        arch = transaction.run_command('/usr/bin/dpkg', '--print-architecture')
        if arch not in LEGACY_SHA or hashlib.sha256(legacy_snapshot[0]).hexdigest() != LEGACY_SHA[arch]:
            raise ValueError('legacy guard changed after scope validation')
    for target, data, mode in targets:
        original = transaction.file(target, mode=mode, limit=16*1024*1024) if transaction.exists(target) else None
        originals[str(target)] = original
        transitioning = transitioning or (original is not None and original[0] != data)
    if transitioning:
        # Do not mutate legacy conditions without retained private authority.
        # Whole-scope proof is durable before the new binary or any condition.
        if transaction.backup is None:
            raise ValueError('v1 transition requires a private upgrade transaction backup')
        transaction.parents(transaction.backup)
        transaction.directory(transaction.backup, private=True)
        proof = transaction.backup/'startup-guard-v2-transition.json'
        if transaction.exists(proof):
            raise ValueError('retained v2 transition evidence must not be overwritten')
        legacy_data, legacy_info = transaction.file(transaction.path(LEGACY), mode=0o755, limit=16*1024*1024)
        record = {'format':1,'legacy_retained':True,'legacy_sha256':hashlib.sha256(legacy_data).hexdigest(),'legacy_identity':identity(legacy_info),'files':[]}
        for target, data, mode in targets:
            original = originals[str(target)]
            record['files'].append({'path':str(target),'candidate_sha256':hashlib.sha256(data).hexdigest(),'candidate_mode':mode,'previous_sha256':hashlib.sha256(original[0]).hexdigest() if original is not None else None,'previous_identity':identity(original[1]) if original is not None else None})
        transaction.atomic(proof, (json.dumps(record,sort_keys=True)+'\n').encode(), 0o600)
    for target, data, mode in targets:
        if legacy_snapshot is not None:
            actual_legacy = transaction.file(legacy, mode=0o755, limit=16*1024*1024)
            if actual_legacy[0] != legacy_snapshot[0] or identity(actual_legacy[1]) != identity(legacy_snapshot[1]):
                raise ValueError('immutable legacy guard changed during transition')
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
        original = originals[str(target)]
        actual = transaction.file(target, mode=mode, limit=16*1024*1024) if transaction.exists(target) else None
        if (actual is None) != (original is None) or (actual is not None and (actual[0] != original[0] or identity(actual[1]) != identity(original[1]))):
            raise ValueError('startup interlock changed during installation')
        if actual is not None and actual[0] == data:
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
