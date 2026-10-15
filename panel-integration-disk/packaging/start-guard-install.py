#!/usr/bin/env python3
"""Install the fixed v4 service interlock; never start, enable or stop services.

Every previous binary is retained byte-for-byte. Only the fixed reviewed
architecture/digest pairs authorize a recorded transition of the conditions.
Reviewed v1/v2/v3 binaries remain immutable. Foreign files, links or writable
parents refuse; a compiler update never overwrites an existing guard version.
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

GUARD_VERSION = 4
GUARD = '/usr/lib/panel-program-upgrade/start-guard-v4'
TRANSITION_PROOF = 'startup-guard-v4-transition.json'
LEGACY = '/usr/lib/panel-program-upgrade/start-guard-v1'
OLDER = '/usr/lib/panel-program-upgrade/start-guard-v2'
OLDER_SHA = {
    'amd64':'f5278ef513c8bb412ebfd6ffeb7c80edd61c2cf997090c9e7557a1c67bf9cc61',
    'arm64':'b9ad134b1a8220a4eaf70b1d3123403ab5d6d0096de5c3d0105300e1150804c2',
}
PREVIOUS = '/usr/lib/panel-program-upgrade/start-guard-v3'
PREVIOUS_SHA = {
    'amd64':'832c30b7708fd9fd83187a851ec7e19b43fab78aff5a2086baf43063554c6cd6',
    'arm64':'0ad6a58956ba7d0320e44f7b9a36561cbd1db8f514bdb9ce217c783093e17fec',
}
LEGACY_SHA = {
    'amd64':'31a497fdd653b13b1c3ab254e914a71f3a73f24313fa5aad2abfea14dcb13f9f',
    'arm64':'26daa8f5c8360000ab5471ccde5b5eec35c06439fdd777d12c75331bb283c61e',
}
SERVICES = production.PROGRAMS+('panel-mysql-overwrite-recovery.service',)
DROPIN = '00-panel-program-start-guard.conf'

def retained_guards(transaction):
    retained = []
    for name, pins in ((LEGACY, LEGACY_SHA), (OLDER, OLDER_SHA), (PREVIOUS, PREVIOUS_SHA)):
        target = transaction.path(name)
        if not transaction.exists(target):
            continue
        transaction.parents(target)
        data, info = transaction.file(target, mode=0o755, limit=16*1024*1024)
        arch = transaction.run_command('/usr/bin/dpkg', '--print-architecture')
        if arch not in pins or hashlib.sha256(data).hexdigest() != pins[arch]:
            raise ValueError('unreviewed immutable previous guard; transition refused')
        retained.append((target, data, info))
    return retained


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
    retained = retained_guards(transaction)
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
            reviewed_condition = mode == 0o644 and any(actual == data.replace(GUARD.encode(), ('/'+path.relative_to(transaction.root).as_posix()).encode('ascii')) for path, _, _ in retained)
            if actual != data and not reviewed_condition:
                raise ValueError('existing startup interlock differs; immutable v4 cannot overwrite it')
    return targets


def install(transaction):
    targets = inventory(transaction)  # Whole-scope validation before writes.
    originals = {}
    transitioning = False
    identity = lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    retained = retained_guards(transaction)
    for target, data, mode in targets:
        original = transaction.file(target, mode=mode, limit=16*1024*1024) if transaction.exists(target) else None
        originals[str(target)] = original
        transitioning = transitioning or (original is not None and original[0] != data)
    if transitioning:
        # Do not mutate legacy conditions without retained private authority.
        # Whole-scope proof is durable before the new binary or any condition.
        if transaction.backup is None or not retained:
            raise ValueError('previous guard transition requires private authority and retained verified binaries')
        transaction.parents(transaction.backup)
        transaction.directory(transaction.backup, private=True)
        proof = transaction.backup/TRANSITION_PROOF
        if transaction.exists(proof):
            raise ValueError('retained v4 transition evidence must not be overwritten')
        _, legacy_data, legacy_info = retained[-1]
        record = {'format':2,'guard_version':GUARD_VERSION,'legacy_retained':True,'legacy_sha256':hashlib.sha256(legacy_data).hexdigest(),'legacy_identity':identity(legacy_info),'retained_guards':[{'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'identity':identity(info)} for path,data,info in retained],'files':[]}
        for target, data, mode in targets:
            original = originals[str(target)]
            record['files'].append({'path':str(target),'candidate_sha256':hashlib.sha256(data).hexdigest(),'candidate_mode':mode,'previous_sha256':hashlib.sha256(original[0]).hexdigest() if original is not None else None,'previous_identity':identity(original[1]) if original is not None else None})
        transaction.atomic(proof, (json.dumps(record,sort_keys=True)+'\n').encode(), 0o600)
    for target, data, mode in targets:
        for legacy, data_before, info_before in retained:
            actual_legacy = transaction.file(legacy, mode=0o755, limit=16*1024*1024)
            if actual_legacy[0] != data_before or identity(actual_legacy[1]) != identity(info_before):
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
