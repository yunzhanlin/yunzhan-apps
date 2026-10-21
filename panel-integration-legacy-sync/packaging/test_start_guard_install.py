"""Immutable interlock filesystem fixtures, not native systemd/boot proof."""
import importlib.util
import contextlib
import hashlib
import json
import os
import pathlib
import stat
import sys
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('own_start_guard', HERE/'start-guard-install.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
SPEC = importlib.util.spec_from_file_location('own_guard_support', HERE/'test_production_upgrade.py')
support = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(support)


class StartupInterlockPackagingTests(unittest.TestCase):
    def test_fixed_condition_is_before_constructors_without_skip_or_mutation(self):
        for unit in guard.SERVICES:
            self.assertEqual(guard.dropin(unit), ('[Service]\nExecCondition=+'+guard.GUARD+' '+unit+'\n').encode())
        with self.assertRaises(ValueError):
            guard.dropin('nginx.service')
        source = (HERE.parent/'cmd/startguard/main.go').read_text()
        self.assertIn('os.Exit(255)', source)
        for forbidden in ('core.OpenStore', 'executor.New', 'os.Remove', 'os.WriteFile', 'os.Getenv', 'flag.'):
            self.assertNotIn(forbidden, source)
        builder = (HERE/'build-release.sh').read_text()
        self.assertIn('./cmd/startguard)', builder)
        self.assertIn('development-upgrade.py start-guard-install.py;', builder)
        installer = (HERE/'install.sh').read_text()
        self.assertLess(installer.index('python3 "$HERE/start-guard-install.py" check'), installer.index('apt-get update'))
        self.assertLess(installer.index('python3 "$HERE/start-guard-install.py" install'), installer.index('restart_release_services || FAILED=1'))


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'actual root Linux ordinary ownership fixture required')
class StartupInterlockFilesystemTests(unittest.TestCase):
    def test_mixed_v1_v2_v3_conditions_keep_all_original_binaries_and_authority(self):
        for foreign in (False, True):
            with self.subTest(foreign=foreign),support.UpgradeTransactionTests().fixture() as (transaction,runner,root),contextlib.ExitStack() as patches:
                versions = ((guard.LEGACY,guard.LEGACY_SHA),(guard.OLDER,guard.OLDER_SHA),(guard.PREVIOUS,guard.PREVIOUS_SHA))
                originals = {}
                for name,pins in versions:
                    target=root/name.lstrip('/')
                    target.parent.mkdir(mode=0o755,exist_ok=True)
                    raw=('owned synthetic immutable '+name).encode()
                    target.write_bytes(raw);target.chmod(0o755)
                    originals[name]=(target.stat().st_ino,target.read_bytes())
                    patches.enter_context(mock.patch.dict(pins,{'arm64':hashlib.sha256(raw).hexdigest()}))
                conditions = {}
                for index,unit in enumerate(guard.SERVICES):
                    target=root/'etc/systemd/system'/(unit+'.d')/guard.DROPIN
                    target.parent.mkdir(mode=0o755)
                    value=guard.dropin(unit).replace(guard.GUARD.encode(),versions[index%3][0].encode())
                    target.write_bytes(value);target.chmod(0o644)
                    conditions[str(target)]=value
                transaction.backup=root/'var/backups/panel/system/owned-mixed-transition'
                transaction.backup.mkdir(mode=0o700)
                if foreign:
                    previous=root/guard.PREVIOUS.lstrip('/')
                    previous.write_bytes(b'unknown immutable previous executable')
                    with self.assertRaises(ValueError):guard.install(transaction)
                    self.assertFalse((root/guard.GUARD.lstrip('/')).exists())
                    self.assertFalse((transaction.backup/guard.TRANSITION_PROOF).exists())
                    self.assertEqual(conditions,{str(p):p.read_bytes() for p in (root/'etc/systemd/system').rglob(guard.DROPIN)})
                else:
                    guard.install(transaction)
                    proof=json.loads((transaction.backup/guard.TRANSITION_PROOF).read_bytes())
                    self.assertEqual(proof['guard_version'],4)
                    self.assertEqual(len(proof['retained_guards']),3)
                    self.assertEqual(set(row['sha256'] for row in proof['retained_guards']),set(hashlib.sha256(raw).hexdigest() for _,raw in originals.values()))
                    for name,(inode,raw) in originals.items():
                        target=root/name.lstrip('/')
                        self.assertEqual((target.stat().st_ino,target.read_bytes()),(inode,raw))
                    self.assertFalse(any(call[0]=='/usr/bin/systemctl' and call[1] in ('start','stop','restart','enable') for call in runner.calls))

    def test_reviewed_previous_transition_keeps_every_old_binary_and_refuses_unknown_v3(self):
        for reviewed in (False, True):
            with self.subTest(reviewed=reviewed),support.UpgradeTransactionTests().fixture() as (transaction,runner,root):
                previous=root/guard.PREVIOUS.lstrip('/')
                previous.parent.mkdir(mode=0o755)
                data=b'owned synthetic reviewed v3; not native executable evidence'
                previous.write_bytes(data);previous.chmod(0o755)
                before=(previous.stat().st_ino,previous.read_bytes())
                conditions={}
                for unit in guard.SERVICES:
                    target=root/'etc/systemd/system'/(unit+'.d')/guard.DROPIN
                    target.parent.mkdir(mode=0o755)
                    value=guard.dropin(unit).replace(guard.GUARD.encode(),guard.PREVIOUS.encode())
                    target.write_bytes(value);target.chmod(0o644);conditions[str(target)]=value
                transaction.backup=root/'var/backups/panel/system/owned-v3-transition'
                transaction.backup.mkdir(mode=0o700)
                with mock.patch.dict(guard.PREVIOUS_SHA,{'arm64':hashlib.sha256(data).hexdigest()} if reviewed else {}):
                    if not reviewed:
                        with self.assertRaises(ValueError):guard.install(transaction)
                        self.assertFalse((root/guard.GUARD.lstrip('/')).exists())
                        self.assertEqual(conditions,{str(p):p.read_bytes() for p in (root/'etc/systemd/system').rglob(guard.DROPIN)})
                    else:
                        guard.install(transaction)
                        proof=json.loads((transaction.backup/guard.TRANSITION_PROOF).read_bytes())
                        self.assertEqual(proof['guard_version'],4)
                        self.assertEqual(len(proof['retained_guards']),1)
                        self.assertEqual(proof['retained_guards'][0]['sha256'],hashlib.sha256(data).hexdigest())
                        self.assertTrue((root/guard.GUARD.lstrip('/')).is_file())
                        for unit in guard.SERVICES:
                            self.assertEqual((root/'etc/systemd/system'/(unit+'.d')/guard.DROPIN).read_bytes(),guard.dropin(unit))
                self.assertEqual((previous.stat().st_ino,previous.read_bytes()),before)

    def legacy(self, transaction, root):
        """Synthetic bytes only; real v1 hash/architecture tested natively."""
        path = root/guard.LEGACY.lstrip('/')
        path.parent.mkdir(mode=0o755)
        data = b'synthetic scope-owned old guard; no native proof'
        path.write_bytes(data);path.chmod(0o755)
        for unit in guard.SERVICES:
            target = root/'etc/systemd/system'/(unit+'.d')/guard.DROPIN
            target.parent.mkdir(mode=0o755)
            target.write_bytes(guard.dropin(unit).replace(guard.GUARD.encode(),guard.LEGACY.encode()));target.chmod(0o644)
        return path, data

    def test_reviewed_legacy_transition_keeps_binary_and_records_scope_before_first_mutation(self):
        with support.UpgradeTransactionTests().fixture() as (transaction, runner, root):
            legacy, data = self.legacy(transaction, root)
            before = (legacy.stat().st_ino, legacy.read_bytes())
            transaction.backup = root/'var/backups/panel/system/own-transition'
            transaction.backup.mkdir(mode=0o700)
            original = transaction.atomic
            def atomic(target, value, mode, *args):
                proof = transaction.backup/guard.TRANSITION_PROOF
                if target != proof:
                    record = json.loads(proof.read_bytes())
                    self.assertTrue(record['legacy_retained']);self.assertEqual(len(record['files']),6)
                    self.assertEqual(record['legacy_sha256'],hashlib.sha256(data).hexdigest())
                    self.assertEqual(stat.S_IMODE(proof.stat().st_mode),0o600)
                return original(target,value,mode,*args)
            transaction.atomic = atomic
            with mock.patch.dict(guard.LEGACY_SHA, {'arm64':hashlib.sha256(data).hexdigest()}):
                guard.install(transaction)
                identities={str(p):p.stat().st_ino for p,_,_ in guard.inventory(transaction)}
                guard.install(transaction)
                self.assertEqual(identities,{str(p):p.stat().st_ino for p,_,_ in guard.inventory(transaction)})
            self.assertEqual((legacy.stat().st_ino,legacy.read_bytes()),before)
            self.assertTrue((root/guard.GUARD.lstrip('/')).is_file())
            self.assertFalse(any(call[0]=='/usr/bin/systemctl' and call[1] in ('start','stop','restart','enable') for call in runner.calls))

    def test_unknown_legacy_or_missing_private_authority_never_writes_v2(self):
        for reviewed in (False,True):
            with self.subTest(reviewed=reviewed),support.UpgradeTransactionTests().fixture() as (transaction,runner,root):
                legacy,data=self.legacy(transaction,root)
                before={str(p):p.read_bytes() for p in (root/'etc/systemd/system').rglob(guard.DROPIN)}
                with mock.patch.dict(guard.LEGACY_SHA, {'arm64':hashlib.sha256(data).hexdigest()} if reviewed else {}):
                    with self.assertRaises(ValueError):guard.install(transaction)
                self.assertFalse((root/guard.GUARD.lstrip('/')).exists())
                self.assertEqual(before,{str(p):p.read_bytes() for p in (root/'etc/systemd/system').rglob(guard.DROPIN)})

    def test_legacy_drift_and_transition_evidence_write_failure_do_not_replace_any_condition(self):
        for fault in ('proof','identity'):
            with self.subTest(fault=fault),support.UpgradeTransactionTests().fixture() as (transaction,runner,root):
                legacy,data=self.legacy(transaction,root)
                transaction.backup=root/'var/backups/panel/system/own-transition';transaction.backup.mkdir(mode=0o700)
                originals={str(p):p.read_bytes() for p in (root/'etc/systemd/system').rglob(guard.DROPIN)}
                atomic=transaction.atomic
                def changed(target,value,mode,*args):
                    if target.name==guard.TRANSITION_PROOF:
                        if fault=='proof':raise OSError('own retained evidence fixture failure')
                        result=atomic(target,value,mode,*args)
                        replacement=legacy.with_name('own-legacy-replacement');replacement.write_bytes(data);replacement.chmod(0o755);os.replace(replacement,legacy)
                        return result
                    return atomic(target,value,mode,*args)
                transaction.atomic=changed
                with mock.patch.dict(guard.LEGACY_SHA, {'arm64':hashlib.sha256(data).hexdigest()}):
                    with self.assertRaises((ValueError,OSError)):guard.install(transaction)
                self.assertFalse((root/guard.GUARD.lstrip('/')).exists())
                self.assertEqual(originals,{str(p):p.read_bytes() for p in (root/'etc/systemd/system').rglob(guard.DROPIN)})

    def test_install_is_idempotent_private_umask_independent_and_retains_inode_bytes(self):
        with support.UpgradeTransactionTests().fixture() as (transaction, runner, root):
            original = os.umask(0o077)
            try:
                guard.install(transaction)
            finally:
                os.umask(original)
            targets = guard.inventory(transaction)
            identities = {}
            for path, data, mode in targets:
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat().st_mode & 0o777, mode)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o755)
                identities[str(path)] = path.stat().st_ino
            guard.install(transaction)
            self.assertEqual({str(path):path.stat().st_ino for path, _, _ in guard.inventory(transaction)}, identities)
            self.assertEqual([call for call in runner.calls if call[0] == '/usr/bin/systemctl'], [('/usr/bin/systemctl','daemon-reload')]*2)
            self.assertFalse(transaction.stopping)

    def test_every_foreign_existing_file_parent_and_link_refuses_whole_scope_before_write(self):
        for fault in ('binary', 'condition', 'writable', 'symlink', 'hardlink', 'parent'):
            with self.subTest(fault=fault), support.UpgradeTransactionTests().fixture() as (transaction, runner, root):
                target = root/'etc/systemd/system/panel.service.d'/guard.DROPIN
                target.parent.mkdir()
                if fault == 'parent':
                    target.parent.chmod(0o777)
                elif fault == 'binary':
                    binary = root/guard.GUARD.lstrip('/')
                    binary.parent.mkdir()
                    binary.write_bytes(b'foreign bytes')
                    binary.chmod(0o755)
                elif fault == 'symlink':
                    target.symlink_to(root/'unrelated')
                else:
                    target.write_bytes(guard.dropin('panel.service') if fault != 'condition' else b'foreign condition')
                    target.chmod(0o666 if fault == 'writable' else 0o644)
                    if fault == 'hardlink':
                        os.link(target, root/'unrelated')
                with self.assertRaises((ValueError, OSError)):
                    guard.install(transaction)
                self.assertEqual(runner.calls, [])
                self.assertFalse((root/'etc/systemd/system/panel-executor.service.d').exists())
                if fault != 'binary':
                    self.assertFalse((root/guard.GUARD.lstrip('/')).exists())

    def test_upgrade_installs_guard_before_pending_stop_and_retains_on_rollback(self):
        with support.UpgradeTransactionTests().fixture() as (transaction, runner, root):
            runner.fail_start_once = True
            command = transaction.run_command
            def checked(*args, **kwargs):
                if args[0] == '/usr/bin/systemctl' and args[1] == 'stop':
                    for target, data, mode in guard.inventory(transaction):
                        self.assertEqual(target.read_bytes(), data)
                        self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
                    if args[2:]==(support.upgrade.TIMER,):
                        self.assertTrue(transaction.timer_deferred)
                        self.assertEqual(json.loads((transaction.backup/'timer-deferred.json').read_bytes()),transaction.timer_declaration())
                    else:
                        self.assertTrue(transaction.pending_created)
                return command(*args, **kwargs)
            transaction.run_command = checked
            with self.assertRaises(RuntimeError):
                transaction.run()
            transaction.rollback()
            self.assertFalse(transaction.pending_created)
            self.assertTrue((root/guard.GUARD.lstrip('/')).exists())
            proof = transaction.backup/'startup-interlock.json'
            self.assertEqual(proof.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
