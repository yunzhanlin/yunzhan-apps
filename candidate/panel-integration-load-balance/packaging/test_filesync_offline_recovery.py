"""Closed request policy and real filesystem transaction ordering fixtures.

The service runner here is an explicit model. The separate native Go and
signed-host gates qualify actual services, lease inheritance and publication.
"""
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('filesync_transaction_fixture', pathlib.Path(__file__).with_name('test_production_upgrade.py'))
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)
upgrade = base.upgrade


def condition():
    return {'format': 1, 'remote_target_id': 'owned-original', 'backup_transaction_id': 'a'*32, 'revision': 7,
            'installed_record_sha256': 'b'*64, 'config_spec_sha256': 'c'*64, 'snapshot_sha256': 'd'*64,
            'census_sha256': 'e'*64, 'confirm': 'RETAIN FRAGMENTS ' + 'a'*32}


def witness(request, retained=False):
    census = 'f'*64 if retained else request['census_sha256']
    review = {key: request[key] for key in ('remote_target_id', 'backup_transaction_id', 'revision',
                'installed_record_sha256', 'config_spec_sha256', 'snapshot_sha256')}
    review.update(format=1, kind='files-sync-offline-unpublished-review', installed_version='2.0.0',
                  read_only=True, requires_writer_barrier=True, backup_complete=False,
                  source_authority=False, downloadable=False, census_sha256=census)
    return {'format': 1, 'state': 'observed-original-retained-receipt' if retained else 'original-unpublished',
            'original_census_sha256': request['census_sha256'], 'observed_census_sha256': census,
            'review': review, 'read_only': True, 'writer_permitted': False}


class OfflineRecoveryPolicyTests(unittest.TestCase):
    def test_optional_stdin_and_inherited_leases_preserve_the_ordinary_command_contract(self):
        completed=subprocess.CompletedProcess(['/fixed/program'],0,'original response\n','')
        with mock.patch.object(upgrade.subprocess,'run',return_value=completed)as run:
            self.assertEqual(upgrade.command('/fixed/program','fixed-argument',timeout=10),'original response')
            run.assert_called_once_with(('/fixed/program','fixed-argument'),capture_output=True,text=True,timeout=10)
        with mock.patch.object(upgrade.subprocess,'run',return_value=completed)as run:
            self.assertEqual(upgrade.command('/fixed/program','--retain-filesync-unpublished-offline',timeout=30,
                                            input_text='{"format":1}',pass_fds=(7,8)),'original response')
            run.assert_called_once_with(('/fixed/program','--retain-filesync-unpublished-offline'),capture_output=True,
                                        text=True,timeout=30,input='{"format":1}',pass_fds=(7,8))

    def test_condition_rejects_aliases_duplicates_coercion_paths_and_implicit_scope(self):
        valid = json.dumps(condition(), separators=(',', ':')).encode()
        self.assertEqual(upgrade.decode_filesync_unpublished_condition(valid), condition())
        inputs = [valid.replace(b'"format":1', b'"format":1,"format":1'),
                  valid.replace(b'"format"', b'"Format"'), valid.replace(b'"format"', b'"\\u0066ormat"'),
                  valid.replace(b'"format":1', b'"format":true'), valid.replace(b'"format":1', b'"format":1.0'),
                  valid.replace(b'"revision":7', b'"revision":7e0'), valid.replace(b'"revision":7', b'"revision":null'),
                  valid.replace(b'"format":1', b'"format":1,"root":"/tmp"'), valid + b'{}',
                  valid.replace(b'owned-original', b'../../arbitrary'), b'[]', b' '*2049]
        for index, raw in enumerate(inputs):
            with self.subTest(input=index), self.assertRaises(ValueError):
                upgrade.decode_filesync_unpublished_condition(raw)

    def test_original_receipt_is_only_read_only_observation_without_source_authority(self):
        tx = upgrade.Upgrade(pathlib.Path('/candidate'), filesync_unpublished=condition())
        for retained in (False, True):
            value = witness(condition(), retained)
            self.assertEqual(tx.validate_filesync_witness(json.dumps(value)), value)
        for key, changed in (('read_only', False), ('writer_permitted', True), ('format', True),
                             ('original_census_sha256', 'f'*64), ('state', 'backup-complete')):
            value = witness(condition(), True)
            value[key] = changed
            with self.subTest(field=key), self.assertRaises(ValueError):
                tx.validate_filesync_witness(json.dumps(value))
        for key, changed in (('backup_complete', True), ('source_authority', True), ('downloadable', True),
                             ('revision', 8), ('installed_record_sha256', 'a'*64), ('snapshot_sha256', 'a'*64)):
            value = witness(condition(), True)
            value['review'][key] = changed
            with self.subTest(review=key), self.assertRaises(ValueError):
                tx.validate_filesync_witness(json.dumps(value))
        duplicate = json.dumps(witness(condition())).replace('"format": 1', '"format": 1,"format": 1', 1)
        with self.assertRaises(ValueError):
            tx.validate_filesync_witness(duplicate)

    def test_ordinary_transaction_never_invokes_offline_writer(self):
        calls = []
        tx = upgrade.Upgrade(pathlib.Path('/candidate'), runner=lambda *args, **kwargs: calls.append(args))
        tx.retain_filesync_unpublished()
        self.assertEqual(calls, [])
        for field, value in (('stopping', False), ('pending_created', False), ('changed', True), ('layout', 'development'), ('locks', [])):
            tx = upgrade.Upgrade(pathlib.Path('/candidate'), filesync_unpublished=condition())
            tx.stopping, tx.pending_created, tx.changed, tx.locks = True, True, False, [7, 8]
            setattr(tx, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                tx.retain_filesync_unpublished()

    def test_signed_recovery_never_accepts_installation_scope_or_no_service_flags(self):
        script=pathlib.Path(__file__).with_name('signed-release.py')
        for extra in (['--root','/tmp/untrusted'],['--no-services'],['--preflight-only']):
            result=subprocess.run([sys.executable,'-I','-B',str(script),'recover-filesync','/missing/archive',
                                   '--public-key','/missing/key','--condition','/missing/condition',*extra],capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertIn('unrecognized arguments',result.stderr)


class FilesyncModeledChild:
    def __init__(self, testcase, transaction, runner, root):
        self.case, self.tx, self.runner, self.root = testcase, transaction, runner, root
        self.receipt = root/'owned-modeled-filesync-receipt.json'
        self.calls = root/'owned-modeled-filesync-dispatches.jsonl'
        self.after_publish = None
        self.lose_reply = False

    def __call__(self, *args, **kwargs):
        if len(args) != 2 or args[1] not in ('--check-filesync-unpublished-upgrade', '--retain-filesync-unpublished-offline'):
            return self.runner(*args, **kwargs)
        if args[1] == '--check-filesync-unpublished-upgrade':
            self.case.assertEqual(json.loads(kwargs['input_text']), condition())
            return json.dumps(witness(condition(), self.receipt.exists()))
        self.case.assertTrue(all(self.runner.states[unit]['ActiveState'] == 'inactive' for unit in upgrade.PROGRAMS+(upgrade.TIMER,)))
        self.case.assertTrue(self.tx.pending_created)
        self.case.assertFalse(self.tx.changed)
        self.case.assertEqual(args[0], str(self.tx.private_candidate/'bin/panel-executor'))
        request = json.loads(kwargs['input_text'])
        plan = (self.tx.backup/'recovery-plan.json').read_bytes()
        self.case.assertEqual(request, {'format': 1, 'version': self.tx.version,
                                       'plan_sha256': hashlib.sha256(plan).hexdigest(), 'lease_fds': self.tx.locks})
        self.case.assertEqual(kwargs['pass_fds'], tuple(self.tx.locks))
        for fd, identity in zip(self.tx.locks, json.loads(plan)['owner']['leases']):
            actual = os.fstat(fd)
            self.case.assertEqual([actual.st_dev, actual.st_ino], identity)
        descriptor = os.open(self.calls, os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'a') as stream:
            stream.write(json.dumps(request)+'\n')
        descriptor = os.open(self.receipt, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(witness(condition(), True), stream)
            stream.flush()
            os.fsync(stream.fileno())
        if self.after_publish:
            self.after_publish()
        if self.lose_reply:
            raise RuntimeError('owned modeled original reply lost after publication')
        return json.dumps({'format': 1, 'new_retention': True, 'witness': witness(condition(), True), 'original_fragments_preserved': True})


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'actual Root Linux filesystem/SQLite transaction fixture required')
class OfflineRecoveryRootTransactionTests(unittest.TestCase):
    def configure(self, tx, runner, root):
        tx.filesync_unpublished = condition()
        child = FilesyncModeledChild(self, tx, runner, root)
        tx.run_command = child
        return child

    def test_trusted_verifier_copies_only_one_bounded_independent_root_condition(self):
        spec=importlib.util.spec_from_file_location('filesync_signed_verifier',pathlib.Path(__file__).with_name('signed-release.py'))
        signed=importlib.util.module_from_spec(spec);spec.loader.exec_module(signed)
        for kind in ('safe','symlink','hardlink','unsafe-mode','linked-parent'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix='panel-owned-condition-copy-')as temporary:
                root=pathlib.Path(temporary).resolve();source=root/'original.json';source.write_bytes(json.dumps(condition()).encode());source.chmod(0o600)
                original=source.read_bytes();destination=root/'bounded-copy.json';input_path=source
                if kind=='symlink':
                    input_path=root/'alias.json';input_path.symlink_to(source)
                elif kind=='hardlink':os.link(source,root/'other-link.json')
                elif kind=='unsafe-mode':source.chmod(0o644)
                elif kind=='linked-parent':
                    alias=root/'alias';alias.symlink_to(root,target_is_directory=True);input_path=alias/'original.json'
                if kind=='safe':
                    signed.copy_root_private_condition(input_path,destination)
                    self.assertEqual(destination.read_bytes(),original)
                    self.assertEqual(destination.stat().st_mode&0o777,0o600)
                    self.assertEqual(destination.stat().st_nlink,1)
                else:
                    with self.assertRaises((ValueError,OSError)):signed.copy_root_private_condition(input_path,destination)
                    self.assertFalse(destination.exists())
                self.assertEqual(source.read_bytes(),original)

    def test_retention_is_between_original_writer_stop_and_database_backup(self):
        with base.UpgradeTransactionTests().fixture() as (tx, runner, root):
            child = self.configure(tx, runner, root)
            def inspect():
                self.assertFalse((tx.backup/'panel.db').exists())
                self.assertEqual(json.loads((tx.backup/'transaction.json').read_bytes())['phase'], 'prepared')
                self.assertEqual(json.loads((tx.backup/'recovery-plan.json').read_bytes())['filesync_unpublished'], condition())
            child.after_publish = inspect
            tx.run()
            self.assertTrue(tx.committed)
            self.assertEqual(len(child.calls.read_text().splitlines()), 1)
            self.assertFalse(tx.pending_created)
            self.assertTrue(tx.filesync_retention_observed)
            self.assertTrue((tx.backup/'timer-restored.json').exists())

    def test_original_late_sql_queue_blocks_retention_without_erasing_new_job(self):
        with base.UpgradeTransactionTests().fixture() as (tx, runner, root):
            child = self.configure(tx, runner, root)
            runner.inject_late_queue = True
            database = root/'var/lib/panel/panel.db'
            inode = database.stat().st_ino
            with self.assertRaises(ValueError):
                tx.run()
            tx.rollback()
            self.assertFalse(child.receipt.exists())
            self.assertFalse(child.calls.exists())
            self.assertEqual(database.stat().st_ino, inode)
            with sqlite3.connect(database) as connection:
                self.assertEqual(connection.execute("SELECT state FROM runtime_jobs WHERE id='late'").fetchone(), ('queued',))

    def test_lost_reply_keeps_original_receipt_and_rolls_back_only_program_transaction(self):
        with base.UpgradeTransactionTests().fixture() as (tx, runner, root):
            child = self.configure(tx, runner, root)
            child.lose_reply = True
            states = copy.deepcopy(runner.states)
            database = root/'var/lib/panel/panel.db'
            original = (database.stat().st_ino, database.read_bytes())
            with self.assertRaisesRegex(RuntimeError, 'reply lost'):
                tx.run()
            receipt = (child.receipt.stat().st_ino, child.receipt.read_bytes())
            tx.rollback()
            self.assertEqual((child.receipt.stat().st_ino, child.receipt.read_bytes()), receipt)
            self.assertEqual(len(child.calls.read_text().splitlines()), 1)
            self.assertEqual((database.stat().st_ino, database.read_bytes()), original)
            self.assertEqual(runner.states, states)
            self.assertFalse(tx.changed)
            self.assertFalse(tx.pending_created)

    def test_actual_killed_transaction_recovery_only_observes_condition_or_original_receipt(self):
        for phase in ('prepared', 'after-publish-before-reply', 'writers-stopped', 'committed'):
            with self.subTest(phase=phase), base.UpgradeTransactionTests().fixture() as (tx, runner, root):
                child = self.configure(tx, runner, root)
                states = copy.deepcopy(runner.states)
                def hook(current, suspend):
                    if phase == 'after-publish-before-reply':
                        child.after_publish = suspend
                factory = base.UpgradeTransactionTests()
                backup = factory.kill_transaction_at(tx, runner, root, None if phase == 'after-publish-before-reply' else phase, hook=hook)
                before = (child.receipt.stat().st_ino, child.receipt.read_bytes()) if child.receipt.exists() else None
                calls = child.calls.read_bytes() if child.calls.exists() else None
                recovered = upgrade.Upgrade(backup, root, runner)
                observer = FilesyncModeledChild(self, recovered, runner, root)
                recovered.run_command = observer
                try:
                    recovered.recover(backup)
                    self.assertFalse(recovered.pending_created)
                    self.assertEqual(runner.states, states)
                    self.assertEqual(child.calls.read_bytes() if child.calls.exists() else None, calls)
                    if before:
                        self.assertEqual((child.receipt.stat().st_ino, child.receipt.read_bytes()), before)
                    else:
                        self.assertFalse(child.receipt.exists())
                finally:
                    recovered.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
