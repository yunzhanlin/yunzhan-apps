"""Original-child private diagnostic policy, not installed upgrade acceptance."""
import contextlib
import hashlib
import importlib.util
import json
import os
import pathlib
import sqlite3
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('upgrade_queue_diagnostics', pathlib.Path(__file__).with_name('upgrade-release.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class DiagnosticPolicyTests(unittest.TestCase):
    def test_nonzero_command_has_same_closed_console_message_and_no_arguments(self):
        raw = 'private fixture output: ' + '字' * 4000
        result = subprocess.CompletedProcess(['/private/panel-executor', 'fixture-secret-argument'], 1, raw, 'fixture-private-reason')
        with mock.patch.object(upgrade.subprocess, 'run', return_value=result) as run:
            with self.assertRaises(upgrade.CommandFailure) as caught:
                upgrade.command('/private/panel-executor', 'fixture-secret-argument', timeout=10)
        error = caught.exception
        self.assertEqual(str(error), 'command failed: panel-executor 1')
        self.assertNotIn('fixture-secret', repr(error))
        self.assertNotIn('fixture-private-reason', str(error))
        self.assertFalse(hasattr(error, 'args_received'))
        self.assertEqual(error.output['stdout']['sha256'], hashlib.sha256(raw.encode()).hexdigest())
        self.assertTrue(error.output['stdout']['truncated'])
        self.assertLessEqual(len(error.output['stdout']['text'].encode()), 8195)
        self.assertEqual(error.output['stderr']['text'], 'fixture-private-reason')
        run.assert_called_once_with(('/private/panel-executor', 'fixture-secret-argument'), capture_output=True, text=True, timeout=10)

    def test_preflight_with_no_owned_backup_never_writes_or_retries(self):
        transaction = upgrade.Upgrade(pathlib.Path('/candidate'))
        with mock.patch.object(upgrade.os, 'open', side_effect=AssertionError('unexpected write')):
            transaction.record_native_queue_refusal(upgrade.CommandFailure('panel-executor', 1, '', 'fixture-only'))


@unittest.skipUnless(os.geteuid() == 0, 'Root ownership and exclusive private-file fixture requires root; no ownership policy substitution')
class DiagnosticRootFilesystemTests(unittest.TestCase):
    def fixture(self, root):
        transaction = upgrade.Upgrade(root / 'candidate', root)
        transaction.version = '0.1.0-dev.queuefixture'
        transaction.backup_path = root / 'var/backups/panel/system' / ('production-' + transaction.version)
        transaction.backup_path.mkdir(parents=True, mode=0o700)
        transaction.backup = transaction.backup_path
        transaction.last_phase = 'prepared'
        return transaction

    def test_original_output_is_private_fsynced_and_each_receipt_is_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            transaction = self.fixture(pathlib.Path(temporary))
            error = upgrade.CommandFailure('/private/panel-executor', 1, '', 'fixture-private-reason')
            previous = os.umask(0)
            try:
                transaction.record_native_queue_refusal(error)
                transaction.record_native_queue_refusal(error)
            finally:
                os.umask(previous)
            files = list(transaction.backup.glob('native-queue-refusal-*.json'))
            self.assertEqual(len(files), 2)
            for file in files:
                info = file.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode)); self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertEqual(info.st_uid, 0); self.assertEqual(info.st_nlink, 1)
                value = json.loads(file.read_bytes())
                self.assertEqual(value['exit'], 1); self.assertEqual(value['phase'], 'prepared')
                self.assertEqual(value['output']['stderr']['text'], 'fixture-private-reason')
                self.assertTrue(value['no_retry_or_queue_exemption'])

    def test_receipt_collision_never_overwrites_original_or_follows_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary); transaction = self.fixture(root)
            name = transaction.backup / ('native-queue-refusal-' + 'a' * 32 + '.json')
            original = root / 'original'; original.write_bytes(b'original receipt')
            for symlink in (False, True):
                with self.subTest(symlink=symlink):
                    if symlink: name.symlink_to(original)
                    else: name.write_bytes(b'original receipt')
                    with mock.patch.object(upgrade.uuid, 'uuid4', return_value=types.SimpleNamespace(hex='a' * 32)), self.assertRaises(FileExistsError):
                        transaction.record_native_queue_refusal(upgrade.CommandFailure('panel-executor', 1, '', 'fixture'))
                    self.assertEqual(original.read_bytes(), b'original receipt')
                    self.assertEqual(name.read_bytes(), b'original receipt')
                    name.unlink()

    def test_unowned_or_nonprivate_transaction_and_wrong_command_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            transaction = self.fixture(pathlib.Path(temporary))
            transaction.backup.chmod(0o755)
            with self.assertRaises(ValueError):
                transaction.record_native_queue_refusal(upgrade.CommandFailure('panel-executor', 1, '', 'fixture'))
            transaction.backup.chmod(0o700)
            with self.assertRaises(ValueError):
                transaction.record_native_queue_refusal(upgrade.CommandFailure('other-program', 1, '', 'fixture'))
            self.assertEqual(list(transaction.backup.iterdir()), [])

    def test_original_queue_refusal_is_not_retried_or_replaced_by_diagnostic_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary); transaction = self.fixture(root)
            transaction.database = root / 'panel.db'; transaction.db_owner = 0
            with contextlib.closing(sqlite3.connect(transaction.database)) as db, db:
                for table in upgrade.QUEUES: db.execute('CREATE TABLE ' + table + '(id TEXT PRIMARY KEY,state TEXT)')
            transaction.database.chmod(0o600)
            failure = upgrade.CommandFailure('panel-executor', 1, '', 'original-refusal-fixture')
            run = mock.Mock(side_effect=failure); transaction.run_command = run
            before = transaction.database.read_bytes()
            with self.assertRaises(upgrade.CommandFailure) as caught: transaction.queue_check()
            self.assertIs(caught.exception, failure); self.assertEqual(run.call_count, 1)
            self.assertEqual(transaction.database.read_bytes(), before)
            self.assertEqual(len(list(transaction.backup.glob('native-queue-refusal-*.json'))), 1)


if __name__ == '__main__': unittest.main(verbosity=2)
